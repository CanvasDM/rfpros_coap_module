/*
 * @file lcz_coap_telemetry.c
 * @brief
 *
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2020-2023 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(coap_telemetry, CONFIG_LCZ_COAP_TELEMETRY_LOG_LEVEL);

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/
#include <zephyr.h>
#include <errno.h>
#include <sys/byteorder.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <fs/fs.h>

#include <net/socket.h>
#include <net/net_mgmt.h>
#include <net/net_ip.h>
#include <net/udp.h>
#include <net/coap.h>
#include <net/tls_credentials.h>
#include <mbedtls/ssl.h>

#include "file_system_utilities.h"
#include "lcz_dns.h"
#include "lcz_coap_sock.h"
#include "lcz_coap_telemetry.h"
#include "attr.h"
#include "led_config.h"
#include "lcz_pki_auth.h"
#include "lcz_memfault.h"

/******************************************************************************/
/* Local Constant, Macro and Type Definitions                                 */
/******************************************************************************/
#define TAKE_MUTEX(m) k_mutex_lock(&m, K_FOREVER)
#define GIVE_MUTEX(m) k_mutex_unlock(&m)

#define URL_PROTO_HTTPS_LEN 5
#define URL_PROTO_HTTP_LEN 4
#define URL_PROTO_HTTP "http"
#define URL_PROTO_COAPS_LEN 5
#define URL_PROTO_COAP_LEN 4
#define URL_PROTO_COAP "coap"

#define COAP2COAP_PROXY_URI_PATH "coap2coap"
#define COAP2HTTP_PROXY_URI_PATH "coap2http"

static const sec_tag_t COAP_TELEMETRY_TLS_TAG_LIST[] = {
	CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG
};

#define BREAK_ON_ERROR(x)                                                                          \
	if (x < 0) {                                                                               \
		LOG_ERR("r: %d", x);\
break;                                                                             \
	}

typedef struct coap_telemetry {
	bool credentials_loaded;
	sock_info_t sock_info;

	struct coap_packet request;
	uint8_t request_data[CONFIG_LCZ_COAP_TELEMETRY_MAX_REQUEST_SIZE];

	struct coap_block_context block_context;
	char server_addr[CONFIG_DNS_RESOLVER_ADDR_MAX_SIZE];

	struct coap_packet reply;
	uint8_t reply_buffer[CONFIG_LCZ_COAP_TELEMETRY_MAX_RESPONSE_SIZE];
	int reply_length;
	uint16_t reply_payload_length;
	const uint8_t *reply_payload_ptr;
} coap_telemetry_t;

static sys_slist_t callback_list;

/**************************************************************************************************/
/* Global Data Definitions                                                                        */
/**************************************************************************************************/
K_MUTEX_DEFINE(lcz_coap_mutex);
K_MUTEX_DEFINE(lcz_coap_tx_mutex);

/******************************************************************************/
/* Local Data Definitions                                                     */
/******************************************************************************/
static coap_telemetry_t cf;

//need PSK to be in static memory to be used by TLS
static char *psk_id = "";
static uint8_t *psk = NULL;
/******************************************************************************/
/* Local Function Prototypes                                                  */
/******************************************************************************/
static int process_coap_reply(lcz_coap_telemetry_query_t *p);
static void issue_rx_callback(lcz_coap_telemetry_query_t *pReq, const uint8_t *pReplyPayload,
			      uint16_t replyPayloadLength);
static void coap_hexdump(const uint8_t *str, const uint8_t *packet,
			 size_t length);
static void coap_stop_client(void);
static int coap_load_cred(void);
static int coap_start_client(lcz_coap_telemetry_query_t *p);

static int send_post(lcz_coap_telemetry_query_t *p);

static int packet_start(lcz_coap_telemetry_query_t *p, uint8_t method);
static int packet_init(uint8_t method);
static int packet_build_ack_from_con(uint8_t code);
static int packet_append_uri_path(const uint8_t *path);
static int get_payload(void);

static void handle_coap_response(lcz_coap_telemetry_query_t *p);
static int coap_addr(struct sockaddr *addr, const uint8_t *peer_name,
		     const uint16_t peer_port);
static bool valid_string_parameter(const char *str);

/******************************************************************************/
/* Global Function Definitions                                                */
/******************************************************************************/
void lcz_coap_telemetry_init(void)
{
	lcz_coap_sock_set_name(&cf.sock_info, "coap_telemetry");
	lcz_coap_sock_set_events(&cf.sock_info, POLLIN);
}

void lcz_coap_register_user(struct lcz_coap_user *user)
{
	k_mutex_lock(&lcz_coap_mutex, K_FOREVER);
	sys_slist_append(&callback_list, &user->node);
	k_mutex_unlock(&lcz_coap_mutex);
}

int lcz_coap_telemetry_post(lcz_coap_telemetry_query_t *p)
{
	if (p == NULL) {
		return -EPERM;
	}

	int r = 0;
	while (1) {
		r = coap_start_client(p);
		if(r) {
			LOG_ERR("coap_start_client err %d", r);
		}
		BREAK_ON_ERROR(r);

		r = send_post(p);
		if(r < 0) {
			LOG_ERR("send_post err %d", r);
		}
		BREAK_ON_ERROR(r);

		r = process_coap_reply(p);
		BREAK_ON_ERROR(r);

		int r2 = get_payload();
		if(r2 == 0) {
			handle_coap_response(p);
		}

		if (r < 0) {
			LOG_WRN("Did not receive ACK");
		} else {
			LOG_INF("CoAP Post success");
		}
		break;
	}

	(void)coap_stop_client();
	return r;
}

void lcz_coap_telemetry_reset_creds(void)
{
	cf.credentials_loaded = false;
}

int lcz_coap_certs_unload(void)
{   
	tls_credential_delete(CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG, TLS_CREDENTIAL_PSK_ID);
	tls_credential_delete(CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG, TLS_CREDENTIAL_PSK);

	lcz_pki_auth_tls_credential_unload(LCZ_PKI_AUTH_STORE_TELEMETRY,
					   CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG);

	if(psk) {
		k_free(psk);
	}

	return 0;
}

/******************************************************************************/
/* Local Function Definitions                                                 */
/******************************************************************************/

static int process_coap_reply(lcz_coap_telemetry_query_t *p)
{
	int r = 0;
	while (1) {
		r = lcz_coap_sock_receive(&cf.sock_info, &cf.reply_buffer, sizeof(cf.reply_buffer),
					  CONFIG_LCZ_COAP_TELEMETRY_RESPONSE_TIMEOUT_MS);
		BREAK_ON_ERROR(r);
		cf.reply_length = r;

		coap_hexdump("Response", cf.reply_buffer, cf.reply_length);

		r = coap_packet_parse(&cf.reply, cf.reply_buffer,
					  (uint16_t)cf.reply_length, NULL, 0);
		BREAK_ON_ERROR(r);

		/* The CoAP bridge acks the request and then forwards it on. */
		uint8_t type = coap_header_get_type(&cf.reply);
		bool is_ack = (type == COAP_TYPE_ACK);
		if (is_ack) {
			if(cf.reply_length == COAP_MIN_HDR_SIZE) {
				LOG_INF("ACK received, no data");
			} else {
				LOG_INF("ACK received with data length %d", cf.reply_length - COAP_MIN_HDR_SIZE);
			}
			r = 0;
			break;
		} else {
			/* Confirmed responses require an ACK. */
			if (type == COAP_TYPE_CON) {
				uint8_t code = coap_header_get_code(&cf.reply);
				int r2 = packet_build_ack_from_con(code);
				if (r2 == 0) {
					r2 = lcz_coap_sock_send(&cf.sock_info,
							  cf.request.data,
							  cf.request.offset, 0);
				}
				LOG_DBG("Sent Ack for received Con (%d)", r2);
			} else {
				LOG_DBG("RX unknown type %d", type);
			}
			
			r = -EBADMSG;//did not receive an ACK so return error 
			break;
		}
	}
	return r;
}

static void issue_rx_callback(lcz_coap_telemetry_query_t *pReq, const uint8_t *pReplyPayload,
			      uint16_t replyPayloadLength)
{
	struct lcz_coap_user *iterator;

	k_mutex_lock(&lcz_coap_mutex, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER (&callback_list, iterator, node) {
		if (iterator->rx_callback != NULL) {
			iterator->rx_callback(pReq, pReplyPayload, replyPayloadLength);
		}
	}
	k_mutex_unlock(&lcz_coap_mutex);
}

static void coap_hexdump(const uint8_t *str, const uint8_t *packet,
			 size_t length)
{
#ifdef CONFIG_LCZ_COAP_TELEMETRY_HEXDUMP
if	 (packet == NULL) {
		LOG_INF("%s NULL packet", str);
		return;
	}

	if (!length) {
		LOG_INF("%s zero-length packet", str);
		return;
	} else {
		LOG_INF("%s length: %u", str, length);
	}

	LOG_HEXDUMP_INF(packet, length, str);
#else
	ARG_UNUSED(packet);
	LOG_INF("%s length: %u", str, length);
#endif
}

static void coap_stop_client(void)
{
	lcz_coap_sock_close(&cf.sock_info);
	
	int ret = GIVE_MUTEX(lcz_coap_tx_mutex);
	LOG_DBG("Give coap mutex %s, %d", k_thread_name_get(k_current_get()), ret);
}

static int coap_load_cred(void)
{
	if (cf.credentials_loaded) {
		LOG_INF("Credentials already loaded");
		return 0;
	}

	int r = 0;

	uint8_t security =
		attr_get_uint32(ATTR_ID_coap_telemetry_security, COAP_TELEMETRY_SECURITY_CERT);

	if (security == COAP_TELEMETRY_SECURITY_PSK) {
		if(psk == NULL) {
			psk = k_malloc(MBEDTLS_PSK_MAX_LEN);
		}

		if(psk) {
			psk_id = (char *)attr_get_quasi_static(ATTR_ID_coap_telemetry_psk_id);
			attr_get(ATTR_ID_coap_telemetry_psk, psk, sizeof(psk));

			/* ignore error value */
			tls_credential_delete(CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG, TLS_CREDENTIAL_PSK_ID);

			LOG_INF("Loading CoAP Telemetry PSK ID and PSK");
			r = tls_credential_add(CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG, TLS_CREDENTIAL_PSK_ID,
						psk_id, strlen(psk_id));
			if (r < 0) {
				LOG_ERR("Failed to add %s: %d", "psk id", r);
				return r;
			}

			/* ignore error value */
			tls_credential_delete(CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG, TLS_CREDENTIAL_PSK);

			// LOG_HEXDUMP_DBG(psk, 32, "Loading CoAP Telemetry PSK");
			r = tls_credential_add(CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG, TLS_CREDENTIAL_PSK, psk,
						sizeof(psk));
			if (r < 0) {
				LOG_ERR("Failed to add %s: %d", "psk", r);
				return r;
			}
		} else {
			r = -ENOMEM;
		}
	} else if (security == COAP_TELEMETRY_SECURITY_CERT) {
		LOG_INF("Loading CoAP Telemetry certificates");
		// use telemetry certs (hydrantid) once enabled by coap server
		r = lcz_pki_auth_tls_credential_load(LCZ_PKI_AUTH_STORE_TELEMETRY,
		CONFIG_LCZ_COAP_TELEMETRY_CLIENT_TAG,
		false);
		
		if (r < 0) {
			LOG_ERR("Failed to add telemetry certs: %d" , r);
			return r;
		}
	} else {
		LOG_ERR("Unsupported security type %d", security);
		r = -ENOTSUP;
	}

	if(!r) {
		//If no errors are detected, set flag to true to indicate credentials are loaded and subsequent connections
		//do not need to re-load.
		cf.credentials_loaded = true;
	}
	return r;
}

static int coap_start_client(lcz_coap_telemetry_query_t *p)
{
	int r = -EPERM;

	LOG_DBG("Take coap mutex %s", k_thread_name_get(k_current_get()));
	TAKE_MUTEX(lcz_coap_tx_mutex);

	if (p->dtls) {
		lcz_coap_sock_enable_dtls(&cf.sock_info, coap_load_cred);
		lcz_coap_sock_set_tls_tag_list(&cf.sock_info, COAP_TELEMETRY_TLS_TAG_LIST,
			sizeof(COAP_TELEMETRY_TLS_TAG_LIST));
	} else {
		lcz_coap_sock_disable_dtls(&cf.sock_info);
	}

	struct sockaddr addr;
	memset(&addr, 0, sizeof(addr));
	r = coap_addr(&addr, p->domain, p->port);
	if (r >= 0) {
		r = lcz_coap_sock_udp_start(&cf.sock_info, &addr, p->hostname_verify, p->domain, p->peer_verify);
		if(r == 0){
		} else {
#ifndef CONFIG_LCZ_BLE_GW_DM_DEVICE_MANAGEMENT_STATUS_LED
			//if DM task is not controlling LED, then application can
			lcz_led_turn_off(DM_LED);
			MFLT_METRICS_TIMER_START(cloud_ttf);
#endif
		}
	}

	return r;
}

/* Example:
 * POST coaps:\\<coap_telemetry_endpoint>\p->path <data>
 */
static int send_post(lcz_coap_telemetry_query_t *p)
{
	int r = 0;
	char *cursor;

	while (1) {
		r = packet_start(p, COAP_METHOD_POST);
		BREAK_ON_ERROR(r);

		//Add proxy uri if needed
		if (strlen(p->proxy_url) > 0) {
			if (strlen(p->proxy_url) >= URL_PROTO_HTTPS_LEN &&
				strncasecmp(p->proxy_url, URL_PROTO_HTTP, URL_PROTO_HTTP_LEN) == 0) {
				cursor = COAP2HTTP_PROXY_URI_PATH;
			} else if (strlen(p->proxy_url) >= URL_PROTO_COAPS_LEN &&
				   strncasecmp(p->proxy_url, URL_PROTO_COAP, URL_PROTO_COAP_LEN) ==
					   0) {
				cursor = COAP2COAP_PROXY_URI_PATH;
			} else {
				r = -EPROTONOSUPPORT;
				LOG_ERR("Unsupported protocol in URL: %s", p->proxy_url);
				BREAK_ON_ERROR(r);
			}

			r = coap_packet_append_option(&cf.request, COAP_OPTION_URI_PATH, cursor,
							strlen(cursor));
			if (r < 0) {
				LOG_ERR("Error adding URI_PATH '%s'", cursor);
				BREAK_ON_ERROR(r);
			}

			r = coap_packet_append_option(&cf.request, COAP_OPTION_PROXY_URI,
							p->proxy_url, strlen(p->proxy_url));
			if (r < 0) {
				LOG_ERR("Error adding PROXY_URI '%s'", p->proxy_url);
				BREAK_ON_ERROR(r);
			} else {
				LOG_INF("Coap Proxy Route %s", p->proxy_url);		
			}
		} else {
			if(p->path != NULL || strlen(p->path) != 0) {
				//if no proxy is specified, add topic if non-null
				LOG_INF("CoAP proxy not used, add topic %s", p->path);
				//Add includes URI path from query structure
				r = packet_append_uri_path(p->path);
				BREAK_ON_ERROR(r);
			}
		}

		if (p->dataLen > 0) {
			r = coap_packet_append_payload_marker(&cf.request);
			if (r < 0) {
				LOG_ERR("Unable to append payload marker");
			}
			BREAK_ON_ERROR(r);

			r = coap_packet_append_payload(&cf.request, p->pData, p->dataLen);
			if (r < 0) {
				LOG_ERR("Not able to append payload");
			}
			BREAK_ON_ERROR(r);
		}
		
		coap_hexdump("Sensor Data Request", cf.request.data, cf.request.offset);

		r = lcz_coap_sock_send(&cf.sock_info, cf.request.data,
				  cf.request.offset, 0);
		BREAK_ON_ERROR(r);
		break;
	}
	return r;
}

static int packet_start(lcz_coap_telemetry_query_t *p, uint8_t method)
{
	int r = 0;

	while (1) {
		r = packet_init(method);
		BREAK_ON_ERROR(r);

		break;
	}
	return r;
}

static int packet_init(uint8_t method)
{
	int r = coap_packet_init(&cf.request, cf.request_data,
				 sizeof(cf.request_data), COAP_VERSION,
				 COAP_TYPE_CON, COAP_TOKEN_SIZE,
				 coap_next_token(), method, coap_next_id());
	if (r < 0) {
		LOG_ERR("Failed to init CoAP message");
	}
	return r;
}

static int packet_build_ack_from_con(uint8_t code)
{
	uint8_t token[COAP_TOKEN_SIZE];
	uint8_t tkl = coap_header_get_token(&cf.reply, token);
	int r = coap_packet_init(&cf.request, cf.request_data,
				 sizeof(cf.request_data), COAP_VERSION,
				 COAP_TYPE_ACK, tkl, token, code,
				 coap_header_get_id(&cf.reply));
	if (r < 0) {
		LOG_ERR("Failed to build CoAP ACK");
	}
	return r;
}

static int packet_append_uri_path(const uint8_t *path)
{
	int r = 0;
	if (valid_string_parameter(path)) {
		uint8_t *s1 = (uint8_t *)path;
		uint8_t *s2 = NULL;
		uint8_t *end = (uint8_t *)path + strlen(path);
		do {
			if (s1 != NULL) {
				s2 = strchr(s1 + 1,
						COAP_TELEMETRY_QUERY_URI_PATH_DELIMITER);
			}
			if (s2 == NULL) {
				s2 = end;
			}
			r = coap_packet_append_option(
				&cf.request, COAP_OPTION_URI_PATH, s1, s2 - s1);
			if (r < 0) {
				LOG_ERR("Unable add URI path to request");
			} else if (true) {
				LOG_DBG("Adding %u chars of '%s' to URI path",
					s2 - s1, s1);
			}
			if (s2 != end) {
				s1 = s2 + 1;
			}
		} while (s1 && (s2 != end) && (r >= 0));
	}
	return r;
}

static int get_payload(void)
{
	int r = 0;
	cf.reply_payload_length = 0;
	cf.reply_payload_ptr =
		coap_packet_get_payload(&cf.reply, &cf.reply_payload_length);
	if (cf.reply_payload_ptr == NULL || cf.reply_payload_length == 0) {
		LOG_DBG("No payload");
		r = -1;
	} else {
		LOG_INF("payload length: %u", cf.reply_payload_length);
		r = 0;
	}
	return r;
}

static void handle_coap_response(lcz_coap_telemetry_query_t *p)
{
	issue_rx_callback(p, cf.reply_payload_ptr, cf.reply_payload_length);
}

static int coap_addr(struct sockaddr *addr, const uint8_t *peer_name,
			 const uint16_t peer_port)
{
	if (peer_name == NULL) {
		return -EPERM;
	}

	struct addrinfo *dns_result;
	struct addrinfo hints = {
#if defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_IPV4)
		.ai_family = AF_UNSPEC,
#elif defined(CONFIG_NET_IPV6)
		.ai_family = AF_INET6,
#elif defined(CONFIG_NET_IPV4)
		.ai_family = AF_INET,
#else
		.ai_family = AF_UNSPEC
#endif /* defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_IPV4) */
		.ai_socktype = SOCK_DGRAM
	};

	int r = 0;
	while (1) {
		r = dns_resolve_server_addr((char *)peer_name, NULL, &hints,
						&dns_result);
		BREAK_ON_ERROR(r);

		r = dns_build_addr_string(cf.server_addr, dns_result);
		if (r == 0) {
			LOG_INF("Resolved %s into %s", peer_name,
				cf.server_addr);
		} else {
			break;
		}

		addr->sa_family = dns_result->ai_family;
		if (dns_result->ai_family == AF_INET6) {
			r = net_addr_pton(dns_result->ai_family, cf.server_addr,
					  &net_sin6(addr)->sin6_addr);
			net_sin6(addr)->sin6_port = htons(peer_port);
		} else if (dns_result->ai_family == AF_INET) {
			r = net_addr_pton(dns_result->ai_family, cf.server_addr,
					  &net_sin(addr)->sin_addr);
			net_sin(addr)->sin_port = htons(peer_port);
		}
		if (r < 0) {
			LOG_ERR("Failed to convert resolved address");
		}
		break;
	}

	freeaddrinfo(dns_result);
	return r;
}

static bool valid_string_parameter(const char *str)
{
	if (str != NULL) {
		if (strlen(str) > 0) {
			return true;
		}
	}
	return false;
}
