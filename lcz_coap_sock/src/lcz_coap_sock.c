/**
 * @file lcz_coap_sock.c
 * @brief
 *
 * Copyright (c) 2020 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(coap_sock, CONFIG_LCZ_COAP_TELEMETRY_LOG_LEVEL);

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/
#include <string.h>
#include <mbedtls/ssl.h>

#include "lcz_coap_sock.h"
#include "attr.h"

/******************************************************************************/
/* Local Constant, Macro and Type Definitions                                 */
/******************************************************************************/
#define p_sock p->fds[0].fd

/******************************************************************************/
/* Local Function Prototypes                                                  */
/******************************************************************************/
static void coap_sock_prepare_fds(sock_info_t *p);
static void coap_sock_clear_fds(sock_info_t *p);

/******************************************************************************/
/* Global Function Definitions                                                */
/******************************************************************************/
void lcz_coap_sock_set_name(sock_info_t *p, const char *const name)
{
	if (p != NULL) {
		p->name = name;
	}
}

void lcz_coap_sock_set_events(sock_info_t *p, int events)
{
	if (p != NULL) {
		p->fds[0].events = events;
	}
}

void lcz_coap_sock_enable_dtls(sock_info_t *p, int (*load_credentials)(void))
{
	if (p != NULL) {
		p->use_dtls = true;
		p->load_credentials = load_credentials;
	}
}

void lcz_coap_sock_disable_dtls(sock_info_t *p)
{
	if (p != NULL) {
		p->use_dtls = false;
	}
}

void lcz_coap_sock_set_tls_tag_list(sock_info_t *p, const sec_tag_t *const list,
				   size_t list_size)
{
	if (p != NULL) {
		p->tls_tag_list = list;
		p->list_size = list_size;
	}
}

int lcz_coap_sock_get(sock_info_t *p)
{
	if (p != NULL) {
		return p_sock;
	} else {
		return -1;
	}
}

bool lcz_coap_sock_valid(sock_info_t *p)
{
	if (p == NULL) {
		return false;
	} else {
		return (p->nfds != 0);
	}
}

int lcz_coap_sock_wait(sock_info_t *p, int timeout)
{
	if (p == NULL) {
		LOG_DBG("Invalid parameters");
		return -EINVAL;
	}

	int r = -EPERM;
	if (p->nfds > 0) {
		r = poll(p->fds, p->nfds, timeout);
		if (r < 0) {
			LOG_ERR("%s Poll Error: -%d", p->name,
				errno);
			r = -errno;
		} else if (r == 0) {
			if (IS_ENABLED(CONFIG_COAP_SOCK_VERBOSE_POLL)) {
				LOG_DBG("%s Poll Timeout", p->name);
			}
			r = -ETIME;
		} else {
			if (IS_ENABLED(CONFIG_COAP_SOCK_VERBOSE_POLL)) {
				LOG_DBG("Wait complete");
			}
			r = 0;
		}
	} else {
		LOG_ERR("Sock not valid");
	}
	return r;
}

static void filter_cipher_list(int fd)
{
	int input_cipher_list[CONFIG_LWM2M_TLS_MAX_CIPHERSUITES];
	int output_cipher_list[CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES - 1];
	uint32_t in_list_len = sizeof(input_cipher_list);
	uint32_t out_list_len = 0;
	const struct mbedtls_ssl_ciphersuite_t *cs;
	int ret;
	int i;

	/* Fetch the current list of ciphers */
	memset(input_cipher_list, 0, sizeof(input_cipher_list));
	ret = getsockopt(fd, SOL_TLS, TLS_CIPHERSUITE_LIST, input_cipher_list, &in_list_len);
	if (ret < 0) {
		LOG_ERR("Could not fetch cipher list (%d). Not filtering.", errno);
	} else {
		if (in_list_len == sizeof(input_cipher_list)) {
			LOG_WRN("Input cipher list is max length, possibly truncated");
		}

		/* Copy PSK ciphers into the output list */
		LOG_DBG("Found %d ciphers", in_list_len / sizeof(int));
		for (i = 0; (i < (in_list_len / sizeof(int))) &&
				(out_list_len < (CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES - 1));
			 i++) {
			cs = mbedtls_ssl_ciphersuite_from_id(input_cipher_list[i]);
			if (mbedtls_ssl_ciphersuite_uses_psk(cs)) {
				output_cipher_list[out_list_len++] = input_cipher_list[i];
			}
		}

		if (out_list_len >= (CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES - 1)) {
			LOG_WRN("Output cipher list is max length, possibly truncated");
		}

		/* Set the new cipher list */
		ret = setsockopt(fd, SOL_TLS, TLS_CIPHERSUITE_LIST, output_cipher_list,
				 (out_list_len * sizeof(int)));
		if (ret < 0) {
			LOG_ERR("Could not set filtered list: %d", errno);
		} else {
			LOG_DBG("Successfully set new cert ciphers %d", out_list_len);
		}
	}
}

int lcz_coap_sock_udp_start(sock_info_t *p, struct sockaddr *addr, bool hostname_verify, const char *hostname, bool peer_verify)
{
	if (p == NULL || addr == NULL) {
		LOG_DBG("Invalid parameters");
		return -EINVAL;
	}

	if (lcz_coap_sock_valid(p)) {
		LOG_DBG("Sock already open");
		return -EALREADY;
	}

	int status = -EPERM;
	memcpy(&p->host_addr, addr, sizeof(struct sockaddr));
	if (p->use_dtls) {
		if (p->load_credentials != NULL) {
			status = p->load_credentials();
			if (status < 0) {
				return status;
			}
		} 
	}

	if (p->use_dtls) {
		p_sock = socket(p->host_addr.sa_family, SOCK_DGRAM,
				IPPROTO_DTLS_1_2);
	} else {
		p_sock =
			socket(p->host_addr.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	}

	if (p_sock < 0) {
		LOG_ERR("Failed to create socket: -%d", errno);
		return -errno;
	}

	if (p->use_dtls) {
		status = setsockopt(p_sock, SOL_TLS, TLS_SEC_TAG_LIST,
					p->tls_tag_list, p->list_size);
		if (status < 0) {
			LOG_ERR("Failed to set TLS_SEC_TAG_LIST option: -%d",
				errno);
			return -errno;
		}

		int peer_verify_mode = TLS_PEER_VERIFY_NONE;
		if(peer_verify) {
			peer_verify_mode = TLS_PEER_VERIFY_REQUIRED;
			LOG_DBG("TLS Peer verify required");
		} else {
			LOG_DBG("TLS Peer verify disabled");
		}
		setsockopt(p_sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify_mode, sizeof(peer_verify_mode));

		if (hostname_verify && hostname != NULL) {
			status = setsockopt(p_sock, SOL_TLS, TLS_HOSTNAME, hostname,
						strlen(hostname) + 1);
		} else {
			status = setsockopt(p_sock, SOL_TLS, TLS_HOSTNAME, NULL,
						1);
		}

		if (status < 0) {
			LOG_ERR("Unable to set socket host name '%s': -%d",
				hostname ? hostname : "null", errno);
			return -errno;
		} else {
			LOG_DBG("Set DTLS socket host name: %s",
				hostname ? hostname : "null (disabled)");
		}
	}

	/*
	* If we're using PSK credenentials for DTLS, limit the list of
	* ciphers to just those that support PSK.
	*/
	uint8_t security =
		attr_get_uint32(ATTR_ID_coap_telemetry_security, COAP_TELEMETRY_SECURITY_CERT);

	if (security == COAP_TELEMETRY_SECURITY_PSK) {
		filter_cipher_list(p_sock);
	}

	if (connect(p_sock, &p->host_addr, NET_SOCKADDR_MAX_SIZE) < 0) {
		LOG_ERR("Cannot connect UDP: -%d", errno);
		return -errno;
	} else {
		coap_sock_prepare_fds(p);
	}

	return 0;
}

int lcz_coap_sock_close(sock_info_t *p)
{
	LOG_DBG("Closing socket");
	if (p == NULL) {
		LOG_DBG("Invalid parameters");
		return -EINVAL;
	}

	coap_sock_clear_fds(p);
	return close(p_sock);
}

int lcz_coap_sock_send(sock_info_t *p, void *data, size_t length, int flags)
{
	if (p == NULL || data == NULL) {
		LOG_DBG("Invalid parameters");
		return -EINVAL;
	}

	int r = send(p_sock, data, length, flags);
	if (r < 0) {
		LOG_ERR("Unable to send: %d", r);
	}
	return r;
}

int lcz_coap_sock_receive(sock_info_t *p, void *data, size_t max_size,
			 int timeout_ms)
{
	if (p == NULL || data == NULL) {
		LOG_DBG("Invalid parameters");
		return -EINVAL;
	}

	memset(data, 0, max_size);

#ifdef CONFIG_COAP_SOCK_TIMING
	uint32_t start_time = k_cycle_get_32();
#endif

	LOG_DBG("lcz_coap_sock_wait %d", timeout_ms);
	(void)lcz_coap_sock_wait(p, timeout_ms);

	int count = recv(p_sock, data, max_size, MSG_DONTWAIT);
	if (count == 0) {
		LOG_ERR("No data received");
		count = -ENODATA;
	} else if (count < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LOG_ERR("Would Block");
			count = -errno;
		} else {
			LOG_ERR("Receive Error");
			count = -errno;
		}
	} else {
		LOG_DBG("%u bytes rxed", count);
	}
#ifdef CONFIG_COAP_SOCK_TIMING
	uint32_t stop_time = k_cycle_get_32();
	LOG_DBG("wait ticks: %u", stop_time - start_time);
#endif
	return count;
}

/******************************************************************************/
/* Local Function Definitions                                                 */
/******************************************************************************/
/* set the number of sockets to 1 */
static void coap_sock_prepare_fds(sock_info_t *p)
{
	if (p != NULL) {
		p->nfds = 1;
	}
}

static void coap_sock_clear_fds(sock_info_t *p)
{
	if (p != NULL) {
		p->nfds = 0;
	}
}
