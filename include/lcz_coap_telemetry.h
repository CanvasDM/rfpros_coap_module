/**
 * @file lcz_coap_telemetry.h
 * @brief Communicates with the CoAP bridge to perform firmware updates
 * over the cellular connection.
 *
 * Copyright (c) 2020-2023 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */
#ifndef __LCZ_COAP_TELEMETRY_H__
#define __LCZ_COAP_TELEMETRY_H__

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/
#include <zephyr/types.h>
#include <stddef.h>

#include "fwk_includes.h"

/* Allow path to contain multiple pieces without using array of pointers */
#define COAP_TELEMETRY_QUERY_URI_PATH_DELIMITER '/'

#define COAP_VERSION 1
#define COAP_PAYLOAD_MARKER 0xFF
#define COAP_MIN_HDR_SIZE 4
#define COAP_TOKEN_SIZE 0
#define COAP_ACK_MSG_SIZE COAP_MIN_HDR_SIZE
#define COAP_CON_MSG_SIZE (COAP_MIN_HDR_SIZE + COAP_TOKEN_SIZE)

/******************************************************************************/
/* Global Function Prototypes                                                 */
/******************************************************************************/

/* Empty strings and negative numbers will not be added to CoAP query */
typedef struct lcz_coap_telemetry_query {
	bool dtls;
	uint16_t port;
	int32_t block_size;
	const char *domain;
	const char *path;
	char proxy_url[CONFIG_COAP_EXTENDED_OPTIONS_LEN_VALUE];
	bool peer_verify;
	bool hostname_verify;
	uint8_t *pData;
	uint16_t dataLen;   
    
	/* response data - set by coap query size */
	int32_t last_coll_time;
	uint32_t last_coll_dev;

} lcz_coap_telemetry_query_t;

struct lcz_coap_user {
	sys_snode_t node;
	/* Callback that occurs when CoAP client has received message.
     * When no data is received, the rx_callback is not called.
	 *
	 * A user/node is required for each simultaneous outstanding message.
	 */
	void (*rx_callback)(lcz_coap_telemetry_query_t *pReq, const uint8_t *pReplyPayload, uint16_t reply_payload_length);
};

/**
 * @brief Initialize CoAP Telemetry module.
 */
void lcz_coap_telemetry_init(void);

/*
 * Register callback structure
 *
 * @param user Pointer to static callback structure (linked list node)
 */
void lcz_coap_register_user(struct lcz_coap_user *user);

/**
 * @brief Send a COAP post with or without data
 *
 */
int lcz_coap_telemetry_post(lcz_coap_telemetry_query_t *p);

/**
 * @brief Reset CoAP credentials (will be reloaded on next transfer)
 *
 */
void lcz_coap_telemetry_reset_creds(void);

/**
 * @brief Delete CoAP credentials
 *
 */
int lcz_coap_certs_unload(void);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_COAP_TELEMETRY_H__ */
