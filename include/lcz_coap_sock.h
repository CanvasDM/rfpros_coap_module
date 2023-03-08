/**
 * @file lcz_coap_sock.h
 * @brief Wrapper for single socket.
 *
 * Copyright (c) 2020 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */
#ifndef __LCZ_COAP_SOCK_H__
#define __LCZ_COAP_SOCK_H__

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/
#include <kernel.h>
#include <stddef.h>
#include <net/socket.h>
#include <net/tls_credentials.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/* Global Constants, Macros and Type Definitions                              */
/******************************************************************************/
#define SINGLE_SOCK 1

typedef struct sock_info {
	struct pollfd fds[SINGLE_SOCK];
	int nfds;
	const char *name;
	struct sockaddr host_addr;
	bool use_dtls;
	int (*load_credentials)(void);
	const sec_tag_t *tls_tag_list;
	size_t list_size;
} sock_info_t;

/******************************************************************************/
/* Global Function Prototypes                                                 */
/******************************************************************************/
/**
 * @brief Set the name
 *
 * @param p pointer to sock information
 * @param name of socket for debug printing
 */
void lcz_coap_sock_set_name(sock_info_t *p, const char *const name);

/**
 * @brief Set the type of events to poll for
 *
 * @param p pointer to sock information
 * @param events that should be polled for
 */
void lcz_coap_sock_set_events(sock_info_t *p, int events);

/**
 * @brief Enable DTLS for the socket.
 *
 * @param p pointer to sock information
 * @param load_credentials is an optional callback that will be called when
 * starting socket.
 */
void lcz_coap_sock_enable_dtls(sock_info_t *p, int (*load_credentials)(void));

/**
 * @brief Disable DTLS for a socket.
 *
 * @param p pointer to sock information
 */
void lcz_coap_sock_disable_dtls(sock_info_t *p);

/**
 * @brief Set the security tag list used for a DTLS socket.
 *
 * @param p pointer to sock information
 * @param list array of tags
 * @param list_size size of the list in bytes.
 */
void lcz_coap_sock_set_tls_tag_list(sock_info_t *p, const sec_tag_t *const list,
				   size_t list_size);
/**
 * @brief Accessor function.
 *
 * @param p pointer to sock information
 *
 * @retval true if the sock is valid.
 */
bool lcz_coap_sock_valid(sock_info_t *p);

/**
 * @brief Accessor function.
 *
 * @param p pointer to sock information
 *
 * @retval fds[0].fd
 */
int lcz_coap_sock_get(sock_info_t *p);

/**
 * @brief Wait on a socket
 *
 * @param p pointer to sock information
 * @param timeout in milliseconds
 *
 * @retval negative error code, 0 on success
 */
int lcz_coap_sock_wait(sock_info_t *p, int timeout);

/**
 * @brief Start a socket
 *
 * @param p pointer to sock information
 * @param addr of host
 * @param hostname_verify is a flag indicating whether TLS hostname option should be enabled or not.
 * @param hostname is the hostname. If null then host verification is disabled.
 * @param peer_verify is a flag indicating whether TLS peer verify should be enabled or not.
 *
 * @retval negative error code, 0 on success.
 */
int lcz_coap_sock_udp_start(sock_info_t *p, struct sockaddr *addr, bool hostname_verify,
			const char *hostname, bool peer_verify);

/**
 * @brief Close a socket.
 *
 * @param p pointer to sock information
 *
 * @retval negative error code, 0 on success.
 */
int lcz_coap_sock_close(sock_info_t *p);

/**
 * @brief Send data
 *
 * @param p pointer to sock information
 * @param data pointer to data
 * @param length of data
 * @param flags @ref send
 *
 * @retval negative error code, number of bytes sent on success
 */
int lcz_coap_sock_send(sock_info_t *p, void *data, size_t length, int flags);

/**
 * @brief Wrapper function for receiving data from a sock (poll then recv).
 *
 * @param p pointer to sock information
 * @param data pointer to buffer for received data
 * @param max_size of received data
 * @param timeout_ms is how long to wait for data before returning an error.
 *
 * @note Enable CONFIG_COAP_SOCK_TIMING to print socket timing.
 * @retval negative error code, bytes received on success.
 */
int lcz_coap_sock_receive(sock_info_t *p, void *data, size_t max_size,
			 int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_COAP_SOCK_H__ */
