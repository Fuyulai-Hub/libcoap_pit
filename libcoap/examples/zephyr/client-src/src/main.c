/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(coap_client, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <errno.h>
#include "coap3/coap.h"
#include <stdio.h>

#include <zephyr/net/net_core.h>

#ifdef CONFIG_MBEDTLS
#define COAP_USE_PSK CONFIG_LIBCOAP_PSK_KEY
#define COAP_USE_PSK_ID CONFIG_LIBCOAP_PSK_IDENTITY
#endif /* CONFIG_MBEDTLS */
#define COAP_TARGET_DOMAIN_URI CONFIG_LIBCOAP_TARGET_DOMAIN_URI

const char *coap_uri = COAP_TARGET_DOMAIN_URI;

static int quit;

static int resolve_address(const char *host, const char *service, coap_address_t *dst,
			   int scheme_hint_bits)
{
	uint16_t port = service ? atoi(service) : 0;
	int ret = 0;
	coap_str_const_t str_host;
	coap_addr_info_t *addr_info;

	str_host.s = (const uint8_t *)host;
	str_host.length = strlen(host);
	addr_info = coap_resolve_address_info(&str_host, port, port, port, port, AF_UNSPEC,
					      scheme_hint_bits, COAP_RESOLVE_TYPE_REMOTE);
	if (addr_info) {
		ret = 1;
		*dst = addr_info->addr;
	}

	coap_free_address_info(addr_info);
	return ret;
}

static coap_response_t message_handler(coap_session_t *session, const coap_pdu_t *sent,
				       const coap_pdu_t *received, const coap_mid_t id)
{
	const uint8_t *data;
	size_t len;
	size_t offset;
	size_t total;

	(void)session;
	(void)sent;
	(void)id;
	if (coap_get_data_large(received, &len, &data, &offset, &total)) {
		printf("%*.*s", (int)len, (int)len, (const char *)data);
		if (len + offset == total) {
			printf("\n");
			quit = 1;
		}
	}
	return COAP_RESPONSE_OK;
}

static int coap_client_init(coap_context_t *ctx)
{
	coap_session_t *session = NULL;
	coap_pdu_t *pdu;
	coap_address_t dst;
	coap_mid_t mid;
	int len;
	coap_uri_t uri;
	char portbuf[8];
	coap_optlist_t *optlist = NULL;

#define BUFSIZE 100
	unsigned char buf[BUFSIZE];
	int res;

	/* Parse the URI */
	len = coap_split_uri((const unsigned char *)coap_uri, strlen(coap_uri), &uri);
	if (len != 0) {
		coap_log_warn("Failed to parse uri %s\n", coap_uri);
		goto fail;
	}

	snprintf(portbuf, sizeof(portbuf), "%d", uri.port);
	snprintf((char *)buf, sizeof(buf), "%*.*s", (int)uri.host.length, (int)uri.host.length,
		 (const char *)uri.host.s);
	/* resolve destination address where packet should be sent */
	len = resolve_address((const char *)buf, portbuf, &dst, 1 << uri.scheme);
	if (len <= 0) {
		coap_log_warn("Failed to resolve address %*.*s\n", (int)uri.host.length,
			      (int)uri.host.length, (const char *)uri.host.s);
		goto fail;
	}

	if (uri.scheme == COAP_URI_SCHEME_COAP) {
		session = coap_new_client_session(ctx, NULL, &dst, COAP_PROTO_UDP);
	} else if (uri.scheme == COAP_URI_SCHEME_COAP_TCP) {
		goto fail;
	} else if (uri.scheme == COAP_URI_SCHEME_COAPS_TCP) {
		goto fail;
	} else if (uri.scheme == COAP_URI_SCHEME_COAPS) {
#if defined(COAP_USE_PSK) && defined(COAP_USE_PSK_ID)
		static coap_dtls_cpsk_t dtls_psk;
		static char client_sni[256];

		memset(client_sni, 0, sizeof(client_sni));
		memset(&dtls_psk, 0, sizeof(dtls_psk));
		dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
		if (uri.host.length) {
			memcpy(client_sni, uri.host.s,
			       MIN(uri.host.length, sizeof(client_sni) - 1));
		} else {
			memcpy(client_sni, "localhost", 9);
		}
		dtls_psk.client_sni = client_sni;
		dtls_psk.psk_info.identity.s = (const uint8_t *)COAP_USE_PSK_ID;
		dtls_psk.psk_info.identity.length = strlen(COAP_USE_PSK_ID);
		dtls_psk.psk_info.key.s = (const uint8_t *)COAP_USE_PSK;
		dtls_psk.psk_info.key.length = strlen(COAP_USE_PSK);

		session = coap_new_client_session_psk2(ctx, NULL, &dst, COAP_PROTO_DTLS, &dtls_psk);
#else  /* ! COAP_USE_PSK && ! COAP_USE_PSK_ID */
		coap_log_err("CONFIG_LIBCOAP_USE_PSK and CONFIG_LIBCOAP_USE_PSK_ID not defined\n");
		goto fail;
#endif /* ! COAP_USE_PSK && ! COAP_USE_PSK_ID */
	}

	if (!session) {
		coap_log_warn("Failed to create session\n");
		goto fail;
	}

	coap_register_response_handler(ctx, message_handler);

	/* construct CoAP message */
	pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET, coap_new_message_id(session),
			    coap_session_max_pdu_size(session));
	if (!pdu) {
		coap_log_warn("Failed to create PDU\n");
		goto fail;
	}

	len = coap_uri_into_options(&uri, &dst, &optlist, 1, buf, sizeof(buf));
	if (len) {
		coap_log_warn("Failed to create options\n");
		goto fail;
	}

	/* Add option list (which will be sorted) to the PDU */
	if (optlist) {
		res = coap_add_optlist_pdu(pdu, &optlist);
		if (res != 1) {
			coap_log_warn("Failed to add options to PDU\n");
			goto fail;
		}
	}

	/* and send the PDU */
	mid = coap_send(session, pdu);
	if (mid == COAP_INVALID_MID) {
		coap_log_warn("Failed to send PDU\n");
		goto fail;
	}
	coap_delete_optlist(optlist);
	return 1;

fail:
	coap_delete_optlist(optlist);
	return 0;
}

/* This application itself does nothing as there is net-shell that can be used
 * to monitor things.
 */
int main(void)
{
	LOG_INF("Start application");
	coap_context_t *coap_context;

	/* Initialize libcoap library */
	coap_startup();

	coap_set_log_level(COAP_MAX_LOGGING_LEVEL);

	coap_context = coap_new_context(NULL);
	if (!coap_context) {
		goto fail;
	}
	coap_context_set_block_mode(coap_context, COAP_BLOCK_USE_LIBCOAP);

	/* Set up and initiate client logic */
	coap_client_init(coap_context);
	coap_log_info("libcoap test client started\n");

	/* Keep on processing until response is back in ... */
	while (quit == 0) {
		coap_io_process(coap_context, 1000);
	}
fail:
	/* Clean up library usage so client can be run again */
	coap_free_context(coap_context);

	coap_cleanup();
	exit(0);
}
