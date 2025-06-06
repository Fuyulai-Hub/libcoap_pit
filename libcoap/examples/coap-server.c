/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 *
 * Copyright (C) 2010--2025 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef R_OK
#define R_OK 4
#endif
char *strndup(const char *s1, size_t n);
char *
strndup(const char *s1, size_t n) {
  char *copy = (char *)malloc(n + 1);
  if (copy) {
    memcpy(copy, s1, n);
    copy[n] = 0;
  }
  return copy;
}
#include <io.h>
#define access _access
#define fileno _fileno
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <syslog.h>
#endif

/* Need to refresh time once per sec */
#define COAP_RESOURCE_CHECK_TIME 1

#include <coap3/coap.h>
#include <coap3/coap_defines.h>

#if COAP_THREAD_SAFE
/* Define the number of coap_io_process() threads required */
#ifndef NUM_SERVER_THREADS
#define NUM_SERVER_THREADS 3
#endif /* NUM_SERVER_THREADS */
#endif /* COAP_THREAD_SAFE */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static coap_oscore_conf_t *oscore_conf;
static int doing_oscore = 0;
static int doing_tls_engine = 0;
static char *tls_engine_conf = NULL;
static int ec_jpake = 0;

/* set to 1 to request clean server shutdown */
static volatile int quit = 0;

/* set to 1 if persist information is to be kept on server shutdown */
static int keep_persist = 0;

/* changeable clock base (see handle_put_time()) */
static time_t clock_offset;
static time_t my_clock_base = 0;

coap_resource_t *time_resource = NULL;

static int resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_CON;
static int track_observes = 0;

/*
 * For PKI, if one or more of cert_file, key_file and ca_file is in PKCS11 URI
 * format, then the remainder of cert_file, key_file and ca_file are treated
 * as being in DER format to provide consistency across the underlying (D)TLS
 * libraries.
 */
static char *cert_file = NULL; /* certificate and optional private key in PEM,
                                  or PKCS11 URI*/
static char *key_file = NULL; /* private key in PEM, DER or PKCS11 URI */
static char *pkcs11_pin = NULL; /* PKCS11 pin to unlock access to token */
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM,
                                  DER or PKCS11 URI */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int use_pem_buf = 0; /* Map these cert/key files into memory to test
                               PEM_BUF logic if set */
static int is_rpk_not_cert = 0; /* Cert is RPK if set */
/* Used to hold initial PEM_BUF setup */
static uint8_t *cert_mem_base = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *key_mem_base = NULL; /* private key in PEM_BUF */
static uint8_t *ca_mem_base = NULL;   /* CA for cert checking in PEM_BUF */
/* Used for verify_pki_sni_callback PEM_BUF temporary holding */
static uint8_t *cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *key_mem = NULL; /* private key in PEM_BUF */
static uint8_t *ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t key_mem_len = 0;
static size_t ca_mem_len = 0;
static int verify_peer_cert = 1; /* PKI granularity - by default set */
static int no_trust_store = 0; /* Trust store not to be installed. */
#define MAX_KEY   64 /* Maximum length of a pre-shared key in bytes. */
static uint8_t *key = NULL;
static ssize_t key_length = 0;
int key_defined = 0;
static const char *hint = "CoAP";
static int support_dynamic = 0;
static uint32_t block_mode = COAP_BLOCK_USE_LIBCOAP;
static int echo_back = 0;
static uint32_t csm_max_message_size = 0;
static size_t extended_token_size = COAP_TOKEN_DEFAULT_MAX;
static coap_proto_t use_unix_proto = COAP_PROTO_NONE;
static int enable_ws = 0;
static int ws_port = 80;
static int wss_port = 443;
static uint32_t reconnect_secs = 0;

static coap_dtls_pki_t *setup_pki(coap_context_t *ctx, coap_dtls_role_t role, char *sni);

typedef struct psk_sni_def_t {
  char *sni_match;
  coap_bin_const_t *new_key;
  coap_bin_const_t *new_hint;
} psk_sni_def_t;

typedef struct valid_psk_snis_t {
  size_t count;
  psk_sni_def_t *psk_sni_list;
} valid_psk_snis_t;

static valid_psk_snis_t valid_psk_snis = {0, NULL};

typedef struct id_def_t {
  char *hint_match;
  coap_bin_const_t *identity_match;
  coap_bin_const_t *new_key;
} id_def_t;

typedef struct valid_ids_t {
  size_t count;
  id_def_t *id_list;
} valid_ids_t;

static valid_ids_t valid_ids = {0, NULL};
typedef struct pki_sni_def_t {
  char *sni_match;
  char *new_cert;
  char *new_ca;
} pki_sni_def_t;

typedef struct valid_pki_snis_t {
  size_t count;
  pki_sni_def_t *pki_sni_list;
} valid_pki_snis_t;

static valid_pki_snis_t valid_pki_snis = {0, NULL};

typedef struct transient_value_t {
  coap_binary_t *value;
  size_t ref_cnt;
} transient_value_t;

/* temporary storage for dynamic resource representations */
static transient_value_t *example_data_value = NULL;
static int example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum COAP_UNUSED) {
  quit = 1;
  coap_send_recv_terminate();
#if NUM_SERVER_THREADS
  coap_io_process_terminate_loop();
#endif /* NUM_SERVER_THREADS */
}

#ifndef _WIN32
/*
 * SIGUSR2 handler: set quit to 1 for graceful termination
 * Disable sending out 4.04 for any active observations.
 * Note: coap_*() functions should not be called at sig interrupt.
 */
static void
handle_sigusr2(int signum COAP_UNUSED) {
  quit = 1;
  keep_persist = 1;
#if NUM_SERVER_THREADS
  coap_io_process_terminate_loop();
#endif /* NUM_SERVER_THREADS */
}
#endif /* ! _WIN32 */

/*
 * This will return a correctly formed transient_value_t *, or NULL.
 * If an error, the passed in coap_binary_t * will get deleted.
 * Note: transient_value->value will never be returned as NULL.
 */
static transient_value_t *
alloc_resource_data(coap_binary_t *value) {
  transient_value_t *transient_value;
  if (!value)
    return NULL;
  transient_value = coap_malloc(sizeof(transient_value_t));
  if (!transient_value) {
    coap_delete_binary(value);
    return NULL;
  }
  transient_value->ref_cnt = 1;
  transient_value->value = value;
  return transient_value;
}

/*
 * Need to handle race conditions of data being updated (by PUT) and
 * being read by a blocked response to GET.
 */
static void
release_resource_data(coap_session_t *session COAP_UNUSED,
                      void *app_ptr) {
  transient_value_t *transient_value = (transient_value_t *)app_ptr;

  if (!transient_value)
    return;

  if (--transient_value->ref_cnt > 0)
    return;
  coap_delete_binary(transient_value->value);
  coap_free(transient_value);
}

/*
 * Bump the reference count and return reference to data
 */
static coap_binary_t
reference_resource_data(transient_value_t *entry) {
  coap_binary_t body;
  if (entry) {
    /* Bump reference so not removed elsewhere */
    entry->ref_cnt++;
    assert(entry->value);
    body.length = entry->value->length;
    body.s = entry->value->s;
  } else {
    body.length = 0;
    body.s = NULL;
  }
  return body;
}

#define INDEX "This is a test server made with libcoap (see https://libcoap.net)\n" \
  "Copyright (C) 2010--2025 Olaf Bergmann <bergmann@tzi.org> and others\n\n"

static void
hnd_get_index(coap_resource_t *resource,
              coap_session_t *session,
              const coap_pdu_t *request,
              const coap_string_t *query COAP_UNUSED,
              coap_pdu_t *response) {

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN,
                               0x2ffff, 0, strlen(INDEX),
                               (const uint8_t *)INDEX, NULL, NULL);
}

static void
hnd_get_fetch_time(coap_resource_t *resource,
                   coap_session_t *session,
                   const coap_pdu_t *request,
                   const coap_string_t *query,
                   coap_pdu_t *response) {
  unsigned char buf[40];
  size_t len;
  time_t now;
  coap_tick_t t;
  (void)request;
  coap_pdu_code_t code = coap_pdu_get_code(request);
  size_t size;
  const uint8_t *data;
  coap_str_const_t *ticks = coap_make_str_const("ticks");

  if (my_clock_base) {

    /* calculate current time */
    coap_ticks(&t);
    now = my_clock_base + (t / COAP_TICKS_PER_SECOND);

    /* coap_get_data() sets size to 0 on error */
    (void)coap_get_data(request, &size, &data);

    if (code == COAP_REQUEST_CODE_GET && query != NULL &&
        coap_string_equal(query, ticks)) {
      /* parameter is in query, output ticks */
      len = snprintf((char *)buf, sizeof(buf), "%" PRIi64, (int64_t)now);
    } else if (code == COAP_REQUEST_CODE_FETCH && size == ticks->length &&
               memcmp(data, ticks->s, ticks->length) == 0) {
      /* parameter is in data, output ticks */
      len = snprintf((char *)buf, sizeof(buf), "%" PRIi64, (int64_t)now);
    } else {      /* output human-readable time */
      struct tm *tmp;
      tmp = gmtime(&now);
      if (!tmp) {
        /* If 'now' is not valid */
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
        return;
      } else {
        len = strftime((char *)buf, sizeof(buf), "%b %d %H:%M:%S", tmp);
      }
    }
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 1, 0,
                                 len,
                                 buf, NULL, NULL);
  } else {
    /* if my_clock_base was deleted, we pretend to have no such resource */
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
  }
}

static void
hnd_put_time(coap_resource_t *resource,
             coap_session_t *session COAP_UNUSED,
             const coap_pdu_t *request,
             const coap_string_t *query COAP_UNUSED,
             coap_pdu_t *response) {
  coap_tick_t t;
  size_t size;
  const uint8_t *data;

  /* FIXME: re-set my_clock_base to clock_offset if my_clock_base == 0
   * and request is empty. When not empty, set to value in request payload
   * (insist on query ?ticks). Return Created or Ok.
   */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  coap_pdu_set_code(response, my_clock_base ? COAP_RESPONSE_CODE_CHANGED :
                    COAP_RESPONSE_CODE_CREATED);

  coap_resource_notify_observers(resource, NULL);

  /* coap_get_data() sets size to 0 on error */
  (void)coap_get_data(request, &size, &data);

  if (size == 0) {      /* re-init */
    my_clock_base = clock_offset;
  } else {
    my_clock_base = 0;
    coap_ticks(&t);
    while (size--)
      my_clock_base = my_clock_base * 10 + *data++;
    my_clock_base -= t / COAP_TICKS_PER_SECOND;

    /* Sanity check input value */
    if (!gmtime(&my_clock_base)) {
      unsigned char buf[3];
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
      coap_add_option(response,
                      COAP_OPTION_CONTENT_FORMAT,
                      coap_encode_var_safe(buf, sizeof(buf),
                                           COAP_MEDIATYPE_TEXT_PLAIN), buf);
      coap_add_data(response, 22, (const uint8_t *)"Invalid set time value");
      /* re-init as value is bad */
      my_clock_base = clock_offset;
    }
  }
}

static void
hnd_delete_time(coap_resource_t *resource COAP_UNUSED,
                coap_session_t *session COAP_UNUSED,
                const coap_pdu_t *request COAP_UNUSED,
                const coap_string_t *query COAP_UNUSED,
                coap_pdu_t *response COAP_UNUSED) {
  my_clock_base = 0;    /* mark clock as "deleted" */

  /* type = request->hdr->type == COAP_MESSAGE_CON  */
  /*   ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON; */
}

/*
 * This logic is used to test out that the client correctly handles a
 * "separate" response (empty ACK followed by data response at a later stage).
 */
static void
hnd_get_async(coap_resource_t *resource,
              coap_session_t *session,
              const coap_pdu_t *request,
              const coap_string_t *query,
              coap_pdu_t *response) {
  unsigned long delay = 4; /* Less than COAP_DEFAULT_LEISURE */
  size_t size;
  coap_async_t *async;
  coap_bin_const_t token = coap_pdu_get_token(request);

  /*
   * See if this is the initial, or delayed request
   */

  async = coap_find_async(session, token);
  if (!async) {
    /* Set up an async request to trigger delay in the future */
    if (query) {
      /* Expect the query to just be the number of seconds to delay */
      const uint8_t *p = query->s;

      if (isdigit(*p)) {
        delay = 0;
        for (size = query->length; size; --size, ++p) {
          if (!isdigit(*p))
            break;
          delay = delay * 10 + (*p - '0');
        }
      } else {
        coap_log_debug("async: query is just a number of seconds to alter delay\n");
      }
      if (delay == 0) {
        coap_log_info("async: delay of 0 not supported\n");
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
        return;
      }
    }
    async = coap_register_async(session,
                                request,
                                COAP_TICKS_PER_SECOND * delay);
    if (async == NULL) {
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
      return;
    }
    /*
     * Not setting response code will cause empty ACK to be sent
     * if Confirmable
     */
    return;
  }
  /* no request (observe) or async set up, so this is the delayed request */

  /* Send back the appropriate data */
  coap_add_data_large_response(resource, session, request, response,
                               query, COAP_MEDIATYPE_TEXT_PLAIN, -1, 0, 4,
                               (const uint8_t *)"done", NULL, NULL);
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);

  /* async is automatically removed by libcoap on return from this handler */
}

/*
 * Large Data GET handler
 */

#ifndef INITIAL_EXAMPLE_SIZE
#define INITIAL_EXAMPLE_SIZE 1500
#endif
static void
hnd_get_example_data(coap_resource_t *resource,
                     coap_session_t *session,
                     const coap_pdu_t *request,
                     const coap_string_t *query,
                     coap_pdu_t *response) {
  coap_binary_t body;
  if (!example_data_value) {
    /* Initialise for the first time */
    int i;
    coap_binary_t *value = coap_new_binary(INITIAL_EXAMPLE_SIZE);
    if (value) {
      for (i = 0; i < INITIAL_EXAMPLE_SIZE; i++) {
        if ((i % 10) == 0) {
          value->s[i] = 'a' + (i/10) % 26;
        } else {
          value->s[i] = '0' + i%10;
        }
      }
    }
    example_data_value = alloc_resource_data(value);
  }
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  body = reference_resource_data(example_data_value);
  coap_add_data_large_response(resource, session, request, response,
                               query, example_data_media_type, -1, 0,
                               body.length,
                               body.s,
                               release_resource_data, example_data_value);
}

static void
cache_free_app_data(void *data) {
  coap_binary_t *bdata = (coap_binary_t *)data;
  coap_delete_binary(bdata);
}

/*
 * Large Data PUT handler
 */

static void
hnd_put_example_data(coap_resource_t *resource,
                     coap_session_t *session,
                     const coap_pdu_t *request,
                     const coap_string_t *query COAP_UNUSED,
                     coap_pdu_t *response) {
  size_t size;
  const uint8_t *data;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  size_t offset;
  size_t total;
  coap_binary_t *data_so_far;

  if (coap_get_data_large(request, &size, &data, &offset, &total) &&
      size != total) {
    coap_binary_t *old_data_in_cache;
    /*
     * A part of the data has been received (COAP_BLOCK_SINGLE_BODY not set).
     * However, total unfortunately is only an indication, so it is not safe to
     * allocate a block based on total.  As per
     * https://rfc-editor.org/rfc/rfc7959#section-4
     *   o  In a request carrying a Block1 Option, to indicate the current
     *         estimate the client has of the total size of the resource
     *         representation, measured in bytes ("size indication").
     *
     * coap_cache_ignore_options() must have previously been called with at
     * least COAP_OPTION_BLOCK1 set as the option value will change per block.
     */
    coap_cache_entry_t *cache_entry = coap_cache_get_by_pdu(session,
                                                            request,
                                                            COAP_CACHE_IS_SESSION_BASED);

    if (offset == 0) {
      if (!cache_entry) {
        /*
         * Set idle_timeout parameter to COAP_MAX_TRANSMIT_WAIT if you want
         * early removal on transmission failure. 0 means only delete when
         * the session is deleted as session_based is set here.
         */
        cache_entry = coap_new_cache_entry(session, request,
                                           COAP_CACHE_NOT_RECORD_PDU,
                                           COAP_CACHE_IS_SESSION_BASED, 0);
      } else {
        old_data_in_cache = coap_cache_set_app_data2(cache_entry, NULL, NULL);
        coap_delete_binary(old_data_in_cache);
      }
    }
    if (!cache_entry) {
      if (offset == 0) {
        coap_log_warn("Unable to create a new cache entry\n");
      } else {
        coap_log_warn("No cache entry available for the non-first BLOCK\n");
      }
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
      return;
    }

    if (size) {
      /* Add in the new data to cache entry */
      data_so_far = coap_cache_get_app_data(cache_entry);
      data_so_far = coap_block_build_body(data_so_far, size, data,
                                          offset, total);
      /* Yes, data_so_far can be NULL if error */
      coap_cache_set_app_data2(cache_entry, data_so_far, cache_free_app_data);
    }
    if (offset + size == total) {
      /* All the data is now in */
      data_so_far = coap_cache_set_app_data2(cache_entry, NULL, NULL);
    } else {
      /* Give us the next block response */
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTINUE);
      return;
    }
  } else {
    /* single body of data received */
    data_so_far = coap_new_binary(size);
    if (data_so_far) {
      memcpy(data_so_far->s, data, size);
    }
  }

  if (example_data_value) {
    /* pre-existed response */
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
    /* Need to de-reference as value may be in use elsewhere */
    release_resource_data(session, example_data_value);
  } else
    /* just generated response */
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);

  example_data_value = alloc_resource_data(data_so_far);
  if (!example_data_value) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  if ((option = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT,
                                  &opt_iter)) != NULL) {
    example_data_media_type =
        coap_decode_var_bytes(coap_opt_value(option),
                              coap_opt_length(option));
  } else {
    example_data_media_type = COAP_MEDIATYPE_TEXT_PLAIN;
  }

  coap_resource_notify_observers(resource, NULL);
  if (echo_back) {
    coap_binary_t body;

    body = reference_resource_data(example_data_value);
    coap_add_data_large_response(resource, session, request, response,
                                 query, example_data_media_type, -1, 0,
                                 body.length,
                                 body.s,
                                 release_resource_data, example_data_value);
  }
}

#if COAP_PROXY_SUPPORT

#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
static unsigned char *user = NULL;
static ssize_t user_length = -1;

static size_t proxy_host_name_count = 0;
static const char **proxy_host_name_list = NULL;
static coap_proxy_server_list_t forward_proxy = { NULL, 0, 0, COAP_PROXY_FORWARD_STATIC, 0, 300};
static coap_proxy_server_list_t reverse_proxy = { NULL, 0, 0, COAP_PROXY_REVERSE_STRIP, 0, 10};

static coap_dtls_cpsk_t *
setup_cpsk(char *client_sni) {
  static coap_dtls_cpsk_t dtls_cpsk;

  memset(&dtls_cpsk, 0, sizeof(dtls_cpsk));
  dtls_cpsk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  dtls_cpsk.client_sni = client_sni;
  dtls_cpsk.psk_info.identity.s = user;
  dtls_cpsk.psk_info.identity.length = user_length;
  dtls_cpsk.psk_info.key.s = key;
  dtls_cpsk.psk_info.key.length = key_length;
  return &dtls_cpsk;
}

static void
hnd_forward_proxy_uri(coap_resource_t *resource,
                      coap_session_t *req_session,
                      const coap_pdu_t *request,
                      const coap_string_t *query COAP_UNUSED,
                      coap_pdu_t *response) {

  if (!coap_proxy_forward_request(req_session, request, response, resource,
                                  NULL, &forward_proxy)) {
    coap_log_debug("hnd_forward_proxy_uri: Failed to forward PDU\n");
    /* Non ACK response code set on error detection */
  }

  /* Leave response code as is */
}

static void
hnd_reverse_proxy_uri(coap_resource_t *resource,
                      coap_session_t *rsp_session,
                      const coap_pdu_t *request,
                      const coap_string_t *query COAP_UNUSED,
                      coap_pdu_t *response) {

  if (!coap_proxy_forward_request(rsp_session, request, response, resource,
                                  NULL, &reverse_proxy)) {
    coap_log_debug("hnd_reverse_proxy_uri: Failed to forward PDU\n");
    /* Non ACK response code set on error detection */
  }

  /* Leave response code as is */
}

#endif /* COAP_PROXY_SUPPORT */

typedef struct dynamic_resource_t {
  coap_string_t *uri_path;
  transient_value_t *value;
  coap_resource_t *resource;
  int created;
  uint16_t media_type;
} dynamic_resource_t;

static int dynamic_count = 0;
static dynamic_resource_t *dynamic_entry = NULL;

/*
 * Regular DELETE handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_delete(coap_resource_t *resource,
           coap_session_t *session COAP_UNUSED,
           const coap_pdu_t *request,
           const coap_string_t *query COAP_UNUSED,
           coap_pdu_t *response) {
  int i;
  coap_string_t *uri_path;

  /* get the uri_path */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
    return;
  }

  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      /* Dynamic entry no longer required - delete it */
      release_resource_data(session, dynamic_entry[i].value);
      coap_delete_string(dynamic_entry[i].uri_path);
      if (dynamic_count-i > 1) {
        memmove(&dynamic_entry[i],
                &dynamic_entry[i+1],
                (dynamic_count-i-1) * sizeof(dynamic_entry[0]));
      }
      dynamic_count--;
      break;
    }
  }

  /* Dynamic resource no longer required - delete it */
  coap_delete_resource(NULL, resource);
  coap_delete_string(uri_path);
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_DELETED);
}

/*
 * Regular GET handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_get(coap_resource_t *resource,
        coap_session_t *session,
        const coap_pdu_t *request,
        const coap_string_t *query,
        coap_pdu_t *response) {
  coap_str_const_t *uri_path;
  int i;
  dynamic_resource_t *resource_entry = NULL;
  coap_binary_t body;
  /*
   * request will be NULL if an Observe triggered request, so the uri_path,
   * if needed, must be abstracted from the resource.
   * The uri_path string is a const pointer
   */

  uri_path = coap_resource_get_uri_path(resource);
  if (!uri_path) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
    return;
  }

  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      break;
    }
  }
  if (i == dynamic_count) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
    return;
  }

  resource_entry = &dynamic_entry[i];

  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  body = reference_resource_data(resource_entry->value);
  coap_add_data_large_response(resource, session, request, response,
                               query, resource_entry->media_type, -1, 0,
                               body.length,
                               body.s,
                               release_resource_data, resource_entry->value);
}

/*
 * Regular PUT or POST handler - used by resources created by the
 * Unknown Resource PUT/POST handler
 */

static void
hnd_put_post(coap_resource_t *resource,
             coap_session_t *session,
             const coap_pdu_t *request,
             const coap_string_t *query COAP_UNUSED,
             coap_pdu_t *response) {
  coap_string_t *uri_path;
  int i;
  size_t size;
  const uint8_t *data;
  size_t offset;
  size_t total;
  dynamic_resource_t *resource_entry = NULL;
  unsigned char buf[6];      /* space to hold encoded/decoded uints */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  coap_binary_t *data_so_far;
  transient_value_t *transient_value;

  /* get the uri_path */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
    return;
  }

  /*
   * Locate the correct dynamic block for this request
   */
  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      break;
    }
  }
  if (i == dynamic_count) {
    if (dynamic_count >= support_dynamic) {
      /* Should have been caught hnd_put_post_unknown() */
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_ACCEPTABLE);
      coap_delete_string(uri_path);
      return;
    }
    dynamic_count++;
    dynamic_entry = realloc(dynamic_entry,
                            dynamic_count * sizeof(dynamic_entry[0]));
    if (dynamic_entry) {
      dynamic_entry[i].uri_path = uri_path;
      dynamic_entry[i].value = NULL;
      dynamic_entry[i].resource = resource;
      dynamic_entry[i].created = 1;
      if ((option = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT,
                                      &opt_iter)) != NULL) {
        dynamic_entry[i].media_type =
            coap_decode_var_bytes(coap_opt_value(option),
                                  coap_opt_length(option));
      } else {
        dynamic_entry[i].media_type = COAP_MEDIATYPE_TEXT_PLAIN;
      }
      /* Store media type of new resource in ct. We can use buf here
       * as coap_add_attr() will copy the passed string. */
      memset(buf, 0, sizeof(buf));
      snprintf((char *)buf, sizeof(buf), "%d", dynamic_entry[i].media_type);
      /* ensure that buf is always zero-terminated */
      assert(buf[sizeof(buf) - 1] == '\0');
      buf[sizeof(buf) - 1] = '\0';
      coap_add_attr(resource,
                    coap_make_str_const("ct"),
                    coap_make_str_const((char *)buf),
                    0);
    } else {
      dynamic_count--;
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
      coap_delete_string(uri_path);
      return;
    }
  } else {
    /* Need to do this as coap_get_uri_path() created it */
    coap_delete_string(uri_path);
  }

  resource_entry = &dynamic_entry[i];

  if (coap_get_data_large(request, &size, &data, &offset, &total) &&
      size != total) {
    coap_binary_t *old_data_in_cache;
    /*
     * A part of the data has been received (COAP_BLOCK_SINGLE_BODY not set).
     * However, total unfortunately is only an indication, so it is not safe to
     * allocate a block based on total.  As per
     * https://rfc-editor.org/rfc/rfc7959#section-4
     *   o  In a request carrying a Block1 Option, to indicate the current
     *         estimate the client has of the total size of the resource
     *         representation, measured in bytes ("size indication").
     *
     * coap_cache_ignore_options() must have previously been called with at
     * least COAP_OPTION_BLOCK1 set as the option value will change per block.
     */
    coap_cache_entry_t *cache_entry = coap_cache_get_by_pdu(session,
                                                            request,
                                                            COAP_CACHE_IS_SESSION_BASED);

    if (offset == 0) {
      if (!cache_entry) {
        cache_entry = coap_new_cache_entry(session, request,
                                           COAP_CACHE_NOT_RECORD_PDU,
                                           COAP_CACHE_IS_SESSION_BASED, 0);
      } else {
        old_data_in_cache = coap_cache_set_app_data2(cache_entry, NULL, NULL);
        coap_delete_binary(old_data_in_cache);
      }
    }
    if (!cache_entry) {
      if (offset == 0) {
        coap_log_warn("Unable to create a new cache entry\n");
      } else {
        coap_log_warn("No cache entry available for the non-first BLOCK\n");
      }
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
      return;
    }

    if (size) {
      /* Add in the new data to cache entry */
      data_so_far = coap_cache_get_app_data(cache_entry);
      if (!data_so_far) {
        data_so_far = coap_new_binary(size);
        if (data_so_far)
          memcpy(data_so_far->s, data, size);
      } else {
        /* Add in new block to end of current data */
        coap_binary_t *new = coap_resize_binary(data_so_far, offset + size);

        if (new) {
          data_so_far = new;
          memcpy(&data_so_far->s[offset], data, size);
        } else {
          /* Insufficient space to extend data_so_far */
          coap_delete_binary(data_so_far);
          data_so_far = NULL;
        }
      }
      /* Yes, data_so_far can be NULL */
      coap_cache_set_app_data2(cache_entry, data_so_far, cache_free_app_data);
    }
    if (offset + size == total) {
      /* All the data is now in */
      data_so_far = coap_cache_set_app_data2(cache_entry, NULL, NULL);
    } else {
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTINUE);
      return;
    }
  } else {
    /* single body of data received */
    data_so_far = coap_new_binary(size);
    if (data_so_far && size) {
      memcpy(data_so_far->s, data, size);
    }
  }
  /* Need to de-reference as value may be in use elsewhere */
  release_resource_data(session, resource_entry->value);
  resource_entry->value = NULL;
  transient_value = alloc_resource_data(data_so_far);
  if (!transient_value) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  resource_entry->value = transient_value;

  if (resource_entry->created) {
    coap_pdu_code_t code = coap_pdu_get_code(request);

    resource_entry->created = 0;
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    if (code == COAP_REQUEST_CODE_POST) {
      /* Add in Location-Path / Location-Query Options */
      coap_option_iterator_init(request, &opt_iter, COAP_OPT_ALL);
      while ((option = coap_option_next(&opt_iter))) {
        switch (opt_iter.number) {
        case COAP_OPTION_URI_PATH:
          if (!coap_add_option(response, COAP_OPTION_LOCATION_PATH,
                               coap_opt_length(option),
                               coap_opt_value(option)))
            goto fail;
          break;
        case COAP_OPTION_URI_QUERY:
          if (!coap_add_option(response, COAP_OPTION_LOCATION_QUERY,
                               coap_opt_length(option),
                               coap_opt_value(option)))
            goto fail;
          break;
        default:
          break;
        }
      }
    }
  } else {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
    coap_resource_notify_observers(resource_entry->resource, NULL);
  }

  if (echo_back) {
    coap_binary_t body;

    body = reference_resource_data(resource_entry->value);
    coap_add_data_large_response(resource, session, request, response,
                                 query, resource_entry->media_type, -1, 0,
                                 body.length,
                                 body.s,
                                 release_resource_data, resource_entry->value);
  }
  return;

fail:
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
  return;
}

/*
 * Unknown Resource PUT handler
 */

static void
hnd_put_post_unknown(coap_resource_t *resource COAP_UNUSED,
                     coap_session_t *session,
                     const coap_pdu_t *request,
                     const coap_string_t *query,
                     coap_pdu_t *response) {
  coap_resource_t *r;
  coap_string_t *uri_path;

  /* check if creating a new resource is allowed */
  if (dynamic_count >= support_dynamic) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_ACCEPTABLE);
    return;
  }

  /* get the uri_path - will get used by coap_resource_init() */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_FOUND);
    return;
  }

  /*
   * Create a resource to handle the new URI
   * uri_path will get deleted when the resource is removed
   */
  r = coap_resource_init((coap_str_const_t *)uri_path,
                         COAP_RESOURCE_FLAGS_RELEASE_URI | resource_flags);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Dynamic\""), 0);
  coap_register_request_handler(r, COAP_REQUEST_PUT, hnd_put_post);
  coap_register_request_handler(r, COAP_REQUEST_POST, hnd_put_post);
  coap_register_request_handler(r, COAP_REQUEST_DELETE, hnd_delete);
  coap_register_request_handler(r, COAP_REQUEST_FETCH, hnd_get);
  /* We possibly want to Observe the GETs */
  coap_resource_set_get_observable(r, 1);
  coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get);
  coap_add_resource(coap_session_get_context(session), r);

  /* Do the PUT/POST for this first call */
  hnd_put_post(r, session, request, query, response);
}

#if COAP_PROXY_SUPPORT
static int
proxy_event_handler(coap_session_t *session COAP_UNUSED,
                    coap_event_t event) {

  switch (event) {
  case COAP_EVENT_DTLS_CLOSED:
  case COAP_EVENT_TCP_CLOSED:
  case COAP_EVENT_SESSION_CLOSED:
  case COAP_EVENT_OSCORE_DECRYPTION_FAILURE:
  case COAP_EVENT_OSCORE_NOT_ENABLED:
  case COAP_EVENT_OSCORE_NO_PROTECTED_PAYLOAD:
  case COAP_EVENT_OSCORE_NO_SECURITY:
  case COAP_EVENT_OSCORE_INTERNAL_ERROR:
  case COAP_EVENT_OSCORE_DECODE_ERROR:
  case COAP_EVENT_WS_PACKET_SIZE:
  case COAP_EVENT_WS_CLOSED:
  case COAP_EVENT_DTLS_CONNECTED:
  case COAP_EVENT_DTLS_RENEGOTIATE:
  case COAP_EVENT_DTLS_ERROR:
  case COAP_EVENT_TCP_CONNECTED:
  case COAP_EVENT_TCP_FAILED:
  case COAP_EVENT_SESSION_CONNECTED:
  case COAP_EVENT_SESSION_FAILED:
  case COAP_EVENT_PARTIAL_BLOCK:
  case COAP_EVENT_XMIT_BLOCK_FAIL:
  case COAP_EVENT_SERVER_SESSION_NEW:
  case COAP_EVENT_SERVER_SESSION_DEL:
  case COAP_EVENT_BAD_PACKET:
  case COAP_EVENT_MSG_RETRANSMITTED:
  case COAP_EVENT_WS_CONNECTED:
  case COAP_EVENT_KEEPALIVE_FAILURE:
  default:
    break;
  }
  return 0;
}

static coap_pdu_t *
proxy_response_handler(coap_session_t *rsp_session COAP_UNUSED,
                       const coap_pdu_t *sent COAP_UNUSED,
                       coap_pdu_t *received,
                       coap_cache_key_t *cache_key COAP_UNUSED) {
  return received;
}

static void
proxy_nack_handler(coap_session_t *session COAP_UNUSED,
                   const coap_pdu_t *sent COAP_UNUSED,
                   const coap_nack_reason_t reason,
                   const coap_mid_t mid COAP_UNUSED) {

  switch (reason) {
  case COAP_NACK_TOO_MANY_RETRIES:
  case COAP_NACK_NOT_DELIVERABLE:
  case COAP_NACK_RST:
  case COAP_NACK_TLS_FAILED:
  case COAP_NACK_WS_FAILED:
  case COAP_NACK_TLS_LAYER_FAILED:
  case COAP_NACK_WS_LAYER_FAILED:
  case COAP_NACK_ICMP_ISSUE:
  case COAP_NACK_BAD_RESPONSE:
  default:
    break;
  }
  return;
}

#endif /* COAP_PROXY_SUPPORT */

static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

#if COAP_PROXY_SUPPORT
  if (reverse_proxy.entry_count) {
    /* Create a reverse proxy resource to handle PUTs */
    r = coap_resource_reverse_proxy_init(hnd_reverse_proxy_uri, 0);
    coap_add_resource(ctx, r);
    coap_register_event_handler(ctx, proxy_event_handler);
    coap_register_proxy_response_handler(ctx, proxy_response_handler);
    coap_register_nack_handler(ctx, proxy_nack_handler);
  } else {
#endif /* COAP_PROXY_SUPPORT */
    r = coap_resource_init(NULL, COAP_RESOURCE_FLAGS_HAS_MCAST_SUPPORT);
    coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_index);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
    coap_add_resource(ctx, r);

    /* store clock base to use in /time */
    my_clock_base = clock_offset;

    r = coap_resource_init(coap_make_str_const("time"), resource_flags);
    coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_fetch_time);
    coap_register_request_handler(r, COAP_REQUEST_FETCH, hnd_get_fetch_time);
    coap_register_request_handler(r, COAP_REQUEST_PUT, hnd_put_time);
    coap_register_request_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);
    coap_resource_set_get_observable(r, 1);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Internal Clock\""), 0);
    coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ticks\""), 0);
    coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"clock\""), 0);

    coap_add_resource(ctx, r);
    time_resource = r;

    if (support_dynamic > 0) {
      /* Create a resource to handle PUTs to unknown URIs */
      r = coap_resource_unknown_init2(hnd_put_post_unknown, 0);
      /* Add in handling POST as well */
      coap_register_handler(r, COAP_REQUEST_POST, hnd_put_post_unknown);
      coap_add_resource(ctx, r);
    }

    if (coap_async_is_supported()) {
      r = coap_resource_init(coap_make_str_const("async"),
                             resource_flags |
                             COAP_RESOURCE_FLAGS_HAS_MCAST_SUPPORT |
                             COAP_RESOURCE_FLAGS_LIB_DIS_MCAST_DELAYS);
      coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_async);

      coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
      coap_add_resource(ctx, r);
    }

    r = coap_resource_init(coap_make_str_const("example_data"), resource_flags);
    coap_register_request_handler(r, COAP_REQUEST_GET, hnd_get_example_data);
    coap_register_request_handler(r, COAP_REQUEST_PUT, hnd_put_example_data);
    coap_register_request_handler(r, COAP_REQUEST_FETCH, hnd_get_example_data);
    coap_resource_set_get_observable(r, 1);

    coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Example Data\""), 0);
    coap_add_resource(ctx, r);

#if COAP_PROXY_SUPPORT
  }
  if (proxy_host_name_count) {
    r = coap_resource_proxy_uri_init2(hnd_forward_proxy_uri, proxy_host_name_count,
                                      proxy_host_name_list, 0);
    coap_add_resource(ctx, r);
    coap_register_event_handler(ctx, proxy_event_handler);
    coap_register_proxy_response_handler(ctx, proxy_response_handler);
    coap_register_nack_handler(ctx, proxy_nack_handler);
  }
#endif /* COAP_PROXY_SUPPORT */
}

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert COAP_UNUSED,
                   size_t asn1_length COAP_UNUSED,
                   coap_session_t *session COAP_UNUSED,
                   unsigned depth,
                   int validated COAP_UNUSED,
                   void *arg) {
  union {
    coap_dtls_role_t r;
    void *v;
  } role = { .v = arg };

  coap_log_info("CN '%s' presented by %s (%s)\n",
                cn, role.r == COAP_DTLS_ROLE_SERVER ? "client" : "server",
                depth ? "CA" : "Certificate");
  return 1;
}

static uint8_t *
read_file_mem(const char *file, size_t *length) {
  FILE *f;
  uint8_t *buf;
  struct stat statbuf;

  *length = 0;
  if (!file || !(f = fopen(file, "r")))
    return NULL;

  if (fstat(fileno(f), &statbuf) == -1) {
    fclose(f);
    return NULL;
  }

  buf = coap_malloc(statbuf.st_size+1);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  if (fread(buf, 1, statbuf.st_size, f) != (size_t)statbuf.st_size) {
    fclose(f);
    coap_free(buf);
    return NULL;
  }
  buf[statbuf.st_size] = '\000';
  *length = (size_t)(statbuf.st_size + 1);
  fclose(f);
  return buf;
}

static void
update_pki_key(coap_dtls_key_t *dtls_key, const char *key_name,
               const char *cert_name, const char *ca_name) {
  memset(dtls_key, 0, sizeof(*dtls_key));
  if (doing_tls_engine) {
    dtls_key->key_type = COAP_PKI_KEY_DEFINE;
    dtls_key->key.define.public_cert.s_byte = cert_file;
    dtls_key->key.define.private_key.s_byte = key_file ? key_file : cert_file;
    dtls_key->key.define.ca.s_byte = ca_file;
    dtls_key->key.define.public_cert_def = COAP_PKI_KEY_DEF_ENGINE;
    dtls_key->key.define.private_key_def = COAP_PKI_KEY_DEF_ENGINE;
    dtls_key->key.define.ca_def = COAP_PKI_KEY_DEF_ENGINE;
    dtls_key->key.define.user_pin = pkcs11_pin;
  } else if ((key_name && strncasecmp(key_name, "pkcs11:", 7) == 0) ||
             (cert_name && strncasecmp(cert_name, "pkcs11:", 7) == 0) ||
             (ca_name && strncasecmp(ca_name, "pkcs11:", 7) == 0)) {
    dtls_key->key_type = COAP_PKI_KEY_PKCS11;
    dtls_key->key.pkcs11.public_cert = cert_name;
    dtls_key->key.pkcs11.private_key = key_name ?  key_name : cert_name;
    dtls_key->key.pkcs11.ca = ca_name;
    dtls_key->key.pkcs11.user_pin = pkcs11_pin;
  } else if (!use_pem_buf && !is_rpk_not_cert) {
    dtls_key->key_type = COAP_PKI_KEY_PEM;
    dtls_key->key.pem.public_cert = cert_name;
    dtls_key->key.pem.private_key = key_name ? key_name : cert_name;
    dtls_key->key.pem.ca_file = ca_name;
  } else {
    /* Map file into memory */
    coap_free(ca_mem);
    coap_free(cert_mem);
    coap_free(key_mem);
    ca_mem = read_file_mem(ca_name, &ca_mem_len);
    cert_mem = read_file_mem(cert_name, &cert_mem_len);
    key_mem = read_file_mem(key_name, &key_mem_len);

    dtls_key->key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_key->key.pem_buf.ca_cert = ca_mem;
    dtls_key->key.pem_buf.public_cert = cert_mem;
    dtls_key->key.pem_buf.private_key = key_mem ? key_mem : cert_mem;
    dtls_key->key.pem_buf.ca_cert_len = ca_mem_len;
    dtls_key->key.pem_buf.public_cert_len = cert_mem_len;
    dtls_key->key.pem_buf.private_key_len = key_mem ?
                                            key_mem_len : cert_mem_len;
  }
}

static coap_dtls_key_t *
verify_pki_sni_callback(const char *sni,
                        void *arg COAP_UNUSED) {
  static coap_dtls_key_t dtls_key;

  update_pki_key(&dtls_key, key_file, cert_file, ca_file);

  if (sni[0]) {
    size_t i;
    coap_log_info("SNI '%s' requested\n", sni);
    for (i = 0; i < valid_pki_snis.count; i++) {
      /* Test for SNI to change cert + ca */
      if (strcasecmp(sni, valid_pki_snis.pki_sni_list[i].sni_match) == 0) {
        coap_log_info("Switching to using cert '%s' + ca '%s'\n",
                      valid_pki_snis.pki_sni_list[i].new_cert,
                      valid_pki_snis.pki_sni_list[i].new_ca);
        update_pki_key(&dtls_key, valid_pki_snis.pki_sni_list[i].new_cert,
                       valid_pki_snis.pki_sni_list[i].new_cert,
                       valid_pki_snis.pki_sni_list[i].new_ca);
        break;
      }
    }
  } else {
    coap_log_debug("SNI not requested\n");
  }
  return &dtls_key;
}

static const coap_dtls_spsk_info_t *
verify_psk_sni_callback(const char *sni,
                        coap_session_t *c_session COAP_UNUSED,
                        void *arg COAP_UNUSED) {
  static coap_dtls_spsk_info_t psk_info;

  /* Preset with the defined keys */
  memset(&psk_info, 0, sizeof(psk_info));
  psk_info.hint.s = (const uint8_t *)hint;
  psk_info.hint.length = hint ? strlen(hint) : 0;
  psk_info.key.s = key;
  psk_info.key.length = key_length;
  if (sni) {
    size_t i;
    coap_log_info("SNI '%s' requested\n", sni);
    for (i = 0; i < valid_psk_snis.count; i++) {
      /* Test for identity match to change key */
      if (strcasecmp(sni,
                     valid_psk_snis.psk_sni_list[i].sni_match) == 0) {
        coap_log_info("Switching to using '%.*s' hint + '%.*s' key\n",
                      (int)valid_psk_snis.psk_sni_list[i].new_hint->length,
                      valid_psk_snis.psk_sni_list[i].new_hint->s,
                      (int)valid_psk_snis.psk_sni_list[i].new_key->length,
                      valid_psk_snis.psk_sni_list[i].new_key->s);
        psk_info.hint = *valid_psk_snis.psk_sni_list[i].new_hint;
        psk_info.key = *valid_psk_snis.psk_sni_list[i].new_key;
        break;
      }
    }
  } else {
    coap_log_debug("SNI not requested\n");
  }
  return &psk_info;
}

static const coap_bin_const_t *
verify_id_callback(coap_bin_const_t *identity,
                   coap_session_t *c_session,
                   void *arg COAP_UNUSED) {
  static coap_bin_const_t psk_key;
  const coap_bin_const_t *s_psk_hint = coap_session_get_psk_hint(c_session);
  const coap_bin_const_t *s_psk_key;
  size_t i;

  coap_log_info("Identity '%.*s' requested, current hint '%.*s'\n", (int)identity->length,
                identity->s,
                s_psk_hint ? (int)s_psk_hint->length : 0,
                s_psk_hint ? (const char *)s_psk_hint->s : "");

  for (i = 0; i < valid_ids.count; i++) {
    /* Check for hint match */
    if (s_psk_hint &&
        strcmp((const char *)s_psk_hint->s,
               valid_ids.id_list[i].hint_match)) {
      continue;
    }
    /* Test for identity match to change key */
    if (coap_binary_equal(identity, valid_ids.id_list[i].identity_match)) {
      coap_log_info("Switching to using '%.*s' key\n",
                    (int)valid_ids.id_list[i].new_key->length,
                    valid_ids.id_list[i].new_key->s);
      return valid_ids.id_list[i].new_key;
    }
  }

  s_psk_key = coap_session_get_psk_key(c_session);
  if (s_psk_key) {
    /* Been updated by SNI callback */
    psk_key = *s_psk_key;
    return &psk_key;
  }

  /* Just use the defined key for now */
  psk_key.s = key;
  psk_key.length = key_length;
  return &psk_key;
}

static coap_dtls_pki_t *
setup_pki(coap_context_t *ctx, coap_dtls_role_t role, char *client_sni) {
  static coap_dtls_pki_t dtls_pki;

  /* If trust store CAs are to be defined */
  if (verify_peer_cert && !no_trust_store && !ca_file) {
    coap_context_load_pki_trust_store(ctx);
  }

  /* If general root CAs are defined */
  if (role == COAP_DTLS_ROLE_SERVER && root_ca_file) {
    struct stat stbuf;
    if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
      coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
    } else {
      coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
    }
  }

  memset(&dtls_pki, 0, sizeof(dtls_pki));
  dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
  /*
   * Add in additional certificate checking.
   * This list of enabled can be tuned for the specific
   * requirements - see 'man coap_encryption'.
   *
   * Note: root_ca_file is setup separately using
   * coap_context_set_pki_root_cas(), but this is used to define what
   * checking actually takes place.
   */
  dtls_pki.verify_peer_cert        = verify_peer_cert;
  dtls_pki.check_common_ca         = !root_ca_file;
  dtls_pki.allow_self_signed       = 1;
  dtls_pki.allow_expired_certs     = 1;
  dtls_pki.cert_chain_validation   = 1;
  dtls_pki.cert_chain_verify_depth = 2;
  dtls_pki.check_cert_revocation   = 1;
  dtls_pki.allow_no_crl            = 1;
  dtls_pki.allow_expired_crl       = 1;
  dtls_pki.is_rpk_not_cert        = is_rpk_not_cert;
  dtls_pki.validate_cn_call_back  = verify_cn_callback;
  dtls_pki.cn_call_back_arg       = (void *)role;
  dtls_pki.validate_sni_call_back = role == COAP_DTLS_ROLE_SERVER ?
                                    verify_pki_sni_callback : NULL;
  dtls_pki.sni_call_back_arg      = NULL;

  if (role == COAP_DTLS_ROLE_CLIENT) {
    dtls_pki.client_sni = client_sni;
  }

  update_pki_key(&dtls_pki.pki_key, key_file, cert_file, ca_file);
  /* Need to keep base initialization copies of any COAP_PKI_KEY_PEM_BUF */
  ca_mem_base = ca_mem;
  cert_mem_base = cert_mem;
  key_mem_base = key_mem;
  ca_mem = NULL;
  cert_mem = NULL;
  key_mem = NULL;
  return &dtls_pki;
}

static coap_dtls_spsk_t *
setup_spsk(void) {
  static coap_dtls_spsk_t dtls_spsk;

  memset(&dtls_spsk, 0, sizeof(dtls_spsk));
  dtls_spsk.version = COAP_DTLS_SPSK_SETUP_VERSION;
  dtls_spsk.ec_jpake = ec_jpake;
  dtls_spsk.validate_id_call_back = valid_ids.count ?
                                    verify_id_callback : NULL;
  dtls_spsk.validate_sni_call_back = valid_psk_snis.count ?
                                     verify_psk_sni_callback : NULL;
  dtls_spsk.psk_info.hint.s = (const uint8_t *)hint;
  dtls_spsk.psk_info.hint.length = hint ? strlen(hint) : 0;
  dtls_spsk.psk_info.key.s = key;
  dtls_spsk.psk_info.key.length = key_length;
  return &dtls_spsk;
}

static void
fill_keystore(coap_context_t *ctx) {

  if (cert_file == NULL && key_defined == 0) {
    if (coap_dtls_is_supported() || coap_tls_is_supported()) {
      coap_log_debug("(D)TLS not enabled as none of -k, -c or -M options specified\n");
    }
    return;
  }
  if (cert_file) {
    coap_dtls_pki_t *dtls_pki = setup_pki(ctx,
                                          COAP_DTLS_ROLE_SERVER, NULL);
    if (!coap_context_set_pki(ctx, dtls_pki)) {
      coap_log_info("Unable to set up %s keys\n",
                    is_rpk_not_cert ? "RPK" : "PKI");
      /* So we do not set up DTLS */
      cert_file = NULL;
    }
  }
  if (key_defined) {
    coap_dtls_spsk_t *dtls_spsk = setup_spsk();

    if (!coap_context_set_psk2(ctx, dtls_spsk)) {
      coap_log_info("Unable to set up PSK\n");
      /* So we do not set up DTLS */
      key_defined = 0;
    }
  }
}

#if COAP_PROXY_SUPPORT
static void
proxy_dtls_setup(coap_context_t *ctx, coap_proxy_server_list_t *proxy_info) {
  size_t i;
  static char client_sni[256];

  for (i = 0; i < proxy_info->entry_count; i++) {
    coap_proxy_server_t *proxy_server = &proxy_info->entry[i];

    if (proxy_info->type == COAP_PROXY_FORWARD_DYNAMIC ||
        proxy_info->type == COAP_PROXY_FORWARD_DYNAMIC_STRIP) {
      /* This will get filled in by the libcoap proxy logic */
      memset(client_sni, 0, sizeof(client_sni));
    } else {
      snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)proxy_server->uri.host.length,
               (int)proxy_server->uri.host.length, proxy_server->uri.host.s);
    }
    if (!key_defined) {
      /* Use our defined PKI certs (or NULL)  */
      proxy_server->dtls_pki = setup_pki(ctx, COAP_DTLS_ROLE_CLIENT,
                                         client_sni);
      proxy_server->dtls_cpsk = NULL;
    } else {
      /* Use our defined PSK */
      proxy_server->dtls_cpsk = setup_cpsk(client_sni);
      proxy_server->dtls_pki = NULL;
    }
    /*
     * Set this to a client specific oscore_conf if needed.
     * proxy_server->oscore_conf = oscore_conf;
     */
  }
}
#endif /* COAP_PROXY_SUPPORT */


static void
usage(const char *program, const char *version) {
  const char *p;
  char buffer[120];
  const char *lib_build = coap_package_build();

  p = strrchr(program, '/');
  if (p)
    program = ++p;

  fprintf(stderr, "%s v%s -- a small CoAP implementation\n"
          "(c) 2010,2011,2015-2025 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
          "Build: %s\n"
          "%s\n"
          , program, version, lib_build,
          coap_string_tls_version(buffer, sizeof(buffer)));
  fprintf(stderr, "%s\n", coap_string_tls_support(buffer, sizeof(buffer)));
  fprintf(stderr, "\n"
          "Usage: %s [-a priority] [-b max_block_size] [-d max] [-e]\n"
          "\t\t[-f scheme://address[:port] [-g group] -l loss] [-o] [-p port]\n"
          "\t\t[-q tls_engine_conf_file] [-r] [-v num] [-w [port][,secure_port]]\n"
          "\t\t[-x] [-y rec_secs] [-A address] [-E oscore_conf_file[,seq_file]]\n"
          "\t\t[-G group_if]\n"
          "\t\t[-L value] [-N] [-P scheme://address[:port],[name1[,name2..]]]\n"
          "\t\t[-T max_token_size] [-U type] [-V num] [-X size]\n"
          "\t\t[[-h hint] [-i match_identity_file] [-k key]\n"
          "\t\t[-s match_psk_sni_file] [-u user] [-2]]\n"
          "\t\t[[-c certfile] [-j keyfile] [-m] [-n] [-C cafile]\n"
          "\t\t[-J pkcs11_pin] [-M rpk_file] [-R trust_casfile]\n"
          "\t\t[-S match_pki_sni_file] [-Y]]\n"
          "General Options\n"
          "\t-a priority\tSend logging output to syslog at priority (0-7) level\n"
          "\t-b max_block_size\n"
          "\t       \t\tMaximum block size server supports (16, 32, 64,\n"
          "\t       \t\t128, 256, 512 or 1024) in bytes\n"
          "\t-d max \t\tAllow dynamic creation of up to a total of max\n"
          "\t       \t\tresources. If max is reached, a 4.06 code is returned\n"
          "\t       \t\tuntil one of the dynamic resources has been deleted\n"
          "\t-e     \t\tEcho back the data sent with a PUT\n"
          "\t-f scheme://address[:port]\n"
          "\t       \t\tAct as a reverse proxy where scheme, address and optional\n"
          "\t       \t\tport define how to connect to the internal server.\n"
          "\t       \t\tScheme is one of coap, coaps, coap+tcp, coaps+tcp,\n"
          "\t       \t\tcoap+ws, and coaps+ws. http(s) is not currently supported.\n"
          "\t       \t\tThis option can be repeated to provide multiple internal\n"
          "\t       \t\tservers (each has to be different) that are round-robin\n"
          "\t       \t\tload balanced\n"
          "\t-g group\tJoin the given multicast group\n"
          "\t       \t\tNote: DTLS over multicast is not currently supported\n"
          "\t-l list\t\tFail to send some datagrams specified by a comma\n"
          "\t       \t\tseparated list of numbers or number ranges\n"
          "\t       \t\t(for debugging only)\n"
          "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
          "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
          "\t       \t\t(for debugging only)\n"
          "\t-o     \t\tDisable sending observe failures on shutdown\n"
          "\t-p port\t\tListen on specified port for UDP and TCP. If (D)TLS is\n"
          "\t       \t\tenabled, then the coap-server will also listen on\n"
          "\t       \t\t'port'+1 for DTLS and TLS.  The default port is 5683\n"
          "\t-q tls_engine_conf_file\n"
          "\t       \t\ttls_engine_conf_file contains TLS ENGINE configuration.\n"
          "\t       \t\tSee coap-tls-engine-conf(5) for definitions.\n"
          "\t-r     \t\tEnable multicast per resource support.  If enabled,\n"
          "\t       \t\tonly '/', '/async' and '/.well-known/core' are enabled\n"
          "\t       \t\tfor multicast requests support, otherwise all\n"
          "\t       \t\tresources are enabled\n"
          "\t-t     \t\tTrack resource's observe values so observe\n"
          "\t       \t\tsubscriptions can be maintained over a server restart.\n"
          "\t       \t\tNote: Use 'kill SIGUSR2 <pid>' for controlled shutdown\n"
          "\t-v num \t\tVerbosity level (default 4, maximum is 8) for general\n"
          "\t       \t\tCoAP logging\n"
          "\t-w [port][,secure_port]\n"
          "\t       \t\tEnable WebSockets support on port (WS) and/or secure_port\n"
          "\t       \t\t(WSS), comma separated\n"
          "\t-x     \t\tDisable output of PDU data when displaying PDUs\n"
          "\t-y rec_secs\tAttempt to reconnect a failed proxy session every\n"
          "\t       \t\trec_secs\n"
          "\t-A address\tInterface address to bind to\n"
          "\t-E oscore_conf_file[,seq_file]\n"
          "\t       \t\toscore_conf_file contains OSCORE configuration. See\n"
          "\t       \t\tcoap-oscore-conf(5) for definitions.\n"
          "\t       \t\tOptional seq_file is used to save the current transmit\n"
          "\t       \t\tsequence number, so on restart sequence numbers continue\n"
          "\t-G group_if\tUse this interface for listening for the multicast\n"
          "\t       \t\tgroup. This can be different from the implied interface\n"
          "\t       \t\tif the -A option is used\n"
          "\t-L value\tSum of one or more COAP_BLOCK_* flag valuess for block\n"
          "\t       \t\thandling methods. Default is 1 (COAP_BLOCK_USE_LIBCOAP)\n"
          "\t       \t\t(Sum of one or more of 1,2,4 64, 128 and 256)\n"
          "\t-N     \t\tMake \"observe\" responses NON-confirmable. Even if set\n"
          "\t       \t\tevery fifth response will still be sent as a confirmable\n"
          "\t       \t\tresponse (RFC 7641 requirement)\n"
          , program);
  fprintf(stderr,
          "\t-P scheme://address[:port],[name1[,name2[,name3..]]]\n"
          "\t       \t\tScheme, address, optional port of how to connect to the\n"
          "\t       \t\tnext proxy server and zero or more names (comma\n"
          "\t       \t\tseparated) that this proxy server is known by. The\n"
          "\t       \t\t, (comma) is required. If there is no name1 or if the\n"
          "\t       \t\thostname of the incoming proxy request matches one of\n"
          "\t       \t\tthese names, then this server is considered to be the\n"
          "\t       \t\tfinal endpoint. If scheme://address[:port] is not\n"
          "\t       \t\tdefined before the leading , (comma) of the first name,\n"
          "\t       \t\tthen the ongoing connection will be a direct connection.\n"
          "\t       \t\tScheme is one of coap, coaps, coap+tcp, coaps+tcp,\n"
          "\t       \t\tcoap+ws, and coaps+ws. http(s) is not currently supported.\n"
          "\t       \t\tThis option can be repeated to provide multiple upstream\n"
          "\t       \t\tservers that are round-robin load balanced\n"
          "\t-T max_token_length\tSet the maximum token length (8-65804)\n"
          "\t-U type\t\tTreat address defined by -A as a Unix socket address.\n"
          "\t       \t\ttype is 'coap', 'coaps', 'coap+tcp' or 'coaps+tcp'\n"
          "\t-V num \t\tVerbosity level (default 3, maximum is 7) for (D)TLS\n"
          "\t       \t\tlibrary logging\n"
          "\t-X size\t\tMaximum message size to use for TCP based connections\n"
          "\t       \t\t(default is 8388864). Maximum value of 2^32 -1\n"
          "PSK Options (if supported by underlying (D)TLS library)\n"
          "\t-h hint\t\tIdentity Hint to send. Default is CoAP. Zero length is\n"
          "\t       \t\tno hint\n"
          "\t-i match_identity_file\n"
          "\t       \t\tThis is a file that contains one or more lines of\n"
          "\t       \t\tIdentity Hints and (user) Identities to match for\n"
          "\t       \t\ta different new Pre-Shared Key (PSK) (comma separated)\n"
          "\t       \t\tto be used. E.g., per line\n"
          "\t       \t\t hint_to_match,identity_to_match,use_key\n"
          "\t       \t\tNote: -k still needs to be defined for the default case\n"
          "\t       \t\tNote: A match using the -s option may mean that the\n"
          "\t       \t\tcurrent Identity Hint is different to that defined by -h\n"
          "\t-k key \t\tPre-Shared Key. This argument requires (D)TLS with PSK\n"
          "\t       \t\tto be available. This cannot be empty if defined.\n"
          "\t       \t\tNote that both -c and -k need to be defined for both\n"
          "\t       \t\tPSK and PKI to be concurrently supported. If the\n"
          "\t       \t\tkey begins with 0x, then the hex text (two [0-9a-f] per\n"
          "\t       \t\tbyte) is converted to binary data\n"
          "\t-s match_psk_sni_file\n"
          "\t       \t\tThis is a file that contains one or more lines of\n"
          "\t       \t\treceived Subject Name Identifier (SNI) to match to use\n"
          "\t       \t\ta different Identity Hint and associated Pre-Shared Key\n"
          "\t       \t\t(PSK) (comma separated) instead of the '-h hint' and\n"
          "\t       \t\t'-k key' options. E.g., per line\n"
          "\t       \t\t sni_to_match,use_hint,with_key\n"
          "\t       \t\tNote: -k still needs to be defined for the default case\n"
          "\t       \t\tif there is not a match\n"
          "\t       \t\tNote: The associated Pre-Shared Key will get updated if\n"
          "\t       \t\tthere is also a -i match.  The update checking order is\n"
          "\t       \t\t-s followed by -i\n"
          "\t-u user\t\tUser identity for pre-shared key mode (only used if\n"
          "\t       \t\toption -P is set)\n"
          "\t-2     \t\tUse EC-JPAKE negotiation (if supported)\n"
         );
  fprintf(stderr,
          "PKI Options (if supported by underlying (D)TLS library)\n"
          "\tNote: If any one of '-c certfile', '-j keyfile' or '-C cafile' is in\n"
          "\tPKCS11 URI naming format (pkcs11: prefix), then any remaining non\n"
          "\tPKCS11 URI file definitions have to be in DER, not PEM, format.\n"
          "\tOtherwise all of '-c certfile', '-j keyfile' or '-C cafile' are in\n"
          "\tPEM format.\n\n"
          "\t-c certfile\tPEM file or PKCS11 URI for the certificate. The private\n"
          "\t       \t\tkey can also be in the PEM file, or has the same PKCS11\n"
          "\t       \t\tURI. If not, the private key is defined by '-j keyfile'.\n"
          "\t       \t\tNote that both -c and -k need to be defined for both\n"
          "\t       \t\tPSK and PKI to be concurrently supported\n"
          "\t-j keyfile\tPEM file or PKCS11 URI for the private key for the\n"
          "\t       \t\tcertificate in '-c certfile' if the parameter is\n"
          "\t       \t\tdifferent from certfile in '-c certfile'\n"
          "\t-m     \t\tUse COAP_PKI_KEY_PEM_BUF instead of COAP_PKI_KEY_PEM i/f\n"
          "\t       \t\tby reading into memory the Cert / CA file (for testing)\n"
          "\t-n     \t\tDisable remote peer certificate checking. This gives\n"
          "\t       \t\tclients the ability to use PKI, but without any defined\n"
          "\t       \t\tcertificates\n"
          "\t-C cafile\tPEM file or PKCS11 URI that contains a list of one or\n"
          "\t       \t\tmore CAs that are to be passed to the client for the\n"
          "\t       \t\tclient to determine what client certificate to use.\n"
          "\t       \t\tNormally, this list of CAs would be the root CA and\n"
          "\t       \t\tany intermediate CAs. Ideally the server certificate\n"
          "\t       \t\tshould be signed by the same CA so that mutual\n"
          "\t       \t\tauthentication can take place. The contents of cafile\n"
          "\t       \t\tare added to the trusted store of root CAs.\n"
          "\t       \t\tUsing the -C or -R options will trigger the\n"
          "\t       \t\tvalidation of the client certificate unless overridden\n"
          "\t       \t\tby the -n option\n"
          "\t-J pkcs11_pin\tThe user pin to unlock access to the PKCS11 token\n"
          "\t-M rpk_file\tRaw Public Key (RPK) PEM file or PKCS11 URI that\n"
          "\t       \t\tcontains both PUBLIC KEY and PRIVATE KEY or just\n"
          "\t       \t\tEC PRIVATE KEY. (GnuTLS and TinyDTLS(PEM) support only).\n"
          "\t       \t\t'-C cafile' or '-R trust_casfile' are not required\n"
          "\t-R trust_casfile\n"
          "\t       \t\tPEM file containing the set of trusted root CAs\n"
          "\t       \t\tthat are to be used to validate the client certificate.\n"
          "\t       \t\tAlternatively, this can point to a directory containing\n"
          "\t       \t\ta set of CA PEM files.\n"
          "\t       \t\tUsing '-R trust_casfile' disables common CA mutual\n"
          "\t       \t\tauthentication which can only be done by using\n"
          "\t       \t\t'-C cafile'.\n"
          "\t       \t\tUsing the -C or -R options will trigger the\n"
          "\t       \t\tvalidation of the client certificate unless overridden\n"
          "\t       \t\tby the -n option\n"
          "\t-S match_pki_sni_file\n"
          "\t       \t\tThis option denotes a file that contains one or more\n"
          "\t       \t\tlines of Subject Name Identifier (SNI) to match for new\n"
          "\t       \t\tCert file and new CA file (comma separated) to be used.\n"
          "\t       \t\tE.g., per line\n"
          "\t       \t\t sni_to_match,new_cert_file,new_ca_file\n"
          "\t       \t\tNote: -c and -C still need to be defined for the default\n"
          "\t       \t\tcase\n"
          "\t-Y\n"
          "\t       \t\tDo not load the default system Trusted Root CA Store\n"
         );
}

static coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;
  coap_addr_info_t *info = NULL;
  coap_addr_info_t *info_list = NULL;
  coap_str_const_t local;
  int have_ep = 0;
  uint16_t u_s_port = 0;
  uint16_t s_port = 0;
  uint32_t scheme_hint_bits = 0;

  ctx = coap_new_context(NULL);
  if (!ctx) {
    return NULL;
  }

  /* Need PKI/RPK/PSK set up before we set up (D)TLS endpoints */
  fill_keystore(ctx);

  if (node) {
    local.s = (const uint8_t *)node;
    local.length = strlen(node);
  }

  if (port) {
    u_s_port = atoi(port);
    s_port = u_s_port + 1;
  }
  scheme_hint_bits =
      coap_get_available_scheme_hint_bits(cert_file != NULL || key_defined != 0,
                                          enable_ws, use_unix_proto);
  info_list = coap_resolve_address_info(node ? &local : NULL, u_s_port, s_port,
                                        ws_port, wss_port,
                                        AI_PASSIVE | AI_NUMERICHOST,
                                        scheme_hint_bits,
                                        COAP_RESOLVE_TYPE_LOCAL);
  for (info = info_list; info != NULL; info = info->next) {
    coap_endpoint_t *ep;

    ep = coap_new_endpoint(ctx, &info->addr, info->proto);
    if (!ep) {
      coap_log_warn("cannot create endpoint for proto %u\n",
                    info->proto);
    } else {
      have_ep = 1;
    }
  }
  coap_free_address_info(info_list);
  if (!have_ep) {
    coap_log_err("No context available for interface '%s'\n", node);
    coap_free_context(ctx);
    return NULL;
  }
  return ctx;
}

#if COAP_PROXY_SUPPORT
static int
cmdline_proxy(char *arg) {
  char *host_start = strchr(arg, ',');
  char *next_name = host_start;
  size_t ofs;
  coap_uri_t uri;
  coap_proxy_server_t *new_entry;

  if (!host_start) {
    coap_log_warn("Zero or more proxy host names not defined\n");
    return 0;
  }
  *host_start = '\000';

  if (host_start != arg) {
    /* Next upstream proxy is defined */
    if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0 ||
        uri.path.length != 0 || uri.query.length != 0) {
      coap_log_err("Invalid CoAP Proxy definition\n");
      return 0;
    }
    if (!coap_verify_proxy_scheme_supported(uri.scheme)) {
      coap_log_err("Unsupported CoAP Proxy protocol\n");
      return 0;
    }
    forward_proxy.type = COAP_PROXY_FORWARD_STATIC;
    forward_proxy.idle_timeout_secs = 300;
  } else {
    memset(&uri, 0, sizeof(uri));
    forward_proxy.type = COAP_PROXY_FORWARD_DYNAMIC_STRIP;
    forward_proxy.idle_timeout_secs = 10;
  }

  new_entry = realloc(forward_proxy.entry,
                      (forward_proxy.entry_count + 1)*sizeof(forward_proxy.entry[0]));
  if (!new_entry) {
    coap_log_err("CoAP Proxy realloc() error\n");
    return 0;
  }
  forward_proxy.entry = new_entry;
  memset(&forward_proxy.entry[forward_proxy.entry_count], 0, sizeof(forward_proxy.entry[0]));
  forward_proxy.entry[forward_proxy.entry_count].uri = uri;
  forward_proxy.entry_count++;

  proxy_host_name_count = 0;
  while (next_name) {
    proxy_host_name_count++;
    next_name = strchr(next_name+1, ',');
  }
  proxy_host_name_list = coap_malloc(proxy_host_name_count * sizeof(char *));
  next_name = host_start;
  ofs = 0;
  while (next_name) {
    proxy_host_name_list[ofs++] = next_name+1;
    next_name = strchr(next_name+1, ',');
    if (next_name)
      *next_name = '\000';
  }
  return 1;
}

static int
cmdline_reverse_proxy(char *arg) {
  /* upstream server is defined */
  coap_uri_t uri;
  coap_proxy_server_t *new_entry;

  if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0 ||
      uri.path.length != 0 || uri.query.length != 0) {
    coap_log_err("Invalid CoAP Reverse-Proxy definition\n");
    return 0;
  }
  if (!coap_verify_proxy_scheme_supported(uri.scheme)) {
    coap_log_err("Unsupported CoAP Reverse-Proxy protocol\n");
    return 0;
  }

  new_entry = realloc(reverse_proxy.entry,
                      (reverse_proxy.entry_count + 1)*sizeof(reverse_proxy.entry[0]));
  if (!new_entry) {
    coap_log_err("CoAP Reverse-Proxy realloc() error\n");
    return 0;
  }
  reverse_proxy.entry = new_entry;
  memset(&reverse_proxy.entry[reverse_proxy.entry_count], 0, sizeof(reverse_proxy.entry[0]));
  reverse_proxy.entry[reverse_proxy.entry_count].uri = uri;
  reverse_proxy.entry_count++;
  return 1;
}

static ssize_t
cmdline_read_user(char *arg, unsigned char **buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    *buf = (unsigned char *)arg;
    /* len is the size or less, so 0 terminate to maxlen */
    (*buf)[len] = '\000';
  }
  /* 0 length Identity is valid */
  return len;
}
#endif /* COAP_PROXY_SUPPORT */

static FILE *oscore_seq_num_fp = NULL;
static const char *oscore_conf_file = NULL;
static const char *oscore_seq_save_file = NULL;

static int
oscore_save_seq_num(uint64_t sender_seq_num, void *param COAP_UNUSED) {
  if (oscore_seq_num_fp) {
    rewind(oscore_seq_num_fp);
    fprintf(oscore_seq_num_fp, "%" PRIu64 "\n", sender_seq_num);
    fflush(oscore_seq_num_fp);
  }
  return 1;
}

static coap_oscore_conf_t *
get_oscore_conf(coap_context_t *context) {
  uint8_t *buf;
  size_t length;
  coap_str_const_t file_mem;
  uint64_t start_seq_num = 0;

  /* Need a rw var to free off later and file_mem.s is a const */
  buf = read_file_mem(oscore_conf_file, &length);
  if (buf == NULL) {
    fprintf(stderr, "OSCORE configuration file error: %s\n", oscore_conf_file);
    return NULL;
  }
  file_mem.s = buf;
  file_mem.length = length;
  if (oscore_seq_save_file) {
    oscore_seq_num_fp = fopen(oscore_seq_save_file, "r+");
    if (oscore_seq_num_fp == NULL) {
      /* Try creating it */
      oscore_seq_num_fp = fopen(oscore_seq_save_file, "w+");
      if (oscore_seq_num_fp == NULL) {
        fprintf(stderr, "OSCORE save restart info file error: %s\n",
                oscore_seq_save_file);
        coap_free(buf);
        return NULL;
      }
    }
    if (fscanf(oscore_seq_num_fp, "%" PRIu64, &start_seq_num) != 1) {
      /* Must be empty */
      start_seq_num = 0;
    }
  }
  oscore_conf = coap_new_oscore_conf(file_mem,
                                     oscore_save_seq_num,
                                     NULL, start_seq_num);
  coap_free(buf);
  if (oscore_conf == NULL) {
    fprintf(stderr, "OSCORE configuration file error: %s\n", oscore_conf_file);
    return NULL;
  }
  coap_context_oscore_server(context, oscore_conf);
  return oscore_conf;
}

static int
cmdline_oscore(char *arg) {
  if (coap_oscore_is_supported()) {
    char *sep = strchr(arg, ',');

    if (sep)
      *sep = '\000';
    oscore_conf_file = arg;

    if (sep) {
      sep++;
      oscore_seq_save_file = sep;
    }
    return 1;
  }
  fprintf(stderr, "OSCORE support not enabled\n");
  return 0;
}

static int
cmdline_tls_engine(char *arg) {
  uint8_t *buf;
  size_t length;
  coap_str_const_t file_mem;

  /* Need a rw var to free off later and file_mem.s is a const */
  buf = read_file_mem(arg, &length);
  if (buf == NULL) {
    fprintf(stderr, "Openssl ENGINE configuration file error: %s\n", arg);
    return 0;
  }
  file_mem.s = buf;
  file_mem.length = length;
  if (!coap_tls_engine_configure(&file_mem)) {
    coap_free(buf);
    return 0;
  }
  coap_free(buf);
  return 1;
}

/**
 * Utility function to convert a hex digit to its corresponding
 * numerical value.
 *
 * param c  The hex digit to convert. Must be in [0-9A-Fa-f].
 *
 * return The numerical representation of @p c.
 */
static uint8_t
hex2char(char c) {
  assert(isxdigit(c));
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  else
    return c - '0';
}

/**
 * Converts the sequence of hex digits in src to a sequence of bytes.
 *
 * This function returns the number of bytes that have been written to
 * @p dst.
 *
 * param[in]  src  The null-terminated hex string to convert.
 * param[out] dst  Conversion result.
 *
 * return The length of @p dst.
 */
static size_t
convert_hex_string(const char *src, uint8_t *dst) {
  uint8_t *p = dst;
  while (isxdigit((int)src[0]) && isxdigit((int)src[1])) {
    *p++ = (hex2char(src[0]) << 4) + hex2char(src[1]);
    src += 2;
  }
  if (src[0] != '\0') { /* error in hex input */
    coap_log_warn("invalid hex string in option '%s'\n", src);
  }
  return p - dst;
}

static ssize_t
cmdline_read_key(char *arg, unsigned char **buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    /* read hex string alternative when arg starts with "0x" */
    if (len >= 4 && arg[0] == '0' && arg[1] == 'x') {
      /* As the command line option is part of our environment we can do
       * the conversion in place. */
      len = convert_hex_string(arg + 2, (uint8_t *)arg);
    }
    *buf = (unsigned char *)arg;
    return len;
  }
  /* Need at least one byte for the pre-shared key */
  coap_log_crit("Invalid Pre-Shared Key specified\n");
  return -1;
}

static int
cmdline_read_psk_sni_check(char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log_err("SNI file: %s: Unable to open\n", arg);
    return 0;
  }
  while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
    char *cp = tmpbuf;
    char *tcp = strchr(cp, '\n');

    if (tmpbuf[0] == '#')
      continue;
    if (tcp)
      *tcp = '\000';

    tcp = strchr(cp, ',');
    if (tcp) {
      psk_sni_def_t *new_psk_sni_list;
      new_psk_sni_list = realloc(valid_psk_snis.psk_sni_list,
                                 (valid_psk_snis.count + 1)*sizeof(valid_psk_snis.psk_sni_list[0]));
      if (new_psk_sni_list == NULL) {
        break;
      }
      valid_psk_snis.psk_sni_list = new_psk_sni_list;
      valid_psk_snis.psk_sni_list[valid_psk_snis.count].sni_match = strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        valid_psk_snis.psk_sni_list[valid_psk_snis.count].new_hint =
            coap_new_bin_const((const uint8_t *)cp, tcp-cp);
        cp = tcp+1;
        valid_psk_snis.psk_sni_list[valid_psk_snis.count].new_key =
            coap_new_bin_const((const uint8_t *)cp, strlen(cp));
        valid_psk_snis.count++;
      } else {
        free(valid_psk_snis.psk_sni_list[valid_psk_snis.count].sni_match);
      }
    }
  }
  fclose(fp);
  return valid_psk_snis.count > 0;
}

static int
cmdline_read_identity_check(char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log_err("Identity file: %s: Unable to open\n", arg);
    return 0;
  }
  while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
    char *cp = tmpbuf;
    char *tcp = strchr(cp, '\n');

    if (tmpbuf[0] == '#')
      continue;
    if (tcp)
      *tcp = '\000';

    tcp = strchr(cp, ',');
    if (tcp) {
      id_def_t *new_id_list;
      new_id_list = realloc(valid_ids.id_list,
                            (valid_ids.count + 1)*sizeof(valid_ids.id_list[0]));
      if (new_id_list == NULL) {
        break;
      }
      valid_ids.id_list = new_id_list;
      valid_ids.id_list[valid_ids.count].hint_match = strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        valid_ids.id_list[valid_ids.count].identity_match =
            coap_new_bin_const((const uint8_t *)cp, tcp-cp);
        cp = tcp+1;
        valid_ids.id_list[valid_ids.count].new_key =
            coap_new_bin_const((const uint8_t *)cp, strlen(cp));
        valid_ids.count++;
      } else {
        free(valid_ids.id_list[valid_ids.count].hint_match);
      }
    }
  }
  fclose(fp);
  return valid_ids.count > 0;
}

static int
cmdline_unix(char *arg) {
  if (!strcmp("coap", arg)) {
    use_unix_proto = COAP_PROTO_UDP;
    return 1;
  } else if (!strcmp("coaps", arg)) {
    if (!coap_dtls_is_supported()) {
      coap_log_err("unix with dtls is not supported\n");
      return 0;
    }
    use_unix_proto = COAP_PROTO_DTLS;
    return 1;
  } else if (!strcmp("coap+tcp", arg)) {
    if (!coap_tcp_is_supported()) {
      coap_log_err("unix with stream is not supported\n");
      return 0;
    }
    use_unix_proto = COAP_PROTO_TCP;
    return 1;
  } else if (!strcmp("coaps+tcp", arg)) {
    if (!coap_tls_is_supported()) {
      coap_log_err("unix with tls is not supported\n");
      return 0;
    }
    use_unix_proto = COAP_PROTO_TLS;
    return 1;
  }
  return 0;
}

static int
cmdline_ws(char *arg) {
  char *cp = strchr(arg, ',');

  if (cp) {
    if (cp != arg)
      ws_port = atoi(arg);
    cp++;
    if (*cp != '\000')
      wss_port = atoi(cp);
  } else {
    ws_port = atoi(arg);
  }
  return 1;
}

static int
cmdline_read_pki_sni_check(char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log_err("SNI file: %s: Unable to open\n", arg);
    return 0;
  }
  while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
    char *cp = tmpbuf;
    char *tcp = strchr(cp, '\n');

    if (tmpbuf[0] == '#')
      continue;
    if (tcp)
      *tcp = '\000';

    tcp = strchr(cp, ',');
    if (tcp) {
      pki_sni_def_t *new_pki_sni_list;
      new_pki_sni_list = realloc(valid_pki_snis.pki_sni_list,
                                 (valid_pki_snis.count + 1)*sizeof(valid_pki_snis.pki_sni_list[0]));
      if (new_pki_sni_list == NULL) {
        break;
      }
      valid_pki_snis.pki_sni_list = new_pki_sni_list;
      valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match =
          strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        int fail = 0;
        valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert =
            strndup(cp, tcp-cp);
        cp = tcp+1;
        valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca =
            strndup(cp, strlen(cp));
        if (access(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert,
                   R_OK)) {
          coap_log_err("SNI file: Cert File: %s: Unable to access\n",
                       valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert);
          fail = 1;
        }
        if (access(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca,
                   R_OK)) {
          coap_log_err("SNI file: CA File: %s: Unable to access\n",
                       valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca);
          fail = 1;
        }
        if (fail) {
          free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match);
          free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_cert);
          free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].new_ca);
        } else {
          valid_pki_snis.count++;
        }
      } else {
        coap_log_err("SNI file: SNI_match,Use_Cert_file,Use_CA_file not defined\n");
        free(valid_pki_snis.pki_sni_list[valid_pki_snis.count].sni_match);
      }
    }
  }
  fclose(fp);
  return valid_pki_snis.count > 0;
}

static int
cmdline_read_extended_token_size(char *arg) {
  extended_token_size = strtoul(arg, NULL, 0);
  if (extended_token_size < COAP_TOKEN_DEFAULT_MAX) {
    coap_log_err("Extended Token Length must be 8 or greater\n");
    return 0;
  } else if (extended_token_size > COAP_TOKEN_EXT_MAX) {
    coap_log_err("Extended Token Length must be 65804 or less\n");
    return 0;
  }
  return 1;
}

#ifndef _WIN32

uint32_t syslog_pri = 0;

static void
syslog_handler(coap_log_t level, const char *message) {
  char *cp = strchr(message, '\n');

  if (cp) {
    char *lcp = strchr(message, '\r');
    if (lcp && lcp < cp)
      cp = lcp;
  }
  syslog(syslog_pri, "%s %*.*s", coap_log_level_desc(level), (int)(cp-message),
         (int)(cp-message), message);
}
#endif /* ! _WIN32 */

/*
 * This function only initiates an Observe unsolicited response when the time
 * (in seconds) changes.
 */
static void
do_time_observe_code(void *arg) {
  static coap_time_t t_last = 0;
  coap_time_t t_now;
  coap_tick_t now;

  (void)arg;
  coap_ticks(&now);
  t_now = coap_ticks_to_rt(now);
  if (t_now != t_last) {
    t_last = t_now;
    coap_resource_notify_observers(time_resource, NULL);
  }
}

int
main(int argc, char **argv) {
  coap_context_t *ctx = NULL;
  char *group = NULL;
  char *group_if = NULL;
  char addr_str[NI_MAXHOST] = "::";
  char *port_str = NULL;
  int opt;
  int mcast_per_resource = 0;
  coap_log_t log_level = COAP_LOG_WARN;
  coap_log_t dtls_log_level = COAP_LOG_ERR;
  unsigned wait_ms;
  size_t i;
  int exit_code = 0;
  uint32_t max_block_size = 0;
  int shutdown_no_observe = 0;
#ifndef _WIN32
  int use_syslog = 0;
#endif /* ! _WIN32 */
  uint16_t cache_ignore_options[] = { COAP_OPTION_BLOCK1,
                                      COAP_OPTION_BLOCK2,
                                      /* See https://rfc-editor.org/rfc/rfc7959#section-2.10 */
                                      COAP_OPTION_MAXAGE,
                                      /* See https://rfc-editor.org/rfc/rfc7959#section-2.10 */
                                      COAP_OPTION_IF_NONE_MATCH
                                    };
#ifndef _WIN32
  struct sigaction sa;
#endif

  /* Initialize libcoap library */
  coap_startup();

  clock_offset = time(NULL);

  while ((opt = getopt(argc, argv,
                       "a:b:c:d:ef:g:h:i:j:k:l:mnop:q:rs:tu:v:w:y:A:C:E:G:J:L:M:NP:R:S:T:U:V:X:Y2")) != -1) {
    switch (opt) {
#ifndef _WIN32
    case 'a':
      use_syslog = 1;
      syslog_pri = atoi(optarg);
      if (syslog_pri > 7)
        syslog_pri = 7;
      break;
#endif /* ! _WIN32 */
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'b':
      max_block_size = atoi(optarg);
      break;
    case 'c' :
      cert_file = optarg;
      break;
    case 'C' :
      ca_file = optarg;
      break;
    case 'd' :
      support_dynamic = atoi(optarg);
      break;
    case 'e':
      echo_back = 1;
      break;
    case 'E':
      doing_oscore = cmdline_oscore(optarg);
      if (!doing_oscore) {
        goto failed;
      }
      break;
    case 'f':
      if (!coap_proxy_is_supported()) {
        fprintf(stderr, "Reverse Proxy support not available as libcoap proxy code not enabled\n");
        goto failed;
      }
#if COAP_PROXY_SUPPORT
      if (!cmdline_reverse_proxy(optarg)) {
        fprintf(stderr, "Reverse Proxy error specifying upstream address\n");
        goto failed;
      }
      block_mode |= COAP_BLOCK_SINGLE_BODY;
#endif /* COAP_PROXY_SUPPORT */
      break;
    case 'g' :
      group = optarg;
      break;
    case 'G' :
      group_if = optarg;
      break;
    case 'h' :
      if (!optarg[0]) {
        hint = NULL;
        break;
      }
      hint = optarg;
      break;
    case 'i':
      if (!cmdline_read_identity_check(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        goto failed;
      }
      break;
    case 'j' :
      key_file = optarg;
      break;
    case 'J' :
      pkcs11_pin = optarg;
      break;
    case 'k' :
      key_length = cmdline_read_key(optarg, &key, MAX_KEY);
      if (key_length < 0) {
        break;
      }
      key_defined = 1;
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        goto failed;
      }
      break;
    case 'L':
      block_mode = strtoul(optarg, NULL, 0);
      if (!(block_mode & COAP_BLOCK_USE_LIBCOAP)) {
        fprintf(stderr, "Block mode must include COAP_BLOCK_USE_LIBCOAP (1)\n");
        goto failed;
      }
      break;
    case 'm':
      use_pem_buf = 1;
      break;
    case 'M':
      cert_file = optarg;
      is_rpk_not_cert = 1;
      break;
    case 'n':
      verify_peer_cert = 0;
      break;
    case 'N':
      resource_flags = COAP_RESOURCE_FLAGS_NOTIFY_NON;
      break;
    case 'o':
      shutdown_no_observe = 1;
      break;
    case 'p' :
      port_str = optarg;
      break;
    case 'P':
      if (!coap_proxy_is_supported()) {
        fprintf(stderr, "Proxy support not available as libcoap proxy code not enabled\n");
        goto failed;
      }
#if COAP_PROXY_SUPPORT
      if (!cmdline_proxy(optarg)) {
        fprintf(stderr, "error specifying proxy address or host names\n");
        goto failed;
      }
      block_mode |= COAP_BLOCK_SINGLE_BODY;
#endif /* COAP_PROXY_SUPPORT */
      break;
    case 'q':
      tls_engine_conf = optarg;
      doing_tls_engine = 1;
      break;
    case 'r' :
      mcast_per_resource = 1;
      break;
    case 'R' :
      root_ca_file = optarg;
      break;
    case 's':
      if (!cmdline_read_psk_sni_check(optarg)) {
        goto failed;
      }
      break;
    case 'S':
      if (!cmdline_read_pki_sni_check(optarg)) {
        goto failed;
      }
      break;
    case 'T':
      if (!cmdline_read_extended_token_size(optarg)) {
        goto failed;
      }
      break;
    case 't':
      track_observes = 1;
      break;
    case 'u':
      if (!coap_proxy_is_supported()) {
        fprintf(stderr, "Proxy support not available as libcoap proxy code not enabled\n");
        goto failed;
      }
#if COAP_PROXY_SUPPORT
      user_length = cmdline_read_user(optarg, &user, MAX_USER);
#endif /* COAP_PROXY_SUPPORT */
      break;
    case 'U':
      if (!cmdline_unix(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        goto failed;
      }
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'V':
      dtls_log_level = strtol(optarg, NULL, 10);
      break;
    case 'w':
      if (!coap_ws_is_supported() || !cmdline_ws(optarg)) {
        fprintf(stderr, "WebSockets not enabled in libcoap\n");
        exit(1);
      }
      enable_ws = 1;
      break;
    case 'x':
      coap_enable_pdu_data_output(0);
      break;
    case 'X':
      csm_max_message_size = strtol(optarg, NULL, 10);
      break;
    case 'y':
      reconnect_secs = atoi(optarg);
      break;
    case 'Y':
      no_trust_store = 1;
      break;
    case '2':
      ec_jpake = 1;
      break;
    default:
      usage(argv[0], LIBCOAP_PACKAGE_VERSION);
      goto failed;
    }
  }

#ifdef _WIN32
  signal(SIGINT, handle_sigint);
#else
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sigint;
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sa.sa_handler = handle_sigusr2;
  sigaction(SIGUSR2, &sa, NULL);
  /* So we do not exit on a SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);
#endif

#ifndef _WIN32
  if (use_syslog) {
    openlog("coap-server", 0, LOG_DAEMON);
    coap_set_show_pdu_output(0);
    coap_set_log_handler(syslog_handler);
  }
#endif /* ! _WIN32 */
  coap_set_log_level(log_level);
  coap_dtls_set_log_level(dtls_log_level);

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

  init_resources(ctx);
  if (mcast_per_resource)
    coap_mcast_per_resource(ctx);
  if (shutdown_no_observe)
    coap_context_set_shutdown_no_observe(ctx);
  coap_context_set_block_mode(ctx, block_mode);
  coap_context_set_max_block_size(ctx, max_block_size);
  coap_context_set_session_reconnect_time(ctx, reconnect_secs);
  coap_context_set_keepalive(ctx, 30);
  if (csm_max_message_size)
    coap_context_set_csm_max_message_size(ctx, csm_max_message_size);
  if (doing_tls_engine) {
    if (!cmdline_tls_engine(tls_engine_conf))
      goto failed;
  }
  if (doing_oscore) {
    if (get_oscore_conf(ctx) == NULL)
      goto failed;
  }
#if COAP_PROXY_SUPPORT
  if (reverse_proxy.entry_count) {
    proxy_dtls_setup(ctx, &reverse_proxy);
  }
  if (forward_proxy.entry_count) {
    proxy_dtls_setup(ctx, &forward_proxy);
  }
#endif /* COAP_PROXY_SUPPORT */
  if (extended_token_size > COAP_TOKEN_DEFAULT_MAX)
    coap_context_set_max_token_size(ctx, extended_token_size);

  /* Define the options to ignore when setting up cache-keys */
  coap_cache_ignore_options(ctx, cache_ignore_options,
                            sizeof(cache_ignore_options)/sizeof(cache_ignore_options[0]));
  /* join multicast group if requested at command line */
  if (group)
    coap_join_mcast_group_intf(ctx, group, group_if);

  if (track_observes) {
    /*
     * Read in and set up appropriate persist information.
     * Note that this should be done after ctx is properly set up.
     */
    if (!coap_persist_startup(ctx,
                              "/tmp/coap_dyn_resource_save_file",
                              "/tmp/coap_observe_save_file",
                              "/tmp/coap_obs_cnt_save_file", 10)) {
      fprintf(stderr, "Unable to set up persist logic\n");
      goto finish;
    }
  }

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

#if NUM_SERVER_THREADS
  if (!coap_io_process_loop(ctx, time_resource ? do_time_observe_code : NULL,
                            NULL, wait_ms, NUM_SERVER_THREADS)) {
    coap_log_err("coap_io_process_loop: Failed\n");
  }
#else
  int nfds = 0;
  int coap_fd;
  fd_set m_readfds;

  coap_fd = coap_context_get_coap_fd(ctx);
  if (coap_fd != -1) {
    /* if coap_fd is -1, then epoll is not supported within libcoap */
    FD_ZERO(&m_readfds);
    FD_SET(coap_fd, &m_readfds);
    nfds = coap_fd + 1;
  }

  while (!quit) {
    int result;
    coap_tick_t now;

    if (coap_fd != -1) {
      /*
       * Using epoll.  It is more usual to call coap_io_process() with wait_ms
       * (as in the non-epoll branch), but doing it this way gives the
       * flexibility of potentially working with other file descriptors that
       * are not a part of libcoap.
       */
      fd_set readfds = m_readfds;
      struct timeval tv;
      coap_tick_t begin, end;

      coap_ticks(&begin);

      tv.tv_sec = wait_ms / 1000;
      tv.tv_usec = (wait_ms % 1000) * 1000;
      /* Wait until any i/o takes place or timeout */
      result = select(nfds, &readfds, NULL, NULL, &tv);
      if (result == -1) {
        if (errno != EAGAIN) {
          coap_log_debug("select: %s (%d)\n", coap_socket_strerror(), errno);
          break;
        }
      }
      if (result > 0) {
        if (FD_ISSET(coap_fd, &readfds)) {
          result = coap_io_process(ctx, COAP_IO_NO_WAIT);
        }
      }
      if (result >= 0) {
        coap_ticks(&end);
        /* Track the overall time spent in select() and coap_io_process() */
        result = (int)(end - begin);
      }
    } else {
      /*
       * epoll is not supported within libcoap
       *
       * result is time spent in coap_io_process()
       */
      result = coap_io_process(ctx, wait_ms);
    }
    if (result < 0) {
      break;
    } else if (result && (unsigned)result < wait_ms) {
      /* decrement if there is a result wait time returned */
      wait_ms -= result;
    } else {
      /*
       * result == 0, or result >= wait_ms
       * (wait_ms could have decremented to a small value, below
       * the granularity of the timer in coap_io_process() and hence
       * result == 0)
       */
      wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    }
    if (time_resource) {
      unsigned int next_sec_ms;

      do_time_observe_code(NULL);

      /* need to wait until next second starts if wait_ms is too large */
      coap_ticks(&now);
      next_sec_ms = 1000 - (now % COAP_TICKS_PER_SECOND) *
                    1000 / COAP_TICKS_PER_SECOND;
      if (next_sec_ms && next_sec_ms < wait_ms)
        wait_ms = next_sec_ms;
    }
  }
#endif /* NUM_SERVER_THREADS */
  exit_code = 0;

finish:
  /* Clean up local usage */
  if (keep_persist)
    coap_persist_stop(ctx);

  coap_free(ca_mem);
  coap_free(cert_mem);
  coap_free(key_mem);
  coap_free(ca_mem_base);
  coap_free(cert_mem_base);
  coap_free(key_mem_base);
  for (i = 0; i < valid_psk_snis.count; i++) {
    free(valid_psk_snis.psk_sni_list[i].sni_match);
    coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_hint);
    coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_key);
  }
  if (valid_psk_snis.count)
    free(valid_psk_snis.psk_sni_list);

  for (i = 0; i < valid_ids.count; i++) {
    free(valid_ids.id_list[i].hint_match);
    coap_delete_bin_const(valid_ids.id_list[i].identity_match);
    coap_delete_bin_const(valid_ids.id_list[i].new_key);
  }
  if (valid_ids.count)
    free(valid_ids.id_list);

  for (i = 0; i < valid_pki_snis.count; i++) {
    free(valid_pki_snis.pki_sni_list[i].sni_match);
    free(valid_pki_snis.pki_sni_list[i].new_cert);
    free(valid_pki_snis.pki_sni_list[i].new_ca);
  }
  if (valid_pki_snis.count)
    free(valid_pki_snis.pki_sni_list);

  for (i = 0; i < (size_t)dynamic_count; i++) {
    coap_delete_string(dynamic_entry[i].uri_path);
    release_resource_data(NULL, dynamic_entry[i].value);
  }
  free(dynamic_entry);
  release_resource_data(NULL, example_data_value);
#if COAP_PROXY_SUPPORT
  free(reverse_proxy.entry);
  free(forward_proxy.entry);
#if defined(_WIN32) && !defined(__MINGW32__)
#pragma warning( disable : 4090 )
#endif
  coap_free(proxy_host_name_list);
#endif /* COAP_PROXY_SUPPORT */
  if (oscore_seq_num_fp)
    fclose(oscore_seq_num_fp);

  /* Clean up library usage */
  coap_free_context(ctx);
  coap_cleanup();

  return exit_code;

failed:
  exit_code = 1;
  goto finish;
}
