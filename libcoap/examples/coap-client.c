/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap-client -- simple CoAP client
 *
 * Copyright (C) 2010--2025 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define fileno _fileno
#define getpid GetCurrentProcessId
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
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
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#endif

#include <coap3/coap.h>

#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */

int flags = 0;

static coap_session_t *global_session;
static unsigned char _token_data[24]; /* With support for RFC8974 */
static coap_binary_t the_token = { 0, _token_data };

typedef struct {
  coap_binary_t *token;
  int observe;
} track_token;

static track_token *tracked_tokens = NULL;
static size_t tracked_tokens_count = 0;

#define FLAGS_BLOCK 0x01

static coap_optlist_t *optlist = NULL;
/* Request URI.
 * TODO: associate the resources with transaction id and make it expireable */
static coap_uri_t uri;
static coap_uri_t proxy = { {0, NULL}, 0, {0, NULL}, {0, NULL}, 0 };
static int proxy_scheme_option = 0;
static int uri_host_option = 0;
static unsigned int ping_seconds = 0;
static int setup_cid = 0;
static uint32_t reconnect_secs = 0;

#define REPEAT_DELAY_MS 1000
static size_t repeat_count = 1;

/* reading is done when this flag is set */
static int ready = 0;

/* processing a block response when this flag is set */
static int doing_getting_block = 0;
static int single_block_requested = 0;
static uint32_t block_mode = COAP_BLOCK_USE_LIBCOAP;

static coap_string_t output_file = { 0, NULL };   /* output file name */
static FILE *file = NULL;               /* output file stream */

static coap_string_t payload = { 0, NULL };       /* optional payload to send */

static int reliable = 0;

static int add_nl = 0;
static int is_mcast = 0;
static uint32_t csm_max_message_size = 0;

static unsigned char msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */

static char *cert_file = NULL; /* certificate and optional private key in PEM,
                                  or PKCS11 URI*/
static char *key_file = NULL; /* private key in PEM, DER or PKCS11 URI */
static char *pkcs11_pin = NULL; /* PKCS11 pin to unlock access to token */
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM,
                                  DER or PKCS11 URI */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */
static int no_trust_store = 0; /* Trust store not to be installed. */
static int is_rpk_not_cert = 0; /* Cert is RPK if set */
static uint8_t *cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *key_mem = NULL; /* private key in PEM_BUF */
static uint8_t *ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t key_mem_len = 0;
static size_t ca_mem_len = 0;
static int verify_peer_cert = 1; /* PKI granularity - by default set */

typedef struct ih_def_t {
  char *hint_match;
  coap_bin_const_t *new_identity;
  coap_bin_const_t *new_key;
} ih_def_t;

typedef struct valid_ihs_t {
  size_t count;
  ih_def_t *ih_list;
} valid_ihs_t;

static valid_ihs_t valid_ihs = {0, NULL};

typedef unsigned char method_t;
static method_t method = 1;                    /* the method we are using in our requests */

static coap_block_t block = { .num = 0, .m = 0, .szx = 6 };

#define DEFAULT_WAIT_TIME 90

static unsigned int wait_seconds = DEFAULT_WAIT_TIME; /* default timeout in seconds */
static unsigned int wait_ms = 0;
static int obs_started = 0;
static unsigned int obs_seconds = 30;          /* default observe time */
static unsigned int obs_ms = 0;                /* timeout for current subscription */
static int obs_ms_reset = 0;
static int doing_observe = 0;

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static coap_oscore_conf_t *oscore_conf = NULL;
static int doing_oscore = 0;
static int doing_tls_engine = 0;
static char *tls_engine_conf = NULL;
static int ec_jpake = 0;

static int quit = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum COAP_UNUSED) {
  quit = 1;
  coap_send_recv_terminate();
}

static int
append_to_output(const uint8_t *data, size_t len) {
  size_t written;

  if (!file) {
    if (!output_file.s || (output_file.length && output_file.s[0] == '-')) {
      file = stdout;
    } else {
      if (!(file = fopen((char *)output_file.s, "w"))) {
        perror("fopen");
        return -1;
      }
    }
  }

  do {
    written = fwrite(data, 1, len, file);
    len -= written;
    data += written;
  } while (written && len);
  fflush(file);

  return 0;
}

static void
close_output(void) {
  if (file) {

    /* add a newline before closing if no option '-o' was specified */
    if (!output_file.s)
      (void)fwrite("\n", 1, 1, file);

    fflush(file);
    fclose(file);
  }
}

static void
free_xmit_data(coap_session_t *session COAP_UNUSED, void *app_ptr) {
  coap_free(app_ptr);
  return;
}

static void
track_new_token(size_t tokenlen, uint8_t *token) {
  track_token *new_list = realloc(tracked_tokens,
                                  (tracked_tokens_count + 1) * sizeof(tracked_tokens[0]));
  if (!new_list) {
    coap_log_info("Unable to track new token\n");
    return;
  }
  tracked_tokens = new_list;
  tracked_tokens[tracked_tokens_count].token = coap_new_binary(tokenlen);
  if (!tracked_tokens[tracked_tokens_count].token)
    return;
  memcpy(tracked_tokens[tracked_tokens_count].token->s, token, tokenlen);
  tracked_tokens[tracked_tokens_count].observe = doing_observe;
  tracked_tokens_count++;
}

static int
track_check_token(coap_bin_const_t *token) {
  size_t i;

  for (i = 0; i < tracked_tokens_count; i++) {
    if (coap_binary_equal(token, tracked_tokens[i].token)) {
      return 1;
    }
  }
  return 0;
}

static void
track_flush_token(coap_bin_const_t *token, int force) {
  size_t i;

  for (i = 0; i < tracked_tokens_count; i++) {
    if (coap_binary_equal(token, tracked_tokens[i].token)) {
      if (force || !tracked_tokens[i].observe || !obs_started) {
        /* Only remove if not Observing */
        coap_delete_binary(tracked_tokens[i].token);
        if (tracked_tokens_count-i > 1) {
          memmove(&tracked_tokens[i],
                  &tracked_tokens[i+1],
                  (tracked_tokens_count-i-1) * sizeof(tracked_tokens[0]));
        }
        tracked_tokens_count--;
      }
      break;
    }
  }
}


static coap_pdu_t *
coap_new_request(coap_context_t *ctx,
                 coap_session_t *session,
                 method_t m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) {
  coap_pdu_t *pdu;
  uint8_t token[8];
  size_t tokenlen;
  (void)ctx;

  if (!(pdu = coap_new_pdu(msgtype, m, session))) {
    free_xmit_data(session, data);
    return NULL;
  }

  /*
   * Create unique token for this request for handling unsolicited /
   * delayed responses.
   * Note that only up to 8 bytes are returned
   */
  if (the_token.length > COAP_TOKEN_DEFAULT_MAX) {
    coap_session_new_token(session, &tokenlen, token);
    /* Update the last part 8 bytes of the large token */
    memcpy(&the_token.s[the_token.length - tokenlen], token, tokenlen);
  } else {
    coap_session_new_token(session, &the_token.length, the_token.s);
  }
  track_new_token(the_token.length, the_token.s);
  if (!coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log_debug("cannot add token to request\n");
  }

  if (options)
    coap_add_optlist_pdu(pdu, options);

  if (length) {
    /* Let the underlying libcoap decide how this data should be sent */
    coap_add_data_large_request(session, pdu, length, data,
                                free_xmit_data, data);
  }

  return pdu;
}

static int
event_handler(coap_session_t *session COAP_UNUSED,
              const coap_event_t event) {

  switch (event) {
  case COAP_EVENT_TCP_CLOSED:
  case COAP_EVENT_DTLS_CLOSED:
    if (!reconnect_secs)
      quit = 1;
    break;
  case COAP_EVENT_SESSION_CLOSED:
  case COAP_EVENT_OSCORE_DECRYPTION_FAILURE:
  case COAP_EVENT_OSCORE_NOT_ENABLED:
  case COAP_EVENT_OSCORE_NO_PROTECTED_PAYLOAD:
  case COAP_EVENT_OSCORE_NO_SECURITY:
  case COAP_EVENT_OSCORE_INTERNAL_ERROR:
  case COAP_EVENT_OSCORE_DECODE_ERROR:
  case COAP_EVENT_WS_PACKET_SIZE:
  case COAP_EVENT_WS_CLOSED:
  case COAP_EVENT_BAD_PACKET:
    quit = 1;
    break;
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
  case COAP_EVENT_MSG_RETRANSMITTED:
  case COAP_EVENT_WS_CONNECTED:
  case COAP_EVENT_KEEPALIVE_FAILURE:
  default:
    break;
  }
  return 0;
}

static void
nack_handler(coap_session_t *session COAP_UNUSED,
             const coap_pdu_t *sent,
             const coap_nack_reason_t reason,
             const coap_mid_t mid COAP_UNUSED) {
  if (sent) {
    coap_bin_const_t token = coap_pdu_get_token(sent);

    if (coap_pdu_get_code(sent) != COAP_EMPTY_CODE && !track_check_token(&token)) {
      coap_show_pdu(0, sent);
      coap_log_err("nack_handler: %d: Unexpected token\n", reason);
    }
  }

  switch (reason) {
  case COAP_NACK_NOT_DELIVERABLE:
  case COAP_NACK_TLS_FAILED:
  case COAP_NACK_TOO_MANY_RETRIES:
    coap_log_err("cannot send CoAP pdu\n");
    if (!reconnect_secs)
      quit = 1;
    break;
  case COAP_NACK_WS_FAILED:
  case COAP_NACK_TLS_LAYER_FAILED:
  case COAP_NACK_WS_LAYER_FAILED:
    coap_log_err("cannot send CoAP pdu\n");
    quit = 1;
    break;
  case COAP_NACK_RST:
    coap_log_info("received RST pdu response\n");
    quit = 1;
    break;
  case COAP_NACK_BAD_RESPONSE:
    coap_log_info("received bad response pdu\n");
    quit = 1;
    break;
  case COAP_NACK_ICMP_ISSUE:
  default:
    ;
  }
  return;
}

/*
 * Response handler used for coap_send() responses
 */
static coap_response_t
response_handler(coap_session_t *session COAP_UNUSED,
                 const coap_pdu_t *sent,
                 const coap_pdu_t *received,
                 const coap_mid_t id COAP_UNUSED) {

  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  size_t len;
  const uint8_t *databuf;
  size_t offset;
  size_t total;
  coap_pdu_code_t rcv_code = coap_pdu_get_code(received);
  coap_pdu_type_t rcv_type = coap_pdu_get_type(received);
  coap_bin_const_t token = coap_pdu_get_token(received);

  coap_log_debug("** process incoming %d.%02d response:\n",
                 COAP_RESPONSE_CLASS(rcv_code), rcv_code & 0x1F);
  if (coap_get_log_level() < COAP_LOG_DEBUG)
    coap_show_pdu(COAP_LOG_INFO, received);

  /* check if this is a response to our original request */
  if (!track_check_token(&token)) {
    /* drop if this was just some message, or send RST in case of notification */
    if (!sent && (rcv_type == COAP_MESSAGE_CON ||
                  rcv_type == COAP_MESSAGE_NON)) {
      /* Cause a CoAP RST to be sent */
      return COAP_RESPONSE_FAIL;
    }
    return COAP_RESPONSE_OK;
  }

  if (rcv_type == COAP_MESSAGE_RST) {
    coap_log_info("got RST\n");
    return COAP_RESPONSE_OK;
  }

  /* output the received data, if any */
  if (COAP_RESPONSE_CLASS(rcv_code) == 2) {

    /* set obs timer if we have successfully subscribed a resource */
    if (doing_observe && !obs_started &&
        coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter)) {
      coap_log_debug("observation relationship established, set timeout to %d\n",
                     obs_seconds);
      obs_started = 1;
      obs_ms = obs_seconds * 1000;
      obs_ms_reset = 1;
    }

    if (coap_get_data_large(received, &len, &databuf, &offset, &total)) {
      append_to_output(databuf, len);
      if ((len + offset == total) && add_nl)
        append_to_output((const uint8_t *)"\n", 1);
    }

    /* Check if Block2 option is set */
    block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
    if (!single_block_requested && block_opt) { /* handle Block2 */

      /* TODO: check if we are looking at the correct block number */
      if (coap_opt_block_num(block_opt) == 0) {
        /* See if observe is set in first response */
        ready = doing_observe ? coap_check_option(received,
                                                  COAP_OPTION_OBSERVE, &opt_iter) == NULL : 1;
      }
      if (COAP_OPT_BLOCK_MORE(block_opt)) {
        doing_getting_block = 1;
      } else {
        doing_getting_block = 0;
        if (!is_mcast)
          track_flush_token(&token, 0);
      }
      return COAP_RESPONSE_OK;
    }
  } else {      /* no 2.05 */
    /* check if an error was signaled and output payload if so */
    if (COAP_RESPONSE_CLASS(rcv_code) >= 4) {
      fprintf(stderr, "%d.%02d", COAP_RESPONSE_CLASS(rcv_code),
              rcv_code & 0x1F);
      if (coap_get_data_large(received, &len, &databuf, &offset, &total)) {
        fprintf(stderr, " ");
        while (len--) {
          fprintf(stderr, "%c", isprint(*databuf) ? *databuf : '.');
          databuf++;
        }
      }
      fprintf(stderr, "\n");
      track_flush_token(&token, 1);
    }

  }
  if (!is_mcast)
    track_flush_token(&token, 0);

  /* our job is done, we can exit at any time */
  ready = is_mcast ? 0 : doing_observe ?
          coap_check_option(received,
                            COAP_OPTION_OBSERVE, &opt_iter) == NULL : 1;
  return COAP_RESPONSE_OK;
}

static void
usage(const char *program, const char *version) {
  const char *p;
  char buffer[120];
  const char *lib_build = coap_package_build();

  p = strrchr(program, '/');
  if (p)
    program = ++p;

  fprintf(stderr, "%s v%s -- a small CoAP implementation\n"
          "Copyright (C) 2010-2025 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
          "Build: %s\n"
          "%s\n"
          , program, version, lib_build,
          coap_string_tls_version(buffer, sizeof(buffer)));
  fprintf(stderr, "%s\n", coap_string_tls_support(buffer, sizeof(buffer)));
  fprintf(stderr, "\n"
          "Usage: %s [-a addr] [-b [num,]size] [-e text] [-f file] [-l loss]\n"
          "\t\t[-m method] [-o file] [-p port] [-q tls_engine_conf_file] [-r]\n"
          "\t\t[-s duration] [-t type] [-v num] [-w] [-x]  [-y rec_secs]\n"
          "\t\t[-A type] [-B seconds]\n"
          "\t\t[-E oscore_conf_file[,seq_file]] [-G count] [-H hoplimit]\n"
          "\t\t[-K interval] [-N] [-O num,text] [-P scheme://address[:port]\n"
          "\t\t[-T token] [-U] [-V num] [-X size]\n"
          "\t\t[[-d count]]\n"
          "\t\t[[h match_hint_file] [-k key] [-u user] [-2]]\n"
          "\t\t[[-c certfile] [-j keyfile] [-n] [-C cafile]\n"
          "\t\t[-J pkcs11_pin] [-M raw_pk] [-R trust_casfile] [-Y]] URI\n"
          "\tURI can be an absolute URI or a URI prefixed with scheme and host\n\n"
          "General Options\n"
          "\t-a addr\t\tThe local interface address to use\n"
          "\t-b [num,]size\tBlock size to be used in GET/PUT/POST requests\n"
          "\t       \t\t(value must be 16, 32, 64, 128, 256, 512 or 1024)\n"
          "\t       \t\tIf num is present, the request chain will start at\n"
          "\t       \t\tblock num\n"
          "\t-e text\t\tInclude text as payload (use percent-encoding for\n"
          "\t       \t\tnon-ASCII characters)\n"
          "\t-f file\t\tFile to send with PUT/POST (use '-' for STDIN)\n"
          "\t-l list\t\tFail to send some datagrams specified by a comma\n"
          "\t       \t\tseparated list of numbers or number ranges\n"
          "\t       \t\t(for debugging only)\n"
          "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
          "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
          "\t-m method\tRequest method (get|put|post|delete|fetch|patch|ipatch),\n"
          "\t       \t\tdefault is 'get'\n"
          "\t-o file\t\tOutput received data to this file (use '-' for STDOUT)\n"
          "\t-p port\t\tSend from the specified port\n"
          "\t-q tls_engine_conf_file\n"
          "\t       \t\ttls_engine_conf_file contains TLS ENGINE configuration.\n"
          "\t       \t\tSee coap-tls-engine-conf(5) for definitions.\n"
          "\t-s duration\tSubscribe to / Observe resource for given duration\n"
          "\t       \t\tin seconds\n"
          "\t-t type\t\tContent format for given resource for PUT/POST\n"
          "\t-v num \t\tVerbosity level (default 4, maximum is 8) for general\n"
          "\t       \t\tCoAP logging\n"
          "\t-w     \t\tAppend a newline to received data\n"
          "\t-x     \t\tDisable output of PDU data when displaying PDUs\n"
          "\t-y rec_secs\tAttempt to reconnect a failed session every rec_secs\n"
          "\t-A type\t\tAccepted media type\n"
          "\t-B seconds\tBreak operation after waiting given seconds\n"
          "\t       \t\t(default is %d)\n"
          "\t-E oscore_conf_file[,seq_file]\n"
          "\t       \t\toscore_conf_file contains OSCORE configuration. See\n"
          "\t       \t\tcoap-oscore-conf(5) for definitions.\n"
          "\t       \t\tOptional seq_file is used to save the current transmit\n"
          "\t       \t\tsequence number, so on restart sequence numbers continue\n"
          "\t-G count\tRepeat the Request 'count' times with a second delay\n"
          "\t       \t\tbetween each one. Must have a value between 1 and 255\n"
          "\t       \t\tinclusive. Default is '1'\n"
          "\t-H hoplimit\tSet the Hop Limit count to hoplimit for proxies. Must\n"
          "\t       \t\thave a value between 1 and 255 inclusive.\n"
          "\t       \t\tDefault is '16'\n"
          "\t-K interval\tSend a ping after interval seconds of inactivity\n"
          "\t-L value\tSum of one or more COAP_BLOCK_* flag valuess for block\n"
          "\t       \t\thandling methods. Default is 1 (COAP_BLOCK_USE_LIBCOAP)\n"
          "\t       \t\t(Sum of one or more of 1,2,4,8,16 and 32)\n"
          "\t-N     \t\tSend NON-confirmable message\n"
          "\t-O num,text\tAdd option num with contents text to request. If the\n"
          "\t       \t\ttext begins with 0x, then the hex text (two [0-9a-f] per\n"
          "\t       \t\tbyte) is converted to binary data\n"
          "\t-P scheme://address[:port]\n"
          "\t       \t\tScheme, address and optional port to define how to\n"
          "\t       \t\tconnect to a CoAP proxy (automatically adds Proxy-Uri\n"
          "\t       \t\toption to request) to forward the request to.\n"
          "\t       \t\tScheme is one of coap, coaps, coap+tcp, coaps+tcp,\n"
          "\t       \t\tcoap+ws, and coaps+ws\n"
          "\t-T token\tDefine the initial starting token (up to 24 characters)\n"
          "\t-U     \t\tNever include Uri-Host or Uri-Port options\n"
          "\t-V num \t\tVerbosity level (default 3, maximum is 7) for (D)TLS\n"
          "\t       \t\tlibrary logging\n"
          "\t-X size\t\tMaximum message size to use for TCP based connections\n"
          "\t       \t\t(default is 8388864). Maximum value of 2^32 -1\n"
          ,program, wait_seconds);
  fprintf(stderr,
          "DTLS Options (if supported by underlying (D)TLS library)\n"
          "\t-d count\n"
          "\t       \t\tFor DTLS, enable use of Connection-ID. If count\n"
          "\t       \t\tis not 0, then the client will changes its source port\n"
          "\t       \t\tevery count packets to test CID\n"
         );
  fprintf(stderr,
          "PSK Options (if supported by underlying (D)TLS library)\n"
          "\t-h match_hint_file\n"
          "\t       \t\tThis is a file that contains one or more lines of\n"
          "\t       \t\treceived Identity Hints to match to use different\n"
          "\t       \t\tuser identity and associated pre-shared key (PSK) (comma\n"
          "\t       \t\tseparated) instead of the '-k key' and '-u user'\n"
          "\t       \t\toptions. E.g., per line\n"
          "\t       \t\t hint_to_match,use_user,with_key\n"
          "\t       \t\tNote: -k and -u still need to be defined for the default\n"
          "\t       \t\tin case there is no match\n"
          "\t-k key \t\tPre-shared key for the specified user identityt. If the\n"
          "\t       \t\tkey begins with 0x, then the hex text (two [0-9a-f] per\n"
          "\t       \t\tbyte) is converted to binary data\n"
          "\t-u user\t\tUser identity to send for pre-shared key mode\n"
          "\t-2     \t\tUse EC-JPAKE negotiation (if supported)\n"
          "PKI Options (if supported by underlying (D)TLS library)\n"
          "\tNote: If any one of '-c certfile', '-j keyfile' or '-C cafile' is in\n"
          "\tPKCS11 URI naming format (pkcs11: prefix), then any remaining non\n"
          "\tPKCS11 URI file definitions have to be in DER, not PEM, format.\n"
          "\tOtherwise all of '-c certfile', '-j keyfile' or '-C cafile' are in\n"
          "\tPEM format.\n\n"
          "\t-c certfile\tPEM file or PKCS11 URI for the certificate. The private\n"
          "\t       \t\tkey can also be in the PEM file, or has the same PKCS11\n"
          "\t       \t\tURI. If not, the private key is defined by '-j keyfile'\n"
          "\t       \t\tIf both the  '-c certfile' and '-k key' options are not\n"
          "\t       \t\tprovided, but the protocol is using encryption (e.g.\n"
          "\t       \t\tcoaps), then the client logic will use internally\n"
          "\t       \t\tgenerated certificates (as do web browsers) but will\n"
          "\t       \t\tcheck the server certificate based on the trust store\n"
          "\t       \t\t(or the '-R trust_casfile' option) unless the '-n'\n"
          "\t       \t\toption is specified\n"
          "\t-j keyfile\tPEM file or PKCS11 URI for the private key for the\n"
          "\t       \t\tcertificate in '-c certfile' if the parameter is\n"
          "\t       \t\tdifferent from certfile in '-c certfile'\n"
          "\t-n     \t\tDisable remote peer certificate checking\n"
          "\t-C cafile\tPEM file or PKCS11 URI for the CA certificate and any\n"
          "\t       \t\tintermediate CAs that was\n"
          "\t       \t\tused to sign the server certfile. Ideally the client\n"
          "\t       \t\tcertificate should be signed by the same CA so that\n"
          "\t       \t\tmutual authentication can take place. The contents of\n"
          "\t       \t\tcafile are added to the trusted store of root CAs.\n"
          "\t       \t\tUsing the -C or -R options will trigger the\n"
          "\t       \t\tvalidation of the server certificate unless overridden\n"
          "\t       \t\tby the -n option\n"
          "\t-J pkcs11_pin\tThe user pin to unlock access to the PKCS11 token\n"
          "\t-M rpk_file\tRaw Public Key (RPK) PEM file or PKCS11 URI that\n"
          "\t       \t\tcontains both PUBLIC KEY and PRIVATE KEY or just\n"
          "\t       \t\tEC PRIVATE KEY. (GnuTLS and TinyDTLS(PEM) support only).\n"
          "\t       \t\t'-C cafile' or '-R trust_casfile' are not required\n"
          "\t-R trust_casfile\n"
          "\t       \t\tPEM file containing the set of trusted root CAs\n"
          "\t       \t\tthat are to be used to validate the server certificate.\n"
          "\t       \t\tAlternatively, this can point to a directory containing\n"
          "\t       \t\ta set of CA PEM files.\n"
          "\t       \t\tUsing '-R trust_casfile' disables common CA mutual\n"
          "\t       \t\tauthentication which can only be done by using\n"
          "\t       \t\t'-C cafile'.\n"
          "\t       \t\tUsing the -C or -R options will trigger the\n"
          "\t       \t\tvalidation of the server certificate unless overridden\n"
          "\t       \t\tby the -n option\n"
          "\t-Y\n"
          "\t       \t\tDo not load the default system Trusted Root CA Store\n"
         );
  fprintf(stderr,
          "Examples:\n"
          "\tcoap-client -m get coap://[::1]/\n"
          "\tcoap-client -m get coap://[::1]/.well-known/core\n"
          "\tcoap-client -m get coap+tcp://[::1]/.well-known/core\n"
          "\tcoap-client -m get coap://%%2Funix%%2Fdomain%%2Fpath%%2Fdgram/.well-known/core\n"
          "\tcoap-client -m get coap+tcp://%%2Funix%%2Fdomain%%2Fpath%%2Fstream/.well-known/core\n"
          "\tcoap-client -m get coaps://[::1]/.well-known/core\n"
          "\tcoap-client -m get coaps+tcp://[::1]/.well-known/core\n"
          "\tcoap-client -m get -N coap://[ff02::fd%%ens32]/.well-known/core\n"
          "\tcoap-client -m get coaps://%%2Funix%%2Fdomain%%2Fpath%%2Fdtls/.well-known/core\n"
          "\tcoap-client -m get coaps+tcp://%%2Funix%%2Fdomain%%2Fpath%%2Ftls/.well-known/core\n"
          "\tcoap-client -m get -T cafe coap://[::1]/time\n"
          "\tcoap-client -m get -T cafe -P coap://upstream-proxy coap://[::1]/time\n"
          "\techo -n 1000 | coap-client -m put -T cafe coap://[::1]/time -f -\n"
         );
}

typedef struct {
  unsigned char code;
  const char *media_type;
} content_type_t;

static void
cmdline_content_type(char *arg, uint16_t key) {
  static content_type_t content_types[] = {
    {  0, "plain" },
    {  0, "text/plain" },
    { 40, "link" },
    { 40, "link-format" },
    { 40, "application/link-format" },
    { 41, "xml" },
    { 41, "application/xml" },
    { 42, "binary" },
    { 42, "octet-stream" },
    { 42, "application/octet-stream" },
    { 47, "exi" },
    { 47, "application/exi" },
    { 50, "json" },
    { 50, "application/json" },
    { 60, "cbor" },
    { 60, "application/cbor" },
    { 255, NULL }
  };
  coap_optlist_t *node;
  unsigned char i;
  uint16_t value;
  uint8_t buf[4];

  if (isdigit((int)arg[0])) {
    value = atoi(arg);
  } else {
    for (i=0;
         content_types[i].media_type &&
         strncmp(arg, content_types[i].media_type, strlen(arg)) != 0 ;
         ++i)
      ;

    if (content_types[i].media_type) {
      value = content_types[i].code;
    } else {
      coap_log_warn("W: unknown content-format '%s'\n",arg);
      return;
    }
  }

  node = coap_new_optlist(key, coap_encode_var_safe(buf, sizeof(buf), value), buf);
  if (node) {
    coap_insert_optlist(&optlist, node);
  }
}

static int
cmdline_hop_limit(char *arg) {
  coap_optlist_t *node;
  uint32_t value;
  uint8_t buf[4];

  value = strtol(arg, NULL, 10);
  if (value < 1 || value > 255) {
    return 0;
  }
  node = coap_new_optlist(COAP_OPTION_HOP_LIMIT, coap_encode_var_safe(buf, sizeof(buf), value), buf);
  if (node) {
    coap_insert_optlist(&optlist, node);
  }
  return 1;
}

static uint8_t *
read_file_mem(const char *filename, size_t *length) {
  FILE *f;
  uint8_t *buf;
  struct stat statbuf;

  *length = 0;
  if (!filename || !(f = fopen(filename, "r")))
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
get_oscore_conf(void) {
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
 * Sets global URI options according to the URI passed as @p arg.
 * This function returns 0 on success or -1 on error.
 *
 * @param arg             The URI string.
 * @param create_uri_opts Flags that indicate whether Uri-Host and
 *                        Uri-Port should be suppressed.
 * @return 0 on success, -1 otherwise
 */
static int
cmdline_uri(char *arg) {

  if (!proxy_scheme_option && proxy.host.length) {
    /* create Proxy-Uri from argument */
    size_t len = strlen(arg);
    if (len > 1034) {
      coap_log_err("Absolute URI length must be <= 1034 bytes for a proxy\n");
      return -1;
    }

    coap_insert_optlist(&optlist,
                        coap_new_optlist(COAP_OPTION_PROXY_URI,
                                         len,
                                         (unsigned char *)arg));

  } else {      /* split arg into Uri-* options */
    if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0) {
      coap_log_err("invalid CoAP URI\n");
      return -1;
    }

    /* Need to special case use of reliable */
    if (uri.scheme == COAP_URI_SCHEME_COAPS && reliable) {
      if (!coap_tls_is_supported()) {
        coap_log_emerg("coaps+tcp URI scheme not supported in this version of libcoap\n");
        return -1;
      } else {
        uri.scheme = COAP_URI_SCHEME_COAPS_TCP;
      }
    }

    if (uri.scheme == COAP_URI_SCHEME_COAP && reliable) {
      if (!coap_tcp_is_supported()) {
        coap_log_emerg("coap+tcp URI scheme not supported in this version of libcoap\n");
        return -1;
      } else {
        uri.scheme = COAP_URI_SCHEME_COAP_TCP;
      }
    }
  }
  return 0;
}

static int
cmdline_blocksize(char *arg) {
  uint16_t size;

again:
  size = 0;
  while (*arg && *arg != ',')
    size = size * 10 + (*arg++ - '0');

  if (*arg == ',') {
    arg++;
    block.num = size;
    if (size != 0) {
      /* Random access selection - only handle single response */
      single_block_requested = 1;
    }
    goto again;
  }

  if (size < 16) {
    coap_log_warn("Minimum block size is 16\n");
    return 0;
  } else if (size > 1024) {
    coap_log_warn("Maximum block size is 1024\n");
    return 0;
  } else if (size != ((1 << (coap_fls(size >> 4) - 1) << 4))) {
    coap_log_warn("Block size %u invalid\n", size);
    return 0;
  }
  if (size)
    block.szx = (coap_fls(size >> 4) - 1) & 0x07;

  flags |= FLAGS_BLOCK;
  return 1;
}

/* Called after processing the options from the commandline to set
 * Block1, Block2, Q-Block1 or Q-Block2 depending on method. */
static void
set_blocksize(void) {
  static unsigned char buf[4];        /* hack: temporarily take encoded bytes */
  uint16_t opt;
  unsigned int opt_length;

  if (method != COAP_REQUEST_DELETE) {
    block.m = (1ull << (block.szx + 4)) < payload.length;

    if (!block.m &&
        (method == COAP_REQUEST_GET || method == COAP_REQUEST_FETCH)) {
      if (coap_q_block_is_supported() && block_mode & COAP_BLOCK_TRY_Q_BLOCK)
        opt = COAP_OPTION_Q_BLOCK2;
      else
        opt = COAP_OPTION_BLOCK2;
    } else {
      if (coap_q_block_is_supported() && block_mode & COAP_BLOCK_TRY_Q_BLOCK)
        opt = COAP_OPTION_Q_BLOCK1;
      else
        opt = COAP_OPTION_BLOCK1;
    }

    block.m = (opt == COAP_OPTION_BLOCK1 || opt == COAP_OPTION_Q_BLOCK1) &&
              ((1ull << (block.szx + 4)) < payload.length);

    opt_length = coap_encode_var_safe(buf, sizeof(buf),
                                      (block.num << 4 | block.m << 3 | block.szx));

    coap_insert_optlist(&optlist, coap_new_optlist(opt, opt_length, buf));
  }
}

static void
cmdline_subscribe(char *arg) {
  uint8_t buf[4];

  obs_seconds = atoi(arg);
  coap_insert_optlist(&optlist,
                      coap_new_optlist(COAP_OPTION_OBSERVE,
                                       coap_encode_var_safe(buf, sizeof(buf),
                                                            COAP_OBSERVE_ESTABLISH), buf)
                     );
  doing_observe = 1;
}

static int
cmdline_proxy(char *arg) {
  if (coap_split_uri((unsigned char *)arg, strlen(arg), &proxy) < 0 ||
      proxy.path.length != 0 || proxy.query.length != 0) {
    coap_log_err("invalid CoAP Proxy definition\n");
    return 0;
  }
  return 1;
}

static inline void
cmdline_token(char *arg) {
  the_token.length = min(sizeof(_token_data), strlen(arg));
  if (the_token.length > 0) {
    memcpy((char *)the_token.s, arg, the_token.length);
  }
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

static void
cmdline_option(char *arg) {
  unsigned int num = 0;

  while (*arg && *arg != ',') {
    num = num * 10 + (*arg - '0');
    ++arg;
  }
  if (*arg == ',')
    ++arg;

  /* read hex string when arg starts with "0x" */
  if (arg[0] == '0' && arg[1] == 'x') {
    /* As the command line option is part of our environment we can do
     * the conversion in place. */
    size_t len = convert_hex_string(arg + 2, (uint8_t *)arg);

    /* On success, 2 * len + 2 == strlen(arg) */
    coap_insert_optlist(&optlist,
                        coap_new_optlist(num, len, (unsigned char *)arg));
  } else { /* null-terminated character string */
    coap_insert_optlist(&optlist,
                        coap_new_optlist(num, strlen(arg), (unsigned char *)arg));
  }
  if (num == COAP_OPTION_PROXY_SCHEME) {
    proxy_scheme_option = 1;
    if (strcasecmp(arg, "coaps+tcp") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAPS_TCP;
      proxy.port = COAPS_DEFAULT_PORT;
    } else if (strcasecmp(arg, "coap+tcp") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAP_TCP;
      proxy.port = COAP_DEFAULT_PORT;
    } else if (strcasecmp(arg, "coaps") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAPS;
      proxy.port = COAPS_DEFAULT_PORT;
    } else if (strcasecmp(arg, "coap") == 0) {
      proxy.scheme = COAP_URI_SCHEME_COAP;
      proxy.port = COAP_DEFAULT_PORT;
    } else {
      coap_log_warn("%s is not a supported CoAP Proxy-Scheme\n", arg);
    }
  }
  if (num == COAP_OPTION_URI_HOST) {
    uri_host_option = 1;
  }
}

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

/**
 * Decodes percent-encoded characters while copying the string @p seg
 * of size @p length to @p buf. The caller of this function must
 * ensure that the percent-encodings are correct (i.e. the character
 * '%' is always followed by two hex digits. and that @p buf provides
 * sufficient space to hold the result. This function is supposed to
 * be called by make_decoded_option() only.
 *
 * @param seg     The segment to decode and copy.
 * @param length  Length of @p seg.
 * @param buf     The result buffer.
 */
static void
decode_segment(const uint8_t *seg, size_t length, unsigned char *buf) {

  while (length--) {

    if (*seg == '%') {
      *buf = (hexchar_to_dec(seg[1]) << 4) + hexchar_to_dec(seg[2]);

      seg += 2;
      length -= 2;
    } else {
      *buf = *seg;
    }

    ++buf;
    ++seg;
  }
}

/**
 * Runs through the given path (or query) segment and checks if
 * percent-encodings are correct. This function returns @c -1 on error
 * or the length of @p s when decoded.
 */
static int
check_segment(const uint8_t *s, size_t length) {

  int n = 0;

  while (length) {
    if (*s == '%') {
      if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
        return -1;

      s += 2;
      length -= 2;
    }

    ++s;
    ++n;
    --length;
  }

  return n;
}

static int
cmdline_input(char *text, coap_string_t *buf) {
  int len;
  len = check_segment((unsigned char *)text, strlen(text));

  if (len < 0)
    return 0;

  buf->s = (unsigned char *)coap_malloc(len);
  if (!buf->s)
    return 0;

  buf->length = len;
  decode_segment((unsigned char *)text, strlen(text), buf->s);
  return 1;
}

static int
cmdline_input_from_file(char *filename, coap_string_t *buf) {
  FILE *inputfile = NULL;
  ssize_t len;
  int result = 1;
  struct stat statbuf;

  if (!filename || !buf)
    return 0;

  if (filename[0] == '-' && !filename[1]) { /* read from stdin */
    buf->length = 20000;
    buf->s = (unsigned char *)coap_malloc(buf->length);
    if (!buf->s)
      return 0;

    inputfile = stdin;
  } else {
    /* read from specified input file */
    inputfile = fopen(filename, "r");
    if (!inputfile) {
      perror("cmdline_input_from_file: fopen");
      return 0;
    }

    if (fstat(fileno(inputfile), &statbuf) < 0) {
      perror("cmdline_input_from_file: stat");
      fclose(inputfile);
      return 0;
    }

    buf->length = statbuf.st_size;
    buf->s = (unsigned char *)coap_malloc(buf->length);
    if (!buf->s) {
      fclose(inputfile);
      return 0;
    }
  }

  len = fread(buf->s, 1, buf->length, inputfile);

  if (len < 0 || ((size_t)len < buf->length)) {
    if (ferror(inputfile) != 0) {
      perror("cmdline_input_from_file: fread");
      coap_free(buf->s);
      buf->length = 0;
      buf->s = NULL;
      result = 0;
    } else {
      buf->length = len;
    }
  }

  if (inputfile != stdin)
    fclose(inputfile);

  return result;
}

static method_t
cmdline_method(char *arg) {
  static const char *methods[] =
  { 0, "get", "post", "put", "delete", "fetch", "patch", "ipatch", 0};
  unsigned char i;

  for (i=1; methods[i] && strcasecmp(arg,methods[i]) != 0 ; ++i)
    ;

  return i;     /* note that we do not prevent illegal methods */
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
cmdline_read_hint_check(const char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log_err("Hint file: %s: Unable to open\n", arg);
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
      ih_def_t *new_ih_list;
      new_ih_list = realloc(valid_ihs.ih_list,
                            (valid_ihs.count + 1)*sizeof(valid_ihs.ih_list[0]));
      if (new_ih_list == NULL) {
        break;
      }
      valid_ihs.ih_list = new_ih_list;
      valid_ihs.ih_list[valid_ihs.count].hint_match = strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        valid_ihs.ih_list[valid_ihs.count].new_identity =
            coap_new_bin_const((const uint8_t *)cp, tcp-cp);
        cp = tcp+1;
        valid_ihs.ih_list[valid_ihs.count].new_key =
            coap_new_bin_const((const uint8_t *)cp, strlen(cp));
        valid_ihs.count++;
      } else {
        /* Badly formatted */
        free(valid_ihs.ih_list[valid_ihs.count].hint_match);
      }
    }
  }
  fclose(fp);
  return valid_ihs.count > 0;
}

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert COAP_UNUSED,
                   size_t asn1_length COAP_UNUSED,
                   coap_session_t *session COAP_UNUSED,
                   unsigned depth,
                   int validated COAP_UNUSED,
                   void *arg COAP_UNUSED) {
  coap_log_info("CN '%s' presented by server (%s)\n",
                cn, depth ? "CA" : "Certificate");
  return 1;
}

static const coap_dtls_cpsk_info_t *
verify_ih_callback(coap_str_const_t *hint,
                   coap_session_t *c_session COAP_UNUSED,
                   void *arg) {
  coap_dtls_cpsk_info_t *psk_info = (coap_dtls_cpsk_info_t *)arg;
  char lhint[COAP_DTLS_HINT_LENGTH];
  static coap_dtls_cpsk_info_t psk_identity_info;
  size_t i;

  snprintf(lhint, sizeof(lhint), "%.*s", (int)hint->length, hint->s);
  coap_log_info("Identity Hint '%s' provided\n", lhint);

  /* Test for hint to possibly change identity + key */
  for (i = 0; i < valid_ihs.count; i++) {
    if (strcmp(lhint, valid_ihs.ih_list[i].hint_match) == 0) {
      /* Preset */
      psk_identity_info = *psk_info;
      if (valid_ihs.ih_list[i].new_key) {
        psk_identity_info.key = *valid_ihs.ih_list[i].new_key;
      }
      if (valid_ihs.ih_list[i].new_identity) {
        psk_identity_info.identity = *valid_ihs.ih_list[i].new_identity;
      }
      coap_log_info("Switching to using '%s' identity + '%s' key\n",
                    psk_identity_info.identity.s, psk_identity_info.key.s);
      return &psk_identity_info;
    }
  }
  /* Just use the defined key for now as passed in by arg */
  return psk_info;
}

static coap_dtls_pki_t *
setup_pki(coap_context_t *ctx) {
  static coap_dtls_pki_t dtls_pki;
  static char client_sni[256];

  /* If general root CAs are defined */
  if (root_ca_file) {
    struct stat stbuf;
    if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
      coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
    } else {
      coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
    }
  }
  /*
   * If trust store CAs are to be defined
   *
   * If need to verify server certificate
   *  If Trust Store load is not disabled
   *  If not mutually validating same CA signed client & server certs
   */
  if (verify_peer_cert && !no_trust_store && !ca_file && !root_ca_file) {
    coap_context_load_pki_trust_store(ctx);
  }

  memset(&dtls_pki, 0, sizeof(dtls_pki));
  dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
  /*
   * Add in additional certificate checking.
   * This list of enabled can be tuned for the specific
   * requirements - see 'man coap_encryption'.
   *
   * Note: root_ca_file is setup separately using
   * coap_context_set_pki_root_cas(), as well as the trust store is added in
   * but this is used to define what checking actually takes place.
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
  dtls_pki.is_rpk_not_cert = is_rpk_not_cert;
  dtls_pki.use_cid = setup_cid;
  dtls_pki.validate_cn_call_back = verify_cn_callback;
  if (proxy.host.length) {
    snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)proxy.host.length, (int)proxy.host.length,
             proxy.host.s);
  } else {
    snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)uri.host.length, (int)uri.host.length,
             uri.host.s);
  }
  dtls_pki.client_sni = client_sni;
  if (doing_tls_engine) {
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_DEFINE;
    dtls_pki.pki_key.key.define.public_cert.s_byte = cert_file;
    dtls_pki.pki_key.key.define.private_key.s_byte = key_file ? key_file : cert_file;
    dtls_pki.pki_key.key.define.ca.s_byte = ca_file;
    dtls_pki.pki_key.key.define.public_cert_def = COAP_PKI_KEY_DEF_ENGINE;
    dtls_pki.pki_key.key.define.private_key_def = COAP_PKI_KEY_DEF_ENGINE;
    dtls_pki.pki_key.key.define.ca_def = COAP_PKI_KEY_DEF_ENGINE;
    dtls_pki.pki_key.key.define.user_pin = pkcs11_pin;
  } else if ((key_file && strncasecmp(key_file, "pkcs11:", 7) == 0) ||
             (cert_file && strncasecmp(cert_file, "pkcs11:", 7) == 0) ||
             (ca_file && strncasecmp(ca_file, "pkcs11:", 7) == 0)) {
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PKCS11;
    dtls_pki.pki_key.key.pkcs11.public_cert = cert_file;
    dtls_pki.pki_key.key.pkcs11.private_key = key_file ?
                                              key_file : cert_file;
    dtls_pki.pki_key.key.pkcs11.ca = ca_file;
    dtls_pki.pki_key.key.pkcs11.user_pin = pkcs11_pin;
  } else if (!is_rpk_not_cert) {
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
    dtls_pki.pki_key.key.pem.public_cert = cert_file;
    dtls_pki.pki_key.key.pem.private_key = key_file ? key_file : cert_file;
    dtls_pki.pki_key.key.pem.ca_file = ca_file;
  } else {
    /* Map file into memory */
    if (ca_mem == 0 && cert_mem == 0 && key_mem == 0) {
      ca_mem = read_file_mem(ca_file, &ca_mem_len);
      cert_mem = read_file_mem(cert_file, &cert_mem_len);
      key_mem = read_file_mem(key_file, &key_mem_len);
    }
    dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_pki.pki_key.key.pem_buf.ca_cert = ca_mem;
    dtls_pki.pki_key.key.pem_buf.public_cert = cert_mem;
    dtls_pki.pki_key.key.pem_buf.private_key = key_mem ? key_mem : cert_mem;
    dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_mem_len;
    dtls_pki.pki_key.key.pem_buf.public_cert_len = cert_mem_len;
    dtls_pki.pki_key.key.pem_buf.private_key_len = key_mem ?
                                                   key_mem_len : cert_mem_len;
  }
  return &dtls_pki;
}

static coap_dtls_cpsk_t *
setup_psk(const uint8_t *identity,
          size_t identity_len,
          const uint8_t *key,
          size_t key_len) {
  static coap_dtls_cpsk_t dtls_psk;
  static char client_sni[256];

  memset(&dtls_psk, 0, sizeof(dtls_psk));
  dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  dtls_psk.ec_jpake = ec_jpake;
  dtls_psk.use_cid = setup_cid;
  if (valid_ihs.count) {
    dtls_psk.validate_ih_call_back = verify_ih_callback;
  }
  dtls_psk.ih_call_back_arg = &dtls_psk.psk_info;
  if (proxy.host.length) {
    snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)proxy.host.length, (int)proxy.host.length,
             proxy.host.s);
  } else {
    snprintf(client_sni, sizeof(client_sni), "%*.*s", (int)uri.host.length, (int)uri.host.length,
             uri.host.s);
  }
  dtls_psk.client_sni = client_sni;
  dtls_psk.psk_info.identity.s = identity;
  dtls_psk.psk_info.identity.length = identity_len;
  dtls_psk.psk_info.key.s = key;
  dtls_psk.psk_info.key.length = key_len;
  return &dtls_psk;
}

static coap_session_t *
open_session(coap_context_t *ctx,
             coap_proto_t proto,
             coap_address_t *bind_addr,
             coap_address_t *dst,
             const uint8_t *identity,
             size_t identity_len,
             const uint8_t *key,
             size_t key_len) {
  coap_session_t *session;

  if (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS ||
      proto == COAP_PROTO_WSS) {
    /* Encrypted session */
    if (root_ca_file || ca_file || cert_file) {
      /* Setup PKI session */
      coap_dtls_pki_t *dtls_pki = setup_pki(ctx);
      if (doing_oscore) {
        session = coap_new_client_session_oscore_pki(ctx, bind_addr, dst,
                                                     proto, dtls_pki,
                                                     oscore_conf);
      } else
        session = coap_new_client_session_pki(ctx, bind_addr, dst, proto,
                                              dtls_pki);
    } else if (identity || key) {
      /* Setup PSK session */
      coap_dtls_cpsk_t *dtls_psk = setup_psk(identity, identity_len,
                                             key, key_len);
      if (doing_oscore) {
        session = coap_new_client_session_oscore_psk(ctx, bind_addr, dst,
                                                     proto, dtls_psk,
                                                     oscore_conf);
      } else
        session = coap_new_client_session_psk2(ctx, bind_addr, dst, proto,
                                               dtls_psk);
    } else {
      /* No PKI or PSK defined, as encrypted, use PKI */
      coap_dtls_pki_t *dtls_pki = setup_pki(ctx);
      if (doing_oscore) {
        session = coap_new_client_session_oscore_pki(ctx, bind_addr, dst,
                                                     proto, dtls_pki,
                                                     oscore_conf);
      } else
        session = coap_new_client_session_pki(ctx, bind_addr, dst, proto,
                                              dtls_pki);
    }
  } else {
    /* Non-encrypted session */
    if (doing_oscore) {
      session = coap_new_client_session_oscore(ctx, bind_addr, dst, proto,
                                               oscore_conf);
    } else
      session = coap_new_client_session(ctx, bind_addr, dst, proto);
  }
  if (session && (proto == COAP_PROTO_WS || proto == COAP_PROTO_WSS)) {
    coap_ws_set_host_request(session, &uri.host);
  }
  return session;
}

static coap_session_t *
get_session(coap_context_t *ctx,
            const char *local_addr,
            const char *local_port,
            coap_uri_scheme_t scheme,
            coap_proto_t proto,
            coap_address_t *dst,
            const uint8_t *identity,
            size_t identity_len,
            const uint8_t *key,
            size_t key_len) {
  coap_session_t *session = NULL;

  is_mcast = coap_is_mcast(dst);
  if (coap_is_af_unix(dst)) {
    coap_address_t bind_addr;

    if (local_addr) {
      if (!coap_address_set_unix_domain(&bind_addr,
                                        (const uint8_t *)local_addr,
                                        strlen(local_addr))) {
        fprintf(stderr, "coap_address_set_unix_domain: %s: failed\n",
                local_addr);
        return NULL;
      }
    } else {
      char buf[COAP_UNIX_PATH_MAX];

      /* Need a unique address */
      snprintf(buf, COAP_UNIX_PATH_MAX,
               "/tmp/coap-client.%d", (int)getpid());
      if (!coap_address_set_unix_domain(&bind_addr, (const uint8_t *)buf,
                                        strlen(buf))) {
        fprintf(stderr, "coap_address_set_unix_domain: %s: failed\n",
                buf);
        remove(buf);
        return NULL;
      }
      (void)remove(buf);
    }
    session = open_session(ctx, proto, &bind_addr, dst,
                           identity, identity_len, key, key_len);
  } else if (local_addr) {
    coap_addr_info_t *info_list = NULL;
    coap_addr_info_t *info;
    coap_str_const_t local;
    uint16_t port = local_port ? atoi(local_port) : 0;

    local.s = (const uint8_t *)local_addr;
    local.length = strlen(local_addr);
    /* resolve local address where data should be sent from (don't update port number */
    info_list = coap_resolve_address_info(&local, port, port, port, port,
                                          AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL,
                                          1 << scheme,
                                          COAP_RESOLVE_TYPE_REMOTE);
    if (!info_list) {
      fprintf(stderr, "coap_resolve_address_info: %s: failed\n", local_addr);
      return NULL;
    }

    /* iterate through results until success */
    for (info = info_list; info != NULL; info = info->next) {
      session = open_session(ctx, proto, &info->addr, dst,
                             identity, identity_len, key, key_len);
      if (session)
        break;
    }
    coap_free_address_info(info_list);
  } else if (local_port) {
    coap_address_t bind_addr;

    coap_address_init(&bind_addr);
    bind_addr.size = dst->size;
    bind_addr.addr.sa.sa_family = dst->addr.sa.sa_family;
    coap_address_set_port(&bind_addr, atoi(local_port));
    session = open_session(ctx, proto, &bind_addr, dst,
                           identity, identity_len, key, key_len);
  } else {
    session = open_session(ctx, proto, NULL, dst,
                           identity, identity_len, key, key_len);
  }
  return session;
}

int
main(int argc, char **argv) {
  coap_context_t  *ctx = NULL;
  coap_session_t *session = NULL;
  coap_address_t dst;
  int result = -1;
  int exit_code = 0;
  coap_pdu_t  *pdu;
  static coap_str_const_t server;
  uint16_t port = COAP_DEFAULT_PORT;
  char port_str[NI_MAXSERV] = "";
  char node_str[NI_MAXHOST] = "";
  int opt;
  coap_log_t log_level = COAP_LOG_WARN;
  coap_log_t dtls_log_level = COAP_LOG_ERR;
  unsigned char *user = NULL, *key = NULL;
  ssize_t user_length = -1, key_length = 0;
  int create_uri_opts = 1;
  size_t i;
  coap_uri_scheme_t scheme;
  coap_proto_t proto;
  uint32_t repeat_ms = REPEAT_DELAY_MS;
  uint8_t *data = NULL;
  size_t data_len = 0;
  coap_addr_info_t *info_list = NULL;
  uint8_t cid_every = 0;
  coap_pdu_t *resp_pdu;
#ifndef _WIN32
  struct sigaction sa;
#endif

  /* Caution:
   * If this code is going to be included into an embedded system that
   * repeatably calls 'main()', then all the defined static variables need to
   * be reset to their initial values - especially those that are freed off
   * at the end of this function.
   */

  /* Initialize libcoap library */
  coap_startup();

  while ((opt = getopt(argc, argv,
                       "a:b:c:d:e:f:h:j:k:l:m:no:p:q:rs:t:u:v:wx:y:A:B:C:E:G:H:J:K:L:M:NO:P:R:T:UV:X:Y2")) != -1) {
    switch (opt) {
    case 'a':
      strncpy(node_str, optarg, NI_MAXHOST - 1);
      node_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'b':
      if (!cmdline_blocksize(optarg))
        goto failed;
      break;
    case 'B':
      wait_seconds = atoi(optarg);
      break;
    case 'c':
      cert_file = optarg;
      break;
    case 'C':
      ca_file = optarg;
      break;
    case 'Y':
      no_trust_store = 1;
      break;
    case 'R':
      root_ca_file = optarg;
      break;
    case 'd':
      cid_every = atoi(optarg);
      setup_cid = 1;
      break;
    case 'e':
      if (!cmdline_input(optarg, &payload))
        payload.length = 0;
      break;
    case 'f':
      if (!cmdline_input_from_file(optarg, &payload))
        payload.length = 0;
      break;
    case 'j' :
      key_file = optarg;
      break;
    case 'J' :
      pkcs11_pin = optarg;
      break;
    case 'k':
      key_length = cmdline_read_key(optarg, &key, MAX_KEY);
      break;
    case 'L':
      block_mode = strtoul(optarg, NULL, 0);
      if (!(block_mode & COAP_BLOCK_USE_LIBCOAP)) {
        fprintf(stderr, "Block mode must include COAP_BLOCK_USE_LIBCOAP (1)\n");
        goto failed;
      }
      break;
    case 'p':
      strncpy(port_str, optarg, NI_MAXSERV - 1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'm':
      method = cmdline_method(optarg);
      break;
    case 'w':
      add_nl = 1;
      break;
    case 'x':
      coap_enable_pdu_data_output(0);
      break;
    case 'y':
      reconnect_secs = atoi(optarg);
      break;
    case 'N':
      msgtype = COAP_MESSAGE_NON;
      break;
    case 's':
      cmdline_subscribe(optarg);
      break;
    case 'o':
      output_file.length = strlen(optarg);
      output_file.s = (unsigned char *)coap_malloc(output_file.length + 1);

      if (!output_file.s) {
        fprintf(stderr, "cannot set output file: insufficient memory\n");
        goto failed;
      } else {
        /* copy filename including trailing zero */
        memcpy(output_file.s, optarg, output_file.length + 1);
      }
      break;
    case 'A':
      cmdline_content_type(optarg, COAP_OPTION_ACCEPT);
      break;
    case 't':
      cmdline_content_type(optarg, COAP_OPTION_CONTENT_TYPE);
      break;
    case 'M':
      cert_file = optarg;
      is_rpk_not_cert = 1;
      break;
    case 'O':
      cmdline_option(optarg);
      break;
    case 'P':
      if (!cmdline_proxy(optarg)) {
        fprintf(stderr, "error specifying proxy address\n");
        goto failed;
      }
      break;
    case 'T':
      cmdline_token(optarg);
      break;
    case 'u':
      user_length = cmdline_read_user(optarg, &user, MAX_USER);
      break;
    case 'U':
      create_uri_opts = 0;
      break;
    case 'v':
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'V':
      dtls_log_level = strtol(optarg, NULL, 10);
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        goto failed;
      }
      break;
    case 'r':
      reliable = coap_tcp_is_supported();
      break;
    case 'K':
      ping_seconds = atoi(optarg);
      break;
    case 'h':
      if (!cmdline_read_hint_check(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        goto failed;
      }
      break;
    case 'H':
      if (!cmdline_hop_limit(optarg))
        fprintf(stderr, "Hop Limit has to be > 0 and < 256\n");
      break;
    case 'n':
      verify_peer_cert = 0;
      break;
    case 'G':
      repeat_count = atoi(optarg);
      if (!repeat_count || repeat_count > 255) {
        fprintf(stderr, "'-G count' has to be > 0 and < 256\n");
        repeat_count = 1;
      }
      break;
    case 'X':
      csm_max_message_size = strtol(optarg, NULL, 10);
      break;
    case 'E':
      doing_oscore = cmdline_oscore(optarg);
      if (!doing_oscore) {
        goto failed;
      }
      break;
    case 'q':
      tls_engine_conf = optarg;
      doing_tls_engine = 1;
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
  /* So we do not exit on a SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);
#endif

  coap_set_log_level(log_level);
  coap_dtls_set_log_level(dtls_log_level);

  if (optind < argc) {
    if (cmdline_uri(argv[optind]) < 0) {
      goto failed;
    }
  } else {
    usage(argv[0], LIBCOAP_PACKAGE_VERSION);
    goto failed;
  }

  if (key_length < 0) {
    coap_log_crit("Invalid pre-shared key specified\n");
    goto failed;
  }

  if (proxy.host.length) {
    server = proxy.host;
    port = proxy.port;
    scheme = proxy.scheme;
  } else {
    server = uri.host;
    port = proxy_scheme_option ? proxy.port : uri.port;
    scheme = proxy_scheme_option ? proxy.scheme : uri.scheme;
  }

  /* resolve destination address where data should be sent */
  info_list = coap_resolve_address_info(&server, port, port, port, port,
                                        0,
                                        1 << scheme,
                                        COAP_RESOLVE_TYPE_REMOTE);

  if (info_list == NULL) {
    coap_log_err("failed to resolve address\n");
    goto failed;
  }
  proto = info_list->proto;
  memcpy(&dst, &info_list->addr, sizeof(dst));
  coap_free_address_info(info_list);

  ctx = coap_new_context(NULL);
  if (!ctx) {
    coap_log_emerg("cannot create context\n");
    goto failed;
  }

  if (doing_tls_engine) {
    if (!cmdline_tls_engine(tls_engine_conf))
      goto failed;
  }

  if (doing_oscore) {
    if (get_oscore_conf() == NULL)
      goto failed;
  }

  coap_context_set_session_reconnect_time(ctx, reconnect_secs);
  coap_context_set_keepalive(ctx, ping_seconds);
  coap_context_set_block_mode(ctx, block_mode);
  if (csm_max_message_size)
    coap_context_set_csm_max_message_size(ctx, csm_max_message_size);
  coap_register_response_handler(ctx, response_handler);
  coap_register_event_handler(ctx, event_handler);
  coap_register_nack_handler(ctx, nack_handler);
  if (the_token.length > COAP_TOKEN_DEFAULT_MAX)
    coap_context_set_max_token_size(ctx, the_token.length);
  if (cid_every) {
    if (!coap_context_set_cid_tuple_change(ctx, cid_every)) {
      coap_log_warn("coap_context_set_cid_tuple_change: "
                    "Unable to set CID tuple change\n");
    }
  }

  session = get_session(ctx,
                        node_str[0] ? node_str : NULL,
                        port_str[0] ? port_str : NULL,
                        scheme,
                        proto,
                        &dst,
                        user_length >= 0 ? user : NULL,
                        user_length >= 0 ? user_length : 0,
                        key_length > 0 ? key : NULL,
                        key_length > 0 ? key_length : 0
                       );

  if (!session) {
    coap_log_err("cannot create client session\n");
    goto failed;
  }
  global_session = session;
  /*
   * Prime the base token value, which coap_session_new_token() will increment
   * every time it is called to get an unique token.
   * [Option '-T token' is used to seed a different value]
   * Note that only the first 8 bytes of the token are used as the prime.
   */
  coap_session_init_token(session, the_token.length, the_token.s);

  /* Convert provided uri into CoAP options */
  if (!coap_uri_into_optlist(proxy.host.length ? &proxy : &uri, !uri_host_option ?
                             &dst : NULL,
                             &optlist, create_uri_opts)) {
    coap_log_err("Failed to create options for URI\n");
    goto failed;
  }

  /* set block option if requested at commandline */
  if (flags & FLAGS_BLOCK)
    set_blocksize();

  /* Send the first (and may be only PDU) */
  if (payload.length) {
    /* Create some new data to use for this iteration */
    data = coap_malloc(payload.length);
    if (data == NULL)
      goto failed;
    memcpy(data, payload.s, payload.length);
    data_len = payload.length;
  }
  if (!(pdu = coap_new_request(ctx, session, method, &optlist, data,
                               data_len))) {
    goto failed;
  }

  if (wait_seconds == DEFAULT_WAIT_TIME) {
    /* Adjust wait time if needed */
    if (is_mcast) {
      /* Allow for other servers to respond within DEFAULT_LEISURE RFC7252 8.2 */
      int mcast_respond = coap_session_get_default_leisure(session).integer_part + 1;

      if (!doing_observe) {
        wait_seconds = mcast_respond;
      } else {
        /* Allow for observe set up and tear down time and mcast potential delay*/
        wait_seconds = obs_seconds + 5 + mcast_respond;
      }
    } else if (doing_observe) {
      /* Allow for observe set up and tear down time */
      wait_seconds = obs_seconds + 5;
    }
  }

  wait_ms = wait_seconds * 1000;
  coap_log_debug("timeout is set to %u seconds\n", wait_seconds);

  coap_log_debug("sending CoAP request:\n");
  if (coap_get_log_level() < COAP_LOG_DEBUG)
    coap_show_pdu(COAP_LOG_INFO, pdu);

  resp_pdu = NULL;
  result = coap_send_recv(session, pdu, &resp_pdu, wait_ms);
  if (result >= 0) {
    if (response_handler(session, pdu, resp_pdu, coap_pdu_get_mid(resp_pdu))
        != COAP_RESPONSE_OK) {
      coap_log_err("Response PDU issue\n");
    }
    if (result < (int)wait_ms) {
      wait_ms -= result;
    } else {
      wait_ms = 0;
      quit = 1;
    }
  } else {
    switch (result) {
    case -1:
      coap_log_info("coap_send_recv: Invalid timeout value %u\n", wait_ms);
      break;
    case -2:
      coap_log_info("coap_send_recv: Failed to transmit PDU\n");
      break;
    case -3:
      /* Nack / Event handler already reported issue */
      break;
    case -4:
      coap_log_info("coap_send_recv: Internal coap_io_process() failed\n");
      break;
    case -5:
      coap_log_info("coap_send_recv: No response received within the timeout\n");
      break;
    case -6:
      coap_log_info("coap_send_recv: Terminated by user\n");
      break;
    case -7:
      coap_log_info("coap_send_recv: Client Mode code not enabled\n");
      break;
    default:
      coap_log_info("coap_send_recv: Invalid return value %d\n", result);
      break;
    }
    quit = 1;
  }
  coap_delete_pdu(pdu);
  coap_delete_pdu(resp_pdu);

  if (!is_mcast && !doing_observe && repeat_count == 1) {
    quit = 1;
  }
  repeat_count--;

  while (!quit &&                /* immediate quit not required .. and .. */
         (tracked_tokens_count || /* token not responded to or still observe */
          is_mcast ||             /* mcast active */
          repeat_count ||         /* more repeat transmissions to go */
          coap_io_pending(ctx))) { /* i/o not yet complete */
    uint32_t timeout_ms;
    /*
     * 3 factors determine how long to wait in coap_io_process()
     *   Remaining overall wait time (wait_ms)
     *   Remaining overall observe unsolicited response time (obs_ms)
     *   Delay of up to one second before sending off the next request
     */
    if (obs_ms) {
      timeout_ms = min(wait_ms, obs_ms);
    } else {
      timeout_ms = wait_ms;
    }
    if (repeat_count) {
      timeout_ms = min(timeout_ms, repeat_ms);
    }

    result = coap_io_process(ctx, timeout_ms);

    if (result >= 0) {
      if (wait_ms > 0) {
        if ((unsigned)result >= wait_ms) {
          coap_log_info("timeout\n");
          break;
        } else {
          wait_ms -= result;
        }
      }
      if (obs_ms > 0 && !obs_ms_reset) {
        if ((unsigned)result >= obs_ms) {
          coap_log_debug("clear observation relationship\n");
          for (i = 0; i < tracked_tokens_count; i++) {
            if (tracked_tokens[i].observe) {
              coap_cancel_observe(session, tracked_tokens[i].token, msgtype);
              tracked_tokens[i].observe = 0;
              coap_io_process(ctx, COAP_IO_NO_WAIT);
            }
          }
          doing_observe = 0;

          /* make sure that the obs timer does not fire again */
          obs_ms = 0;
          obs_seconds = 0;
        } else {
          obs_ms -= result;
        }
      }
      if ((ready || obs_ms) && repeat_count) {
        /* Send off next request if appropriate */
        if (repeat_ms > (unsigned)result) {
          repeat_ms -= (unsigned)result;
        } else {
          /* Doing this once a second */
          repeat_ms = REPEAT_DELAY_MS;
          if (payload.length) {
            /* Create some new data to use for this iteration */
            data = coap_malloc(payload.length);
            if (data == NULL)
              goto failed;
            memcpy(data, payload.s, payload.length);
            data_len = payload.length;
          }
          if (!(pdu = coap_new_request(ctx, session, method, &optlist,
                                       data, data_len))) {
            goto failed;
          }
          coap_log_debug("sending CoAP request:\n");
          if (coap_get_log_level() < COAP_LOG_DEBUG)
            coap_show_pdu(COAP_LOG_INFO, pdu);

          ready = 0;
          if (coap_send(session, pdu) == COAP_INVALID_MID) {
            coap_log_err("cannot send CoAP pdu\n");
            if (reconnect_secs)
              ready = 1;
            else
              quit = 1;
          }
          repeat_count--;
        }
      }
      obs_ms_reset = 0;
    }
  }

  exit_code = 0;

finish:

  /* Clean up library usage */
  coap_session_release(session);
  coap_free_context(ctx);
  coap_cleanup();

  /* Clean up local usage */
  coap_free(ca_mem);
  coap_free(cert_mem);
  coap_free(key_mem);
  coap_free(payload.s);

  for (i = 0; i < valid_ihs.count; i++) {
    free(valid_ihs.ih_list[i].hint_match);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_identity);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_key);
  }
  if (valid_ihs.count)
    free(valid_ihs.ih_list);

  for (i = 0; i < tracked_tokens_count; i++) {
    coap_delete_binary(tracked_tokens[i].token);
  }
  free(tracked_tokens);

  coap_delete_optlist(optlist);
  if (oscore_seq_num_fp)
    fclose(oscore_seq_num_fp);
  close_output();

  return exit_code;

failed:
  exit_code = 1;
  goto finish;
}
