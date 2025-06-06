/*
 * coap_mbedtls.c -- Mbed TLS Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2019-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
 *               2019      Jitin George <jitin@espressif.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_mbedtls.c
 * @brief Mbed TLS specific interface functions.
 */

/*
 * Naming used to prevent confusion between coap sessions, mbedtls sessions etc.
 * when reading the code.
 *
 * c_context  A coap_context_t *
 * c_session  A coap_session_t *
 * m_context  A coap_mbedtls_context_t * (held in c_context->dtls_context)
 * m_env      A coap_mbedtls_env_t * (held in c_session->tls)
 */

/*
 * Notes
 *
 * Version 3.2.0 or later is needed to provide Connection ID support (RFC9146).
 *
 */

#include "coap3/coap_libcoap_build.h"

#ifdef COAP_WITH_LIBMBEDTLS

/*
 * This code can be conditionally compiled to remove some components if
 * they are not required to make a lighter footprint - all based on how
 * the mbedtls library has been built.  These are not defined within the
 * libcoap environment.
 *
 * MBEDTLS_SSL_SRV_C - defined for server side functionality
 * MBEDTLS_SSL_CLI_C - defined for client side functionality
 * MBEDTLS_SSL_PROTO_DTLS - defined for DTLS support
 * MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED - defined if PSK is to be supported
 * or MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED - defined if PSK is to be supported
 *
 */

#include <mbedtls/version.h>

/* Keep forward-compatibility with Mbed TLS 3.x */
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
#define MBEDTLS_2_X_COMPAT
#else /* !(MBEDTLS_VERSION_NUMBER < 0x03000000) */
/* Macro wrapper for struct's private members */
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif /* MBEDTLS_ALLOW_PRIVATE_ACCESS */
#endif /* !(MBEDTLS_VERSION_NUMBER < 0x03000000) */

#include <mbedtls/platform.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/timing.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/oid.h>
#include <mbedtls/debug.h>
#include <mbedtls/sha256.h>
#if defined(ESPIDF_VERSION) && defined(CONFIG_MBEDTLS_DEBUG)
#include <mbedtls/esp_debug.h>
#endif /* ESPIDF_VERSION && CONFIG_MBEDTLS_DEBUG */
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include <psa/crypto.h>
#endif /* MBEDTLS_PSA_CRYPTO_C */

#define mbedtls_malloc(a) malloc(a)
#define mbedtls_realloc(a,b) realloc(a,b)
#define mbedtls_strdup(a) strdup(a)
#define mbedtls_strndup(a,b) strndup(a,b)
#undef mbedtls_free
#define mbedtls_free(a) free(a)

#ifndef MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
/* definition changed in later mbedtls code versions */
#ifdef MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#endif /* ! MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if ! COAP_SERVER_SUPPORT
#undef MBEDTLS_SSL_SRV_C
#endif /* ! COAP_SERVER_SUPPORT */
#if ! COAP_CLIENT_SUPPORT
#undef MBEDTLS_SSL_CLI_C
#endif /* ! COAP_CLIENT_SUPPORT */

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#define IS_PSK (1 << 0)
#define IS_PKI (1 << 1)
#define IS_CLIENT (1 << 6)
#define IS_SERVER (1 << 7)

typedef struct coap_ssl_t {
  const uint8_t *pdu;
  unsigned pdu_len;
  unsigned peekmode;
} coap_ssl_t;

/*
 * This structure encapsulates the Mbed TLS session object.
 * It handles both TLS and DTLS.
 * c_session->tls points to this.
 */
typedef struct coap_mbedtls_env_t {
  mbedtls_ssl_context ssl;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_timing_delay_context timer;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt public_cert;
  mbedtls_pk_context private_key;
  mbedtls_ssl_cookie_ctx cookie_ctx;
  /* If not set, need to do do_mbedtls_handshake */
  int established;
  int sent_alert;
  int seen_client_hello;
  int ec_jpake;
  coap_tick_t last_timeout;
  unsigned int retry_scalar;
  coap_ssl_t coap_ssl_data;
  uint32_t server_hello_cnt;
} coap_mbedtls_env_t;

typedef struct pki_sni_entry {
  char *sni;
  coap_dtls_key_t pki_key;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt public_cert;
  mbedtls_pk_context private_key;
} pki_sni_entry;

typedef struct psk_sni_entry {
  char *sni;
  coap_dtls_spsk_info_t psk_info;
} psk_sni_entry;

typedef struct coap_mbedtls_context_t {
  coap_dtls_pki_t setup_data;
  size_t pki_sni_count;
  pki_sni_entry *pki_sni_entry_list;
  size_t psk_sni_count;
  psk_sni_entry *psk_sni_entry_list;
  char *root_ca_file;
  char *root_ca_path;
  int trust_store_defined;
  int psk_pki_enabled;
} coap_mbedtls_context_t;

typedef enum coap_enc_method_t {
  COAP_ENC_PSK,
  COAP_ENC_PKI,
  COAP_ENC_ECJPAKE,
} coap_enc_method_t;

#ifndef MBEDTLS_2_X_COMPAT
/*
 * mbedtls_ callback functions expect 0 on success, -ve on failure.
 */
static int
coap_rng(void *ctx COAP_UNUSED, unsigned char *buf, size_t len) {
  return coap_prng_lkd(buf, len) ? 0 : MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
}
#endif /* MBEDTLS_2_X_COMPAT */

static int
coap_dgram_read(void *ctx, unsigned char *out, size_t outl) {
  ssize_t ret = 0;
  coap_session_t *c_session = (coap_session_t *)ctx;
  coap_ssl_t *data;

  if (!c_session->tls) {
    errno = EAGAIN;
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  data = &((coap_mbedtls_env_t *)c_session->tls)->coap_ssl_data;

  if (out != NULL) {
    if (data->pdu_len > 0) {
      if (outl < data->pdu_len) {
        memcpy(out, data->pdu, outl);
        ret = outl;
        data->pdu += outl;
        data->pdu_len -= outl;
      } else {
        memcpy(out, data->pdu, data->pdu_len);
        ret = data->pdu_len;
        if (!data->peekmode) {
          data->pdu_len = 0;
          data->pdu = NULL;
        }
      }
    } else {
      ret = MBEDTLS_ERR_SSL_WANT_READ;
      errno = EAGAIN;
    }
  }
  return ret;
}

/*
 * return +ve data amount
 *        0   no more
 *        -ve  Mbed TLS error
 */
/* callback function given to mbedtls for sending data over socket */
static int
coap_dgram_write(void *ctx, const unsigned char *send_buffer,
                 size_t send_buffer_length) {
  ssize_t result = -1;
  coap_session_t *c_session = (coap_session_t *)ctx;

  if (c_session) {
    coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;

    if (!coap_netif_available(c_session)
#if COAP_SERVER_SUPPORT
        && c_session->endpoint == NULL
#endif /* COAP_SERVER_SUPPORT */
       ) {
      /* socket was closed on client due to error */
      errno = ECONNRESET;
      return -1;
    }
    result = (int)c_session->sock.lfunc[COAP_LAYER_TLS].l_write(c_session,
                                                                send_buffer, send_buffer_length);
    if (result != (ssize_t)send_buffer_length) {
      int keep_errno = errno;

      coap_log_warn("coap_netif_dgrm_write failed (%zd != %zu)\n",
                    result, send_buffer_length);
      errno = keep_errno;
      if (result < 0) {
        if (errno == ENOTCONN || errno == ECONNREFUSED)
          c_session->dtls_event = COAP_EVENT_DTLS_ERROR;
        return -1;
      } else {
        result = 0;
      }
    } else if (m_env) {
      coap_tick_t now;
      coap_ticks(&now);
      m_env->last_timeout = now;
    }
  } else {
    result = 0;
  }
  return result;
}

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && defined(MBEDTLS_SSL_SRV_C)
/*
 * Server side PSK callback
 */
static int
psk_server_callback(void *p_info, mbedtls_ssl_context *ssl,
                    const unsigned char *identity, size_t identity_len) {
  coap_session_t *c_session = (coap_session_t *)p_info;
  coap_dtls_spsk_t *setup_data;
  coap_mbedtls_env_t *m_env;
  coap_bin_const_t lidentity;
  const coap_bin_const_t *psk_key;

  if (c_session == NULL)
    return -1;

  /* Track the Identity being used */
  lidentity.s = identity ? (const uint8_t *)identity : (const uint8_t *)"";
  lidentity.length = identity ? identity_len : 0;
  coap_session_refresh_psk_identity(c_session, &lidentity);

  coap_log_debug("got psk_identity: '%.*s'\n",
                 (int)lidentity.length, (const char *)lidentity.s);

  m_env = (coap_mbedtls_env_t *)c_session->tls;
  setup_data = &c_session->context->spsk_setup_data;

  if (setup_data->validate_id_call_back) {
    psk_key = setup_data->validate_id_call_back(&lidentity,
                                                c_session,
                                                setup_data->id_call_back_arg);

    coap_session_refresh_psk_key(c_session, psk_key);
  } else {
    psk_key = coap_get_session_server_psk_key(c_session);
  }

  if (psk_key == NULL)
    return -1;
  mbedtls_ssl_set_hs_psk(ssl, psk_key->s, psk_key->length);
  m_env->seen_client_hello = 1;
  return 0;
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED && MBEDTLS_SSL_SRV_C */

static char *
get_san_or_cn_from_cert(mbedtls_x509_crt *crt) {
  if (crt) {
    const mbedtls_asn1_named_data *cn_data;

    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
      mbedtls_asn1_sequence *seq = &crt->subject_alt_names;
      while (seq && seq->buf.p == NULL) {
        seq = seq->next;
      }
      if (seq) {
        /* Return the Subject Alt Name */
        return mbedtls_strndup((const char *)seq->buf.p,
                               seq->buf.len);
      }
    }

    cn_data = mbedtls_asn1_find_named_data(&crt->subject,
                                           MBEDTLS_OID_AT_CN,
                                           MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN));
    if (cn_data) {
      /* Return the Common Name */
      return mbedtls_strndup((const char *)cn_data->val.p,
                             cn_data->val.len);
    }
  }
  return NULL;
}

#if COAP_MAX_LOGGING_LEVEL > 0
static char *
get_error_string(int ret) {
  static char buf[128] = {0};
  mbedtls_strerror(ret, buf, sizeof(buf)-1);
  return buf;
}
#endif /* COAP_MAX_LOGGING_LEVEL */

static int
self_signed_cert_verify_callback_mbedtls(void *data,
                                         mbedtls_x509_crt *crt COAP_UNUSED,
                                         int depth COAP_UNUSED,
                                         uint32_t *flags) {
  const coap_session_t *c_session = (coap_session_t *)data;
  const coap_mbedtls_context_t *m_context =
      (coap_mbedtls_context_t *)c_session->context->dtls_context;
  const coap_dtls_pki_t *setup_data = &m_context->setup_data;

  if (*flags & MBEDTLS_X509_BADCERT_EXPIRED) {
    if (setup_data->allow_expired_certs) {
      *flags &= ~MBEDTLS_X509_BADCERT_EXPIRED;
    }
  }
  return 0;
}

/*
 * return 0 All OK
 *        -ve Error Code
 */
static int
cert_verify_callback_mbedtls(void *data, mbedtls_x509_crt *crt,
                             int depth, uint32_t *flags) {
  coap_session_t *c_session = (coap_session_t *)data;
  coap_mbedtls_context_t *m_context =
      (coap_mbedtls_context_t *)c_session->context->dtls_context;
  coap_dtls_pki_t *setup_data = &m_context->setup_data;
  char *cn = NULL;

  if (*flags == 0)
    return 0;

  cn = get_san_or_cn_from_cert(crt);

  if (*flags & MBEDTLS_X509_BADCERT_EXPIRED) {
    if (setup_data->allow_expired_certs) {
      *flags &= ~MBEDTLS_X509_BADCERT_EXPIRED;
      coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                    coap_session_str(c_session),
                    "The certificate has expired", cn ? cn : "?", depth);
    }
  }
  if (*flags & MBEDTLS_X509_BADCERT_FUTURE) {
    if (setup_data->allow_expired_certs) {
      *flags &= ~MBEDTLS_X509_BADCERT_FUTURE;
      coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                    coap_session_str(c_session),
                    "The certificate has a future date", cn ? cn : "?", depth);
    }
  }
  if (*flags & MBEDTLS_X509_BADCERT_BAD_MD) {
    if (setup_data->allow_bad_md_hash) {
      *flags &= ~MBEDTLS_X509_BADCERT_BAD_MD;
      coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                    coap_session_str(c_session),
                    "The certificate has a bad MD hash", cn ? cn : "?", depth);
    }
  }
  if (*flags & MBEDTLS_X509_BADCERT_BAD_KEY) {
    if (setup_data->allow_short_rsa_length) {
      *flags &= ~MBEDTLS_X509_BADCERT_BAD_KEY;
      coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                    coap_session_str(c_session),
                    "The certificate has a short RSA length", cn ? cn : "?", depth);
    }
  }
  if (*flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
    uint32_t lflags;
    int self_signed = !mbedtls_x509_crt_verify(crt, crt, NULL, NULL, &lflags,
                                               self_signed_cert_verify_callback_mbedtls,
                                               data);
    if (self_signed && depth == 0) {
      if (setup_data->allow_self_signed &&
          !setup_data->check_common_ca) {
        *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                      coap_session_str(c_session),
                      "Self-signed",
                      cn ? cn : "?", depth);
      }
    } else if (self_signed) {
      if (!setup_data->verify_peer_cert) {
        *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                      coap_session_str(c_session),
                      "Self-signed", cn ? cn : "?", depth);
      }
    } else {
      if (!setup_data->verify_peer_cert) {
        *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                      coap_session_str(c_session),
                      "The certificate's CA is not trusted", cn ? cn : "?", depth);
      }
    }
  }
  if (*flags & MBEDTLS_X509_BADCRL_EXPIRED) {
    if (setup_data->check_cert_revocation && setup_data->allow_expired_crl) {
      *flags &= ~MBEDTLS_X509_BADCRL_EXPIRED;
      coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                    coap_session_str(c_session),
                    "The certificate's CRL has expired", cn ? cn : "?", depth);
    } else if (!setup_data->check_cert_revocation) {
      *flags &= ~MBEDTLS_X509_BADCRL_EXPIRED;
    }
  }
  if (*flags & MBEDTLS_X509_BADCRL_FUTURE) {
    if (setup_data->check_cert_revocation && setup_data->allow_expired_crl) {
      *flags &= ~MBEDTLS_X509_BADCRL_FUTURE;
      coap_log_info("   %s: %s: overridden: '%s' depth %d\n",
                    coap_session_str(c_session),
                    "The certificate's CRL has a future date", cn ? cn : "?", depth);
    } else if (!setup_data->check_cert_revocation) {
      *flags &= ~MBEDTLS_X509_BADCRL_FUTURE;
    }
  }
  if (setup_data->cert_chain_validation &&
      depth > (setup_data->cert_chain_verify_depth + 1)) {
    *flags |= MBEDTLS_X509_BADCERT_OTHER;
    coap_log_warn("   %s: %s: '%s' depth %d\n",
                  coap_session_str(c_session),
                  "The certificate's verify depth is too long",
                  cn ? cn : "?", depth);
  }

  if (*flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) {
    *flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
  }
  if (setup_data->validate_cn_call_back) {
    int ret;

    coap_lock_callback_ret(ret, c_session->context,
                           setup_data->validate_cn_call_back(cn,
                                                             crt->raw.p,
                                                             crt->raw.len,
                                                             c_session,
                                                             depth,
                                                             *flags == 0,
                                                             setup_data->cn_call_back_arg));
    if (!ret) {
      *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
    }
  }
  if (*flags != 0) {
    char buf[128];
    char *tcp;
    int ret = mbedtls_x509_crt_verify_info(buf, sizeof(buf), "", *flags);

    if (ret >= 0) {
      tcp = strchr(buf, '\n');
      while (tcp) {
        *tcp = '\000';
        coap_log_warn("   %s: %s: issue 0x%" PRIx32 ": '%s' depth %d\n",
                      coap_session_str(c_session),
                      buf, *flags, cn ? cn : "?", depth);
        tcp = strchr(tcp+1, '\n');
      }
    } else {
      coap_log_err("mbedtls_x509_crt_verify_info returned -0x%x: '%s'\n",
                   -ret, get_error_string(ret));
    }
  }

  if (cn)
    mbedtls_free(cn);

  return 0;
}

static int
setup_pki_credentials(mbedtls_x509_crt *cacert,
                      mbedtls_x509_crt *public_cert,
                      mbedtls_pk_context *private_key,
                      coap_mbedtls_env_t *m_env,
                      coap_mbedtls_context_t *m_context,
                      coap_session_t *c_session,
                      coap_dtls_pki_t *setup_data,
                      coap_dtls_role_t role) {
  coap_dtls_key_t key;
  int ret;
  int done_private_key = 0;
  int done_public_cert = 0;
  uint8_t *buffer;
  size_t length;

  /* Map over to the new define format to save code duplication */
  coap_dtls_map_key_type_to_define(setup_data, &key);

  assert(key.key_type == COAP_PKI_KEY_DEFINE);

  /*
   * Configure the Private Key
   */
  if (key.key.define.private_key.u_byte &&
      key.key.define.private_key.u_byte[0]) {
    switch (key.key.define.private_key_def) {
    case COAP_PKI_KEY_DEF_DER: /* define private key */
    /* Fall Through */
    case COAP_PKI_KEY_DEF_PEM: /* define private key */
#if defined(MBEDTLS_FS_IO)
      mbedtls_pk_init(private_key);
#ifdef MBEDTLS_2_X_COMPAT
      ret = mbedtls_pk_parse_keyfile(private_key,
                                     key.key.define.private_key.s_byte, NULL);
#else
      ret = mbedtls_pk_parse_keyfile(private_key,
                                     key.key.define.private_key.s_byte,
                                     NULL, coap_rng, (void *)&m_env->ctr_drbg);
#endif /* MBEDTLS_2_X_COMPAT */
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      done_private_key = 1;
      break;
#else /* ! MBEDTLS_FS_IO */
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
#endif /* ! MBEDTLS_FS_IO */
    case COAP_PKI_KEY_DEF_PEM_BUF: /* define private key */
      mbedtls_pk_init(private_key);
      length = key.key.define.private_key_len;
      if (key.key.define.private_key.u_byte[length-1] != '\000') {
        /* Need to allocate memory to add in NULL terminator */
        buffer = mbedtls_malloc(length + 1);
        if (!buffer) {
          coap_log_err("mbedtls_malloc failed\n");
          return 0;
        }
        memcpy(buffer, key.key.define.private_key.u_byte, length);
        buffer[length] = '\000';
        length++;
#ifdef MBEDTLS_2_X_COMPAT
        ret = mbedtls_pk_parse_key(private_key, buffer, length, NULL, 0);
#else
        ret = mbedtls_pk_parse_key(private_key, buffer, length,
                                   NULL, 0, coap_rng, (void *)&m_env->ctr_drbg);
#endif /* MBEDTLS_2_X_COMPAT */
        mbedtls_free(buffer);
      } else {
#ifdef MBEDTLS_2_X_COMPAT
        ret = mbedtls_pk_parse_key(private_key,
                                   key.key.define.private_key.u_byte,
                                   key.key.define.private_key_len, NULL, 0);
#else
        ret = mbedtls_pk_parse_key(private_key,
                                   key.key.define.private_key.u_byte,
                                   key.key.define.private_key_len,
                                   NULL, 0, coap_rng, (void *)&m_env->ctr_drbg);
#endif /* MBEDTLS_2_X_COMPAT */
      }
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      done_private_key = 1;
      break;
    case COAP_PKI_KEY_DEF_DER_BUF: /* define private key */
      mbedtls_pk_init(private_key);
#ifdef MBEDTLS_2_X_COMPAT
      ret = mbedtls_pk_parse_key(private_key,
                                 key.key.define.private_key.u_byte,
                                 key.key.define.private_key_len, NULL, 0);
#else
      ret = mbedtls_pk_parse_key(private_key,
                                 key.key.define.private_key.u_byte,
                                 key.key.define.private_key_len, NULL, 0, coap_rng,
                                 (void *)&m_env->ctr_drbg);
#endif /* MBEDTLS_2_X_COMPAT */
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      done_private_key = 1;
      break;
    case COAP_PKI_KEY_DEF_RPK_BUF: /* define private key */
    case COAP_PKI_KEY_DEF_PKCS11: /* define private key */
    case COAP_PKI_KEY_DEF_PKCS11_RPK: /* define private key */
    case COAP_PKI_KEY_DEF_ENGINE: /* define private key */
    default:
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
    }
  } else if (role == COAP_DTLS_ROLE_SERVER ||
             (key.key.define.public_cert.u_byte &&
              key.key.define.public_cert.u_byte[0])) {
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PRIVATE,
                                  COAP_DEFINE_FAIL_NONE,
                                  &key, role, -1);
  }

  /*
   * Configure the Public Certificate / Key
   */
  if (key.key.define.public_cert.u_byte &&
      key.key.define.public_cert.u_byte[0]) {
    switch (key.key.define.public_cert_def) {
    case COAP_PKI_KEY_DEF_DER: /* define public cert */
    /* Fall Through */
    case COAP_PKI_KEY_DEF_PEM: /* define public cert */
#if defined(MBEDTLS_FS_IO)
      mbedtls_x509_crt_init(public_cert);
      ret = mbedtls_x509_crt_parse_file(public_cert,
                                        key.key.define.public_cert.s_byte);
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      done_public_cert = 1;
      break;
#else /* ! MBEDTLS_FS_IO */
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
#endif /* ! MBEDTLS_FS_IO */
    case COAP_PKI_KEY_DEF_PEM_BUF: /* define public cert */
      mbedtls_x509_crt_init(public_cert);

      length = key.key.define.public_cert_len;
      if (key.key.define.public_cert.u_byte[length-1] != '\000') {
        /* Need to allocate memory to add in NULL terminator */
        buffer = mbedtls_malloc(length + 1);
        if (!buffer) {
          coap_log_err("mbedtls_malloc failed\n");
          return 0;
        }
        memcpy(buffer, key.key.define.public_cert.u_byte, length);
        buffer[length] = '\000';
        length++;
        ret = mbedtls_x509_crt_parse(public_cert, buffer, length);
        mbedtls_free(buffer);
      } else {
        ret = mbedtls_x509_crt_parse(public_cert,
                                     key.key.define.public_cert.u_byte,
                                     key.key.define.public_cert_len);
      }
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      done_public_cert = 1;
      break;
    case COAP_PKI_KEY_DEF_RPK_BUF: /* define public cert */
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
    case COAP_PKI_KEY_DEF_DER_BUF: /* define public cert */
      mbedtls_x509_crt_init(public_cert);
      ret = mbedtls_x509_crt_parse(public_cert,
                                   key.key.define.public_cert.u_byte,
                                   key.key.define.public_cert_len);
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      done_public_cert = 1;
      break;
    case COAP_PKI_KEY_DEF_PKCS11: /* define public cert */
    case COAP_PKI_KEY_DEF_PKCS11_RPK: /* define public cert */
    case COAP_PKI_KEY_DEF_ENGINE: /* define public cert */
    default:
      return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
    }
  } else if (role == COAP_DTLS_ROLE_SERVER ||
             (key.key.define.private_key.u_byte &&
              key.key.define.private_key.u_byte[0])) {
    return coap_dtls_define_issue(COAP_DEFINE_KEY_PUBLIC,
                                  COAP_DEFINE_FAIL_NONE,
                                  &key, role, -1);
  }

  if (done_private_key && done_public_cert) {
    ret = mbedtls_ssl_conf_own_cert(&m_env->conf, public_cert, private_key);
    if (ret < 0) {
      coap_log_err("mbedtls_ssl_conf_own_cert returned -0x%x: '%s'\n",
                   -ret, get_error_string(ret));
      return 0;
    }
  }

  /*
   * Configure the CA
   */
  if (
      key.key.define.ca.u_byte &&
      key.key.define.ca.u_byte[0]) {
    switch (key.key.define.ca_def) {
    case COAP_PKI_KEY_DEF_DER: /* define ca */
    /* Fall Through */
    case COAP_PKI_KEY_DEF_PEM:
#if defined(MBEDTLS_FS_IO)
      mbedtls_x509_crt_init(cacert);
      ret = mbedtls_x509_crt_parse_file(cacert,
                                        key.key.define.ca.s_byte);
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      mbedtls_ssl_conf_ca_chain(&m_env->conf, cacert, NULL);
#else /* ! MBEDTLS_FS_IO */
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
#endif /* ! MBEDTLS_FS_IO */
      break;
    case COAP_PKI_KEY_DEF_PEM_BUF: /* define ca */
      mbedtls_x509_crt_init(cacert);
      length = key.key.define.ca_len;
      if (key.key.define.ca.u_byte[length-1] != '\000') {
        /* Need to allocate memory to add in NULL terminator */
        buffer = mbedtls_malloc(length + 1);
        if (!buffer) {
          coap_log_err("mbedtls_malloc failed\n");
          return 0;
        }
        memcpy(buffer, key.key.define.ca.u_byte, length);
        buffer[length] = '\000';
        length++;
        ret = mbedtls_x509_crt_parse(cacert, buffer, length);
        mbedtls_free(buffer);
      } else {
        ret = mbedtls_x509_crt_parse(cacert,
                                     key.key.define.ca.u_byte,
                                     key.key.define.ca_len);
      }
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      mbedtls_ssl_conf_ca_chain(&m_env->conf, cacert, NULL);
      break;
    case COAP_PKI_KEY_DEF_RPK_BUF: /* define ca */
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
    case COAP_PKI_KEY_DEF_DER_BUF: /* define ca */
      mbedtls_x509_crt_init(cacert);
      ret = mbedtls_x509_crt_parse(cacert,
                                   key.key.define.ca.u_byte,
                                   key.key.define.ca_len);
      if (ret < 0) {
        return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                      COAP_DEFINE_FAIL_BAD,
                                      &key, role, ret);
      }
      mbedtls_ssl_conf_ca_chain(&m_env->conf, cacert, NULL);
      break;
    case COAP_PKI_KEY_DEF_PKCS11: /* define ca */
    case COAP_PKI_KEY_DEF_PKCS11_RPK: /* define ca */
    case COAP_PKI_KEY_DEF_ENGINE: /* define ca */
    default:
      return coap_dtls_define_issue(COAP_DEFINE_KEY_CA,
                                    COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                    &key, role, -1);
    }
  }

  /* Add in any root CA definitons */

#if defined(MBEDTLS_FS_IO)
  if (m_context->root_ca_file) {
    ret = mbedtls_x509_crt_parse_file(cacert, m_context->root_ca_file);
    if (ret < 0) {
      key.key.define.ca_def = COAP_PKI_KEY_DEF_PEM;
      return coap_dtls_define_issue(COAP_DEFINE_KEY_ROOT_CA,
                                    COAP_DEFINE_FAIL_BAD,
                                    &key, role, ret);
    }
    mbedtls_ssl_conf_ca_chain(&m_env->conf, cacert, NULL);
  }
  if (m_context->root_ca_path) {
    ret = mbedtls_x509_crt_parse_path(cacert, m_context->root_ca_path);
    if (ret < 0) {
      key.key.define.ca_def = COAP_PKI_KEY_DEF_PEM;
      return coap_dtls_define_issue(COAP_DEFINE_KEY_ROOT_CA,
                                    COAP_DEFINE_FAIL_BAD,
                                    &key, role, ret);
    }
    mbedtls_ssl_conf_ca_chain(&m_env->conf, cacert, NULL);
  }
  if (m_context->trust_store_defined) {
    /* Until Trust Store is implemented in MbedTLS */
    const char *trust_list[] = {
      "/etc/ssl/ca-bundle.pem",
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/cert.pem",
      "/usr/local/share/certs/ca-root-nss.crt",
      "/etc/ssl/cert.pem"
    };
    static const char *trust_file_found = NULL;
    static int trust_file_done = 0;
    unsigned int i;

    if (trust_file_found) {
      ret = mbedtls_x509_crt_parse_file(cacert, trust_file_found);
      if (ret >= 0) {
        mbedtls_ssl_conf_ca_chain(&m_env->conf, cacert, NULL);
      } else {
        coap_log_warn("Unable to load trusted root CAs (%s)\n",
                      trust_file_found);
      }
    } else if (!trust_file_done) {
      trust_file_done = 1;
      for (i = 0; i < sizeof(trust_list)/sizeof(trust_list[0]); i++) {
        ret = mbedtls_x509_crt_parse_file(cacert, trust_list[i]);
        if (ret >= 0) {
          mbedtls_ssl_conf_ca_chain(&m_env->conf, cacert, NULL);
          trust_file_found = trust_list[i];
          break;
        }
      }
      if (i == sizeof(trust_list)/sizeof(trust_list[0])) {
        coap_log_warn("Unable to load trusted root CAs\n");
      }
    }
  }
#else /* ! MBEDTLS_FS_IO */
  (void)m_context;
  return coap_dtls_define_issue(COAP_DEFINE_KEY_ROOT_CA,
                                COAP_DEFINE_FAIL_NOT_SUPPORTED,
                                &key, role, -1);
#endif /* ! MBEDTLS_FS_IO */

#if defined(MBEDTLS_SSL_SRV_C)
  mbedtls_ssl_conf_cert_req_ca_list(&m_env->conf,
                                    setup_data->check_common_ca ?
                                    MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED :
                                    MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);
#endif
  mbedtls_ssl_conf_authmode(&m_env->conf, setup_data->verify_peer_cert ?
                            MBEDTLS_SSL_VERIFY_REQUIRED :
                            MBEDTLS_SSL_VERIFY_NONE);
  /*
   * Verify Peer.
   *  Need to do all checking, even if setup_data->verify_peer_cert is not set
   */
  mbedtls_ssl_conf_verify(&m_env->conf,
                          cert_verify_callback_mbedtls, c_session);

  return 1;
}

#if defined(MBEDTLS_SSL_SRV_C)
/*
 * PKI SNI callback.
 */
static int
pki_sni_callback(void *p_info, mbedtls_ssl_context *ssl,
                 const unsigned char *uname, size_t name_len) {
  unsigned int i;
  coap_dtls_pki_t sni_setup_data;
  coap_session_t *c_session = (coap_session_t *)p_info;
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;
  coap_mbedtls_context_t *m_context =
      (coap_mbedtls_context_t *)c_session->context->dtls_context;
  char *name;

  name = mbedtls_malloc(name_len+1);
  if (!name)
    return -1;

  memcpy(name, uname, name_len);
  name[name_len] = '\000';

  /* Is this a cached entry? */
  for (i = 0; i < m_context->pki_sni_count; i++) {
    if (strcasecmp(name, m_context->pki_sni_entry_list[i].sni) == 0) {
      break;
    }
  }
  if (i == m_context->pki_sni_count) {
    /*
     * New PKI SNI request
     */
    coap_dtls_key_t *new_entry;
    pki_sni_entry *pki_sni_entry_list;

    coap_lock_callback_ret(new_entry, c_session->context,
                           m_context->setup_data.validate_sni_call_back(name,
                               m_context->setup_data.sni_call_back_arg));
    if (!new_entry) {
      mbedtls_free(name);
      return -1;
    }

    pki_sni_entry_list = mbedtls_realloc(m_context->pki_sni_entry_list,
                                         (i+1)*sizeof(pki_sni_entry));

    if (pki_sni_entry_list == NULL) {
      mbedtls_free(name);
      return -1;
    }
    m_context->pki_sni_entry_list = pki_sni_entry_list;
    memset(&m_context->pki_sni_entry_list[i], 0,
           sizeof(m_context->pki_sni_entry_list[i]));
    m_context->pki_sni_entry_list[i].sni = name;
    m_context->pki_sni_entry_list[i].pki_key = *new_entry;
    sni_setup_data = m_context->setup_data;
    sni_setup_data.pki_key = *new_entry;
    if (setup_pki_credentials(&m_context->pki_sni_entry_list[i].cacert,
                              &m_context->pki_sni_entry_list[i].public_cert,
                              &m_context->pki_sni_entry_list[i].private_key,
                              m_env,
                              m_context,
                              c_session,
                              &sni_setup_data, COAP_DTLS_ROLE_SERVER) < 0) {
      mbedtls_free(name);
      return -1;
    }
    /* name has been absorbed into pki_sni_entry_list[].sni entry */
    m_context->pki_sni_count++;
  } else {
    mbedtls_free(name);
  }

  mbedtls_ssl_set_hs_ca_chain(ssl, &m_context->pki_sni_entry_list[i].cacert,
                              NULL);
  return mbedtls_ssl_set_hs_own_cert(ssl,
                                     &m_context->pki_sni_entry_list[i].public_cert,
                                     &m_context->pki_sni_entry_list[i].private_key);
}

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
/*
 * PSK SNI callback.
 */
static int
psk_sni_callback(void *p_info, mbedtls_ssl_context *ssl,
                 const unsigned char *uname, size_t name_len) {
  unsigned int i;
  coap_session_t *c_session = (coap_session_t *)p_info;
  coap_mbedtls_context_t *m_context =
      (coap_mbedtls_context_t *)c_session->context->dtls_context;
  char *name;

  name = mbedtls_malloc(name_len+1);
  if (!name)
    return -1;

  memcpy(name, uname, name_len);
  name[name_len] = '\000';

  /* Is this a cached entry? */
  for (i = 0; i < m_context->psk_sni_count; i++) {
    if (strcasecmp(name, m_context->psk_sni_entry_list[i].sni) == 0) {
      break;
    }
  }
  if (i == m_context->psk_sni_count) {
    /*
     * New PSK SNI request
     */
    const coap_dtls_spsk_info_t *new_entry;
    psk_sni_entry *psk_sni_entry_list;

    coap_lock_callback_ret(new_entry, c_session->context,
                           c_session->context->spsk_setup_data.validate_sni_call_back(name,
                               c_session,
                               c_session->context->spsk_setup_data.sni_call_back_arg));
    if (!new_entry) {
      mbedtls_free(name);
      return -1;
    }

    psk_sni_entry_list = mbedtls_realloc(m_context->psk_sni_entry_list,
                                         (i+1)*sizeof(psk_sni_entry));

    if (psk_sni_entry_list == NULL) {
      mbedtls_free(name);
      return -1;
    }
    m_context->psk_sni_entry_list = psk_sni_entry_list;
    m_context->psk_sni_entry_list[i].sni = name;
    m_context->psk_sni_entry_list[i].psk_info = *new_entry;
    /* name has been absorbed into psk_sni_entry_list[].sni entry */
    m_context->psk_sni_count++;
  } else {
    mbedtls_free(name);
  }

  coap_session_refresh_psk_hint(c_session,
                                &m_context->psk_sni_entry_list[i].psk_info.hint);
  coap_session_refresh_psk_key(c_session,
                               &m_context->psk_sni_entry_list[i].psk_info.key);
  return mbedtls_ssl_set_hs_psk(ssl,
                                m_context->psk_sni_entry_list[i].psk_info.key.s,
                                m_context->psk_sni_entry_list[i].psk_info.key.length);
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

static int
setup_server_ssl_session(coap_session_t *c_session,
                         coap_mbedtls_env_t *m_env) {
  coap_mbedtls_context_t *m_context =
      (coap_mbedtls_context_t *)c_session->context->dtls_context;
  int ret = 0;
  m_context->psk_pki_enabled |= IS_SERVER;

  mbedtls_ssl_cookie_init(&m_env->cookie_ctx);
  if ((ret = mbedtls_ssl_config_defaults(&m_env->conf,
                                         MBEDTLS_SSL_IS_SERVER,
                                         c_session->proto == COAP_PROTO_DTLS ?
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM :
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    coap_log_err("mbedtls_ssl_config_defaults returned -0x%x: '%s'\n",
                 -ret, get_error_string(ret));
    goto fail;
  }

  mbedtls_ssl_conf_rng(&m_env->conf, mbedtls_ctr_drbg_random, &m_env->ctr_drbg);

#if defined(MBEDTLS_SSL_PROTO_DTLS)
  mbedtls_ssl_conf_handshake_timeout(&m_env->conf, COAP_DTLS_RETRANSMIT_MS,
                                     COAP_DTLS_RETRANSMIT_TOTAL_MS);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

  if (m_context->psk_pki_enabled & IS_PSK) {
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    mbedtls_ssl_conf_psk_cb(&m_env->conf, psk_server_callback, c_session);
    if (c_session->context->spsk_setup_data.validate_sni_call_back) {
      mbedtls_ssl_conf_sni(&m_env->conf, psk_sni_callback, c_session);
    }
#ifdef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    m_env->ec_jpake = c_session->context->spsk_setup_data.ec_jpake;
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#else /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
    coap_log_warn("PSK not enabled in Mbed TLS library\n");
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
  }

  if (m_context->psk_pki_enabled & IS_PKI) {
    ret = setup_pki_credentials(&m_env->cacert, &m_env->public_cert,
                                &m_env->private_key, m_env, m_context,
                                c_session, &m_context->setup_data,
                                COAP_DTLS_ROLE_SERVER);
    if (ret < 0) {
      coap_log_err("PKI setup failed\n");
      return ret;
    }
    if (m_context->setup_data.validate_sni_call_back) {
      mbedtls_ssl_conf_sni(&m_env->conf, pki_sni_callback, c_session);
    }
  }

  if ((ret = mbedtls_ssl_cookie_setup(&m_env->cookie_ctx,
                                      mbedtls_ctr_drbg_random,
                                      &m_env->ctr_drbg)) != 0) {
    coap_log_err("mbedtls_ssl_cookie_setup: returned -0x%x: '%s'\n",
                 -ret, get_error_string(ret));
    goto fail;
  }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
  mbedtls_ssl_conf_dtls_cookies(&m_env->conf, mbedtls_ssl_cookie_write,
                                mbedtls_ssl_cookie_check,
                                &m_env->cookie_ctx);
#if MBEDTLS_VERSION_NUMBER >= 0x02100100
  mbedtls_ssl_set_mtu(&m_env->ssl, (uint16_t)c_session->mtu);
#endif /* MBEDTLS_VERSION_NUMBER >= 0x02100100 */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#ifdef MBEDTLS_SSL_DTLS_CONNECTION_ID
  /*
   * Configure CID max length.
   *
   * Note: Set MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT to 0 (the default)
   * to use RFC9146 extension ID of 54, rather than the draft version -05
   * value of 254.
   */
  mbedtls_ssl_conf_cid(&m_env->conf, COAP_DTLS_CID_LENGTH, MBEDTLS_SSL_UNEXPECTED_CID_IGNORE);
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
fail:
  return ret;
}
#endif /* MBEDTLS_SSL_SRV_C */

#if COAP_CLIENT_SUPPORT
static int *psk_ciphers = NULL;
static int *pki_ciphers = NULL;
static int *ecjpake_ciphers = NULL;
static int processed_ciphers = 0;

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static int
coap_ssl_ciphersuite_uses_psk(const mbedtls_ssl_ciphersuite_t *info) {
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
  switch (info->key_exchange) {
  case MBEDTLS_KEY_EXCHANGE_PSK:
  case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
  case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
  case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
    return 1;
  case MBEDTLS_KEY_EXCHANGE_NONE:
  case MBEDTLS_KEY_EXCHANGE_RSA:
  case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
  case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
  case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
  case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
  case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
  case MBEDTLS_KEY_EXCHANGE_ECJPAKE:
  default:
    return 0;
  }
#else /* MBEDTLS_VERSION_NUMBER < 0x03060000 */
  return mbedtls_ssl_ciphersuite_uses_psk(info);
#endif /* MBEDTLS_VERSION_NUMBER < 0x03060000 */
}
#endif /* defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) */

static void
set_ciphersuites(mbedtls_ssl_config *conf, coap_enc_method_t method) {
  if (!processed_ciphers) {
    const int *list = mbedtls_ssl_list_ciphersuites();
    const int *base = list;
    int *psk_list;
    int *pki_list;
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    int *ecjpake_list;
    int ecjpake_count = 1;
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
    int psk_count = 1; /* account for empty terminator */
    int pki_count = 1;

    while (*list) {
      const mbedtls_ssl_ciphersuite_t *cur =
          mbedtls_ssl_ciphersuite_from_id(*list);

      if (cur) {
#if MBEDTLS_VERSION_NUMBER >= 0x03020000
        if (cur->max_tls_version < MBEDTLS_SSL_VERSION_TLS1_2) {
          /* Minimum of TLS1.2 required - skip */
        }
#else
        if (cur->max_minor_ver < MBEDTLS_SSL_MINOR_VERSION_3) {
          /* Minimum of TLS1.2 required - skip */
        }
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03020000 */
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
        else if (cur->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE) {
          ecjpake_count++;
        }
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
        else if (cur->min_tls_version >= MBEDTLS_SSL_VERSION_TLS1_3) {
          psk_count++;
          pki_count++;
        }
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03060000 */
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
        else if (coap_ssl_ciphersuite_uses_psk(cur)) {
          psk_count++;
        }
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
        else {
          pki_count++;
        }
      }
      list++;
    }
    list = base;

    psk_ciphers = mbedtls_malloc(psk_count * sizeof(psk_ciphers[0]));
    if (psk_ciphers == NULL) {
      coap_log_err("set_ciphers: mbedtls_malloc with count %d failed\n", psk_count);
      return;
    }
    pki_ciphers = mbedtls_malloc(pki_count * sizeof(pki_ciphers[0]));
    if (pki_ciphers == NULL) {
      coap_log_err("set_ciphers: mbedtls_malloc with count %d failed\n", pki_count);
      mbedtls_free(psk_ciphers);
      psk_ciphers = NULL;
      return;
    }
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    ecjpake_ciphers = mbedtls_malloc(ecjpake_count * sizeof(ecjpake_ciphers[0]));
    if (ecjpake_ciphers == NULL) {
      coap_log_err("set_ciphers: mbedtls_malloc with count %d failed\n", pki_count);
      mbedtls_free(psk_ciphers);
      mbedtls_free(pki_ciphers);
      psk_ciphers = NULL;
      pki_ciphers = NULL;
      return;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

    psk_list = psk_ciphers;
    pki_list = pki_ciphers;
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    ecjpake_list = ecjpake_ciphers;
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

    while (*list) {
      const mbedtls_ssl_ciphersuite_t *cur =
          mbedtls_ssl_ciphersuite_from_id(*list);
      if (cur) {
#if MBEDTLS_VERSION_NUMBER >= 0x03020000
        if (cur->max_tls_version < MBEDTLS_SSL_VERSION_TLS1_2) {
          /* Minimum of TLS1.2 required - skip */
        }
#else
        if (cur->max_minor_ver < MBEDTLS_SSL_MINOR_VERSION_3) {
          /* Minimum of TLS1.2 required - skip */
        }
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03020000 */
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
        else if (cur->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE) {
          *ecjpake_list = *list;
          ecjpake_list++;
        }
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
        else if (cur->min_tls_version >= MBEDTLS_SSL_VERSION_TLS1_3) {
          *psk_list = *list;
          psk_list++;
          *pki_list = *list;
          pki_list++;
        }
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03060000 */
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
        else if (coap_ssl_ciphersuite_uses_psk(cur)) {
          *psk_list = *list;
          psk_list++;
        }
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
        else {
          *pki_list = *list;
          pki_list++;
        }
      }
      list++;
    }
    /* zero terminate */
    *psk_list = 0;
    *pki_list = 0;
    processed_ciphers = 1;
  }
  switch (method) {
  case COAP_ENC_PSK:
    mbedtls_ssl_conf_ciphersuites(conf, psk_ciphers);
    break;
  case COAP_ENC_PKI:
    mbedtls_ssl_conf_ciphersuites(conf, pki_ciphers);
    break;
  case COAP_ENC_ECJPAKE:
    mbedtls_ssl_conf_ciphersuites(conf, ecjpake_ciphers);
    break;
  default:
    assert(0);
    break;
  }
}

static int
setup_client_ssl_session(coap_session_t *c_session,
                         coap_mbedtls_env_t *m_env) {
  int ret;

  coap_mbedtls_context_t *m_context =
      (coap_mbedtls_context_t *)c_session->context->dtls_context;

  m_context->psk_pki_enabled |= IS_CLIENT;

  if ((ret = mbedtls_ssl_config_defaults(&m_env->conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         c_session->proto == COAP_PROTO_DTLS ?
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM :
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    coap_log_err("mbedtls_ssl_config_defaults returned -0x%x: '%s'\n",
                 -ret, get_error_string(ret));
    goto fail;
  }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
  mbedtls_ssl_conf_handshake_timeout(&m_env->conf, COAP_DTLS_RETRANSMIT_MS,
                                     COAP_DTLS_RETRANSMIT_TOTAL_MS);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

  mbedtls_ssl_conf_authmode(&m_env->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&m_env->conf, mbedtls_ctr_drbg_random, &m_env->ctr_drbg);

  if (m_context->psk_pki_enabled & IS_PSK) {
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    const coap_bin_const_t *psk_key;
    const coap_bin_const_t *psk_identity;

    coap_log_info("Setting PSK key\n");

    psk_key = coap_get_session_client_psk_key(c_session);
    psk_identity = coap_get_session_client_psk_identity(c_session);
    if (psk_key == NULL || psk_identity == NULL) {
      ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
      goto fail;
    }

    if ((ret = mbedtls_ssl_conf_psk(&m_env->conf, psk_key->s,
                                    psk_key->length, psk_identity->s,
                                    psk_identity->length)) != 0) {
      coap_log_err("mbedtls_ssl_conf_psk returned -0x%x: '%s'\n",
                   -ret, get_error_string(ret));
      goto fail;
    }
    if (c_session->cpsk_setup_data.client_sni) {
      if ((ret = mbedtls_ssl_set_hostname(&m_env->ssl,
                                          c_session->cpsk_setup_data.client_sni)) != 0) {
        coap_log_err("mbedtls_ssl_set_hostname returned -0x%x: '%s'\n",
                     -ret, get_error_string(ret));
        goto fail;
      }
    }
    /* Identity Hint currently not supported in Mbed TLS so code removed */

#ifdef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    if (c_session->cpsk_setup_data.ec_jpake) {
      m_env->ec_jpake = 1;
      set_ciphersuites(&m_env->conf, COAP_ENC_ECJPAKE);
#if MBEDTLS_VERSION_NUMBER >= 0x03020000
      mbedtls_ssl_conf_max_tls_version(&m_env->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03020000 */
    } else {
      set_ciphersuites(&m_env->conf, COAP_ENC_PSK);
    }
#else /* ! MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
    set_ciphersuites(&m_env->conf, COAP_ENC_PSK);
#endif /* ! MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#else /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
    coap_log_warn("PSK not enabled in Mbed TLS library\n");
#endif /* ! MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */
  } else if ((m_context->psk_pki_enabled & IS_PKI) ||
             (m_context->psk_pki_enabled & (IS_PSK | IS_PKI)) == 0) {
    /*
     * If neither PSK or PKI have been set up, use PKI basics.
     * This works providing COAP_PKI_KEY_PEM has a value of 0.
     */
    coap_dtls_pki_t *setup_data = &m_context->setup_data;

    if (!(m_context->psk_pki_enabled & IS_PKI)) {
      /* PKI not defined - set up some defaults */
      setup_data->verify_peer_cert        = 1;
      setup_data->check_common_ca         = 0;
      setup_data->allow_self_signed       = 1;
      setup_data->allow_expired_certs     = 1;
      setup_data->cert_chain_validation   = 1;
      setup_data->cert_chain_verify_depth = 2;
      setup_data->check_cert_revocation   = 1;
      setup_data->allow_no_crl            = 1;
      setup_data->allow_expired_crl       = 1;
      setup_data->is_rpk_not_cert         = 0;
      setup_data->use_cid                 = 0;
    }
    mbedtls_ssl_conf_authmode(&m_env->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    ret = setup_pki_credentials(&m_env->cacert, &m_env->public_cert,
                                &m_env->private_key, m_env, m_context,
                                c_session, setup_data,
                                COAP_DTLS_ROLE_CLIENT);
    if (ret < 0) {
      coap_log_err("PKI setup failed\n");
      return ret;
    }
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_ALPN)
    if (c_session->proto == COAP_PROTO_TLS ||
        c_session->proto == COAP_PROTO_WSS) {
      static const char *alpn_list[] = { "coap", NULL };

      ret = mbedtls_ssl_conf_alpn_protocols(&m_env->conf, alpn_list);
      if (ret != 0) {
        coap_log_err("ALPN setup failed %d)\n", ret);
      }
    }
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_ALPN */
    if (m_context->setup_data.client_sni) {
      mbedtls_ssl_set_hostname(&m_env->ssl, m_context->setup_data.client_sni);
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if MBEDTLS_VERSION_NUMBER >= 0x02100100
    mbedtls_ssl_set_mtu(&m_env->ssl, (uint16_t)c_session->mtu);
#endif /* MBEDTLS_VERSION_NUMBER >= 0x02100100 */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    set_ciphersuites(&m_env->conf, COAP_ENC_PKI);
  }
  return 0;

fail:
  return ret;
}
#endif /* COAP_CLIENT_SUPPORT */

static void
mbedtls_cleanup(coap_mbedtls_env_t *m_env) {
  if (!m_env) {
    return;
  }

  mbedtls_x509_crt_free(&m_env->cacert);
  mbedtls_x509_crt_free(&m_env->public_cert);
  mbedtls_pk_free(&m_env->private_key);
  mbedtls_entropy_free(&m_env->entropy);
  mbedtls_ssl_config_free(&m_env->conf);
  mbedtls_ctr_drbg_free(&m_env->ctr_drbg);
  mbedtls_ssl_free(&m_env->ssl);
  mbedtls_ssl_cookie_free(&m_env->cookie_ctx);
}

static void
coap_dtls_free_mbedtls_env(coap_mbedtls_env_t *m_env) {
  if (m_env) {
    if (!m_env->sent_alert)
      mbedtls_ssl_close_notify(&m_env->ssl);
    mbedtls_cleanup(m_env);
    mbedtls_free(m_env);
  }
}

#if COAP_MAX_LOGGING_LEVEL > 0
static const char *
report_mbedtls_alert(unsigned char alert) {
  switch (alert) {
  case MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC:
    return ": Bad Record MAC";
  case MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE:
    return ": Handshake failure";
  case MBEDTLS_SSL_ALERT_MSG_NO_CERT:
    return ": No Certificate provided";
  case MBEDTLS_SSL_ALERT_MSG_BAD_CERT:
    return ": Certificate is bad";
  case MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN:
    return ": Certificate is unknown";
  case MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA:
    return ": CA is unknown";
  case MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED:
    return ": Access was denied";
  case MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR:
    return ": Decrypt error";
  default:
    return "";
  }
}
#endif /* COAP_MAX_LOGGING_LEVEL */

/*
 * return -1  failure
 *         0  not completed
 *         1  established
 */
static int
do_mbedtls_handshake(coap_session_t *c_session,
                     coap_mbedtls_env_t *m_env) {
  int ret;
  int alert;

  ret = mbedtls_ssl_handshake(&m_env->ssl);
  switch (ret) {
  case 0:
    m_env->established = 1;
    coap_log_debug("*  %s: Mbed TLS established\n",
                   coap_session_str(c_session));
    ret = 1;
#ifdef MBEDTLS_SSL_DTLS_CONNECTION_ID
#if COAP_CLIENT_SUPPORT
    if (c_session->type == COAP_SESSION_TYPE_CLIENT &&
        c_session->proto == COAP_PROTO_DTLS) {
      coap_mbedtls_context_t *m_context;

      m_context = (coap_mbedtls_context_t *)c_session->context->dtls_context;
      if ((m_context->psk_pki_enabled & IS_PSK && c_session->cpsk_setup_data.use_cid) ||
          m_context->setup_data.use_cid) {
        unsigned char peer_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX];
        int enabled;
        size_t peer_cid_len;

        /* See whether CID was negotiated */
        if (mbedtls_ssl_get_peer_cid(&m_env->ssl, &enabled, peer_cid, &peer_cid_len) == 0 &&
            enabled == MBEDTLS_SSL_CID_ENABLED) {
          c_session->negotiated_cid = 1;
        } else {
          coap_log_info("** %s: CID was not negotiated\n", coap_session_str(c_session));
          c_session->negotiated_cid = 0;
        }
      }
    }
#endif /* COAP_CLIENT_SUPPORT */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
    break;
  case MBEDTLS_ERR_SSL_WANT_READ:
  case MBEDTLS_ERR_SSL_WANT_WRITE:
    if (m_env->ssl.state == MBEDTLS_SSL_SERVER_HELLO
#if MBEDTLS_VERSION_NUMBER >= 0x03030000
        || m_env->ssl.state == MBEDTLS_SSL_NEW_SESSION_TICKET
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03030000 */
       ) {
      if (++m_env->server_hello_cnt > 10) {
        /* retried this too many times */
        goto fail;
      }
    }
    errno = EAGAIN;
    ret = 0;
    break;
  case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
    coap_log_debug("hello verification requested\n");
    goto reset;
  case MBEDTLS_ERR_SSL_INVALID_MAC:
    goto fail;
#ifdef MBEDTLS_2_X_COMPAT
  case MBEDTLS_ERR_SSL_UNKNOWN_CIPHER:
#else /* ! MBEDTLS_2_X_COMPAT */
  case MBEDTLS_ERR_SSL_DECODE_ERROR:
#endif /* ! MBEDTLS_2_X_COMPAT */
    goto fail;
  case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
    alert = MBEDTLS_SSL_ALERT_MSG_NO_CERT;
    goto fail_alert;
#ifdef MBEDTLS_2_X_COMPAT
  case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO:
  case MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO:
    alert = MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE;
    goto fail_alert;
#endif /* MBEDTLS_2_X_COMPAT */
  case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
    goto fail;
  case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
    if (m_env->ssl.in_msg[1] != MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY)
      coap_log_warn("***%s: Alert '%d'%s\n",
                    coap_session_str(c_session), m_env->ssl.in_msg[1],
                    report_mbedtls_alert(m_env->ssl.in_msg[1]));
  /* Fall through */
  case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
  case MBEDTLS_ERR_SSL_CONN_EOF:
  case MBEDTLS_ERR_NET_CONN_RESET:
    c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
    ret = -1;
    break;
  default:
    coap_log_warn("do_mbedtls_handshake: session establish "
                  "returned -0x%x: '%s'\n",
                  -ret, get_error_string(ret));
    ret = -1;
    break;
  }
  return ret;

fail_alert:
  mbedtls_ssl_send_alert_message(&m_env->ssl,
                                 MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                 alert);
  m_env->sent_alert = 1;
fail:
  c_session->dtls_event = COAP_EVENT_DTLS_ERROR;
  coap_log_warn("do_mbedtls_handshake: session establish "
                "returned '%s'\n",
                get_error_string(ret));
reset:
  mbedtls_ssl_session_reset(&m_env->ssl);
#ifdef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
  if (m_env->ec_jpake) {
    const coap_bin_const_t *psk_key;

#if COAP_CLIENT_SUPPORT && COAP_SERVER_SUPPORT
    if (c_session->type == COAP_SESSION_TYPE_CLIENT) {
      psk_key = coap_get_session_client_psk_key(c_session);
    } else {
      psk_key = coap_get_session_server_psk_key(c_session);
    }
#elif COAP_CLIENT_SUPPORT
    psk_key = coap_get_session_client_psk_key(c_session);
#else /* COAP_SERVER_SUPPORT */
    psk_key = coap_get_session_server_psk_key(c_session);
#endif /* COAP_SERVER_SUPPORT */
    if (psk_key) {
      mbedtls_ssl_set_hs_ecjpake_password(&m_env->ssl, psk_key->s, psk_key->length);
    }
  }
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
  return -1;
}

static void
mbedtls_debug_out(void *ctx COAP_UNUSED, int level,
                  const char *file COAP_UNUSED,
                  int line COAP_UNUSED, const char *str) {

  coap_log_t coap_level = COAP_LOG_DEBUG;
  /*
   *  0 No debug
   *  1 Error
   *  2 State change
   *  3 Informational
   *  4 Verbose
   */
  switch (level) {
  case 0:
    coap_level = COAP_LOG_EMERG;
    break;
  case 1:
    coap_level = COAP_LOG_WARN;
    break;
  case 2:
    coap_level = COAP_LOG_NOTICE;
    break;
  case 3:
    coap_level = COAP_LOG_INFO;
    break;
  case 4:
  default:
    coap_level = COAP_LOG_DEBUG;
    break;
  }
  coap_dtls_log(coap_level, "%s", str);
}

#if !COAP_DISABLE_TCP
/*
 * strm
 * return +ve data amount
 *        0   no more
 *        -ve  Mbed TLS error
 */
static int
coap_sock_read(void *ctx, unsigned char *out, size_t outl) {
  int ret = MBEDTLS_ERR_SSL_CONN_EOF;
  coap_session_t *c_session = (coap_session_t *)ctx;

  if (out != NULL) {
    ret = (int)c_session->sock.lfunc[COAP_LAYER_TLS].l_read(c_session, out, outl);
    /* Translate layer returns into what MbedTLS expects */
    if (ret == -1) {
      if (errno == ECONNRESET) {
        /* graceful shutdown */
        ret = MBEDTLS_ERR_SSL_CONN_EOF;
      } else {
        ret = MBEDTLS_ERR_NET_RECV_FAILED;
      }
    } else if (ret == 0) {
      errno = EAGAIN;
      ret = MBEDTLS_ERR_SSL_WANT_READ;
    }
  }
  return ret;
}

/*
 * strm
 * return +ve data amount
 *        0   no more
 *        -ve  Mbed TLS error
 */
static int
coap_sock_write(void *context, const unsigned char *in, size_t inl) {
  int ret = 0;
  coap_session_t *c_session = (coap_session_t *)context;

  ret = c_session->sock.lfunc[COAP_LAYER_TLS].l_write(c_session,
                                                      (const uint8_t *)in,
                                                      inl);
  /* Translate layer what returns into what MbedTLS expects */
  if (ret < 0) {
    if ((c_session->state == COAP_SESSION_STATE_CSM ||
         c_session->state == COAP_SESSION_STATE_HANDSHAKE) &&
        (errno == EPIPE || errno == ECONNRESET)) {
      /*
       * Need to handle a TCP timing window where an agent continues with
       * the sending of the next handshake or a CSM.
       * However, the peer does not like a certificate and so sends a
       * fatal alert and closes the TCP session.
       * The sending of the next handshake or CSM may get terminated because
       * of the closed TCP session, but there is still an outstanding alert
       * to be read in and reported on.
       * In this case, pretend that sending the info was fine so that the
       * alert can be read (which effectively is what happens with DTLS).
       */
      ret = inl;
    } else {
#ifdef _WIN32
      int lasterror = WSAGetLastError();

      if (lasterror == WSAEWOULDBLOCK) {
        ret = MBEDTLS_ERR_SSL_WANT_WRITE;
      } else if (lasterror == WSAECONNRESET) {
        ret = MBEDTLS_ERR_NET_CONN_RESET;
      }
#else
      if (errno == EAGAIN || errno == EINTR) {
        ret = MBEDTLS_ERR_SSL_WANT_WRITE;
      } else if (errno == EPIPE || errno == ECONNRESET) {
        ret = MBEDTLS_ERR_NET_CONN_RESET;
      }
#endif
      else {
        ret = MBEDTLS_ERR_NET_SEND_FAILED;
      }
      coap_log_debug("*  %s: failed to send %zd bytes (%s) state %d\n",
                     coap_session_str(c_session), inl, coap_socket_strerror(),
                     c_session->state);
    }
  }
  if (ret == 0) {
    errno = EAGAIN;
    ret = MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  return ret;
}
#endif /* !COAP_DISABLE_TCP */

static coap_mbedtls_env_t *
coap_dtls_new_mbedtls_env(coap_session_t *c_session,
                          coap_dtls_role_t role,
                          coap_proto_t proto) {
  int ret = 0;
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;

  if (m_env)
    return m_env;

  m_env = (coap_mbedtls_env_t *)mbedtls_malloc(sizeof(coap_mbedtls_env_t));
  if (!m_env) {
    return NULL;
  }
  memset(m_env, 0, sizeof(coap_mbedtls_env_t));

  mbedtls_ssl_init(&m_env->ssl);
  mbedtls_ctr_drbg_init(&m_env->ctr_drbg);
  mbedtls_ssl_config_init(&m_env->conf);
  mbedtls_entropy_init(&m_env->entropy);

#if defined(MBEDTLS_PSA_CRYPTO_C)
  psa_crypto_init();
#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(ESPIDF_VERSION) && defined(CONFIG_MBEDTLS_DEBUG)
  mbedtls_esp_enable_debug_log(&m_env->conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif /* ESPIDF_VERSION && CONFIG_MBEDTLS_DEBUG */
  if ((ret = mbedtls_ctr_drbg_seed(&m_env->ctr_drbg,
                                   mbedtls_entropy_func, &m_env->entropy, NULL, 0)) != 0) {
    if (ret != MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED) {
      coap_log_info("mbedtls_ctr_drbg_seed returned -0x%x: '%s'\n",
                    -ret, get_error_string(ret));
      goto fail;
    }
    coap_log_err("mbedtls_ctr_drbg_seed returned -0x%x: '%s'\n",
                 -ret, get_error_string(ret));
  }

  if (role == COAP_DTLS_ROLE_CLIENT) {
#if COAP_CLIENT_SUPPORT
    if (setup_client_ssl_session(c_session, m_env) != 0) {
      goto fail;
    }
#else /* !COAP_CLIENT_SUPPORT */
    goto fail;
#endif /* !COAP_CLIENT_SUPPORT */
  } else if (role == COAP_DTLS_ROLE_SERVER) {
#if defined(MBEDTLS_SSL_SRV_C)
    if (setup_server_ssl_session(c_session, m_env) != 0) {
      goto fail;
    }
#else /* ! MBEDTLS_SSL_SRV_C */
    goto fail;
#endif /* ! MBEDTLS_SSL_SRV_C */
  } else {
    goto fail;
  }

#if MBEDTLS_VERSION_NUMBER >= 0x03020000
  mbedtls_ssl_conf_min_tls_version(&m_env->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
  mbedtls_ssl_conf_min_version(&m_env->conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                               MBEDTLS_SSL_MINOR_VERSION_3);
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03020000 */

  if (mbedtls_ssl_setup(&m_env->ssl, &m_env->conf) != 0) {
    goto fail;
  }
  if (proto == COAP_PROTO_DTLS) {
    mbedtls_ssl_set_bio(&m_env->ssl, c_session, coap_dgram_write,
                        coap_dgram_read, NULL);
#ifdef MBEDTLS_SSL_DTLS_CONNECTION_ID
    if (COAP_PROTO_NOT_RELIABLE(c_session->proto)) {
      if (role == COAP_DTLS_ROLE_CLIENT) {
#if COAP_CLIENT_SUPPORT
        coap_mbedtls_context_t *m_context =
            (coap_mbedtls_context_t *)c_session->context->dtls_context;

        if ((m_context->psk_pki_enabled & IS_PSK && c_session->cpsk_setup_data.use_cid) ||
            m_context->setup_data.use_cid) {
          /*
           * Enable passive DTLS CID support.
           *
           * Note: Set MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT to 0 (the default)
           * to use RFC9146 extension ID of 54, rather than the draft version -05
           * value of 254.
           */
          mbedtls_ssl_set_cid(&m_env->ssl, MBEDTLS_SSL_CID_ENABLED, NULL, 0);
        }
#endif /* COAP_CLIENT_SUPPORT */
      } else {
#if COAP_SERVER_SUPPORT
        uint8_t cid[COAP_DTLS_CID_LENGTH];
        /*
         * Enable server DTLS CID support.
         *
         * Note: Set MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT to 0 (the default)
         * to use RFC9146 extension ID of 54, rather than the draft version -05
         * value of 254.
         */
        coap_prng_lkd(cid, sizeof(cid));
        mbedtls_ssl_set_cid(&m_env->ssl, MBEDTLS_SSL_CID_ENABLED, cid,
                            sizeof(cid));
        c_session->client_cid = coap_new_bin_const(cid, sizeof(cid));
#endif /* COAP_SERVER_SUPPORT */
      }
    }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
  }
#if !COAP_DISABLE_TCP
  else {
    assert(proto == COAP_PROTO_TLS);
    mbedtls_ssl_set_bio(&m_env->ssl, c_session, coap_sock_write,
                        coap_sock_read, NULL);
  }
#endif /* ! COAP_DISABLE_TCP */
#ifdef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
  coap_mbedtls_context_t *m_context =
      ((coap_mbedtls_context_t *)c_session->context->dtls_context);
  if ((m_context->psk_pki_enabled & IS_PSK) &&
      m_env->ec_jpake) {
    const coap_bin_const_t *psk_key;

#if COAP_CLIENT_SUPPORT && COAP_SERVER_SUPPORT
    if (role == COAP_DTLS_ROLE_CLIENT) {
      psk_key = coap_get_session_client_psk_key(c_session);
    } else {
      psk_key = coap_get_session_server_psk_key(c_session);
    }
#elif COAP_CLIENT_SUPPORT
    psk_key = coap_get_session_client_psk_key(c_session);
#else /* COAP_SERVER_SUPPORT */
    psk_key = coap_get_session_server_psk_key(c_session);
#endif /* COAP_SERVER_SUPPORT */
    mbedtls_ssl_set_hs_ecjpake_password(&m_env->ssl, psk_key->s, psk_key->length);
  }
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
  mbedtls_ssl_set_timer_cb(&m_env->ssl, &m_env->timer,
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  mbedtls_ssl_conf_dbg(&m_env->conf, mbedtls_debug_out, stdout);
  return m_env;

fail:
  if (m_env) {
    mbedtls_free(m_env);
  }
  return NULL;
}

int
coap_dtls_is_supported(void) {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
  return 1;
#else /* !MBEDTLS_SSL_PROTO_DTLS */
  static int reported = 0;
  if (!reported) {
    reported = 1;
    coap_log_emerg("libcoap not compiled for DTLS with Mbed TLS"
                   " - update Mbed TLS to include DTLS\n");
  }
  return 0;
#endif /* !MBEDTLS_SSL_PROTO_DTLS */
}

int
coap_tls_is_supported(void) {
#if !COAP_DISABLE_TCP
  return 1;
#else /* COAP_DISABLE_TCP */
  return 0;
#endif /* COAP_DISABLE_TCP */
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_psk_is_supported(void) {
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pki_is_supported(void) {
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pkcs11_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_rpk_is_supported(void) {
  return 0;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_cid_is_supported(void) {
#ifdef MBEDTLS_SSL_DTLS_CONNECTION_ID
  return 1;
#else /* ! MBEDTLS_SSL_DTLS_CONNECTION_ID */
  return 0;
#endif /* ! MBEDTLS_SSL_DTLS_CONNECTION_ID */
}

#if COAP_CLIENT_SUPPORT
int
coap_dtls_set_cid_tuple_change(coap_context_t *c_context, uint8_t every) {
#ifdef MBEDTLS_SSL_DTLS_CONNECTION_ID
  c_context->testing_cids = every;
  return 1;
#else /* ! MBEDTLS_SSL_DTLS_CONNECTION_ID */
  (void)c_context;
  (void)every;
  return 0;
#endif /* ! MBEDTLS_SSL_DTLS_CONNECTION_ID */
}
#endif /* COAP_CLIENT_SUPPORT */

void *
coap_dtls_new_context(coap_context_t *c_context) {
  coap_mbedtls_context_t *m_context;
  (void)c_context;

  m_context = (coap_mbedtls_context_t *)mbedtls_malloc(sizeof(coap_mbedtls_context_t));
  if (m_context) {
    memset(m_context, 0, sizeof(coap_mbedtls_context_t));
  }
  return m_context;
}

#if COAP_SERVER_SUPPORT
/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_context_set_spsk(coap_context_t *c_context,
                           coap_dtls_spsk_t *setup_data
                          ) {
  coap_mbedtls_context_t *m_context =
      ((coap_mbedtls_context_t *)c_context->dtls_context);

#if !defined(MBEDTLS_SSL_SRV_C)
  coap_log_emerg("coap_context_set_spsk:"
                 " libcoap not compiled for Server Mode for Mbed TLS"
                 " - update Mbed TLS to include Server Mode\n");
  return 0;
#endif /* !MBEDTLS_SSL_SRV_C */
  if (!m_context || !setup_data)
    return 0;

  if (setup_data->ec_jpake) {
#ifndef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    coap_log_warn("Mbed TLS not compiled for EC-JPAKE support\n");
#endif /* ! MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
  }
  m_context->psk_pki_enabled |= IS_PSK;
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_context_set_cpsk(coap_context_t *c_context,
                           coap_dtls_cpsk_t *setup_data
                          ) {
#if !defined(MBEDTLS_SSL_CLI_C)
  (void)c_context;
  (void)setup_data;

  coap_log_emerg("coap_context_set_cpsk:"
                 " libcoap not compiled for Client Mode for Mbed TLS"
                 " - update Mbed TLS to include Client Mode\n");
  return 0;
#else /* MBEDTLS_SSL_CLI_C */
  coap_mbedtls_context_t *m_context =
      ((coap_mbedtls_context_t *)c_context->dtls_context);

  if (!m_context || !setup_data)
    return 0;

  if (setup_data->validate_ih_call_back) {
    coap_log_warn("CoAP Client with Mbed TLS does not support Identity Hint selection\n");
  }
  if (setup_data->ec_jpake) {
#ifndef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    coap_log_warn("Mbed TLS not compiled for EC-JPAKE support\n");
#endif /* ! MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
  }
  if (setup_data->use_cid) {
#ifndef MBEDTLS_SSL_DTLS_CONNECTION_ID
    coap_log_warn("Mbed TLS not compiled for Connection-ID support\n");
#endif /* ! MBEDTLS_SSL_DTLS_CONNECTION_ID */
  }
  m_context->psk_pki_enabled |= IS_PSK;
  return 1;
#endif /* MBEDTLS_SSL_CLI_C */
}
#endif /* COAP_CLIENT_SUPPORT */

int
coap_dtls_context_set_pki(coap_context_t *c_context,
                          const coap_dtls_pki_t *setup_data,
                          const coap_dtls_role_t role COAP_UNUSED) {
  coap_mbedtls_context_t *m_context =
      ((coap_mbedtls_context_t *)c_context->dtls_context);

  m_context->setup_data = *setup_data;
  if (!m_context->setup_data.verify_peer_cert) {
    /* Needs to be clear so that no CA DNs are transmitted */
    m_context->setup_data.check_common_ca = 0;
    /* Allow all of these but warn if issue */
    m_context->setup_data.allow_self_signed = 1;
    m_context->setup_data.allow_expired_certs = 1;
    m_context->setup_data.cert_chain_validation = 1;
    m_context->setup_data.cert_chain_verify_depth = 10;
    m_context->setup_data.check_cert_revocation = 1;
    m_context->setup_data.allow_no_crl = 1;
    m_context->setup_data.allow_expired_crl = 1;
    m_context->setup_data.allow_bad_md_hash = 1;
    m_context->setup_data.allow_short_rsa_length = 1;
  }
  m_context->psk_pki_enabled |= IS_PKI;
  if (setup_data->use_cid) {
#ifndef MBEDTLS_SSL_DTLS_CONNECTION_ID
    coap_log_warn("Mbed TLS not compiled for Connection-ID support\n");
#endif /* ! MBEDTLS_SSL_DTLS_CONNECTION_ID */
  }
  return 1;
}

int
coap_dtls_context_set_pki_root_cas(coap_context_t *c_context,
                                   const char *ca_file,
                                   const char *ca_path) {
  coap_mbedtls_context_t *m_context =
      ((coap_mbedtls_context_t *)c_context->dtls_context);

  if (!m_context) {
    coap_log_warn("coap_context_set_pki_root_cas: (D)TLS environment "
                  "not set up\n");
    return 0;
  }

  if (ca_file == NULL && ca_path == NULL) {
    coap_log_warn("coap_context_set_pki_root_cas: ca_file and/or ca_path "
                  "not defined\n");
    return 0;
  }
  if (m_context->root_ca_file) {
    mbedtls_free(m_context->root_ca_file);
    m_context->root_ca_file = NULL;
  }

  if (ca_file) {
    m_context->root_ca_file = mbedtls_strdup(ca_file);
  }

  if (m_context->root_ca_path) {
    mbedtls_free(m_context->root_ca_path);
    m_context->root_ca_path = NULL;
  }

  if (ca_path) {
    m_context->root_ca_path = mbedtls_strdup(ca_path);
  }
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_context_load_pki_trust_store(coap_context_t *c_context) {
  coap_mbedtls_context_t *m_context =
      ((coap_mbedtls_context_t *)c_context->dtls_context);

  if (!m_context) {
    coap_log_warn("coap_context_load_pki_trust_store: (D)TLS environment "
                  "not set up\n");
    return 0;
  }
  m_context->trust_store_defined = 1;

  /* No proper support for this in MbedTLS at this point */
  return 1;
}


int
coap_dtls_context_check_keys_enabled(coap_context_t *c_context) {
  coap_mbedtls_context_t *m_context =
      ((coap_mbedtls_context_t *)c_context->dtls_context);
  return m_context->psk_pki_enabled ? 1 : 0;
}

void
coap_dtls_free_context(void *dtls_context) {
  coap_mbedtls_context_t *m_context = (coap_mbedtls_context_t *)dtls_context;
  unsigned int i;

  for (i = 0; i < m_context->pki_sni_count; i++) {
    mbedtls_free(m_context->pki_sni_entry_list[i].sni);

    mbedtls_x509_crt_free(&m_context->pki_sni_entry_list[i].public_cert);

    mbedtls_pk_free(&m_context->pki_sni_entry_list[i].private_key);

    mbedtls_x509_crt_free(&m_context->pki_sni_entry_list[i].cacert);
  }
  if (m_context->pki_sni_entry_list)
    mbedtls_free(m_context->pki_sni_entry_list);

  for (i = 0; i < m_context->psk_sni_count; i++) {
    mbedtls_free(m_context->psk_sni_entry_list[i].sni);
  }
  if (m_context->psk_sni_entry_list)
    mbedtls_free(m_context->psk_sni_entry_list);

  if (m_context->root_ca_path)
    mbedtls_free(m_context->root_ca_path);
  if (m_context->root_ca_file)
    mbedtls_free(m_context->root_ca_file);

  mbedtls_free(m_context);
}

#if COAP_CLIENT_SUPPORT
void *
coap_dtls_new_client_session(coap_session_t *c_session) {
#if !defined(MBEDTLS_SSL_CLI_C)
  (void)c_session;
  coap_log_emerg("coap_dtls_new_client_session:"
                 " libcoap not compiled for Client Mode for Mbed TLS"
                 " - update Mbed TLS to include Client Mode\n");
  return NULL;
#else /* MBEDTLS_SSL_CLI_C */
  coap_mbedtls_env_t *m_env = coap_dtls_new_mbedtls_env(c_session,
                                                        COAP_DTLS_ROLE_CLIENT,
                                                        COAP_PROTO_DTLS);
  int ret;

  if (m_env) {
    coap_tick_t now;

    coap_ticks(&now);
    m_env->last_timeout = now;
    ret = do_mbedtls_handshake(c_session, m_env);
    if (ret == -1) {
      coap_dtls_free_mbedtls_env(m_env);
      return NULL;
    }
  }
  return m_env;
#endif /* MBEDTLS_SSL_CLI_C */
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_dtls_new_server_session(coap_session_t *c_session) {
#if !defined(MBEDTLS_SSL_SRV_C)
  (void)c_session;
  coap_log_emerg("coap_dtls_new_server_session:"
                 " libcoap not compiled for Server Mode for Mbed TLS"
                 " - update Mbed TLS to include Server Mode\n");
  return NULL;
#else /* MBEDTLS_SSL_SRV_C */
  coap_mbedtls_env_t *m_env =
      (coap_mbedtls_env_t *)c_session->tls;
  if (m_env) {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if MBEDTLS_VERSION_NUMBER >= 0x02100100
    mbedtls_ssl_set_mtu(&m_env->ssl, (uint16_t)c_session->mtu);
#endif /* MBEDTLS_VERSION_NUMBER >= 0x02100100 */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
  }
  return m_env;
#endif /* MBEDTLS_SSL_SRV_C */
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_dtls_free_session(coap_session_t *c_session) {
  if (c_session && c_session->context && c_session->tls) {
    coap_dtls_free_mbedtls_env(c_session->tls);
    c_session->tls = NULL;
    coap_handle_event_lkd(c_session->context, COAP_EVENT_DTLS_CLOSED, c_session);
  }
  return;
}

void
coap_dtls_session_update_mtu(coap_session_t *c_session) {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
  coap_mbedtls_env_t *m_env =
      (coap_mbedtls_env_t *)c_session->tls;
  if (m_env) {
#if MBEDTLS_VERSION_NUMBER >= 0x02100100
    mbedtls_ssl_set_mtu(&m_env->ssl, (uint16_t)c_session->mtu);
#endif /* MBEDTLS_VERSION_NUMBER >= 0x02100100 */
  }
#else /* ! MBEDTLS_SSL_PROTO_DTLS */
  (void)c_session;
#endif /* MBEDTLS_SSL_PROTO_DTLS */
}

ssize_t
coap_dtls_send(coap_session_t *c_session,
               const uint8_t *data, size_t data_len) {
  int ret;
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;

  assert(m_env != NULL);

  if (!m_env) {
    return -1;
  }
  c_session->dtls_event = -1;
  coap_log_debug("*  %s: dtls:  sent %4d bytes\n",
                 coap_session_str(c_session), (int)data_len);
  if (m_env->established) {
    ret = mbedtls_ssl_write(&m_env->ssl, (const unsigned char *) data, data_len);
    if (ret <= 0) {
      switch (ret) {
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        ret = 0;
        break;
      case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
        c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
        ret = -1;
        break;
      default:
        coap_log_warn("coap_dtls_send: "
                      "returned -0x%x: '%s'\n",
                      -ret, get_error_string(ret));
        ret = -1;
        break;
      }
      if (ret == -1) {
        coap_log_warn("coap_dtls_send: cannot send PDU\n");
      }
    }
  } else {
    ret = do_mbedtls_handshake(c_session, m_env);
    if (ret == 1) {
      /* Just connected, so send the data */
      return coap_dtls_send(c_session, data, data_len);
    }
    ret = -1;
  }

  if (c_session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
    if (c_session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event_lkd(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(c_session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }
  return ret;
}

int
coap_dtls_is_context_timeout(void) {
  return 0;
}

coap_tick_t
coap_dtls_get_context_timeout(void *dtls_context COAP_UNUSED) {
  return 0;
}

coap_tick_t
coap_dtls_get_timeout(coap_session_t *c_session, coap_tick_t now) {
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;
  int ret = mbedtls_timing_get_delay(&m_env->timer);
  unsigned int scalar = 1 << m_env->retry_scalar;

  assert(c_session->state == COAP_SESSION_STATE_HANDSHAKE);
  switch (ret) {
  case 0:
    /* int_ms has not timed out */
    if (m_env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS * scalar > now) {
      /* Need to indicate remaining timeout time */
      return m_env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS * scalar;
    }
    m_env->last_timeout = now;
    /* This may cause a minor extra delay */
    return now + COAP_DTLS_RETRANSMIT_COAP_TICKS * scalar;
  case 1:
    /* int_ms has timed out, but not fin_ms */
    /*
     * Need to make sure that we do not do this too frequently
     */
    if (m_env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS * scalar > now) {
      return m_env->last_timeout + COAP_DTLS_RETRANSMIT_COAP_TICKS * scalar;
    }

    /* Reset for the next time */
    m_env->last_timeout = now;
    return now;
  case 2:
    /* fin_ms has timed out - timed out  - one final try */
    return now;
  default:
    break;
  }

  return 0;
}

/*
 * return 1 timed out
 *        0 still timing out
 */
int
coap_dtls_handle_timeout(coap_session_t *c_session) {
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;

  assert(m_env != NULL && c_session->state == COAP_SESSION_STATE_HANDSHAKE);
  m_env->retry_scalar++;
  if ((++c_session->dtls_timeout_count > c_session->max_retransmit) ||
      (do_mbedtls_handshake(c_session, m_env) < 0)) {
    /* Too many retries */
    coap_session_disconnected_lkd(c_session, COAP_NACK_TLS_FAILED);
    return 1;
  }
  return 0;
}

/*
 * return +ve data amount
 *          0 no more
 *         -1 error
 */
int
coap_dtls_receive(coap_session_t *c_session,
                  const uint8_t *data,
                  size_t data_len) {
  int ret = 1;

  c_session->dtls_event = -1;
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;
  coap_ssl_t *ssl_data;

  assert(m_env != NULL);

  ssl_data = &m_env->coap_ssl_data;
  if (ssl_data->pdu_len) {
    coap_log_err("** %s: Previous data not read %u bytes\n",
                 coap_session_str(c_session), ssl_data->pdu_len);
  }
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  if (m_env->established) {
#if COAP_CONSTRAINED_STACK
    /* pdu can be protected by global_lock if needed */
    static uint8_t pdu[COAP_RXBUFFER_SIZE];
#else /* ! COAP_CONSTRAINED_STACK */
    uint8_t pdu[COAP_RXBUFFER_SIZE];
#endif /* ! COAP_CONSTRAINED_STACK */

    if (c_session->state == COAP_SESSION_STATE_HANDSHAKE) {
      coap_handle_event_lkd(c_session->context, COAP_EVENT_DTLS_CONNECTED,
                            c_session);
      c_session->sock.lfunc[COAP_LAYER_TLS].l_establish(c_session);
    }

    ret = mbedtls_ssl_read(&m_env->ssl, pdu, sizeof(pdu));
    if (ret > 0) {
      coap_log_debug("*  %s: dtls:  recv %4d bytes\n",
                     coap_session_str(c_session), ret);
      ret = coap_handle_dgram(c_session->context, c_session, pdu, (size_t)ret);
      goto finish;
    }
    switch (ret) {
    case 0:
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
    case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
      c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      break;
    case MBEDTLS_ERR_SSL_WANT_READ:
      break;
    default:
      coap_log_warn("coap_dtls_receive: "
                    "returned -0x%x: '%s' (length %zd)\n",
                    -ret, get_error_string(ret), data_len);
      break;
    }
    ret = -1;
  } else {
    ret = do_mbedtls_handshake(c_session, m_env);
    if (ret == 1) {
      /* Just connected, so send the data */
      coap_session_connected(c_session);
    } else {
      if (ssl_data->pdu_len) {
        /* Do the handshake again incase of internal timeout */
        ret = do_mbedtls_handshake(c_session, m_env);
        if (ret == 1) {
          /* Just connected, so send the data */
          coap_session_connected(c_session);
        }
      }
      ret = -1;
    }
  }
  if (c_session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
    if (c_session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event_lkd(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(c_session, COAP_NACK_TLS_FAILED);
      ssl_data = NULL;
      ret = -1;
    }
  }
finish:
  if (ssl_data && ssl_data->pdu_len) {
    /* pdu data is held on stack which will not stay there */
    coap_log_debug("coap_dtls_receive: ret %d: remaining data %u\n", ret, ssl_data->pdu_len);
    ssl_data->pdu_len = 0;
    ssl_data->pdu = NULL;
  }
  return ret;
}

#if COAP_SERVER_SUPPORT
/*
 * return -1  failure
 *         0  not completed
 *         1  client hello seen
 */
int
coap_dtls_hello(coap_session_t *c_session,
                const uint8_t *data,
                size_t data_len) {
#if !defined(MBEDTLS_SSL_PROTO_DTLS) || !defined(MBEDTLS_SSL_SRV_C)
  (void)c_session;
  (void)data;
  (void)data_len;
  coap_log_emerg("coap_dtls_hello:"
                 " libcoap not compiled for DTLS or Server Mode for Mbed TLS"
                 " - update Mbed TLS to include DTLS and Server Mode\n");
  return -1;
#else /* MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_SRV_C */
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;
  coap_ssl_t *ssl_data;
  int ret;

  if (!m_env) {
    m_env = coap_dtls_new_mbedtls_env(c_session, COAP_DTLS_ROLE_SERVER,
                                      COAP_PROTO_DTLS);
    if (m_env) {
      c_session->tls = m_env;
    } else {
      /* error should have already been reported */
      return -1;
    }
  }

  if ((ret = mbedtls_ssl_set_client_transport_id(&m_env->ssl,
                                                 (unsigned char *)&c_session->addr_info.remote,
                                                 sizeof(c_session->addr_info.remote))) != 0) {
    coap_log_err("mbedtls_ssl_set_client_transport_id() returned -0x%x: '%s'\n",
                 -ret, get_error_string(ret));
    return -1;
  }

  ssl_data = &m_env->coap_ssl_data;
  if (ssl_data->pdu_len) {
    coap_log_err("** %s: Previous data not read %u bytes\n",
                 coap_session_str(c_session), ssl_data->pdu_len);
  }
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  ret = do_mbedtls_handshake(c_session, m_env);
  if (ret == 0 || m_env->seen_client_hello) {
    /* The test for seen_client_hello gives the ability to setup a new
       c_session to continue the do_mbedtls_handshake past the client hello
       and safely allow updating of the m_env and separately
       letting a new session cleanly start up.
     */
    m_env->seen_client_hello = 0;
    ret = 1;
  } else {
    ret = 0;
  }

  if (ssl_data->pdu_len) {
    /* pdu data is held on stack which will not stay there */
    coap_log_debug("coap_dtls_hello: ret %d: remaining data %u\n", ret, ssl_data->pdu_len);
    ssl_data->pdu_len = 0;
    ssl_data->pdu = NULL;
  }
  return ret;
#endif /* MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_SSL_SRV_C */
}
#endif /* COAP_SERVER_SUPPORT */

unsigned int
coap_dtls_get_overhead(coap_session_t *c_session) {
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;
  int expansion = mbedtls_ssl_get_record_expansion(&m_env->ssl);

  if (expansion == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE) {
    return 13 + 8 + 8;
  }
  return expansion;
}

#if !COAP_DISABLE_TCP
#if COAP_CLIENT_SUPPORT
void *
coap_tls_new_client_session(coap_session_t *c_session) {
#if !defined(MBEDTLS_SSL_CLI_C)
  (void)c_session;
  *connected = 0;
  coap_log_emerg("coap_tls_new_client_session:"
                 " libcoap not compiled for Client Mode for Mbed TLS"
                 " - update Mbed TLS to include Client Mode\n");
  return NULL;
#else /* MBEDTLS_SSL_CLI_C */
  coap_mbedtls_env_t *m_env = coap_dtls_new_mbedtls_env(c_session,
                                                        COAP_DTLS_ROLE_CLIENT,
                                                        COAP_PROTO_TLS);
  int ret;
  coap_tick_t now;
  coap_ticks(&now);

  if (!m_env)
    return NULL;

  m_env->last_timeout = now;
  c_session->tls = m_env;
  ret = do_mbedtls_handshake(c_session, m_env);
  if (ret == 1) {
    coap_handle_event_lkd(c_session->context, COAP_EVENT_DTLS_CONNECTED, c_session);
    c_session->sock.lfunc[COAP_LAYER_TLS].l_establish(c_session);
  }
  return m_env;
#endif /* MBEDTLS_SSL_CLI_C */
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_tls_new_server_session(coap_session_t *c_session) {
#if !defined(MBEDTLS_SSL_SRV_C)
  (void)c_session;
  (void)connected;

  coap_log_emerg("coap_tls_new_server_session:"
                 " libcoap not compiled for Server Mode for Mbed TLS"
                 " - update Mbed TLS to include Server Mode\n");
  return NULL;
#else /* MBEDTLS_SSL_SRV_C */
  coap_mbedtls_env_t *m_env = coap_dtls_new_mbedtls_env(c_session,
                                                        COAP_DTLS_ROLE_SERVER,
                                                        COAP_PROTO_TLS);
  int ret;

  if (!m_env)
    return NULL;

  c_session->tls = m_env;
  ret = do_mbedtls_handshake(c_session, m_env);
  if (ret == 1) {
    coap_handle_event_lkd(c_session->context, COAP_EVENT_DTLS_CONNECTED, c_session);
    c_session->sock.lfunc[COAP_LAYER_TLS].l_establish(c_session);
  }
  return m_env;
#endif /* MBEDTLS_SSL_SRV_C */
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_tls_free_session(coap_session_t *c_session) {
  coap_dtls_free_session(c_session);
  return;
}

/*
 * strm
 * return +ve Number of bytes written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_write(coap_session_t *c_session, const uint8_t *data,
               size_t data_len) {
  int ret = 0;
  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;
  size_t amount_sent = 0;

  assert(m_env != NULL);

  if (!m_env) {
    errno = ENXIO;
    return -1;
  }
  c_session->dtls_event = -1;
  if (m_env->established) {
    while (amount_sent < data_len) {
      ret = mbedtls_ssl_write(&m_env->ssl, &data[amount_sent],
                              data_len - amount_sent);
      if (ret <= 0) {
        switch (ret) {
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
          if (amount_sent)
            ret = amount_sent;
          else
            ret = 0;
          c_session->sock.flags |= COAP_SOCKET_WANT_WRITE;
          break;
        case MBEDTLS_ERR_NET_CONN_RESET:
        case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
          c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
          break;
        default:
          coap_log_warn("coap_tls_write: "
                        "returned -0x%x: '%s'\n",
                        -ret, get_error_string(ret));
          ret = -1;
          break;
        }
        if (ret == -1) {
          coap_log_warn("coap_tls_write: cannot send PDU\n");
        }
        break;
      }
      amount_sent += ret;
    }
  } else {
    ret = do_mbedtls_handshake(c_session, m_env);
    if (ret == 1) {
      coap_handle_event_lkd(c_session->context, COAP_EVENT_DTLS_CONNECTED,
                            c_session);
      c_session->sock.lfunc[COAP_LAYER_TLS].l_establish(c_session);
    } else {
      ret = -1;
    }
  }

  if (c_session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
    if (c_session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event_lkd(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(c_session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }
  if (ret > 0) {
    if (ret == (ssize_t)data_len)
      coap_log_debug("*  %s: tls:   sent %4d bytes\n",
                     coap_session_str(c_session), ret);
    else
      coap_log_debug("*  %s: tls:   sent %4d of %4zd bytes\n",
                     coap_session_str(c_session), ret, data_len);
  }
  return ret;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_read(coap_session_t *c_session, uint8_t *data, size_t data_len) {
  int ret = -1;

  coap_mbedtls_env_t *m_env = (coap_mbedtls_env_t *)c_session->tls;

  if (!m_env) {
    errno = ENXIO;
    return -1;
  }

  c_session->dtls_event = -1;

  if (!m_env->established && !m_env->sent_alert) {
    ret = do_mbedtls_handshake(c_session, m_env);
    if (ret == 1) {
      coap_handle_event_lkd(c_session->context, COAP_EVENT_DTLS_CONNECTED,
                            c_session);
      c_session->sock.lfunc[COAP_LAYER_TLS].l_establish(c_session);
    }
  }

  if (c_session->state != COAP_SESSION_STATE_NONE && m_env->established) {
    ret = mbedtls_ssl_read(&m_env->ssl, data, data_len);
    if (ret <= 0) {
      switch (ret) {
      case 0:
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
        ret = -1;
        break;
      case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
        /* Stop the sending of an alert on closedown */
        m_env->sent_alert = 1;
        c_session->dtls_event = COAP_EVENT_DTLS_CLOSED;
        break;
#if MBEDTLS_VERSION_NUMBER >= 0x03060000
      case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03060000 */
      case MBEDTLS_ERR_SSL_WANT_READ:
        errno = EAGAIN;
        ret = 0;
        break;
      default:
        coap_log_warn("coap_tls_read: "
                      "returned -0x%x: '%s' (length %zd)\n",
                      -ret, get_error_string(ret), data_len);
        ret = -1;
        break;
      }
    } else if (ret < (int)data_len) {
      c_session->sock.flags &= ~COAP_SOCKET_CAN_READ;
    }
  }

  if (c_session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected_lkd() */
    if (c_session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event_lkd(c_session->context, c_session->dtls_event, c_session);
    if (c_session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        c_session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected_lkd(c_session, COAP_NACK_TLS_FAILED);
      ret = -1;
    }
  }
  if (ret > 0) {
    coap_log_debug("*  %s: tls:   recv %4d bytes\n",
                   coap_session_str(c_session), ret);
  }
  return ret;
}
#endif /* !COAP_DISABLE_TCP */

void
coap_dtls_startup(void) {
}

void
coap_dtls_shutdown(void) {
#if COAP_CLIENT_SUPPORT
  mbedtls_free(psk_ciphers);
  mbedtls_free(pki_ciphers);
  mbedtls_free(ecjpake_ciphers);
  psk_ciphers = NULL;
  pki_ciphers = NULL;
  ecjpake_ciphers = NULL;
  processed_ciphers = 0;
#endif /* COAP_CLIENT_SUPPORT */
  coap_dtls_set_log_level(COAP_LOG_EMERG);
}

void *
coap_dtls_get_tls(const coap_session_t *c_session,
                  coap_tls_library_t *tls_lib) {
  if (tls_lib)
    *tls_lib = COAP_TLS_LIBRARY_MBEDTLS;
  if (c_session && c_session->tls) {
    coap_mbedtls_env_t *m_env;

    /* To get around const issue */
    memcpy(&m_env, &c_session->tls, sizeof(m_env));

    return (void *)&m_env->ssl;
  }
  return NULL;
}

static coap_log_t keep_log_level = COAP_LOG_EMERG;

void
coap_dtls_set_log_level(coap_log_t level) {
#if !defined(ESPIDF_VERSION)
  int use_level;
  /*
   * Mbed TLS debug levels filter
   *  0 No debug
   *  1 Error
   *  2 State change
   *  3 Informational
   *  4 Verbose
   */
  switch ((int)level) {
  case COAP_LOG_EMERG:
    use_level = 0;
    break;
  case COAP_LOG_ALERT:
  case COAP_LOG_CRIT:
  case COAP_LOG_ERR:
  case COAP_LOG_WARN:
    use_level = 1;
    break;
  case COAP_LOG_NOTICE:
    use_level = 2;
    break;
  case COAP_LOG_INFO:
    use_level = 3;
    break;
  case COAP_LOG_DEBUG:
  default:
    use_level = 4;
    break;
  }
  mbedtls_debug_set_threshold(use_level);
#endif /* !ESPIDF_VERSION) */
  keep_log_level = level;
}

coap_log_t
coap_dtls_get_log_level(void) {
  return keep_log_level;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = mbedtls_version_get_number();
  version.built_version = MBEDTLS_VERSION_NUMBER;
  version.type = COAP_TLS_LIBRARY_MBEDTLS;
  return &version;
}

#if COAP_SERVER_SUPPORT
coap_digest_ctx_t *
coap_digest_setup(void) {
  mbedtls_sha256_context *digest_ctx = mbedtls_malloc(sizeof(mbedtls_sha256_context));

  if (digest_ctx) {
    mbedtls_sha256_init(digest_ctx);
#ifdef MBEDTLS_2_X_COMPAT
    if (mbedtls_sha256_starts_ret(digest_ctx, 0) != 0) {
#else
    if (mbedtls_sha256_starts(digest_ctx, 0) != 0) {
#endif /* MBEDTLS_2_X_COMPAT */
      coap_digest_free(digest_ctx);
      return NULL;
    }
  }
  return digest_ctx;
}

void
coap_digest_free(coap_digest_ctx_t *digest_ctx) {
  if (digest_ctx) {
    mbedtls_sha256_free(digest_ctx);
    mbedtls_free(digest_ctx);
  }
}

int
coap_digest_update(coap_digest_ctx_t *digest_ctx,
                   const uint8_t *data,
                   size_t data_len) {
#ifdef MBEDTLS_2_X_COMPAT
  int ret = mbedtls_sha256_update_ret(digest_ctx, data, data_len);
#else
  int ret = mbedtls_sha256_update(digest_ctx, data, data_len);
#endif /* MBEDTLS_2_X_COMPAT */

  return ret == 0;
}

int
coap_digest_final(coap_digest_ctx_t *digest_ctx,
                  coap_digest_t *digest_buffer) {
#ifdef MBEDTLS_2_X_COMPAT
  int ret = mbedtls_sha256_finish_ret(digest_ctx, (uint8_t *)digest_buffer);
#else
  int ret = mbedtls_sha256_finish(digest_ctx, (uint8_t *)digest_buffer);
#endif /* MBEDTLS_2_X_COMPAT */

  coap_digest_free(digest_ctx);
  return ret == 0;
}
#endif /* COAP_SERVER_SUPPORT */

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

#ifndef MBEDTLS_CIPHER_MODE_AEAD
#error need MBEDTLS_CIPHER_MODE_AEAD, please enable MBEDTLS_CCM_C
#endif /* MBEDTLS_CIPHER_MODE_AEAD */

#ifdef MBEDTLS_ERROR_C
#include <mbedtls/error.h>
#endif /* MBEDTLS_ERROR_C */

#ifdef MBEDTLS_ERROR_C
#define C(Func)                                                                \
  do {                                                                         \
    int c_tmp = (int)(Func);                                                   \
    if (c_tmp != 0) {                                                          \
      char error_buf[64];                                                      \
      mbedtls_strerror(c_tmp, error_buf, sizeof(error_buf));                   \
      coap_log_err("mbedtls: -0x%04x: %s\n", -c_tmp, error_buf);               \
      goto error;                                                              \
    }                                                                          \
  } while (0);
#else /* !MBEDTLS_ERROR_C */
#define C(Func)                                                                \
  do {                                                                         \
    int c_tmp = (int)(Func);                                                   \
    if (c_tmp != 0) {                                                          \
      coap_log_err("mbedtls: %d\n", tmp);                                      \
      goto error;                                                              \
    }                                                                          \
  } while (0);
#endif /* !MBEDTLS_ERROR_C */

#if COAP_WS_SUPPORT
/*
 * The struct hash_algs and the function get_hash_alg() are used to
 * determine which hash type to use for creating the required hash object.
 */
static struct hash_algs {
  cose_alg_t alg;
  mbedtls_md_type_t hash_type;
  size_t hash_size;
} hashs[] = {
  {COSE_ALGORITHM_SHA_1,       MBEDTLS_MD_SHA1,   20},
  {COSE_ALGORITHM_SHA_256_256, MBEDTLS_MD_SHA256, 32},
  {COSE_ALGORITHM_SHA_512,     MBEDTLS_MD_SHA512, 64},
};

static mbedtls_md_type_t
get_hash_alg(cose_alg_t alg, size_t *hash_len) {
  size_t idx;

  for (idx = 0; idx < sizeof(hashs) / sizeof(struct hash_algs); idx++) {
    if (hashs[idx].alg == alg) {
      *hash_len = hashs[idx].hash_size;
      return hashs[idx].hash_type;
    }
  }
  coap_log_debug("get_hash_alg: COSE hash %d not supported\n", alg);
  return MBEDTLS_MD_NONE;
}

int
coap_crypto_hash(cose_alg_t alg,
                 const coap_bin_const_t *data,
                 coap_bin_const_t **hash) {
  mbedtls_md_context_t ctx;
  int ret = 0;
  const mbedtls_md_info_t *md_info;
  unsigned int len;
  coap_binary_t *dummy = NULL;
  size_t hash_length;
  mbedtls_md_type_t dig_type = get_hash_alg(alg, &hash_length);

  if (dig_type == MBEDTLS_MD_NONE) {
    coap_log_debug("coap_crypto_hash: algorithm %d not supported\n", alg);
    return 0;
  }
  md_info = mbedtls_md_info_from_type(dig_type);

  len = mbedtls_md_get_size(md_info);
  if (len == 0) {
    return 0;
  }

  mbedtls_md_init(&ctx);
  C(mbedtls_md_setup(&ctx, md_info, 0));

  C(mbedtls_md_starts(&ctx));
  C(mbedtls_md_update(&ctx, (const unsigned char *)data->s, data->length));
  dummy = coap_new_binary(len);
  if (dummy == NULL)
    goto error;
  C(mbedtls_md_finish(&ctx, dummy->s));

  *hash = (coap_bin_const_t *)dummy;
  ret = 1;
error:
  mbedtls_md_free(&ctx);
  return ret;
}
#endif /* COAP_WS_SUPPORT */

#if COAP_OSCORE_SUPPORT
int
coap_oscore_is_supported(void) {
  return 1;
}

/*
 * The struct cipher_algs and the function get_cipher_alg() are used to
 * determine which cipher type to use for creating the required cipher
 * suite object.
 */
static struct cipher_algs {
  cose_alg_t alg;
  mbedtls_cipher_type_t cipher_type;
} ciphers[] = {{COSE_ALGORITHM_AES_CCM_16_64_128, MBEDTLS_CIPHER_AES_128_CCM},
  {COSE_ALGORITHM_AES_CCM_16_64_256, MBEDTLS_CIPHER_AES_256_CCM}
};

static mbedtls_cipher_type_t
get_cipher_alg(cose_alg_t alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(ciphers) / sizeof(struct cipher_algs); idx++) {
    if (ciphers[idx].alg == alg)
      return ciphers[idx].cipher_type;
  }
  coap_log_debug("get_cipher_alg: COSE cipher %d not supported\n", alg);
  return 0;
}

/*
 * The struct hmac_algs and the function get_hmac_alg() are used to
 * determine which hmac type to use for creating the required hmac
 * suite object.
 */
static struct hmac_algs {
  cose_hmac_alg_t hmac_alg;
  mbedtls_md_type_t hmac_type;
} hmacs[] = {
  {COSE_HMAC_ALG_HMAC256_256, MBEDTLS_MD_SHA256},
  {COSE_HMAC_ALG_HMAC384_384, MBEDTLS_MD_SHA384},
  {COSE_HMAC_ALG_HMAC512_512, MBEDTLS_MD_SHA512},
};

static mbedtls_md_type_t
get_hmac_alg(cose_hmac_alg_t hmac_alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(hmacs) / sizeof(struct hmac_algs); idx++) {
    if (hmacs[idx].hmac_alg == hmac_alg)
      return hmacs[idx].hmac_type;
  }
  coap_log_debug("get_hmac_alg: COSE HMAC %d not supported\n", hmac_alg);
  return 0;
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  return get_cipher_alg(alg) != 0;
}

int
coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg) {
  cose_hmac_alg_t hmac_alg;

  if (!cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg))
    return 0;
  return get_hmac_alg(hmac_alg) != 0;
}

/**
 * Initializes the cipher context @p ctx. On success, this function
 * returns true and @p ctx must be released by the caller using
 * mbedtls_ciper_free(). */
static int
setup_cipher_context(mbedtls_cipher_context_t *ctx,
                     cose_alg_t coap_alg,
                     const uint8_t *key_data,
                     size_t key_length,
                     mbedtls_operation_t mode) {
  const mbedtls_cipher_info_t *cipher_info;
  mbedtls_cipher_type_t cipher_type;
  uint8_t key[COAP_CRYPTO_MAX_KEY_SIZE]; /* buffer for normalizing the key
                                            according to its key length */
  int klen;
  memset(key, 0, sizeof(key));

  if ((cipher_type = get_cipher_alg(coap_alg)) == 0) {
    coap_log_debug("coap_crypto_encrypt: algorithm %d not supported\n",
                   coap_alg);
    return 0;
  }
  cipher_info = mbedtls_cipher_info_from_type(cipher_type);
  if (!cipher_info) {
    coap_log_crit("coap_crypto_encrypt: cannot get cipher info\n");
    return 0;
  }

  mbedtls_cipher_init(ctx);

  C(mbedtls_cipher_setup(ctx, cipher_info));
  klen = mbedtls_cipher_get_key_bitlen(ctx);
  if ((klen > (int)(sizeof(key) * 8)) || (key_length > sizeof(key))) {
    coap_log_crit("coap_crypto: cannot set key\n");
    goto error;
  }
  memcpy(key, key_data, key_length);
  C(mbedtls_cipher_setkey(ctx, key, klen, mode));

  /* On success, the cipher context is released by the caller. */
  return 1;
error:
  mbedtls_cipher_free(ctx);
  return 0;
}

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  mbedtls_cipher_context_t ctx;
  const coap_crypto_aes_ccm_t *ccm;
#if (MBEDTLS_VERSION_NUMBER < 0x02150000)
  unsigned char tag[16];
#endif /* MBEDTLS_VERSION_NUMBER < 0x02150000 */
  int ret = 0;
  size_t result_len = *max_result_len;
  coap_bin_const_t laad;

  if (data == NULL)
    return 0;

  assert(params != NULL);

  if (!params) {
    return 0;
  }
  ccm = &params->params.aes;

  if (!setup_cipher_context(&ctx,
                            params->alg,
                            ccm->key.s,
                            ccm->key.length,
                            MBEDTLS_ENCRYPT)) {
    return 0;
  }

  if (aad) {
    laad = *aad;
  } else {
    laad.s = NULL;
    laad.length = 0;
  }

#if (MBEDTLS_VERSION_NUMBER < 0x02150000)
  C(mbedtls_cipher_auth_encrypt(&ctx,
                                ccm->nonce,
                                15 - ccm->l, /* iv */
                                laad.s,
                                laad.length, /* ad */
                                data->s,
                                data->length, /* input */
                                result,
                                &result_len, /* output */
                                tag,
                                ccm->tag_len /* tag */
                               ));
  /* check if buffer is sufficient to hold tag */
  if ((result_len + ccm->tag_len) > *max_result_len) {
    coap_log_err("coap_encrypt: buffer too small\n");
    goto error;
  }
  /* append tag to result */
  memcpy(result + result_len, tag, ccm->tag_len);
  *max_result_len = result_len + ccm->tag_len;
  ret = 1;
#else /* MBEDTLS_VERSION_NUMBER >= 0x02150000 */
  C(mbedtls_cipher_auth_encrypt_ext(&ctx,
                                    ccm->nonce,
                                    15 - ccm->l, /* iv */
                                    laad.s,
                                    laad.length, /* ad */
                                    data->s,
                                    data->length, /* input */
                                    result,
                                    result_len,
                                    &result_len, /* output */
                                    ccm->tag_len /* tag */
                                   ));
  *max_result_len = result_len;
  ret = 1;
#endif /* MBEDTLS_VERSION_NUMBER >= 0x02150000 */

error:
  mbedtls_cipher_free(&ctx);
  return ret;
}

int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  mbedtls_cipher_context_t ctx;
  const coap_crypto_aes_ccm_t *ccm;
#if (MBEDTLS_VERSION_NUMBER < 0x02150000)
  const unsigned char *tag;
#endif /* MBEDTLS_VERSION_NUMBER < 0x02150000 */
  int ret = 0;
  size_t result_len = *max_result_len;
  coap_bin_const_t laad;

  if (data == NULL)
    return 0;

  assert(params != NULL);

  if (!params) {
    return 0;
  }

  ccm = &params->params.aes;

  if (!setup_cipher_context(&ctx,
                            params->alg,
                            ccm->key.s,
                            ccm->key.length,
                            MBEDTLS_DECRYPT)) {
    return 0;
  }

  if (data->length < ccm->tag_len) {
    coap_log_err("coap_decrypt: invalid tag length\n");
    goto error;
  }

  if (aad) {
    laad = *aad;
  } else {
    laad.s = NULL;
    laad.length = 0;
  }

#if (MBEDTLS_VERSION_NUMBER < 0x02150000)
  tag = data->s + data->length - ccm->tag_len;
  C(mbedtls_cipher_auth_decrypt(&ctx,
                                ccm->nonce,
                                15 - ccm->l, /* iv */
                                laad.s,
                                laad.length, /* ad */
                                data->s,
                                data->length - ccm->tag_len, /* input */
                                result,
                                &result_len, /* output */
                                tag,
                                ccm->tag_len /* tag */
                               ));
#else /* MBEDTLS_VERSION_NUMBER >= 0x02150000 */
  C(mbedtls_cipher_auth_decrypt_ext(&ctx,
                                    ccm->nonce,
                                    15 - ccm->l, /* iv */
                                    laad.s,
                                    laad.length, /* ad */
                                    data->s,
                                    //     data->length - ccm->tag_len, /* input */
                                    data->length, /* input */
                                    result,
                                    result_len,
                                    &result_len, /* output */
                                    ccm->tag_len /* tag */
                                   ));
#endif /* MBEDTLS_VERSION_NUMBER >= 0x02150000 */

  *max_result_len = result_len;
  ret = 1;
error:
  mbedtls_cipher_free(&ctx);
  return ret;
}

int
coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  mbedtls_md_context_t ctx;
  int ret = 0;
  const int use_hmac = 1;
  const mbedtls_md_info_t *md_info;
  mbedtls_md_type_t mac_algo;
  unsigned int len;
  coap_binary_t *dummy = NULL;

  assert(key);
  assert(data);
  assert(hmac);

  if ((mac_algo = get_hmac_alg(hmac_alg)) == 0) {
    coap_log_debug("coap_crypto_hmac: algorithm %d not supported\n", hmac_alg);
    return 0;
  }
  md_info = mbedtls_md_info_from_type(mac_algo);

  len = mbedtls_md_get_size(md_info);
  if (len == 0) {
    return 0;
  }

  mbedtls_md_init(&ctx);
  C(mbedtls_md_setup(&ctx, md_info, use_hmac));

  C(mbedtls_md_hmac_starts(&ctx, key->s, key->length));
  C(mbedtls_md_hmac_update(&ctx, (const unsigned char *)data->s, data->length));
  dummy = coap_new_binary(len);
  if (dummy == NULL)
    goto error;
  C(mbedtls_md_hmac_finish(&ctx, dummy->s));

  *hmac = (coap_bin_const_t *)dummy;
  ret = 1;
error:
  mbedtls_md_free(&ctx);
  return ret;
}

#endif /* COAP_OSCORE_SUPPORT */

#else /* !COAP_WITH_LIBMBEDTLS */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* COAP_WITH_LIBMBEDTLS */
