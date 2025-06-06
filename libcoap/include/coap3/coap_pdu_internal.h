/*
 * coap_pdu_internal.h -- CoAP PDU structure
 *
 * Copyright (C) 2010-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_pdu_internal.h
 * @brief CoAP PDU internal information
 */

#ifndef COAP_COAP_PDU_INTERNAL_H_
#define COAP_COAP_PDU_INTERNAL_H_

#include "coap_internal.h"

#ifdef WITH_LWIP
#include <lwip/pbuf.h>
#endif

#ifdef RIOT_VERSION
#include <limits.h>
#endif /* RIOT_VERSION */

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */

#include <stdint.h>

/**
 * @ingroup internal_api
 * @defgroup pdu_internal PDU
 * Internal API for PDUs
 * @{
 */

#define COAP_DEFAULT_VERSION      1 /* version of CoAP supported */

/* TCP Message format constants, do not modify */
#define COAP_MESSAGE_SIZE_OFFSET_TCP8 13
#define COAP_MESSAGE_SIZE_OFFSET_TCP16 269 /* 13 + 256 */
#define COAP_MESSAGE_SIZE_OFFSET_TCP32 65805 /* 269 + 65536 */

/* Derived message size limits */
#define COAP_MAX_MESSAGE_SIZE_TCP0 (COAP_MESSAGE_SIZE_OFFSET_TCP8-1) /* 12 */
#define COAP_MAX_MESSAGE_SIZE_TCP8 (COAP_MESSAGE_SIZE_OFFSET_TCP16-1) /* 268 */
#define COAP_MAX_MESSAGE_SIZE_TCP16 (COAP_MESSAGE_SIZE_OFFSET_TCP32-1) /* 65804 */
#define COAP_MAX_MESSAGE_SIZE_TCP32 (COAP_MESSAGE_SIZE_OFFSET_TCP32+0xFFFFFFFF)
#if COAP_OSCORE_SUPPORT
/* for oscore encryption   */
#define COAP_MAX_CHUNK_SIZE COAP_DEFAULT_MAX_PDU_RX_SIZE
#define OSCORE_CRYPTO_BUFFER_SIZE (COAP_MAX_CHUNK_SIZE+16)
#endif /* COAP_OSCORE_SUPPORT  */

/* Extended Token constants */
#define COAP_TOKEN_EXT_1B_TKL 13
#define COAP_TOKEN_EXT_2B_TKL 14
#define COAP_TOKEN_EXT_1B_BIAS 13
#define COAP_TOKEN_EXT_2B_BIAS 269 /* 13 + 256 */

#ifndef COAP_DEBUG_BUF_SIZE
#if defined(WITH_CONTIKI) || defined(WITH_LWIP)
#define COAP_DEBUG_BUF_SIZE 128
#else /* defined(WITH_CONTIKI) || defined(WITH_LWIP) */
/* 1024 derived from RFC7252 4.6.  Message Size max payload */
#define COAP_DEBUG_BUF_SIZE (8 + 1024 * 2)
#endif /* defined(WITH_CONTIKI) || defined(WITH_LWIP) */
#endif /* COAP_DEBUG_BUF_SIZE */

#ifndef COAP_DEFAULT_MAX_PDU_RX_SIZE
#if defined(WITH_LWIP)
#define COAP_DEFAULT_MAX_PDU_RX_SIZE (COAP_MAX_MESSAGE_SIZE_TCP16+4UL)
#elif defined(WITH_CONTIKI)
#define COAP_DEFAULT_MAX_PDU_RX_SIZE (UIP_APPDATA_SIZE)
#elif (UINT_MAX < (8UL*1024*1024+256))
#define COAP_DEFAULT_MAX_PDU_RX_SIZE (1500UL)
#elif defined(RIOT_VERSION) && defined(COAP_DISABLE_TCP)
#define COAP_DEFAULT_MAX_PDU_RX_SIZE (1500UL)
#else
/* 8 MiB max-message-size plus some space for options */
#define COAP_DEFAULT_MAX_PDU_RX_SIZE (8UL*1024*1024+256)
#endif
#endif /* COAP_DEFAULT_MAX_PDU_RX_SIZE */

/**
 * Indicates that a response is suppressed. This will occur for error
 * responses if the request was received via IP multicast.
 */
#define COAP_DROPPED_RESPONSE -2

#define COAP_PDU_DELAYED -3

#define COAP_PAYLOAD_START 0xFF /* payload marker */

#define COAP_PDU_IS_EMPTY(pdu)     ((pdu)->code == 0)
#define COAP_PDU_IS_REQUEST(pdu)   (!COAP_PDU_IS_EMPTY(pdu) && (pdu)->code < 32)
/* Code 1.xx (32-63) and 6.xx (192-224) currently invalid */
#define COAP_PDU_IS_RESPONSE(pdu)  ((pdu)->code >= 64 && (pdu)->code < 192)
#define COAP_PDU_IS_SIGNALING(pdu) ((pdu)->code >= 224)
#define COAP_PDU_IS_PING(pdu)      ((COAP_PDU_IS_EMPTY(pdu) && \
                                     ((pdu)->type == COAP_MESSAGE_CON)) || \
                                    ((pdu)->code == COAP_SIGNALING_CODE_PING))

#define COAP_PDU_MAX_UDP_HEADER_SIZE 4
#define COAP_PDU_MAX_TCP_HEADER_SIZE 6

/**
 * structure for CoAP PDUs
 *
 * Separate COAP_PDU_BUF is allocated with offsets held in coap_pdu_t.

 * token, if any, follows the fixed size header, then optional options until
 * payload marker (0xff) (if paylooad), then the optional payload.
 *
 * Memory layout is:
 * <---header--->|<---token---><---options--->0xff<---payload--->
 *
 * header is addressed with a negative offset to token, its maximum size is
 * max_hdr_size.
 *
 * allocated buffer always starts max_hdr_size before token.
 *
 * options starts at token + e_token_length.
 * payload starts at data, its length is used_size - (data - token).
 *
 * alloc_size, used_size and max_size are the offsets from token.
 */

struct coap_pdu_t {
  coap_pdu_type_t type;     /**< message type */
  coap_pdu_code_t code;     /**< request method (value 1--31) or response code
                                 (value 64-255) */
  coap_mid_t mid;           /**< message id, if any, in regular host byte
                                 order */
  uint8_t max_hdr_size;     /**< space reserved for protocol-specific header */
  uint8_t hdr_size;         /**< actual size used for protocol-specific
                                 header (0 until header is encoded) */
  uint8_t crit_opt;         /**< Set if unknown critical option for proxy */
  uint16_t max_opt;         /**< highest option number in PDU */
  uint32_t e_token_length;  /**< length of Token space (includes leading
                                 extended bytes */
  unsigned ref;             /**< reference count */
  coap_bin_const_t actual_token; /**< Actual token in pdu */
  size_t alloc_size;        /**< allocated storage for token, options and
                                 payload */
  size_t used_size;         /**< used bytes of storage for token, options and
                                 payload */
  size_t max_size;          /**< maximum size for token, options and payload,
                                 or zero for variable size pdu */
  uint8_t *token;           /**< first byte of token (or extended length bytes
                                 prefix), if any, or options */
  uint8_t *data;            /**< first byte of payload, if any */
#ifdef WITH_LWIP
  struct pbuf *pbuf;        /**< lwIP PBUF. The package data will always reside
                             *   inside the pbuf's payload, but this pointer
                             *   has to be kept because no exact offset can be
                             *   given. This field must not be accessed from
                             *   outside, because the pbuf's reference count
                             *   is checked to be 1 when the pbuf is assigned
                             *   to the pdu, and the pbuf stays exclusive to
                             *   this pdu. */
#endif
  const uint8_t *body_data; /**< Holds ptr to re-assembled data or NULL. This
                                 does not get released by coap_delete_pdu() */
  size_t body_length;       /**< Holds body data length */
  size_t body_offset;       /**< Holds body data offset */
  size_t body_total;        /**< Holds body data total size */
  coap_lg_xmit_t *lg_xmit;  /**< Holds ptr to lg_xmit if sending a set of
                                 blocks */
  coap_session_t *session;  /**< Session responsible for PDU or NULL */
  coap_binary_t *data_free; /**< Data to be freed off by coap_delete_pdu() */
};

/**
 * Dynamically grows the size of @p pdu to @p new_size. The new size
 * must not exceed the PDU's configure maximum size. On success, this
 * function returns 1, otherwise 0.
 *
 * @param pdu      The PDU to resize.
 * @param new_size The new size in bytes.
 * @return         1 if the operation succeeded, 0 otherwise.
 */
int coap_pdu_resize(coap_pdu_t *pdu, size_t new_size);

/**
 * Dynamically grows the size of @p pdu to @p new_size if needed. The new size
 * must not exceed the PDU's configured maximum size. On success, this
 * function returns 1, otherwise 0.
 *
 * @param pdu      The PDU to resize.
 * @param new_size The new size in bytes.
 * @return         1 if the operation succeeded, 0 otherwise.
 */
int coap_pdu_check_resize(coap_pdu_t *pdu, size_t new_size);

/**
* Interprets @p data to determine the number of bytes in the header.
* This function returns @c 0 on error or a number greater than zero on success.
*
* @param proto  Session's protocol
* @param data   The first byte of raw data to parse as CoAP PDU.
*
* @return       A value greater than zero on success or @c 0 on error.
*/
size_t coap_pdu_parse_header_size(coap_proto_t proto,
                                  const uint8_t *data);

/**
 * Parses @p data to extract the message size.
 * @p length must be at least coap_pdu_parse_header_size(proto, data).
 * This function returns @c 0 on error or a number greater than zero on success.
 *
 * @param proto  Session's protocol
 * @param data   The raw data to parse as CoAP PDU.
 * @param length The actual size of @p data.
 *
 * @return       PDU size including token on success or @c 0 on error.
 */
size_t coap_pdu_parse_size(coap_proto_t proto,
                           const uint8_t *data,
                           size_t length);

/**
 * Decode the protocol specific header for the specified PDU.
 * @param pdu A newly received PDU.
 * @param proto The target wire protocol.
 * @return 1 for success or 0 on error.
 */

int coap_pdu_parse_header(coap_pdu_t *pdu, coap_proto_t proto);

/**
 * Verify consistency in the given CoAP PDU structure and locate the data.
 * This function returns @c 0 on error or a number greater than zero on
 * success.
 * This function only parses the token and options, up to the payload start
 * marker.
 *
 * @param pdu     The PDU structure to check.
 *
 * @return       1 on success or @c 0 on error.
 */
int coap_pdu_parse_opt(coap_pdu_t *pdu);

/**
 * Clears any contents from @p pdu and resets @c used_size,
 * and @c data pointers. @c max_size is set to @p size, any
 * other field is set to @c 0. Note that @p pdu must be a valid
 * pointer to a coap_pdu_t object created e.g. by coap_pdu_init().
 *
 * @param pdu   The PDU to clear.
 * @param size  The maximum size of the PDU.
 */
void coap_pdu_clear(coap_pdu_t *pdu, size_t size);

/**
 * Adds option of given @p number to @p pdu that is passed as first
 * parameter.
 *
 * The internal version of coap_add_option() may cause an @p option to be
 * inserted, even if there is any data in the @p pdu.
 *
 * Note: Where possible, the option @p data needs to be stripped of leading
 * zeros (big endian) to reduce the amount of data needed in the PDU, as well
 * as in some cases the maximum data size of an option can be exceeded if not
 * stripped and hence be illegal. This is done by using coap_encode_var_safe()
 * or coap_encode_var_safe8().
 *
 * @param pdu    The PDU where the option is to be added.
 * @param number The number of the new option.
 * @param len    The length of the new option.
 * @param data   The data of the new option.
 *
 * @return The overall length of the option or @c 0 on failure.
 */
size_t coap_add_option_internal(coap_pdu_t *pdu,
                                coap_option_num_t number,
                                size_t len,
                                const uint8_t *data);
/**
 * Removes (first) option of given number from the @p pdu.
 *
 * @param pdu   The PDU to remove the option from.
 * @param number The number of the CoAP option to remove (first only removed).
 *
 * @return @c 1 if success else @c 0 if error.
 */
int coap_remove_option(coap_pdu_t *pdu, coap_option_num_t number);

/**
 * Inserts option of given number in the @p pdu with the appropriate data.
 * The option will be inserted in the appropriate place in the options in
 * the pdu.
 *
 * @param pdu    The PDU where the option is to be inserted.
 * @param number The number of the new option.
 * @param len    The length of the new option.
 * @param data   The data of the new option.
 *
 * @return The overall length of the option or @c 0 on failure.
 */
size_t coap_insert_option(coap_pdu_t *pdu, coap_option_num_t number,
                          size_t len, const uint8_t *data);

/**
 * Updates existing first option of given number in the @p pdu with the new
 * data.
 *
 * @param pdu    The PDU where the option is to be updated.
 * @param number The number of the option to update (first only updated).
 * @param len    The length of the updated option.
 * @param data   The data of the updated option.
 *
 * @return The overall length of the updated option or @c 0 on failure.
 */
size_t coap_update_option(coap_pdu_t *pdu,
                          coap_option_num_t number,
                          size_t len,
                          const uint8_t *data);

/**
 * Compose the protocol specific header for the specified PDU.
 *
 * @param pdu A newly composed PDU.
 * @param proto The target wire protocol.
 *
 * @return Number of header bytes prepended before pdu->token or 0 on error.
 */

size_t coap_pdu_encode_header(coap_pdu_t *pdu, coap_proto_t proto);

/**
 * Updates token in @p pdu with length @p len and @p data.
 * This function returns @c 0 on error or a value greater than zero on success.
 *
 * @param pdu  The PDU where the token is to be updated.
 * @param len  The length of the new token.
 * @param data The token to add.
 *
 * @return     A value greater than zero on success, or @c 0 on error.
 */
int coap_update_token(coap_pdu_t *pdu,
                      size_t len,
                      const uint8_t *data);

/**
 * Check whether the option is allowed to be repeated or not.
 * This function returns @c 0 if not repeatable or @c 1 if repeatable
 *
 * @param number The option number to check for repeatability.
 *
 * @return     @c 0 if not repeatable or @c 1 if repeatable.
 */
int coap_option_check_repeatable(coap_option_num_t number);

/**
 * Creates a new CoAP PDU.
 *
 * Note: This function must be called in the locked state.
 *
 * @param type The type of the PDU (one of COAP_MESSAGE_CON, COAP_MESSAGE_NON,
 *             COAP_MESSAGE_ACK, COAP_MESSAGE_RST).
 * @param code The message code of the PDU.
 * @param session The session that will be using this PDU
 *
 * @return The skeletal PDU or @c NULL if failure.
 */
coap_pdu_t *coap_new_pdu_lkd(coap_pdu_type_t type, coap_pdu_code_t code,
                             coap_session_t *session);

/**
 * Dispose of an CoAP PDU and free off associated storage.
 *
 * Note: This function must be called in the locked state.
 *
 * Note: In general you should not call this function directly.
 * When a PDU is sent with coap_send(), coap_delete_pdu() will be called
 * automatically for you. This is not for the case for coap_send_recv()
 * where the sending and receiving PDUs need to be explicitly deleted.
 *
 * Note: If called with a reference count > 0, the reference count is
 * decremented and the PDU is not deleted.
 *
 * @param pdu The PDU for free off.
 */
void coap_delete_pdu_lkd(coap_pdu_t *pdu);

/**
 * Duplicate an existing PDU. Specific options can be ignored and not copied
 * across.  The PDU data payload is not copied across.
 *
 * Note: This function must be called in the locked state.
 *
 * @param old_pdu      The PDU to duplicate
 * @param session      The session that will be using this PDU.
 * @param token_length The length of the token to use in this duplicated PDU.
 * @param token        The token to use in this duplicated PDU.
 * @param drop_options A list of options not to copy into the duplicated PDU.
 *                     If @c NULL, then all options are copied across.
 *
 * @return The duplicated PDU or @c NULL if failure.
 */
coap_pdu_t *coap_pdu_duplicate_lkd(const coap_pdu_t *old_pdu,
                                   coap_session_t *session,
                                   size_t token_length,
                                   const uint8_t *token,
                                   coap_opt_filter_t *drop_options);

/**
 * Increment reference counter on a pdu to stop it prematurely getting freed off
 * when coap_delete_pdu() is called.
 *
 * In other words, if coap_pdu_reference_lkd() is called once, then the first call
 * to coap_delete_pdu() will decrement the reference counter, but not delete the PDU
 * and the second call to coap_delete_pdu() then actually deletes the PDU.
 *
 * Note: This function must be called in the locked state.
 *
 * @param pdu The CoAP PDU.
 * @return same as PDU
 */
coap_pdu_t *coap_pdu_reference_lkd(coap_pdu_t *pdu);

/**
 * Increment reference counter on a const pdu to stop it prematurely getting freed
 * off when coap_delete_pdu() is called.
 *
 * In other words, if coap_const_pdu_reference_lkd() is called once, then the first
 * call to coap_delete_pdu() will decrement the reference counter, but not delete
 * the PDU and the second call to coap_delete_pdu() then actually deletes the PDU.
 *
 * Needed when const coap_pdu_t* is passed from application handlers.
 *
 * Note: This function must be called in the locked state.
 *
 * @param pdu The CoAP PDU.
 * @return non const version of PDU.
 */
coap_pdu_t *coap_const_pdu_reference_lkd(const coap_pdu_t *pdu);

/** @} */

#endif /* COAP_COAP_PDU_INTERNAL_H_ */
