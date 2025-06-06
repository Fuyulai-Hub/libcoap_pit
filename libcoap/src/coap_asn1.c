/* coap_asn1.c -- ASN.1 handling functions
*
* Copyright (C) 2020-2025 Jon Shallow <supjps-libcoap@jpshallow.com>
*
 * SPDX-License-Identifier: BSD-2-Clause
 *
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

/**
 * @file coap_asn1.c
 * @brief CoAP specific ASN.1 handling
 */

#include "coap3/coap_libcoap_build.h"

size_t
asn1_len(const uint8_t **ptr) {
  size_t len = 0;

  if ((**ptr) & 0x80) {
    size_t octets = (**ptr) & 0x7f;
    (*ptr)++;
    while (octets) {
      len = (len << 8) + (**ptr);
      (*ptr)++;
      octets--;
    }
  } else {
    len = (**ptr) & 0x7f;
    (*ptr)++;
  }
  return len;
}

coap_asn1_tag_t
asn1_tag_c(const uint8_t **ptr, int *constructed, int *cls) {
  coap_asn1_tag_t tag = 0;
  uint8_t byte;

  byte = (**ptr);
  *constructed = (byte & 0x20) ? 1 : 0;
  *cls = byte >> 6;
  tag = byte & 0x1F;
  (*ptr)++;
  if (tag < 0x1F)
    return tag;

  /* Tag can be one byte or more based on B8 */
  byte = (**ptr);
  while (byte & 0x80) {
    tag = (tag << 7) + (byte & 0x7F);
    (*ptr)++;
    byte = (**ptr);
  }
  /* Do the final one */
  tag = (tag << 7) + (byte & 0x7F);
  (*ptr)++;
  return tag;
}

/* caller must free off returned coap_binary_t* */
coap_binary_t *
get_asn1_tag(coap_asn1_tag_t ltag, const uint8_t *ptr, size_t tlen,
             asn1_validate validate) {
  int constructed;
  int class;
  const uint8_t *acp = ptr;
  uint8_t tag = asn1_tag_c(&acp, &constructed, &class);
  size_t len = asn1_len(&acp);
  coap_binary_t *tag_data;

  while (tlen > 0 && len <= tlen) {
    if (class == 2 && constructed == 1) {
      /* Skip over element description */
      tag = asn1_tag_c(&acp, &constructed, &class);
      len = asn1_len(&acp);
    }
    if (tag == ltag) {
      if (!validate || validate(acp, len)) {
        tag_data = coap_new_binary(len);
        if (tag_data == NULL)
          return NULL;
        tag_data->length = len;
        memcpy(tag_data->s, acp, len);
        return tag_data;
      }
    }
    if (tag == 0x10 && constructed == 1) {
      /* SEQUENCE or SEQUENCE OF */
      tag_data = get_asn1_tag(ltag, acp, len, validate);
      if (tag_data)
        return tag_data;
    }
    acp += len;
    tlen -= len;
    tag = asn1_tag_c(&acp, &constructed, &class);
    len = asn1_len(&acp);
  }
  return NULL;
}

/* first part of Raw public key, this is the start of the Subject Public Key */
static const unsigned char cert_asn1_header1[] = {
  0x30, 0x59, /* SEQUENCE, length 89 bytes */
  0x30, 0x13, /* SEQUENCE, length 19 bytes */
  0x06, 0x07, /* OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1) */
  0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
};
/* PrimeX will get inserted */
#if 0
0x06, 0x08, /* OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7) */
      0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
#endif
static const unsigned char cert_asn1_header2[] = {
  0x03, 0x42, /* BIT STRING, length 66 bytes */
  /* Note: 0 bits (0x00) and no compression (0x04) are already in the certificate */
};

coap_binary_t *
get_asn1_spki(const uint8_t *data, size_t size) {
  coap_binary_t *pub_key = get_asn1_tag(COAP_ASN1_BITSTRING, data, size, NULL);
  coap_binary_t *prime = get_asn1_tag(COAP_ASN1_IDENTIFIER, data, size, NULL);
  coap_binary_t *spki = NULL;

  if (pub_key && prime) {
    size_t header_size = sizeof(cert_asn1_header1) +
                         2 +
                         prime->length +
                         sizeof(cert_asn1_header2);
    spki = coap_new_binary(header_size + pub_key->length);
    if (spki) {
      memcpy(&spki->s[header_size], pub_key->s, pub_key->length);
      memcpy(spki->s, cert_asn1_header1, sizeof(cert_asn1_header1));
      spki->s[sizeof(cert_asn1_header1)] = COAP_ASN1_IDENTIFIER;
      spki->s[sizeof(cert_asn1_header1)+1] = (uint8_t)prime->length;
      memcpy(&spki->s[sizeof(cert_asn1_header1)+2],
             prime->s, prime->length);
      memcpy(&spki->s[sizeof(cert_asn1_header1)+2+prime->length],
             cert_asn1_header2, sizeof(cert_asn1_header2));
      spki->length = header_size + pub_key->length;
    }
  }
  if (pub_key)
    coap_delete_binary(pub_key);
  if (prime)
    coap_delete_binary(prime);
  return spki;
}
