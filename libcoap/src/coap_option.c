/*
 * coap_option.c -- helpers for handling options in CoAP PDUs
 *
 * Copyright (C) 2010-2013,2022-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file coap_option.c
 * @brief CoAP option handling functions
 */

#include "coap3/coap_libcoap_build.h"

#include <stdio.h>
#include <string.h>

#define ADVANCE_OPT(o,e,step) if ((e) < step) {           \
    coap_log_debug("cannot advance opt past end\n"); \
    return 0;                                             \
  } else {                                                \
    (e) -= step;                                          \
    (o) = ((o)) + step;                                   \
  }

/*
 * Used to prevent access to *opt when pointing to after end of buffer
 * after doing a ADVANCE_OPT()
 */
#define ADVANCE_OPT_CHECK(o,e,step) do { \
    ADVANCE_OPT(o,e,step);               \
    if ((e) < 1)                         \
      return 0;                          \
  } while (0)

size_t
coap_opt_parse(const coap_opt_t *opt, size_t length, coap_option_t *result) {

  const coap_opt_t *opt_start = opt; /* store where parsing starts  */

  assert(opt);
  assert(result);

  if (length < 1)
    return 0;

  result->delta = (*opt & 0xf0) >> 4;
  result->length = *opt & 0x0f;

  switch (result->delta) {
  case 15:
    if (*opt != COAP_PAYLOAD_START) {
      coap_log_debug("ignored reserved option delta 15\n");
    }
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT_CHECK(opt,length,1);
    result->delta = ((*opt & 0xff) << 8) + 269;
    if (result->delta < 269) {
      coap_log_debug("delta too large\n");
      return 0;
    }
  /* fall through */
  case 13:
    ADVANCE_OPT_CHECK(opt,length,1);
    result->delta += *opt & 0xff;
    break;

  default:
    ;
  }

  switch (result->length) {
  case 15:
    coap_log_debug("found reserved option length 15\n");
    return 0;
  case 14:
    /* Handle two-byte value: First, the MSB + 269 is stored as delta value.
     * After that, the option pointer is advanced to the LSB which is handled
     * just like case delta == 13. */
    ADVANCE_OPT_CHECK(opt,length,1);
    result->length = ((*opt & 0xff) << 8) + 269;
  /* fall through */
  case 13:
    ADVANCE_OPT_CHECK(opt,length,1);
    result->length += *opt & 0xff;
    break;

  default:
    ;
  }

  /* ADVANCE_OPT() is correct here */
  ADVANCE_OPT(opt,length,1);
  /* opt now points to value, if present */

  result->value = opt;
  if (length < result->length) {
    coap_log_debug("invalid option length\n");
    return 0;
  }

#undef ADVANCE_OPT
#undef ADVANCE_OPT_CHECK

  return (opt + result->length) - opt_start;
}

coap_opt_iterator_t *
coap_option_iterator_init(const coap_pdu_t *pdu, coap_opt_iterator_t *oi,
                          const coap_opt_filter_t *filter) {
  assert(pdu);
  assert(pdu->token);
  assert(oi);

  memset(oi, 0, sizeof(coap_opt_iterator_t));

  oi->next_option = pdu->token + pdu->e_token_length;
  if (pdu->token + pdu->used_size <= oi->next_option) {
    oi->bad = 1;
    return NULL;
  }

  oi->length = pdu->used_size - pdu->e_token_length;

  if (filter) {
    memcpy(&oi->filter, filter, sizeof(coap_opt_filter_t));
    oi->filtered = 1;
  }
  return oi;
}

COAP_STATIC_INLINE int
opt_finished(coap_opt_iterator_t *oi) {
  assert(oi);

  if (oi->bad || oi->length == 0 ||
      !oi->next_option || *oi->next_option == COAP_PAYLOAD_START) {
    oi->bad = 1;
  }

  return oi->bad;
}

coap_opt_t *
coap_option_next(coap_opt_iterator_t *oi) {
  coap_option_t option;
  coap_opt_t *current_opt = NULL;
  size_t optsize;

  assert(oi);

  if (opt_finished(oi))
    return NULL;

  while (1) {
    /* oi->next_option always points to the next option to deliver; as
     * opt_finished() filters out any bad conditions, we can assume that
     * oi->next_option is valid. */
    current_opt = oi->next_option;

    /*
     * Advance internal pointer to next option.
     * optsize will be 0 when no more options
     */
    optsize = coap_opt_parse(oi->next_option, oi->length, &option);
    if (optsize) {
      assert(optsize <= oi->length);

      oi->next_option += optsize;
      oi->length -= optsize;

      oi->number += option.delta;
    } else {                        /* current option is malformed */
      oi->bad = 1;
      return NULL;
    }

    /* Exit the while loop when:
     *   - no filtering is done at all
     *   - the filter matches for the current option
     */
    if (!oi->filtered ||
        coap_option_filter_get(&oi->filter, oi->number) > 0)
      break;
  }

  return current_opt;
}

coap_opt_t *
coap_check_option(const coap_pdu_t *pdu, coap_option_num_t number,
                  coap_opt_iterator_t *oi) {
  coap_opt_filter_t f;

  coap_option_filter_clear(&f);
  coap_option_filter_set(&f, number);

  coap_option_iterator_init(pdu, oi, &f);

  return coap_option_next(oi);
}

uint32_t
coap_opt_length(const coap_opt_t *opt) {
  uint32_t length;

  length = *opt & 0x0f;
  switch (*opt & 0xf0) {
  case 0xf0:
    coap_log_debug("illegal option delta\n");
    return 0;
  case 0xe0:
    ++opt;
  /* fall through */
  /* to skip another byte */
  case 0xd0:
    ++opt;
  /* fall through */
  /* to skip another byte */
  default:
    ++opt;
  }

  switch (length) {
  case 0x0f:
    coap_log_debug("illegal option length\n");
    return 0;
  case 0x0e:
    length = (*opt++ << 8) + 269;
  /* fall through */
  case 0x0d:
    length += *opt++;
    break;
  default:
    ;
  }
  return length;
}

const uint8_t *
coap_opt_value(const coap_opt_t *opt) {
  size_t ofs = 1;

  switch (*opt & 0xf0) {
  case 0xf0:
    coap_log_debug("illegal option delta\n");
    return 0;
  case 0xe0:
    ++ofs;
  /* fall through */
  case 0xd0:
    ++ofs;
    break;
  default:
    ;
  }

  switch (*opt & 0x0f) {
  case 0x0f:
    coap_log_debug("illegal option length\n");
    return 0;
  case 0x0e:
    ++ofs;
  /* fall through */
  case 0x0d:
    ++ofs;
    break;
  default:
    ;
  }

  return (const uint8_t *)opt + ofs;
}

size_t
coap_opt_size(const coap_opt_t *opt) {
  coap_option_t option;

  /* we must assume that opt is encoded correctly */
  return coap_opt_parse(opt, (size_t)-1, &option);
}

size_t
coap_opt_setheader(coap_opt_t *opt, size_t maxlen,
                   uint16_t delta, size_t length) {
  size_t skip = 0;

  assert(opt);

  if (maxlen == 0)                /* need at least one byte */
    return 0;

  if (delta < 13) {
    opt[0] = (coap_opt_t)(delta << 4);
  } else if (delta < 269) {
    if (maxlen < 2) {
      coap_log_debug("insufficient space to encode option delta %d\n",
                     delta);
      return 0;
    }

    opt[0] = 0xd0;
    opt[++skip] = (coap_opt_t)(delta - 13);
  } else {
    if (maxlen < 3) {
      coap_log_debug("insufficient space to encode option delta %d\n",
                     delta);
      return 0;
    }

    opt[0] = 0xe0;
    opt[++skip] = ((delta - 269) >> 8) & 0xff;
    opt[++skip] = (delta - 269) & 0xff;
  }

  if (length < 13) {
    opt[0] |= length & 0x0f;
  } else if (length < 269) {
    if (maxlen < skip + 2) {
      coap_log_debug("insufficient space to encode option length %zu\n",
                     length);
      return 0;
    }

    opt[0] |= 0x0d;
    opt[++skip] = (coap_opt_t)(length - 13);
  } else {
    if (maxlen < skip + 3) {
      coap_log_debug("insufficient space to encode option delta %d\n",
                     delta);
      return 0;
    }

    opt[0] |= 0x0e;
    opt[++skip] = ((length - 269) >> 8) & 0xff;
    opt[++skip] = (length - 269) & 0xff;
  }

  return skip + 1;
}

size_t
coap_opt_encode_size(uint16_t delta, size_t length) {
  size_t n = 1;

  if (delta >= 13) {
    if (delta < 269)
      n += 1;
    else
      n += 2;
  }

  if (length >= 13) {
    if (length < 269)
      n += 1;
    else
      n += 2;
  }

  return n + length;
}

size_t
coap_opt_encode(coap_opt_t *opt, size_t maxlen, uint16_t delta,
                const uint8_t *val, size_t length) {
  size_t l = 1;

  l = coap_opt_setheader(opt, maxlen, delta, length);
  assert(l <= maxlen);

  if (!l) {
    coap_log_debug("coap_opt_encode: cannot set option header\n");
    return 0;
  }

  maxlen -= l;
  opt += l;

  if (maxlen < length) {
    coap_log_debug("coap_opt_encode: option too large for buffer\n");
    return 0;
  }

  if (val)                        /* better be safe here */
    memcpy(opt, val, length);

  return l + length;
}

#define LONG_MASK ((1 << COAP_OPT_FILTER_LONG) - 1)
#define SHORT_MASK \
  (~LONG_MASK & ((1 << (COAP_OPT_FILTER_LONG + COAP_OPT_FILTER_SHORT)) - 1))

/** Returns true iff @p number denotes an option number larger than 255. */
COAP_STATIC_INLINE int
is_long_option(coap_option_num_t number) {
  return number > 255;
}

/** Operation specifiers for coap_filter_op(). */
enum filter_op_t { FILTER_SET, FILTER_CLEAR, FILTER_GET };

/**
 * Applies @p op on @p filter with respect to @p number. The following
 * operations are defined:
 *
 * FILTER_SET: Store @p number into an empty slot in @p filter. Returns
 * @c 1 on success, or @c 0 if no spare slot was available.
 *
 * FILTER_CLEAR: Remove @p number from filter if it exists.
 *
 * FILTER_GET: Search for @p number in @p filter. Returns @c 1 if found,
 * or @c 0 if not found.
 *
 * @param filter The filter object.
 * @param number The option number to set, get or clear in @p filter.
 * @param op     The operation to apply to @p filter and @p number.
 *
 * @return 1 on success, and 0 when FILTER_GET yields no
 * hit or no free slot is available to store @p number with FILTER_SET.
 */
static int
coap_option_filter_op(coap_opt_filter_t *filter,
                      coap_option_num_t number,
                      enum filter_op_t op) {
  size_t lindex = 0;
  coap_opt_filter_t *of = filter;
  uint16_t nr, mask = 0;

  if (is_long_option(number)) {
    mask = LONG_MASK;

    for (nr = 1; lindex < COAP_OPT_FILTER_LONG; nr <<= 1, lindex++) {

      if (((of->mask & nr) > 0) && (of->long_opts[lindex] == number)) {
        if (op == FILTER_CLEAR) {
          of->mask &= ~nr;
        }

        return 1;
      }
    }
  } else {
    mask = SHORT_MASK;

    for (nr = 1 << COAP_OPT_FILTER_LONG; lindex < COAP_OPT_FILTER_SHORT;
         nr <<= 1, lindex++) {

      if (((of->mask & nr) > 0) && (of->short_opts[lindex] == (number & 0xff))) {
        if (op == FILTER_CLEAR) {
          of->mask &= ~nr;
        }

        return 1;
      }
    }
  }

  /* number was not found, so there is nothing to do if op is CLEAR or GET */
  if ((op == FILTER_CLEAR) || (op == FILTER_GET)) {
    return 0;
  }

  /* handle FILTER_SET: */

  lindex = coap_fls(~of->mask & mask);
  if (!lindex) {
    return 0;
  }

  if (is_long_option(number)) {
    of->long_opts[lindex - 1] = number;
  } else {
    of->short_opts[lindex - COAP_OPT_FILTER_LONG - 1] = (uint8_t)number;
  }

  of->mask |= 1 << (lindex - 1);

  return 1;
}

void
coap_option_filter_clear(coap_opt_filter_t *filter) {
  memset(filter, 0, sizeof(coap_opt_filter_t));
}

int
coap_option_filter_set(coap_opt_filter_t *filter, coap_option_num_t option) {
  return coap_option_filter_op(filter, option, FILTER_SET);
}

int
coap_option_filter_unset(coap_opt_filter_t *filter, coap_option_num_t option) {
  return coap_option_filter_op(filter, option, FILTER_CLEAR);
}

int
coap_option_filter_get(coap_opt_filter_t *filter, coap_option_num_t option) {
  return coap_option_filter_op(filter, option, FILTER_GET);
}

coap_optlist_t *
coap_new_optlist(uint16_t number,
                 size_t length,
                 const uint8_t *data
                ) {
  coap_optlist_t *node;

#ifdef WITH_LWIP
  if (length > MEMP_LEN_COAPOPTLIST) {
    coap_log_crit("coap_new_optlist: size too large (%zu > MEMP_LEN_COAPOPTLIST)\n",
                  length);
    return NULL;
  }
#endif /* WITH_LWIP */
  node = coap_malloc_type(COAP_OPTLIST, sizeof(coap_optlist_t) + length);

  if (node) {
    memset(node, 0, (sizeof(coap_optlist_t) + length));
    node->number = number;
    node->length = length;
    node->data = (uint8_t *)&node[1];
    memcpy(node->data, data, length);
  } else {
    coap_log_warn("coap_new_optlist: malloc failure\n");
  }

  return node;
}

static int
order_opts(void *a, void *b) {
  coap_optlist_t *o1 = (coap_optlist_t *)a;
  coap_optlist_t *o2 = (coap_optlist_t *)b;

  if (!a || !b)
    return a < b ? -1 : 1;

  return (int)(o1->number - o2->number);
}

int
coap_add_optlist_pdu(coap_pdu_t *pdu, coap_optlist_t **options) {
  coap_optlist_t *opt;

  if (options && *options) {
    if (pdu->data) {
      coap_log_warn("coap_add_optlist_pdu: PDU already contains data\n");
      return 0;
    }
    /* sort options for delta encoding */
    LL_SORT((*options), order_opts);

    LL_FOREACH((*options), opt) {
      if (!coap_add_option_internal(pdu, opt->number, opt->length, opt->data))
        return 0;
    }
  }
  return 1;
}

int
coap_insert_optlist(coap_optlist_t **head, coap_optlist_t *node) {
  if (!node) {
    coap_log_debug("optlist not provided\n");
  } else {
    /* must append at the list end to avoid re-ordering of
     * options during sort */
    LL_APPEND((*head), node);
  }

  return node != NULL;
}

static int
coap_internal_delete(coap_optlist_t *node) {
  if (node) {
    coap_free_type(COAP_OPTLIST, node);
  }
  return 1;
}

void
coap_delete_optlist(coap_optlist_t *queue) {
  coap_optlist_t *elt, *tmp;

  if (!queue)
    return;

  LL_FOREACH_SAFE(queue, elt, tmp) {
    coap_internal_delete(elt);
  }
}
