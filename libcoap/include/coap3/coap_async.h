/*
 * coap_async.h -- state management for asynchronous messages
 *
 * Copyright (C) 2010-2025 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_async.h
 * @brief State management for asynchronous messages
 */

#ifndef COAP_ASYNC_H_
#define COAP_ASYNC_H_

#include "coap_net.h"

/**
 * @ingroup application_api
 * @defgroup coap_async Asynchronous Messaging
 * @{
 * API for delayed "separate" messages.
 * A coap_context_t object holds a list of coap_async_t objects that can
 * be used to generate a separate response in the case a result of a request
 * cannot be delivered immediately.
 */

/**
 * Allocates a new coap_async_t object and fills its fields according to
 * the given @p request. This function returns a pointer to the registered
 * coap_async_t object or @c NULL on error. Note that this function will
 * return @c NULL in case that an object with the same identifier is already
 * registered.
 *
 * When the delay expires, a copy of the @p request will get sent to the
 * appropriate request handler.
 *
 * @param session  The session that is used for asynchronous transmissions.
 * @param request  The request that is handled asynchronously.
 * @param delay    The amount of time to delay before sending response, 0 means
 *                 wait forever.
 *
 * @return         A pointer to the registered coap_async_t object or @c
 *                 NULL in case of an error.
 */
COAP_API coap_async_t *coap_register_async(coap_session_t *session,
                                           const coap_pdu_t *request,
                                           coap_tick_t delay);

/**
 * Update the delay timeout, so changing when the registered @p async triggers.
 *
 * When the new delay expires, a copy of the original request will get sent to
 * the appropriate request handler.
 *
 * @param async The object to update.
 * @param delay    The amount of time to delay before sending response, 0 means
 *                 wait forever.
 */
COAP_API void coap_async_set_delay(coap_async_t *async, coap_tick_t delay);

/**
 * Trigger the registered @p async.
 *
 * A copy of the original request will get sent to the appropriate request
 * handler.
 *
 * @param async The async object to trigger.
 */
COAP_API void coap_async_trigger(coap_async_t *async);

/**
 * Releases the memory that was allocated by coap_register_async() for the
 * object @p async.
 *
 * @param session  The session to use.
 * @param async The object to delete.
 */
COAP_API void coap_free_async(coap_session_t *session, coap_async_t *async);

/**
 * Retrieves the object identified by @p token from the list of asynchronous
 * transactions that are registered with @p context. This function returns a
 * pointer to that object or @c NULL if not found.
 *
 * @param session The session that is used for asynchronous transmissions.
 * @param token   The PDU's token of the object to retrieve.
 *
 * @return        A pointer to the object identified by @p token or @c NULL if
 *                not found.
 */
COAP_API coap_async_t *coap_find_async(coap_session_t *session, coap_bin_const_t token);

/**
 * Set the application data pointer held in @p async. This overwrites any
 * existing data pointer.
 *
 * @deprecated Use coap_async_set_app_data2() instead.
 *
 * @param async The async state object.
 * @param app_data The pointer to the data.
 */
COAP_DEPRECATED void coap_async_set_app_data(coap_async_t *async, void *app_data);

/**
 * Gets the application data pointer held in @p async.
 *
 * @param async The async state object.
 *
 * @return The applicaton data pointer.
 */
void *coap_async_get_app_data(const coap_async_t *async);

/**
 * Stores @p data with the given async, returning the previously stored
 * value or NULL. The data @p callback can be defined if the data is to be
 * released when the cache_entry is deleted.
 *
 * Note: It is the responsibility of the caller to free off (if appropriate) any
 * returned data.
 *
 * @param async_entry The async state object.
 * @param data The pointer to the data to store or NULL to just clear out the
 *             previous data.
 * @param callback The optional release call-back for data on async
 *                 removal or NULL.
 *
 * @return The previous data (if any) stored in the async.
 */
COAP_API void *coap_async_set_app_data2(coap_async_t *async_entry,
                                        void *data,
                                        coap_app_data_free_callback_t callback);

/** @} */

#endif /* COAP_ASYNC_H_ */
