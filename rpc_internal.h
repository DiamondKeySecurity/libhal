/*
 * rpc_internal.h
 * --------------
 * Internal (not public API) declarations for HAL RPC mechanism.
 *
 * Authors: Rob Austein, Paul Selkirk
 * Copyright (c) 2015, NORDUnet A/S All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the NORDUnet nor the names of its contributors may
 *   be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _HAL_RPC_INTERNAL_H_
#define _HAL_RPC_INTERNAL_H_

#include "hal_rpc.h"

/*
 * Everything in this file is part of the internal API, that is,
 * subject to change without notice.  Nothing outside of libhal itself
 * should be looking at this file.  Access from outside of libhal
 * should use the public hal_rpc_*() API.
 *
 * In particular, the breakdown of which functions go into which
 * dispatch vectors is based entirely on pesky details like making
 * sure that the right functions get linked in the right cases, and
 * should not be construed as making any particular sense in any
 * larger context.
 */

/*
 * In theory eventually we might want a fully general mechanism to
 * allow us to dispatch arbitrary groups of functions either locally
 * or remotely on a per-user basis.  In practice, we probably want to
 * run everything on the HSM except for hashing and digesting, so just
 * code for that case initially while leaving the design open for a
 * more general mechanism later if warranted.
 *
 * So we have three cases:
 *
 * - We're the HSM, so we do everything locally (ie, we run the RPC
 *   server functions.
 *
 * - We're the host, so we do everything remotely (ie, we do
 *   everything using the client-side RPC calls.
 *
 * - We're the host but are doing hashing locally, so we do a mix.
 *   This is slightly more complicated than it might at first appear,
 *   because we must handle the case of one of the pkey functions
 *   taking a hash context instead of a literal hash value, in which
 *   case we have to extract the hash value from the context and
 *   supply it to the pkey RPC client code as a literal value.
 */

typedef struct {

  hal_error_t (*set_pin)(const hal_rpc_user_t which,
                         const char * const newpin, const size_t newpin_len);

  hal_error_t (*login)(const hal_rpc_client_handle_t client,
                       const hal_rpc_user_t user,
                       const char * const newpin, const size_t newpin_len);

  hal_error_t (*logout)(const hal_rpc_client_handle_t client);

  hal_error_t (*get_random)(void *buffer, const size_t length);

} hal_rpc_misc_dispatch_t;


typedef struct {

  hal_error_t (*get_digest_length)(const hal_rpc_hash_alg_t alg, size_t *length);

  hal_error_t (*get_digest_algorithm_id)(const hal_rpc_hash_alg_t alg,
                                         uint8_t *id, size_t *len, const size_t len_max);

  hal_error_t (*get_algorithm)(const hal_rpc_hash_handle_t hash, hal_rpc_hash_alg_t *alg);

  hal_error_t (*initialize)(const hal_rpc_client_handle_t client,
                            const hal_rpc_session_handle_t session,
                            hal_rpc_hash_handle_t *hash,
                            const hal_rpc_hash_alg_t alg,
                            const uint8_t * const key, const size_t key_length);

  hal_error_t (*update)(const hal_rpc_hash_handle_t hash,
                        const uint8_t * data, const size_t length);

  hal_error_t (*finalize)(const hal_rpc_hash_handle_t hash,
                          uint8_t *digest, const size_t length);
} hal_rpc_hash_dispatch_t;


typedef struct {

  hal_error_t  (*load)(const hal_rpc_client_handle_t client,
                       const hal_rpc_session_handle_t session,
                       hal_rpc_pkey_handle_t *pkey,
                       const hal_rpc_pkey_key_type_t type,
                       const hal_rpc_pkey_curve_t curve,
                       const uint8_t * const name, const size_t name_len,
                       const uint8_t * const der, const size_t der_len,
                       const hal_rpc_pkey_flags_t flags);

  hal_error_t  (*find)(const hal_rpc_client_handle_t client,
                       const hal_rpc_session_handle_t session,
                       hal_rpc_pkey_handle_t *pkey,
                       const hal_rpc_pkey_key_type_t type,
                       const uint8_t * const name, const size_t name_len);

  hal_error_t  (*generate_rsa)(const hal_rpc_client_handle_t client,
                               const hal_rpc_session_handle_t session,
                               hal_rpc_pkey_handle_t *pkey,
                               const uint8_t * const name, const size_t name_len,
                               const unsigned key_length,
                               const uint8_t * const public_exponent, const size_t public_exponent_len,
                               const hal_rpc_pkey_flags_t flags);

  hal_error_t  (*generate_ec)(const hal_rpc_client_handle_t client,
                              const hal_rpc_session_handle_t session,
                              hal_rpc_pkey_handle_t *pkey,
                              const uint8_t * const name, const size_t name_len,
                              const hal_rpc_pkey_curve_t curve,
                              const hal_rpc_pkey_flags_t flags);

  hal_error_t  (*delete)(const hal_rpc_pkey_handle_t pkey);

  hal_error_t  (*get_key_type)(const hal_rpc_pkey_handle_t pkey,
                               hal_rpc_pkey_key_type_t *key_type);

  hal_error_t  (*get_key_flags)(const hal_rpc_pkey_handle_t pkey,
                                hal_rpc_pkey_flags_t *flags);

  size_t (*get_public_key_len)(const hal_rpc_pkey_handle_t pkey);

  hal_error_t  (*get_public_key)(const hal_rpc_pkey_handle_t pkey,
                                 uint8_t *der, size_t *der_len, const size_t der_len_max);

  hal_error_t  (*sign)(const hal_rpc_session_handle_t session,
                       const hal_rpc_pkey_handle_t pkey,
                       const hal_rpc_hash_handle_t hash,
                       const uint8_t * const input,  const size_t input_len,
                       uint8_t * output, const size_t output_len);

  hal_error_t  (*verify)(const hal_rpc_session_handle_t session,
                         const hal_rpc_pkey_handle_t pkey,
                         const hal_rpc_hash_handle_t hash,
                         const uint8_t * const input, const size_t input_len,
                         uint8_t * output, const size_t output_len);

  hal_error_t  (*list)(hal_rpc_pkey_key_info_t *result,
                       unsigned *result_len,
                       const unsigned result_max);

} hal_rpc_pkey_dispatch_t;


extern const hal_rpc_misc_dispatch_t hal_rpc_local_misc_dispatch, hal_rpc_remote_misc_dispatch;
extern const hal_rpc_hash_dispatch_t hal_rpc_local_hash_dispatch, hal_rpc_remote_hash_dispatch;
extern const hal_rpc_pkey_dispatch_t hal_rpc_local_pkey_dispatch, hal_rpc_remote_pkey_dispatch, hal_rpc_mixed_pkey_dispatch;

#endif /* _HAL_RPC_INTERNAL_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
