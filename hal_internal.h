/*
 * hal_internal.h
 * --------------
 * Internal API declarations for libhal.
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

#ifndef _HAL_INTERNAL_H_
#define _HAL_INTERNAL_H_

#include "hal.h"

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

  hal_error_t (*get_digest_length)(const hal_digest_algorithm_t alg, size_t *length);

  hal_error_t (*get_digest_algorithm_id)(const hal_digest_algorithm_t alg,
                                         uint8_t *id, size_t *len, const size_t len_max);

  hal_error_t (*get_algorithm)(const hal_rpc_hash_handle_t hash, hal_digest_algorithm_t *alg);

  hal_error_t (*initialize)(const hal_rpc_client_handle_t client,
                            const hal_rpc_session_handle_t session,
                            hal_rpc_hash_handle_t *hash,
                            const hal_digest_algorithm_t alg,
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
                       const hal_key_type_t type,
                       const hal_curve_name_t curve,
                       const uint8_t * const name, const size_t name_len,
                       const uint8_t * const der, const size_t der_len,
                       const hal_key_flags_t flags);

  hal_error_t  (*find)(const hal_rpc_client_handle_t client,
                       const hal_rpc_session_handle_t session,
                       hal_rpc_pkey_handle_t *pkey,
                       const hal_key_type_t type,
                       const uint8_t * const name, const size_t name_len);

  hal_error_t  (*generate_rsa)(const hal_rpc_client_handle_t client,
                               const hal_rpc_session_handle_t session,
                               hal_rpc_pkey_handle_t *pkey,
                               const uint8_t * const name, const size_t name_len,
                               const unsigned key_length,
                               const uint8_t * const public_exponent, const size_t public_exponent_len,
                               const hal_key_flags_t flags);

  hal_error_t  (*generate_ec)(const hal_rpc_client_handle_t client,
                              const hal_rpc_session_handle_t session,
                              hal_rpc_pkey_handle_t *pkey,
                              const uint8_t * const name, const size_t name_len,
                              const hal_curve_name_t curve,
                              const hal_key_flags_t flags);

  hal_error_t  (*close)(const hal_rpc_pkey_handle_t pkey);

  hal_error_t  (*delete)(const hal_rpc_pkey_handle_t pkey);

  hal_error_t  (*get_key_type)(const hal_rpc_pkey_handle_t pkey,
                               hal_key_type_t *key_type);

  hal_error_t  (*get_key_flags)(const hal_rpc_pkey_handle_t pkey,
                                hal_key_flags_t *flags);

  size_t (*get_public_key_len)(const hal_rpc_pkey_handle_t pkey);

  hal_error_t  (*get_public_key)(const hal_rpc_pkey_handle_t pkey,
                                 uint8_t *der, size_t *der_len, const size_t der_len_max);

  hal_error_t  (*sign)(const hal_rpc_session_handle_t session,
                       const hal_rpc_pkey_handle_t pkey,
                       const hal_rpc_hash_handle_t hash,
                       const uint8_t * const input,  const size_t input_len,
                       uint8_t * signature, size_t *signature_len, const size_t signature_max);

  hal_error_t  (*verify)(const hal_rpc_session_handle_t session,
                         const hal_rpc_pkey_handle_t pkey,
                         const hal_rpc_hash_handle_t hash,
                         const uint8_t * const input, const size_t input_len,
                         const uint8_t * const signature, const size_t signature_len);

  hal_error_t  (*list)(hal_rpc_pkey_key_info_t *result,
                       unsigned *result_len,
                       const unsigned result_max);

} hal_rpc_pkey_dispatch_t;


extern const hal_rpc_misc_dispatch_t hal_rpc_local_misc_dispatch, hal_rpc_remote_misc_dispatch;
extern const hal_rpc_hash_dispatch_t hal_rpc_local_hash_dispatch, hal_rpc_remote_hash_dispatch;
extern const hal_rpc_pkey_dispatch_t hal_rpc_local_pkey_dispatch, hal_rpc_remote_pkey_dispatch, hal_rpc_mixed_pkey_dispatch;

/*
 * Keystore API.
 *
 * The original design for this subsystem used two separate tables,
 * one for RSA keys, one for EC keys, because the RSA keys are so much
 * larger than the EC keys.  This led to unnecessarily complex and
 * duplicated code, so for now we treat all keys the same, and waste
 * the unneded space in the case of EC keys.
 *
 * Sizes for ASN.1-encoded keys, this may not be exact due to ASN.1
 * INTEGER encoding rules but should be good enough for buffer sizing:
 *
 * 2048-bit RSA:        1194 bytes
 * 4096-bit RSA:        2351 bytes
 * 8192-bit RSA:	4655 bytes
 * EC P-256:		 121 bytes
 * EC P-384:		 167 bytes
 * EC P-521:             223 bytes
 *
 * Plus we need a bit of AES-keywrap overhead, since we're storing the
 * wrapped form (see hal_aes_keywrap_cyphertext_length()).
 */

#define	HAL_KS_WRAPPED_KEYSIZE  ((4655 + 15) & ~7)

#ifndef HAL_STATIC_PKEY_STATE_BLOCKS
#define HAL_STATIC_PKEY_STATE_BLOCKS 0
#endif

typedef struct {
  hal_key_type_t type;
  hal_curve_name_t curve;
  hal_key_flags_t flags;
  uint8_t name[HAL_RPC_PKEY_NAME_MAX];
  size_t name_len;
  uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
  size_t der_len;
  uint8_t in_use;
} hal_ks_key_t;

typedef struct {
#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
  hal_ks_key_t keys[HAL_STATIC_PKEY_STATE_BLOCKS];
#endif
} hal_ks_keydb_t;

/*
 * Internal functions within the keystore implementation.  Think of
 * these as concrete methods for the keystore API subclassed onto
 * various storage technologies.
 */

extern const hal_ks_keydb_t *hal_ks_get_keydb(void);

extern hal_error_t hal_ks_set_keydb(const hal_ks_key_t * const key,
                                    const int loc);

extern hal_error_t hal_ks_del_keydb(const int loc);

extern hal_error_t hal_ks_get_kek(uint8_t *kek,
                                  size_t *kek_len,
                                  const size_t kek_max);

/*
 * Keystore API for use by the pkey implementation.
 *
 * In an attempt to emulate what current theory says will eventually
 * be the behavior of the underlying Cryptech Verilog "hardware",
 * these functions automatically apply the AES keywrap transformations.
 *
 * Unclear whether these should also call the ASN.1 encode/decode
 * functions.  For the moment, the answer is no, but we may need to
 * revisit this as the underlying Verilog API evolves.
 */

extern hal_error_t hal_ks_store(const hal_key_type_t type,
                                const hal_curve_name_t curve,
                                const hal_key_flags_t flags,
                                const uint8_t * const name, const size_t name_len,
                                const uint8_t * const der,  const size_t der_len,
                                int *hint);

extern hal_error_t hal_ks_exists(const hal_key_type_t type,
                                 const uint8_t * const name, const size_t name_len,
                                 int *hint);

extern hal_error_t hal_ks_fetch(const hal_key_type_t type,
                                const uint8_t * const name, const size_t name_len,
                                hal_curve_name_t *curve,
                                hal_key_flags_t *flags,
                                uint8_t *der, size_t *der_len, const size_t der_max,
                                int *hint);

extern hal_error_t hal_ks_delete(const hal_key_type_t type,
                                 const uint8_t * const name, const size_t name_len,
                                 int *hint);

extern hal_error_t hal_ks_list(hal_rpc_pkey_key_info_t *result,
                               unsigned *result_len,
                               const unsigned result_max);

#endif /* _HAL_INTERNAL_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */