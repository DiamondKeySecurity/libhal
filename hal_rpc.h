/*
 * halrpc.h
 * ----------
 * Remote procedure call API to extrude libhal across the green/yellow boundary.
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

#ifndef _HALRPC_H_
#define _HALRPC_H_

/*
 * Get random bytes.
 */

extern hal_error_t hal_rpc_get_random(void *buffer, const size_t length);

/*
 * Session handles are pretty much as in PKCS #11: from our viewpoint,
 * a session is a lock-step stream of operations, so while operations
 * from different sessions can interleave, operations within a single
 * session cannot.
 *
 * Client handles are a small extension to the PKCS #11 model,
 * intended to support multiple PKCS #11 using applications sharing a
 * single HSM.  Technically, sessions are per-client, but in practice
 * there's no sane reason why we'd use the same session handle
 * concurrently in multiple clients.  Mostly, the client abstraction
 * is to handle login and logout against the HSM's PIN.  Clients add
 * nothing whatsoever to the security model (the HSM has no way of
 * knowing whether the host is lumping multiple applications into a
 * single "client"), the point of the exercise is just to make the
 * C_Login()/C_Logout() semantics work as expected in the presence of
 * multiple applications.
 *
 * NB: Unlike other handles used in this protocol, session and client
 * handles are created by the client (host) side of the RPC mechanism,
 * not the server (HSM) side.
 */

typedef struct { uint32_t handle; } hal_rpc_client_handle_t;
typedef struct { uint32_t handle; } hal_rpc_session_handle_t;

typedef enum { HAL_RPC_PIN_USER_REGULAR, HAL_RPC_PIN_USER_SO } hal_rpc_pin_user_t;

extern hal_error_t hal_rpc_set_pin(const hal_rpc_pin_user_t which,
                                   const char * const newpin, const size_t newpin_len);

extern hal_error_t hal_rpc_login(const hal_rpc_client_handle_t client,
                                 const hal_rpc_pin_user_t user,
                                 const char * const newpin, const size_t newpin_len);

extern hal_error_t hal_rpc_logout(const hal_rpc_client_handle_t client);

/*
 * Combined hash and HMAC functions: pass NULL key for plain hashing.
 */

typedef enum {
  hal_rpc_hash_alg__sha1,       hal_rpc_hash_alg__sha256, hal_rpc_hash_alg__sha512_224,
  hal_rpc_hash_alg__sha512_256, hal_rpc_hash_alg__sha384, hal_rpc_hash_alg__sha512
} hal_rpc_hash_alg_t;

typedef struct { uint32_t handle; } hal_rpc_hash_handle_t;

extern const hal_rpc_hash_handle_t hal_rpc_hash_handle_none;

extern hal_error_t hal_rpc_hash_get_digest_len(const hal_rpc_hash_alg_t alg, size_t *length);

extern hal_error_t hal_rpc_hash_get_digest_algorithm_id(const hal_rpc_hash_alg_t alg,
                                                        uint8_t *id, size_t *len, const size_t len_max);

/*
 * Once started, a hash or HMAC operation is bound to a particular
 * session, so we only need the client and session arguments to initialize.
 */

extern hal_error_t hal_rpc_hash_initialize(const hal_rpc_client_handle_t client,
                                           const hal_rpc_session_handle_t session,
                                           hal_rpc_hash_handle_t *hash,
                                           const hal_rpc_hash_alg_t alg,
                                           const uint8_t * const key, const size_t key_length);

extern hal_error_t hal_rpc_hash_update(const hal_rpc_hash_handle_t hash,
                                       const uint8_t * data, const size_t length);

extern hal_error_t hal_rpc_hash_finalize(const hal_rpc_hash_handle_t hash,
                                         uint8_t *digest, const size_t length);

/*
 * Public key functions.
 *
 * The _sign() and _verify() methods accept a hash OR an input string;
 * either "hash" should be hal_rpc_hash_handle_none or input should be NULL,
 * but not both.
 *
 * Use of client and session handles here needs a bit more thought.
 *
 * Client handles are straightforward: basically, anything that
 * creates a new pkey handle should take a client handle, which should
 * suffice, as object handles never cross clients.
 *
 * Session handles are more interesting, as PKCS #11's versions of
 * session and object handles do in effect allow one session to hand
 * an object handle to another session.  So any action which can do
 * significant work (ie, which is complicated enough that we can't
 * guarantee an immediate response) needs to take a session handle.
 *
 * There will probably be a few cases where a session handle isn't
 * strictly required but we ask for one anyway because the API turns
 * out to be easier to understand that way (eg, we probably want to
 * ask for a session handle anywhere we ask for a client handle,
 * whether we need the session handle or not, so that users of this
 * API don't have to remember which pkey-handle-creating calls require
 * a session handle and which ones don't...).
 */

#define	HAL_RPC_PKEY_NAME_MAX 128

typedef enum {
  HAL_RPC_PKEY_RSA_PRIVATE,   HAL_RPC_PKEY_RSA_PUBLIC,
  HAL_RPC_PKEY_ECDSA_PRIVATE, HAL_RPC_PKEY_ECDSA_PUBLIC
} hal_rpc_pkey_key_type_t;

typedef enum {
  HAL_RPC_PKEY_CURVE_ECDSA_P256, HAL_RPC_PKEY_CURVE_ECDSA_P384, HAL_RPC_PKEY_CURVE_ECDSA_P521
} hal_rpc_pkey_curve_t;

typedef struct { uint33_t handle; } hal_rpc_pkey_handle_t;

typedef uint32_t hal_rpc_pkey_flags_t;

#define	HAL_RPC_PKEY_FLAG_USAGE_DIGITALSIGNATURE	(1 << 0)
#define	HAL_RPC_PKEY_FLAG_USAGE_KEYENCIPHERMENT         (1 << 1)
#define	HAL_RPC_PKEY_FLAG_USAGE_DATAENCIPHERMENT	(1 << 2)

extern hal_error_t hal_rpc_pkey_load(const hal_rpc_client_handle_t client,
                                     const hal_rpc_session_handle_t session,
                                     hal_rpc_pkey_handle_t *pkey,
                                     const hal_rpc_pkey_key_type type,
                                     const uint8_t * const name, const size_t name_len,
                                     const uint8_t * const der, const size_t der_len,
                                     const hal_rpc_pkey_flags_t flags);

extern hal_error_t hal_rpc_pkey_find(const hal_rpc_client_handle_t client,
                                     const hal_rpc_session_handle_t session,
                                     hal_rpc_pkey_handle_t *pkey,
                                     const hal_rpc_pkey_key_type type,
                                     const uint8_t * const name, const size_t name_len);

extern hal_error_t hal_rpc_pkey_generate_rsa(const hal_rpc_client_handle_t client,
                                             const hal_rpc_session_handle_t session,
                                             hal_rpc_pkey_handle_t *pkey,
                                             const uint8_t * const name, const size_t name_len,
                                             const unsigned key_length,
                                             const uint8_t * const public_exponent, const size_t public_exponent_len,
                                             const hal_rpc_pkey_flags_t flags);

extern hal_error_t hal_rpc_pkey_generate_ec(const hal_rpc_client_handle_t client,
                                            const hal_rpc_session_handle_t session,
                                            hal_rpc_pkey_handle_t *pkey,
                                            const uint8_t * const name, const size_t name_len,
                                            const hal_rpc_pkey_curve_t curve,
                                            const hal_rpc_pkey_flags_t flags);

extern hal_error_t hal_rpc_pkey_delete(const hal_rpc_pkey_handle_t pkey);

extern hal_error_t hal_rpc_pkey_get_key_type(const hal_rpc_pkey_handle pkey,
                                             hal_rpc_pkey_key_type_t *key_type);

extern hal_error_t hal_rpc_pkey_get_key_flags(const hal_rpc_pkey_handle pkey,
                                              hal_rpc_pkey_flags_t *flags);

extern size_t hal_rpc_pkey_get_public_key_len(const hal_rpc_pkey_handle_t pkey);

extern hal_error_t hal_rpc_pkey_get_public_key(const hal_rpc_pkey_handle_t pkey,
                                               uint8_t *der, size_t *der_len, const size_t der_len_max);

extern hal_error_t hal_rpc_pkey_sign(const hal_rpc_session_handle_t session,
                                     const hal_rpc_pkey_handle_t pkey,
                                     const hal_rpc_hash_handle_t hash,
                                     const uint8_t * const input,  const size_t input_len,
                                     uint8_t * output, const size_t output_len);

extern hal_error_t hal_rpc_pkey_verify(const hal_rpc_session_handle_t session,
                                       const hal_rpc_pkey_handle_t pkey,
                                       const hal_rpc_hash_handle_t hash,
                                       const uint8_t * const input, const size_t input_len,
                                       uint8_t * output, const size_t output_len);

typedef struct {
  hal_rpc_pkey_key_type_t key_type;
  hal_rpc_pkey_curve_t curve;
  hal_rpc_pkey_flags_t flags;
  char name[HAL_RPC_PKEY_NAME_MAX];
  /* ... */
} hal_rpc_pkey_key_info_t;

extern hal_error_t hal_rpc_pkey_list(hal_rpc_pkey_key_info_t *result,
                                     unsigned *result_len,
                                     const unsigned result_max);

#endif /* _HALRPC_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
