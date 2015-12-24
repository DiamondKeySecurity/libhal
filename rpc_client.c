/*
 * rpc_client.c
 * ------------
 * Remote procedure call client-side private API implementation.
 *
 * Authors: Rob Austein
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

#include "hal.h"
#include "hal_internal.h"

/*
 * RPC calls.  Not implemented yet.
 */

#warning These are all placeholders, waiting to be filled in with the real RPC calls

static hal_error_t get_random(void *buffer, const size_t length)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t set_pin(const hal_client_handle_t client,
                           const hal_user_t user,
                           const char * const newpin, const size_t newpin_len)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t login(const hal_client_handle_t client,
                         const hal_user_t user,
                         const char * const pin, const size_t pin_len)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t logout(const hal_client_handle_t client)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t hash_get_digest_len(const hal_digest_algorithm_t alg, size_t *length)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t hash_get_digest_algorithm_id(const hal_digest_algorithm_t alg,
                                                uint8_t *id, size_t *len, const size_t len_max)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t hash_get_algorithm(const hal_hash_handle_t hash, hal_digest_algorithm_t *alg)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t hash_initialize(const hal_client_handle_t client,
                                   const hal_session_handle_t session,
                                   hal_hash_handle_t *hash,
                                   const hal_digest_algorithm_t alg,
                                   const uint8_t * const key, const size_t key_len)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t hash_update(const hal_hash_handle_t hash,
                               const uint8_t * data, const size_t length)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t hash_finalize(const hal_hash_handle_t hash,
                                 uint8_t *digest, const size_t length)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_load(const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             hal_pkey_handle_t *pkey,
                             const hal_key_type_t type,
                             const hal_curve_name_t curve,
                             const uint8_t * const name, const size_t name_len,
                             const uint8_t * const der, const size_t der_len,
                             const hal_key_flags_t flags)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_find(const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             hal_pkey_handle_t *pkey,
                             const hal_key_type_t type,
                             const uint8_t * const name, const size_t name_len)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_generate_rsa(const hal_client_handle_t client,
                                     const hal_session_handle_t session,
                                     hal_pkey_handle_t *pkey,
                                     const uint8_t * const name, const size_t name_len,
                                     const unsigned key_len,
                                     const uint8_t * const exp, const size_t exp_len,
                                     const hal_key_flags_t flags)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_generate_ec(const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    hal_pkey_handle_t *pkey,
                                    const uint8_t * const name, const size_t name_len,
                                    const hal_curve_name_t curve,
                                    const hal_key_flags_t flags)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_close(const hal_pkey_handle_t pkey)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_delete(const hal_pkey_handle_t pkey)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_get_key_type(const hal_pkey_handle_t pkey,
                                     hal_key_type_t *type)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_get_key_flags(const hal_pkey_handle_t pkey,
                                      hal_key_flags_t *flags)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static size_t pkey_get_public_key_len(const hal_pkey_handle_t pkey)
{
  return 0;
}

static hal_error_t pkey_get_public_key(const hal_pkey_handle_t pkey,
                                       uint8_t *der, size_t *der_len, const size_t der_max)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_remote_sign(const hal_session_handle_t session,
                                    const hal_pkey_handle_t pkey,
                                    const hal_hash_handle_t hash,
                                    const uint8_t * const input,  const size_t input_len,
                                    uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_remote_verify(const hal_session_handle_t session,
                                      const hal_pkey_handle_t pkey,
                                      const hal_hash_handle_t hash,
                                      const uint8_t * const input, const size_t input_len,
                                      const uint8_t * const signature, const size_t signature_len)
{
  return HAL_ERROR_IMPOSSIBLE;
}

static hal_error_t pkey_list(hal_pkey_info_t *result,
                             unsigned *result_len,
                             const unsigned result_max)
{
  return HAL_ERROR_IMPOSSIBLE;
}


/*
 * "Mixed" mode pkey operations, where the public key operation itself
 * takes place on the HSM but the hashing takes place locally.  If
 * we're given a hash context in this case, it's local, so we have to
 * pull the digest from the hash context and send that to the HSM.
 */

static hal_error_t pkey_mixed_sign(const hal_session_handle_t session,
                                   const hal_pkey_handle_t pkey,
                                   const hal_hash_handle_t hash,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  if (input != NULL)
    return pkey_remote_sign(session, pkey, hash, input, input_len,
                            signature, signature_len, signature_max);

  hal_digest_algorithm_t alg;
  size_t digest_len;
  hal_error_t err;

  if ((err = hal_rpc_hash_get_algorithm(hash, &alg))           != HAL_OK ||
      (err = hal_rpc_hash_get_digest_length(alg, &digest_len)) != HAL_OK)
    return err;

  uint8_t digest[digest_len];

  if ((err = hal_rpc_hash_finalize(hash, digest, digest_len)) != HAL_OK)
    return err;

  return pkey_remote_sign(session, pkey, hal_hash_handle_none, digest, digest_len,
                          signature, signature_len, signature_max);
}

static hal_error_t pkey_mixed_verify(const hal_session_handle_t session,
                                     const hal_pkey_handle_t pkey,
                                     const hal_hash_handle_t hash,
                                     const uint8_t * const input, const size_t input_len,
                                     const uint8_t * const signature, const size_t signature_len)
{
  if (input != NULL)
    return pkey_remote_verify(session, pkey, hash, input, input_len,
                              signature, signature_len);

  hal_digest_algorithm_t alg;
  size_t digest_len;
  hal_error_t err;

  if ((err = hal_rpc_hash_get_algorithm(hash, &alg))           != HAL_OK ||
      (err = hal_rpc_hash_get_digest_length(alg, &digest_len)) != HAL_OK)
    return err;

  uint8_t digest[digest_len];

  if ((err = hal_rpc_hash_finalize(hash, digest, digest_len)) != HAL_OK)
    return err;

  return pkey_remote_verify(session, pkey, hal_hash_handle_none, digest, digest_len,
                            signature, signature_len);
}

/*
 * Dispatch vectors.
 */

const hal_rpc_misc_dispatch_t hal_rpc_remote_misc_dispatch = {
  set_pin, login, logout, get_random
};

const hal_rpc_hash_dispatch_t hal_rpc_remote_hash_dispatch = {
  hash_get_digest_len, hash_get_digest_algorithm_id, hash_get_algorithm,
  hash_initialize, hash_update, hash_finalize
};

const hal_rpc_pkey_dispatch_t hal_rpc_remote_pkey_dispatch = {
  pkey_load, pkey_find, pkey_generate_rsa, pkey_generate_ec, pkey_close, pkey_delete,
  pkey_get_key_type, pkey_get_key_flags, pkey_get_public_key_len, pkey_get_public_key,
  pkey_remote_sign, pkey_remote_verify,
  pkey_list
};

const hal_rpc_pkey_dispatch_t hal_rpc_mixed_pkey_dispatch = {
  pkey_load, pkey_find, pkey_generate_rsa, pkey_generate_ec, pkey_close, pkey_delete,
  pkey_get_key_type, pkey_get_key_flags, pkey_get_public_key_len, pkey_get_public_key,
  pkey_mixed_sign, pkey_mixed_verify,
  pkey_list
};

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
