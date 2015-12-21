/*
 * rpc_pkey.c
 * ----------
 * Remote procedure call server-side public key implementation.
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

#include <string.h>
#include <assert.h>

#include "hal.h"
#include "hal_internal.h"

typedef struct {
  hal_rpc_client_handle_t client_handle;
  hal_rpc_session_handle_t session_handle;
  hal_rpc_pkey_handle_t pkey_handle;
  hal_key_type_t type;
  hal_curve_name_t curve;
  hal_key_flags_t flags;
  uint8_t name[HAL_RPC_PKEY_NAME_MAX];
  size_t name_len;
  int ks_hint;
  /*
   * This might be where we'd stash a (hal_core_t *) pointing to a
   * core which has already been loaded with the key, if we were
   * trying to be clever about using multiple signing cores.  Moot
   * point (ie, no way we could possibly test such a thing) as long as
   * the FPGA is too small to hold more than one modexp core and ECDSA
   * is entirely software, so skip it for now, but the implied
   * semantics are interesting: a pkey handle starts to resemble an
   * initialized signing core, and once all the cores are in use, one
   * can't load another key without closing an existing pkey handle.
   */
} pkey_slot_t;

#ifndef HAL_STATIC_PKEY_STATE_BLOCKS
#define HAL_STATIC_PKEY_STATE_BLOCKS 0
#endif

#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
static pkey_slot_t pkey_handle[HAL_STATIC_PKEY_STATE_BLOCKS];
#endif

/*
 * Handle allocation is simple: we look for an unused (name_len == 0)
 * slot in the table, and, assuming we find one, construct a composite
 * handle consisting of the index into the table and a counter whose
 * sole purpose is to keep the same handle from reoccurring anytime
 * soon, to help identify use-after-free bugs in calling code.
 */

static inline pkey_slot_t *alloc_slot(void)
{
#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
  static uint16_t next_glop = 0;
  uint32_t glop = ++next_glop << 16;
  next_glop %= 0xFFFF;

  for (int i = 0; i < sizeof(pkey_handle)/sizeof(*pkey_handle); i++) {
    if (pkey_handle[i].name_len > 0)
      continue;
    pkey_handle[i].pkey_handle.handle = i | glop;
    pkey_handle[i].ks_hint = -1;
    return &pkey_handle[i];
  }
#endif

  return NULL;
}

/*
 * Check a caller-supplied handle.  Must be in range, in use, and have
 * the right glop.  Returns slot pointer on success, NULL otherwise.
 */

static inline pkey_slot_t *find_handle(const hal_rpc_pkey_handle_t handle)
{
#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
  const int i = (int) (handle.handle & 0xFFFF);

  if (i < sizeof(pkey_handle)/sizeof(*pkey_handle) && pkey_handle[i].pkey_handle.handle == handle.handle)
    return &pkey_handle[i];
#endif

  return NULL;
}

/*
 * Construct a PKCS #1 DigestInfo object.  This requires some (very
 * basic) ASN.1 encoding, which we perform inline.
 */

static hal_error_t pkcs1_construct_digestinfo(const hal_rpc_hash_handle_t handle,
                                              uint8_t *digest_info, size_t *digest_info_len, const size_t digest_info_max)
{
  assert(digest_info != NULL && digest_info_len != NULL);

  hal_digest_algorithm_t alg;
  size_t len, alg_len;
  hal_error_t err;

  if ((err = hal_rpc_hash_get_algorithm(handle, &alg))                     != HAL_OK ||
      (err = hal_rpc_hash_get_digest_length(alg, &len))                    != HAL_OK ||
      (err = hal_rpc_hash_get_digest_algorithm_id(alg, NULL, &alg_len, 0)) != HAL_OK)
    return err;

  *digest_info_len = len + alg_len + 4;

  if (*digest_info_len >= digest_info_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  assert(*digest_info_len < 130);

  uint8_t *d = digest_info;

  *d++ = 0x30;                /* SEQUENCE */
  *d++ = (uint8_t) (*digest_info_len - 2);

  if ((err = hal_rpc_hash_get_digest_algorithm_id(alg, d, NULL, alg_len)) != HAL_OK)
    return err;
  d += alg_len;

  *d++ = 0x04;                /* OCTET STRING */
  *d++ = (uint8_t) len;

  assert(digest_info + *digest_info_len == d + len);

  return hal_rpc_hash_finalize(handle, d, len);
}

/*
 * Pad an octet string with PKCS #1.5 padding for use with RSA.
 *
 * For the moment, this only handles type 01 encryption blocks, thus
 * is only suitable for use with signature and verification.  If and
 * when we add support for encryption and decryption, this function
 * should be extended to take an argument specifying the block type
 * and include support for generating type 02 encryption blocks.
 * Other than the block type code, the only difference is the padding
 * value: for type 01 it's constant (0xFF), for type 02 it should be
 * non-zero random bytes from the CSPRNG.
 *
 * We use memmove() instead of memcpy() so that the caller can
 * construct the data to be padded in the same buffer.
 */

static hal_error_t pkcs1_5_pad(const uint8_t * const data, const size_t data_len,
                               uint8_t *block, const size_t block_len)
{
  assert(data != NULL && block != NULL);

  /*
   * Congregation will now please turn to RFC 2313 8.1 as we
   * construct a PKCS #1.5 type 01 encryption block.
   */

  if (data_len > block_len - 11)
    return HAL_ERROR_RESULT_TOO_LONG;

  memmove(block + block_len - data_len, data, data_len);

  block[0] = 0x00;
  block[1] = 0x01;

  /* This is where we'd use non-zero random bytes if constructing a type 02 block. */
  memset(block + 2, 0xFF, block_len - 3 - data_len);

  block[block_len - data_len - 1] = 0x00;

  return HAL_OK;
}

/*
 * Receive key from application, store it with supplied name, return a key handle.
 */

static hal_error_t load(const hal_rpc_client_handle_t client,
                        const hal_rpc_session_handle_t session,
                        hal_rpc_pkey_handle_t *pkey,
                        const hal_key_type_t type,
                        const hal_curve_name_t curve,
                        const uint8_t * const name, const size_t name_len,
                        const uint8_t * const der, const size_t der_len,
                        const hal_key_flags_t flags)
{
  pkey_slot_t *slot;
  hal_error_t err;

  assert(sizeof(slot->name) >= name_len && pkey != NULL);

  if ((slot = alloc_slot()) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  if ((err = hal_ks_store(type, curve, flags, name, name_len, der, der_len, &slot->ks_hint)) != HAL_OK)
    return err;

  memcpy(slot->name, name, name_len);
  slot->client_handle = client;
  slot->session_handle = session;
  slot->type = type;
  slot->curve = curve;
  slot->flags = flags;
  slot->name_len = name_len;

  *pkey = slot->pkey_handle;
  return HAL_OK;
}

/*
 * Look up a key given its name, return a key handle.
 */

static hal_error_t find(const hal_rpc_client_handle_t client,
                        const hal_rpc_session_handle_t session,
                        hal_rpc_pkey_handle_t *pkey,
                        const hal_key_type_t type,
                        const uint8_t * const name, const size_t name_len)
{
  pkey_slot_t *slot;
  hal_error_t err;

  assert(sizeof(slot->name) >= name_len && pkey != NULL);

  if ((slot = alloc_slot()) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  if ((err = hal_ks_fetch(type, name, name_len, &slot->curve, &slot->flags, NULL, NULL, 0, &slot->ks_hint)) != HAL_OK)
    return err;

  memcpy(slot->name, name, name_len);
  slot->client_handle = client;
  slot->session_handle = session;
  slot->type = type;
  slot->name_len = name_len;

  *pkey = slot->pkey_handle;
  return HAL_OK;
}

/*
 * Generate a new RSA key with supplied name, return a key handle.
 */

static hal_error_t generate_rsa(const hal_rpc_client_handle_t client,
                                const hal_rpc_session_handle_t session,
                                hal_rpc_pkey_handle_t *pkey,
                                const uint8_t * const name, const size_t name_len,
                                const unsigned key_length,
                                const uint8_t * const public_exponent, const size_t public_exponent_len,
                                const hal_key_flags_t flags)
{
  pkey_slot_t *slot;
  hal_error_t err;

  assert(sizeof(slot->name) >= name_len && pkey != NULL && (key_length & 7) == 0);

  if ((slot = alloc_slot()) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  uint8_t keybuf[hal_rsa_key_t_size];
  hal_rsa_key_t *key = NULL;

  if ((err = hal_rsa_key_gen(NULL, &key, keybuf, sizeof(keybuf), key_length / 8,
                             public_exponent, public_exponent_len)) != HAL_OK)
    return err;

  uint8_t der[hal_rsa_key_to_der_len(key)];
  size_t der_len;

  if ((err = hal_rsa_key_to_der(key, der, &der_len, sizeof(der))) == HAL_OK)
    err = hal_ks_store(HAL_KEY_TYPE_RSA_PRIVATE, HAL_CURVE_NONE, flags,
                       name, name_len, der, der_len, &slot->ks_hint);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der, 0, sizeof(der));

  if (err != HAL_OK)
    return err;

  memcpy(slot->name, name, name_len);
  slot->client_handle = client;
  slot->session_handle = session;
  slot->type = HAL_KEY_TYPE_RSA_PRIVATE;
  slot->curve = HAL_CURVE_NONE;
  slot->flags = flags;
  slot->name_len = name_len;

  *pkey = slot->pkey_handle;
  return HAL_OK;
}

/*
 * Generate a new EC key with supplied name, return a key handle.
 * At the moment, EC key == ECDSA key, but this is subject to change.
 */

static hal_error_t generate_ec(const hal_rpc_client_handle_t client,
                               const hal_rpc_session_handle_t session,
                               hal_rpc_pkey_handle_t *pkey,
                               const uint8_t * const name, const size_t name_len,
                               const hal_curve_name_t curve,
                               const hal_key_flags_t flags)
{
  pkey_slot_t *slot;
  hal_error_t err;

  assert(sizeof(slot->name) >= name_len && pkey != NULL);

  if ((slot = alloc_slot()) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  uint8_t keybuf[hal_ecdsa_key_t_size];
  hal_ecdsa_key_t *key = NULL;

  if ((err = hal_ecdsa_key_gen(NULL, &key, keybuf, sizeof(keybuf), curve)) != HAL_OK)
    return err;

  uint8_t der[hal_ecdsa_key_to_der_len(key)];
  size_t der_len;

  if ((err = hal_ecdsa_key_to_der(key, der, &der_len, sizeof(der))) == HAL_OK)
    err = hal_ks_store(HAL_KEY_TYPE_EC_PRIVATE, curve, flags,
                       name, name_len, der, der_len, &slot->ks_hint);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der, 0, sizeof(der));

  if (err != HAL_OK)
    return err;

  memcpy(slot->name, name, name_len);
  slot->client_handle = client;
  slot->session_handle = session;
  slot->type = HAL_KEY_TYPE_EC_PRIVATE;
  slot->curve = curve;
  slot->flags = flags;
  slot->name_len = name_len;

  *pkey = slot->pkey_handle;
  return HAL_OK;
}

/*
 * Discard key handle, leaving key intact.
 */

static hal_error_t close(const hal_rpc_pkey_handle_t pkey)
{
  pkey_slot_t *slot;

  if ((slot = find_handle(pkey)) == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  memset(slot, 0, sizeof(*slot));

  return HAL_OK;
}

/*
 * Delete a key from the store, given its key handle.
 */

static hal_error_t delete(const hal_rpc_pkey_handle_t pkey)
{
  pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_error_t err = hal_ks_delete(slot->type, slot->name, slot->name_len, &slot->ks_hint);

  if (err == HAL_OK || err == HAL_ERROR_KEY_NOT_FOUND)
    memset(slot, 0, sizeof(*slot));    

  return err;
}

/*
 * Get type of key associated with handle.
 */

static hal_error_t get_key_type(const hal_rpc_pkey_handle_t pkey,
                                hal_key_type_t *type)
{
  if (type == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  *type = slot->type;

  return HAL_OK;
}

/*
 * Get flags of key associated with handle.
 */

static hal_error_t get_key_flags(const hal_rpc_pkey_handle_t pkey,
                                 hal_key_flags_t *flags)
{
  if (flags == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  *flags = slot->flags;

  return HAL_OK;
}

/*
 * Get length of public key associated with handle.
 */

static size_t get_public_key_len(const hal_rpc_pkey_handle_t pkey)
{
  return 0;
}

/*
 * Get public key associated with handle.
 */

static hal_error_t get_public_key(const hal_rpc_pkey_handle_t pkey,
                                  uint8_t *der, size_t *der_len, const size_t der_len_max)
{
  /*
   * Still missing some of the public key format ASN.1 stuff, apparently.  Feh.
   */
  return HAL_ERROR_IMPOSSIBLE;
#warning get_public_key() not implemented
}

/*
 * Sign something using private key associated with handle.
 *
 * RSA has enough quirks that it's simplest to split this out into
 * algorithm-specific functions.
 */

static hal_error_t sign_rsa(uint8_t *keybuf, const size_t keybuf_len,
                            const uint8_t * const der, const size_t der_len,
                            const hal_rpc_hash_handle_t hash,
                            const uint8_t * input, size_t input_len,
                            uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  hal_rsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len != NULL);
  assert((hash.handle == hal_rpc_hash_handle_none.handle) != (input == NULL || input_len == 0));

  if ((err = hal_rsa_key_from_der(&key, keybuf, keybuf_len, der, der_len)) != HAL_OK ||
      (err = hal_rsa_key_get_modulus(key, NULL, signature_len, 0))         != HAL_OK)
    return err;

  if (*signature_len > signature_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  if (input == NULL) {
    if ((err = pkcs1_construct_digestinfo(hash, signature, &input_len, *signature_len)) != HAL_OK)
      return err;
    input = signature;
  }

  if ((err = pkcs1_5_pad(input, input_len, signature, *signature_len))                         != HAL_OK ||
      (err = hal_rsa_decrypt(NULL, key, signature, *signature_len, signature, *signature_len)) != HAL_OK)
    return err;

  return HAL_OK;
}

static hal_error_t sign_ecdsa(uint8_t *keybuf, const size_t keybuf_len,
                              const uint8_t * const der, const size_t der_len,
                              const hal_rpc_hash_handle_t hash,
                              const uint8_t * input, size_t input_len,
                              uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  hal_ecdsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len != NULL);
  assert((hash.handle == hal_rpc_hash_handle_none.handle) != (input == NULL || input_len == 0));

  if ((err = hal_ecdsa_key_from_der(&key, keybuf, keybuf_len, der, der_len)) != HAL_OK)
    return err;

  if (input == NULL) {
    hal_digest_algorithm_t alg;

    if ((err = hal_rpc_hash_get_algorithm(hash, &alg))          != HAL_OK ||
        (err = hal_rpc_hash_get_digest_length(alg, &input_len)) != HAL_OK)
      return err;

    if (input_len < signature_max)
      return HAL_ERROR_RESULT_TOO_LONG;

    if ((err = hal_rpc_hash_finalize(hash, signature, input_len)) != HAL_OK)
      return err;

    input = signature;
  }

  if ((err = hal_ecdsa_sign(NULL, key, input, input_len, signature, signature_len, signature_max)) != HAL_OK)
    return err;

  return HAL_OK;
}

static hal_error_t sign(const hal_rpc_session_handle_t session,
                        const hal_rpc_pkey_handle_t pkey,
                        const hal_rpc_hash_handle_t hash,
                        const uint8_t * const input,  const size_t input_len,
                        uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_error_t (*signer)(uint8_t *keybuf, const size_t keybuf_len,
                        const uint8_t * const der, const size_t der_len,
                        const hal_rpc_hash_handle_t hash,
                        const uint8_t * const input,  const size_t input_len,
                        uint8_t * signature, size_t *signature_len, const size_t signature_max);

  switch (slot->type) {
  case HAL_KEY_TYPE_RSA_PRIVATE:
    signer = sign_rsa;
    break;
  case HAL_KEY_TYPE_EC_PRIVATE:
    signer = sign_ecdsa;
    break;
  default:
    return HAL_ERROR_UNSUPPORTED_KEY;
  }

  uint8_t keybuf[hal_rsa_key_t_size > hal_ecdsa_key_t_size ? hal_rsa_key_t_size : hal_ecdsa_key_t_size];
  uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
  size_t der_len;
  hal_error_t err;

  err = hal_ks_fetch(slot->type, slot->name, slot->name_len, NULL, NULL, der, &der_len, sizeof(der), &slot->ks_hint);

  if (err == HAL_OK)
    err = signer(keybuf, sizeof(keybuf), der, der_len, hash, input, input_len, signature, signature_len, signature_max);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der,    0, sizeof(der));

  return err;
}

/*
 * Verify something using private key associated with handle.
 *
 * RSA has enough quirks that it's simplest to split this out into
 * algorithm-specific functions.
 */

static hal_error_t verify_rsa(uint8_t *keybuf, const size_t keybuf_len,
                              const uint8_t * const der, const size_t der_len,
                              const hal_rpc_hash_handle_t hash,
                              const uint8_t * input, size_t input_len,
                              const uint8_t * const signature, const size_t signature_len)
{
  uint8_t expected[signature_len], received[signature_len];
  hal_rsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len > 0);
  assert((hash.handle == hal_rpc_hash_handle_none.handle) != (input == NULL || input_len == 0));

  if ((err = hal_rsa_key_from_der(&key, keybuf, keybuf_len, der, der_len)) != HAL_OK)
    return err;

  if (input == NULL) {
    if ((err = pkcs1_construct_digestinfo(hash, expected, &input_len, sizeof(expected))) != HAL_OK)
      return err;
    input = expected;
  }

  if ((err = pkcs1_5_pad(input, input_len, expected, sizeof(expected)))                        != HAL_OK ||
      (err = hal_rsa_encrypt(NULL, key, signature, signature_len, received, sizeof(received))) != HAL_OK)
    return err;

  unsigned diff = 0;
  for (int i = 0; i < signature_len; i++)
    diff |= expected[i] ^ received[i];

  if (diff != 0)
    return HAL_ERROR_INVALID_SIGNATURE;

  return HAL_OK;
}

static hal_error_t verify_ecdsa(uint8_t *keybuf, const size_t keybuf_len,
                                const uint8_t * const der, const size_t der_len,
                                const hal_rpc_hash_handle_t hash,
                                const uint8_t * input, size_t input_len,
                                const uint8_t * const signature, const size_t signature_len)
{
  uint8_t digest[signature_len];
  hal_ecdsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len > 0);
  assert((hash.handle == hal_rpc_hash_handle_none.handle) != (input == NULL || input_len == 0));

  if ((err = hal_ecdsa_key_from_der(&key, keybuf, keybuf_len, der, der_len)) != HAL_OK)
    return err;

  if (input == NULL) {
    hal_digest_algorithm_t alg;

    if ((err = hal_rpc_hash_get_algorithm(hash, &alg))              != HAL_OK ||
        (err = hal_rpc_hash_get_digest_length(alg, &input_len))     != HAL_OK ||
        (err = hal_rpc_hash_finalize(hash, digest, sizeof(digest))) != HAL_OK)
      return err;

    input = digest;
  }

  if ((err = hal_ecdsa_verify(NULL, key, input, input_len, signature, signature_len)) != HAL_OK)
    return err;

  return HAL_OK;
}

static hal_error_t verify(const hal_rpc_session_handle_t session,
                          const hal_rpc_pkey_handle_t pkey,
                          const hal_rpc_hash_handle_t hash,
                          const uint8_t * const input, const size_t input_len,
                          const uint8_t * const signature, const size_t signature_len)
{
  pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_error_t (*verifier)(uint8_t *keybuf, const size_t keybuf_len,
                          const uint8_t * const der, const size_t der_len,
                          const hal_rpc_hash_handle_t hash,
                          const uint8_t * const input,  const size_t input_len,
                          const uint8_t * const signature, const size_t signature_len);

  switch (slot->type) {
  case HAL_KEY_TYPE_RSA_PRIVATE:
  case HAL_KEY_TYPE_RSA_PUBLIC:
    verifier = verify_rsa;
    break;
  case HAL_KEY_TYPE_EC_PRIVATE:
  case HAL_KEY_TYPE_EC_PUBLIC:
    verifier = verify_ecdsa;
    break;
  default:
    return HAL_ERROR_UNSUPPORTED_KEY;
  }

  uint8_t keybuf[hal_rsa_key_t_size > hal_ecdsa_key_t_size ? hal_rsa_key_t_size : hal_ecdsa_key_t_size];
  uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
  size_t der_len;
  hal_error_t err;

  err = hal_ks_fetch(slot->type, slot->name, slot->name_len, NULL, NULL, der, &der_len, sizeof(der), &slot->ks_hint);

  if (err == HAL_OK)
    err = verifier(keybuf, sizeof(keybuf), der, der_len, hash, input, input_len, signature, signature_len);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der,    0, sizeof(der));

  return err;
}


/*
 * List keys in the key store.
 */

static hal_error_t list(hal_rpc_pkey_key_info_t *result,
                        unsigned *result_len,
                        const unsigned result_max)
{
  return hal_ks_list(result, result_len, result_max);
}

const hal_rpc_pkey_dispatch_t hal_rpc_local_pkey_dispatch = {
  load, find, generate_rsa, generate_ec, close, delete,
  get_key_type, get_key_flags, get_public_key_len, get_public_key,
  sign, verify, list
};

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */