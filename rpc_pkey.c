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

#ifndef HAL_STATIC_PKEY_STATE_BLOCKS
#define HAL_STATIC_PKEY_STATE_BLOCKS 0
#endif

#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
static hal_pkey_slot_t pkey_handle[HAL_STATIC_PKEY_STATE_BLOCKS];
#endif

/*
 * Handle allocation is simple: look for an unused (HAL_KEY_TYPE_NONE)
 * slot in the table, and, assuming we find one, construct a composite
 * handle consisting of the index into the table and a counter whose
 * sole purpose is to keep the same handle from reoccurring anytime
 * soon, to help identify use-after-free bugs in calling code.
 *
 * The high order bit of the pkey handle is left free for
 * HAL_PKEY_HANDLE_TOKEN_FLAG, which is used by the mixed-mode
 * handlers to route calls to the appropriate destination.
 */

static inline hal_pkey_slot_t *alloc_slot(const hal_key_flags_t flags)
{
  hal_pkey_slot_t *slot = NULL;
  hal_critical_section_start();

#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
  static uint16_t next_glop = 0;
  uint32_t glop = ++next_glop << 16;
  next_glop %= 0x7FFF;

  assert((glop & HAL_PKEY_HANDLE_TOKEN_FLAG) == 0);

  if ((flags & HAL_KEY_FLAG_TOKEN) != 0)
    glop |= HAL_PKEY_HANDLE_TOKEN_FLAG;

  for (int i = 0; slot == NULL && i < sizeof(pkey_handle)/sizeof(*pkey_handle); i++) {
    if (pkey_handle[i].type != HAL_KEY_TYPE_NONE)
      continue;
    memset(&pkey_handle[i], 0, sizeof(pkey_handle[i]));
    pkey_handle[i].pkey_handle.handle = i | glop;
    pkey_handle[i].hint = -1;
    slot = &pkey_handle[i];
  }
#endif

  hal_critical_section_end();
  return slot;
}

/*
 * Check a caller-supplied handle.  Must be in range, in use, and have
 * the right glop.  Returns slot pointer on success, NULL otherwise.
 */

static inline hal_pkey_slot_t *find_handle(const hal_pkey_handle_t handle)
{
  hal_pkey_slot_t *slot = NULL;
  hal_critical_section_start();

#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
  const int i = (int) (handle.handle & 0xFFFF);

  if (i < sizeof(pkey_handle)/sizeof(*pkey_handle) && pkey_handle[i].pkey_handle.handle == handle.handle)
    slot = &pkey_handle[i];
#endif

  hal_critical_section_end();
  return slot;
}

/*
 * Access rules are a bit complicated, mostly due to PKCS #11.
 *
 * The simple, obvious rule would be that one must be logged in as
 * HAL_USER_NORMAL to create, see, use, or delete a key, full stop.
 *
 * That's almost the rule that PKCS #11 follows for so-called
 * "private" objects (CKA_PRIVATE = CK_TRUE), but PKCS #11 has a more
 * model which not only allows wider visibility to "public" objects
 * (CKA_PRIVATE = CK_FALSE) but also allows write access to "public
 * session" (CKA_PRIVATE = CK_FALSE, CKA_TOKEN = CK_FALSE) objects
 * regardless of login state.
 *
 * PKCS #11 also has a concept of read-only sessions, which we don't
 * bother to implement at all on the HSM, since the PIN is required to
 * be the same as for the corresponding read-write session, so this
 * would just be additional compexity without adding any security on
 * the HSM; the PKCS #11 library still has to support read-only
 * sessions, but that's not our problem here.
 *
 * In general, non-PKCS #11 users of this API should probably never
 * set HAL_KEY_FLAG_PUBLIC, in which case they'll get the simple rule.
 *
 * Note that keystore drivers may need to implement additional
 * additional checks, eg, ks_volatile needs to enforce the rule that
 * session objects are only visible to the client which created them
 * (not the session, that would be too simple, thanks PKCS #11).  In
 * practice, this should not be a serious problem, since such checks
 * will likely only apply to existing objects.  The thing we really
 * want to avoid is doing all the work to create a large key only to
 * have the keystore driver reject access at the end, but since, by
 * definition, that only occurs when creating new objects, the access
 * decision doesn't depend on preexisting data, so the rules here
 * should suffice.  That's the theory, anyway, if this is wrong we may
 * need to refactor.
 */

static inline hal_error_t check_normal_or_wheel(const hal_client_handle_t client)
{
  const hal_error_t err = hal_rpc_is_logged_in(client, HAL_USER_NORMAL);
  return (err == HAL_ERROR_FORBIDDEN
          ? hal_rpc_is_logged_in(client, HAL_USER_WHEEL)
          : err);
}

static inline hal_error_t check_readable(const hal_client_handle_t client,
                                         const hal_key_flags_t flags)
{
  if ((flags & HAL_KEY_FLAG_PUBLIC) != 0)
    return HAL_OK;

  return check_normal_or_wheel(client);
}

static inline hal_error_t check_writable(const hal_client_handle_t client,
                                         const hal_key_flags_t flags)
{
  if ((flags & (HAL_KEY_FLAG_TOKEN | HAL_KEY_FLAG_PUBLIC)) == HAL_KEY_FLAG_PUBLIC)
    return HAL_OK;

  return check_normal_or_wheel(client);
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
 * Given key flags, open appropriate keystore driver.
 */

static inline hal_error_t ks_open_from_flags(hal_ks_t **ks, const hal_key_flags_t flags)
{
  return hal_ks_open((flags & HAL_KEY_FLAG_TOKEN) == 0
                     ? hal_ks_volatile_driver
                     : hal_ks_token_driver,
                     ks);
}

/*
 * Receive key from application, generate a name (UUID), store it, and
 * return a key handle and the name.
 */

static hal_error_t pkey_local_load(const hal_client_handle_t client,
                                   const hal_session_handle_t session,
                                   hal_pkey_handle_t *pkey,
                                   const hal_key_type_t type,
                                   const hal_curve_name_t curve,
                                   hal_uuid_t *name,
                                   const uint8_t * const der, const size_t der_len,
                                   const hal_key_flags_t flags)
{
  assert(pkey != NULL && name != NULL);

  hal_pkey_slot_t *slot;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = check_writable(client, flags)) != HAL_OK)
    return err;

  if ((slot = alloc_slot(flags)) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  if ((err = hal_uuid_gen(&slot->name)) != HAL_OK)
    return err;

  slot->client_handle  = client;
  slot->session_handle = session;
  slot->type  = type;
  slot->curve = curve;
  slot->flags = flags;

  if ((err = ks_open_from_flags(&ks, flags)) == HAL_OK &&
      (err = hal_ks_store(ks, slot, der, der_len)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  if (err != HAL_OK) {
    slot->type = HAL_KEY_TYPE_NONE;
    return err;
  }

  *pkey = slot->pkey_handle;
  *name = slot->name;
  return HAL_OK;
}

/*
 * Look up a key given its name, return a key handle.
 */

static hal_error_t pkey_local_open(const hal_client_handle_t client,
                                   const hal_session_handle_t session,
                                   hal_pkey_handle_t *pkey,
                                   const hal_uuid_t * const name,
                                   const hal_key_flags_t flags)
{
  assert(pkey != NULL && name != NULL);

  hal_pkey_slot_t *slot;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = check_readable(client, flags)) != HAL_OK)
    return err;

  if ((slot = alloc_slot(flags)) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  slot->name = *name;
  slot->client_handle = client;
  slot->session_handle = session;

  if ((err = ks_open_from_flags(&ks, flags)) == HAL_OK &&
      (err = hal_ks_fetch(ks, slot, NULL, NULL, 0)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  if (err != HAL_OK) {
    slot->type = HAL_KEY_TYPE_NONE;
    return err;
  }

  *pkey = slot->pkey_handle;
  return HAL_OK;
}

/*
 * Generate a new RSA key with supplied name, return a key handle.
 */

static hal_error_t pkey_local_generate_rsa(const hal_client_handle_t client,
                                           const hal_session_handle_t session,
                                           hal_pkey_handle_t *pkey,
                                           hal_uuid_t *name,
                                           const unsigned key_length,
                                           const uint8_t * const public_exponent, const size_t public_exponent_len,
                                           const hal_key_flags_t flags)
{
  assert(pkey != NULL && name != NULL && (key_length & 7) == 0);

  uint8_t keybuf[hal_rsa_key_t_size];
  hal_rsa_key_t *key = NULL;
  hal_pkey_slot_t *slot;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = check_writable(client, flags)) != HAL_OK)
    return err;

  if ((slot = alloc_slot(flags)) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  if ((err = hal_uuid_gen(&slot->name)) != HAL_OK)
    return err;

  slot->client_handle  = client;
  slot->session_handle = session;
  slot->type  = HAL_KEY_TYPE_RSA_PRIVATE;
  slot->curve = HAL_CURVE_NONE;
  slot->flags = flags;

  if ((err = hal_rsa_key_gen(NULL, &key, keybuf, sizeof(keybuf), key_length / 8,
                             public_exponent, public_exponent_len)) != HAL_OK) {
    slot->type = HAL_KEY_TYPE_NONE;
    return err;
  }

  uint8_t der[hal_rsa_private_key_to_der_len(key)];
  size_t der_len;

  if ((err = hal_rsa_private_key_to_der(key, der, &der_len, sizeof(der))) == HAL_OK &&
      (err = ks_open_from_flags(&ks, flags)) == HAL_OK &&
      (err = hal_ks_store(ks, slot, der, der_len)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der, 0, sizeof(der));

  if (err != HAL_OK) {
    slot->type = HAL_KEY_TYPE_NONE;
    return err;
  }

  *pkey = slot->pkey_handle;
  *name = slot->name;
  return HAL_OK;
}

/*
 * Generate a new EC key with supplied name, return a key handle.
 * At the moment, EC key == ECDSA key, but this is subject to change.
 */

static hal_error_t pkey_local_generate_ec(const hal_client_handle_t client,
                                          const hal_session_handle_t session,
                                          hal_pkey_handle_t *pkey,
                                          hal_uuid_t *name,
                                          const hal_curve_name_t curve,
                                          const hal_key_flags_t flags)
{
  assert(pkey != NULL && name != NULL);

  uint8_t keybuf[hal_ecdsa_key_t_size];
  hal_ecdsa_key_t *key = NULL;
  hal_pkey_slot_t *slot;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = check_writable(client, flags)) != HAL_OK)
    return err;

  if ((slot = alloc_slot(flags)) == NULL)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  if ((err = hal_uuid_gen(&slot->name)) != HAL_OK)
    return err;

  slot->client_handle  = client;
  slot->session_handle = session;
  slot->type  = HAL_KEY_TYPE_EC_PRIVATE;
  slot->curve = curve;
  slot->flags = flags;

  if ((err = hal_ecdsa_key_gen(NULL, &key, keybuf, sizeof(keybuf), curve)) != HAL_OK) {
    slot->type = HAL_KEY_TYPE_NONE;
    return err;
  }

  uint8_t der[hal_ecdsa_private_key_to_der_len(key)];
  size_t der_len;

  if ((err = hal_ecdsa_private_key_to_der(key, der, &der_len, sizeof(der))) == HAL_OK &&
      (err = ks_open_from_flags(&ks, flags)) == HAL_OK &&
      (err = hal_ks_store(ks, slot, der, der_len)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der, 0, sizeof(der));

  if (err != HAL_OK) {
    slot->type = HAL_KEY_TYPE_NONE;
    return err;
  }

  *pkey = slot->pkey_handle;
  *name = slot->name;
  return HAL_OK;
}

/*
 * Discard key handle, leaving key intact.
 */

static hal_error_t pkey_local_close(const hal_pkey_handle_t pkey)
{
  hal_pkey_slot_t *slot;

  if ((slot = find_handle(pkey)) == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  memset(slot, 0, sizeof(*slot));

  return HAL_OK;
}

/*
 * Delete a key from the store, given its key handle.
 */

static hal_error_t pkey_local_delete(const hal_pkey_handle_t pkey)
{
  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = check_writable(slot->client_handle, slot->flags)) != HAL_OK)
    return err;

  if ((err = ks_open_from_flags(&ks, slot->flags)) == HAL_OK &&
      (err = hal_ks_delete(ks, slot)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  if (err == HAL_OK || err == HAL_ERROR_KEY_NOT_FOUND)
    memset(slot, 0, sizeof(*slot));

  return err;
}

/*
 * Get type of key associated with handle.
 */

static hal_error_t pkey_local_get_key_type(const hal_pkey_handle_t pkey,
                                           hal_key_type_t *type)
{
  if (type == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  *type = slot->type;

  return HAL_OK;
}

/*
 * Get curve of key associated with handle.
 */

static hal_error_t pkey_local_get_key_curve(const hal_pkey_handle_t pkey,
                                           hal_curve_name_t *curve)
{
  if (curve == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  *curve = slot->curve;

  return HAL_OK;
}

/*
 * Get flags of key associated with handle.
 */

static hal_error_t pkey_local_get_key_flags(const hal_pkey_handle_t pkey,
                                            hal_key_flags_t *flags)
{
  if (flags == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  *flags = slot->flags;

  return HAL_OK;
}

/*
 * Get length of public key associated with handle.
 */

static size_t pkey_local_get_public_key_len(const hal_pkey_handle_t pkey)
{
  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return 0;

  size_t result = 0;

  uint8_t keybuf[hal_rsa_key_t_size > hal_ecdsa_key_t_size ? hal_rsa_key_t_size : hal_ecdsa_key_t_size];
  hal_rsa_key_t   *rsa_key   = NULL;
  hal_ecdsa_key_t *ecdsa_key = NULL;
  uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
  size_t der_len;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = ks_open_from_flags(&ks, slot->flags)) == HAL_OK &&
      (err = hal_ks_fetch(ks, slot, der, &der_len, sizeof(der))) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  if (err == HAL_OK) {
    switch (slot->type) {

    case HAL_KEY_TYPE_RSA_PUBLIC:
    case HAL_KEY_TYPE_EC_PUBLIC:
      result = der_len;
      break;

    case HAL_KEY_TYPE_RSA_PRIVATE:
      if (hal_rsa_private_key_from_der(&rsa_key, keybuf, sizeof(keybuf), der, der_len) == HAL_OK)
        result = hal_rsa_public_key_to_der_len(rsa_key);
      break;

    case HAL_KEY_TYPE_EC_PRIVATE:
      if (hal_ecdsa_private_key_from_der(&ecdsa_key, keybuf, sizeof(keybuf), der, der_len) == HAL_OK)
        result = hal_ecdsa_public_key_to_der_len(ecdsa_key);
      break;

    default:
      break;
    }
  }

  memset(keybuf, 0, sizeof(keybuf));
  memset(der,    0, sizeof(der));

  return result;
}

/*
 * Get public key associated with handle.
 */

static hal_error_t pkey_local_get_public_key(const hal_pkey_handle_t pkey,
                                             uint8_t *der, size_t *der_len, const size_t der_max)
{
  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  uint8_t keybuf[hal_rsa_key_t_size > hal_ecdsa_key_t_size ? hal_rsa_key_t_size : hal_ecdsa_key_t_size];
  hal_rsa_key_t   *rsa_key   = NULL;
  hal_ecdsa_key_t *ecdsa_key = NULL;
  uint8_t buf[HAL_KS_WRAPPED_KEYSIZE];
  size_t buf_len;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = ks_open_from_flags(&ks, slot->flags)) == HAL_OK &&
      (err = hal_ks_fetch(ks, slot, buf, &buf_len, sizeof(buf))) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  if (err == HAL_OK) {
    switch (slot->type) {

    case HAL_KEY_TYPE_RSA_PUBLIC:
    case HAL_KEY_TYPE_EC_PUBLIC:
      if (der_len != NULL)
        *der_len = buf_len;
      if (der != NULL && der_max < buf_len)
        err = HAL_ERROR_RESULT_TOO_LONG;
      else if (der != NULL)
        memcpy(der, buf, buf_len);
      break;

    case HAL_KEY_TYPE_RSA_PRIVATE:
      if ((err = hal_rsa_private_key_from_der(&rsa_key, keybuf, sizeof(keybuf), buf, buf_len)) == HAL_OK)
        err = hal_rsa_public_key_to_der(rsa_key, der, der_len, der_max);
      break;

    case HAL_KEY_TYPE_EC_PRIVATE:
      if ((err = hal_ecdsa_private_key_from_der(&ecdsa_key, keybuf, sizeof(keybuf), buf, buf_len)) == HAL_OK)
        err = hal_ecdsa_public_key_to_der(ecdsa_key, der, der_len, der_max);
      break;

    default:
      err = HAL_ERROR_UNSUPPORTED_KEY;
      break;
    }
  }

  memset(keybuf, 0, sizeof(keybuf));
  memset(buf,    0, sizeof(buf));

  return err;
}

/*
 * Sign something using private key associated with handle.
 *
 * RSA has enough quirks that it's simplest to split this out into
 * algorithm-specific functions.
 */

static hal_error_t pkey_local_sign_rsa(uint8_t *keybuf, const size_t keybuf_len,
                                       const uint8_t * const der, const size_t der_len,
                                       const hal_hash_handle_t hash,
                                       const uint8_t * input, size_t input_len,
                                       uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  hal_rsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len != NULL);
  assert((hash.handle == HAL_HANDLE_NONE) != (input == NULL || input_len == 0));

  if ((err = hal_rsa_private_key_from_der(&key, keybuf, keybuf_len, der, der_len)) != HAL_OK ||
      (err = hal_rsa_key_get_modulus(key, NULL, signature_len, 0))         != HAL_OK)
    return err;

  if (*signature_len > signature_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  if (input == NULL || input_len == 0) {
    if ((err = hal_rpc_pkcs1_construct_digestinfo(hash, signature, &input_len, *signature_len)) != HAL_OK)
      return err;
    input = signature;
  }

  if ((err = pkcs1_5_pad(input, input_len, signature, *signature_len))                         != HAL_OK ||
      (err = hal_rsa_decrypt(NULL, key, signature, *signature_len, signature, *signature_len)) != HAL_OK)
    return err;

  return HAL_OK;
}

static hal_error_t pkey_local_sign_ecdsa(uint8_t *keybuf, const size_t keybuf_len,
                                         const uint8_t * const der, const size_t der_len,
                                         const hal_hash_handle_t hash,
                                         const uint8_t * input, size_t input_len,
                                         uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  hal_ecdsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len != NULL);
  assert((hash.handle == HAL_HANDLE_NONE) != (input == NULL || input_len == 0));

  if ((err = hal_ecdsa_private_key_from_der(&key, keybuf, keybuf_len, der, der_len)) != HAL_OK)
    return err;

  if (input == NULL || input_len == 0) {
    hal_digest_algorithm_t alg;

    if ((err = hal_rpc_hash_get_algorithm(hash, &alg))          != HAL_OK ||
        (err = hal_rpc_hash_get_digest_length(alg, &input_len)) != HAL_OK)
      return err;

    if (input_len > signature_max)
      return HAL_ERROR_RESULT_TOO_LONG;

    if ((err = hal_rpc_hash_finalize(hash, signature, input_len)) != HAL_OK)
      return err;

    input = signature;
  }

  if ((err = hal_ecdsa_sign(NULL, key, input, input_len, signature, signature_len, signature_max)) != HAL_OK)
    return err;

  return HAL_OK;
}

static hal_error_t pkey_local_sign(const hal_pkey_handle_t pkey,
                                   const hal_hash_handle_t hash,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_error_t (*signer)(uint8_t *keybuf, const size_t keybuf_len,
                        const uint8_t * const der, const size_t der_len,
                        const hal_hash_handle_t hash,
                        const uint8_t * const input,  const size_t input_len,
                        uint8_t * signature, size_t *signature_len, const size_t signature_max);

  switch (slot->type) {
  case HAL_KEY_TYPE_RSA_PRIVATE:
    signer = pkey_local_sign_rsa;
    break;
  case HAL_KEY_TYPE_EC_PRIVATE:
    signer = pkey_local_sign_ecdsa;
    break;
  default:
    return HAL_ERROR_UNSUPPORTED_KEY;
  }

  uint8_t keybuf[hal_rsa_key_t_size > hal_ecdsa_key_t_size ? hal_rsa_key_t_size : hal_ecdsa_key_t_size];
  uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
  size_t der_len;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = ks_open_from_flags(&ks, slot->flags)) == HAL_OK &&
      (err = hal_ks_fetch(ks, slot, der, &der_len, sizeof(der))) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  if (err == HAL_OK)
    err = signer(keybuf, sizeof(keybuf), der, der_len, hash, input, input_len, signature, signature_len, signature_max);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der,    0, sizeof(der));

  return err;
}

/*
 * Verify something using public key associated with handle.
 *
 * RSA has enough quirks that it's simplest to split this out into
 * algorithm-specific functions.
 */

static hal_error_t pkey_local_verify_rsa(uint8_t *keybuf, const size_t keybuf_len, const hal_key_type_t type,
                                         const uint8_t * const der, const size_t der_len,
                                         const hal_hash_handle_t hash,
                                         const uint8_t * input, size_t input_len,
                                         const uint8_t * const signature, const size_t signature_len)
{
  uint8_t expected[signature_len], received[(signature_len + 3) & ~3];
  hal_rsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len > 0);
  assert((hash.handle == HAL_HANDLE_NONE) != (input == NULL || input_len == 0));

  switch (type) {
  case HAL_KEY_TYPE_RSA_PRIVATE:
    err = hal_rsa_private_key_from_der(&key, keybuf, keybuf_len, der, der_len);
    break;
  case HAL_KEY_TYPE_RSA_PUBLIC:
    err = hal_rsa_public_key_from_der(&key, keybuf, keybuf_len, der, der_len);
    break;
  default:
    err = HAL_ERROR_IMPOSSIBLE;
  }

  if (err != HAL_OK)
    return err;

  if (input == NULL || input_len == 0) {
    if ((err = hal_rpc_pkcs1_construct_digestinfo(hash, expected, &input_len, sizeof(expected))) != HAL_OK)
      return err;
    input = expected;
  }

  if ((err = pkcs1_5_pad(input, input_len, expected, sizeof(expected)))                        != HAL_OK ||
      (err = hal_rsa_encrypt(NULL, key, signature, signature_len, received, sizeof(received))) != HAL_OK)
    return err;

  unsigned diff = 0;
  for (int i = 0; i < signature_len; i++)
    diff |= expected[i] ^ received[i + sizeof(received) - sizeof(expected)];

  if (diff != 0)
    return HAL_ERROR_INVALID_SIGNATURE;

  return HAL_OK;
}

static hal_error_t pkey_local_verify_ecdsa(uint8_t *keybuf, const size_t keybuf_len, const hal_key_type_t type,
                                           const uint8_t * const der, const size_t der_len,
                                           const hal_hash_handle_t hash,
                                           const uint8_t * input, size_t input_len,
                                           const uint8_t * const signature, const size_t signature_len)
{
  uint8_t digest[signature_len];
  hal_ecdsa_key_t *key = NULL;
  hal_error_t err;

  assert(signature != NULL && signature_len > 0);
  assert((hash.handle == HAL_HANDLE_NONE) != (input == NULL || input_len == 0));

  switch (type) {
  case HAL_KEY_TYPE_EC_PRIVATE:
    err = hal_ecdsa_private_key_from_der(&key, keybuf, keybuf_len, der, der_len);
    break;
  case HAL_KEY_TYPE_EC_PUBLIC:
    err = hal_ecdsa_public_key_from_der(&key, keybuf, keybuf_len, der, der_len);
    break;
  default:
    err = HAL_ERROR_IMPOSSIBLE;
  }

  if (err != HAL_OK)
    return err;

  if (input == NULL || input_len == 0) {
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

static hal_error_t pkey_local_verify(const hal_pkey_handle_t pkey,
                                     const hal_hash_handle_t hash,
                                     const uint8_t * const input, const size_t input_len,
                                     const uint8_t * const signature, const size_t signature_len)
{
  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_error_t (*verifier)(uint8_t *keybuf, const size_t keybuf_len, const hal_key_type_t type,
                          const uint8_t * const der, const size_t der_len,
                          const hal_hash_handle_t hash,
                          const uint8_t * const input,  const size_t input_len,
                          const uint8_t * const signature, const size_t signature_len);

  switch (slot->type) {
  case HAL_KEY_TYPE_RSA_PRIVATE:
  case HAL_KEY_TYPE_RSA_PUBLIC:
    verifier = pkey_local_verify_rsa;
    break;
  case HAL_KEY_TYPE_EC_PRIVATE:
  case HAL_KEY_TYPE_EC_PUBLIC:
    verifier = pkey_local_verify_ecdsa;
    break;
  default:
    return HAL_ERROR_UNSUPPORTED_KEY;
  }

  uint8_t keybuf[hal_rsa_key_t_size > hal_ecdsa_key_t_size ? hal_rsa_key_t_size : hal_ecdsa_key_t_size];
  uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
  size_t der_len;
  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = ks_open_from_flags(&ks, slot->flags)) == HAL_OK &&
      (err = hal_ks_fetch(ks, slot, der, &der_len, sizeof(der))) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  if (err == HAL_OK)
    err = verifier(keybuf, sizeof(keybuf), slot->type, der, der_len, hash, input, input_len, signature, signature_len);

  memset(keybuf, 0, sizeof(keybuf));
  memset(der,    0, sizeof(der));

  return err;
}

static hal_error_t pkey_local_match(const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    const hal_key_type_t type,
                                    const hal_curve_name_t curve,
                                    const hal_key_flags_t flags,
                                    const hal_pkey_attribute_t *attributes,
                                    const unsigned attributes_len,
                                    hal_uuid_t *result,
                                    unsigned *result_len,
                                    const unsigned result_max,
                                    const hal_uuid_t * const previous_uuid)
{
  hal_ks_t *ks = NULL;
  hal_error_t err;

  err = check_readable(client, flags);

  if (err == HAL_ERROR_FORBIDDEN) {
    assert(result_len != NULL);
    *result_len = 0;
    return HAL_OK;
  }

  if (err != HAL_OK)
    return err;

  if ((err = ks_open_from_flags(&ks, flags)) == HAL_OK &&
      (err = hal_ks_match(ks, client, session, type, curve, flags, attributes, attributes_len,
                          result, result_len, result_max, previous_uuid)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  return err;
}

static hal_error_t pkey_local_set_attributes(const hal_pkey_handle_t pkey,
                                             const hal_pkey_attribute_t *attributes,
                                             const unsigned attributes_len)
{
  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = check_writable(slot->client_handle, slot->flags)) != HAL_OK)
    return err;

  if ((err = ks_open_from_flags(&ks, slot->flags)) == HAL_OK &&
      (err = hal_ks_set_attributes(ks, slot, attributes, attributes_len)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  return err;
}

static hal_error_t pkey_local_get_attributes(const hal_pkey_handle_t pkey,
                                             hal_pkey_attribute_t *attributes,
                                             const unsigned attributes_len,
                                             uint8_t *attributes_buffer,
                                             const size_t attributes_buffer_len)
{
  hal_pkey_slot_t *slot = find_handle(pkey);

  if (slot == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_ks_t *ks = NULL;
  hal_error_t err;

  if ((err = ks_open_from_flags(&ks, slot->flags)) == HAL_OK &&
      (err = hal_ks_get_attributes(ks, slot, attributes, attributes_len,
                                   attributes_buffer, attributes_buffer_len)) == HAL_OK)
    err = hal_ks_close(ks);
  else if (ks != NULL)
    (void) hal_ks_close(ks);

  return err;
}

const hal_rpc_pkey_dispatch_t hal_rpc_local_pkey_dispatch = {
  .load                 = pkey_local_load,
  .open                 = pkey_local_open,
  .generate_rsa         = pkey_local_generate_rsa,
  .generate_ec          = pkey_local_generate_ec,
  .close                = pkey_local_close,
  .delete               = pkey_local_delete,
  .get_key_type         = pkey_local_get_key_type,
  .get_key_curve        = pkey_local_get_key_curve,
  .get_key_flags        = pkey_local_get_key_flags,
  .get_public_key_len   = pkey_local_get_public_key_len,
  .get_public_key       = pkey_local_get_public_key,
  .sign                 = pkey_local_sign,
  .verify               = pkey_local_verify,
  .match                = pkey_local_match,
  .set_attributes       = pkey_local_set_attributes,
  .get_attributes       = pkey_local_get_attributes
};

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
