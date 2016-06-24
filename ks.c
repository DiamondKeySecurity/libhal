/*
 * ks.c
 * ----
 * Keystore API.  This is internal within libhal.
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
#include "last_gasp_pin_internal.h"

#define KEK_LENGTH (bitsToBytes(256))

/*
 * In "remote" and "mixed" RPC modes we're a software only RPC client
 * without (direct) access to secure hardware, thus there is no real
 * point in encrypting keys.  As precautions, we (a) warn about this
 * when configured in one of these modes, and (b) refuse to store any
 * sort of private keys.
 */

#define USE_KEK (RPC_CLIENT != RPC_CLIENT_REMOTE && RPC_CLIENT != RPC_CLIENT_MIXED)

#if !USE_KEK
#warning ks.c compiled without KEK support and will only accept public keys -- this is normal for the host-side build of libhsm
#endif

static inline int acceptable_key_type(const hal_key_type_t type)
{
  switch (type) {
#if USE_KEK
  case HAL_KEY_TYPE_RSA_PRIVATE:
  case HAL_KEY_TYPE_EC_PRIVATE:
#endif
  case HAL_KEY_TYPE_RSA_PUBLIC:
  case HAL_KEY_TYPE_EC_PUBLIC:
    return 1;
  default:
    return 0;
  }
}

hal_error_t hal_ks_store(const hal_key_type_t type,
                         const hal_curve_name_t curve,
                         const hal_key_flags_t flags,
                         const uint8_t * const name, const size_t name_len,
                         const uint8_t * const der,  const size_t der_len,
                         int *hint)
{
  if (name == NULL || der == NULL || der_len == 0 || !acceptable_key_type(type))
    return HAL_ERROR_BAD_ARGUMENTS;

  if (name_len > HAL_RPC_PKEY_NAME_MAX)
    return HAL_ERROR_KEY_NAME_TOO_LONG;

  const hal_ks_keydb_t * const db = hal_ks_get_keydb();
  hal_error_t err;
  int hint_;

  if (db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if (hint == NULL)
    hint = &hint_;

  *hint = -1;

  for (int i = 0; i < sizeof(db->keys)/sizeof(*db->keys); i++) {
    if (!db->keys[i].in_use && *hint < 0)
      *hint = i;
    if (db->keys[i].in_use &&
        db->keys[i].type == type &&
        db->keys[i].name_len == name_len && memcmp(db->keys[i].name, name, name_len) == 0)
      return HAL_ERROR_KEY_NAME_IN_USE;
  }

  if (*hint < 0)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  hal_ks_key_t k;
  memset(&k, 0, sizeof(k));
  k.der_len = sizeof(k.der);

#if USE_KEK

  uint8_t kek[KEK_LENGTH];
  size_t kek_len;

  if ((err = hal_ks_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k.der, &k.der_len);

  memset(kek, 0, sizeof(kek));

  if (err != HAL_OK)
    return err;

#else /* USE_KEK */

  if (der_len > k.der_len)
    return HAL_ERROR_RESULT_TOO_LONG;

  k.der_len = der_len;
  memcpy(k.der, der, der_len);

#endif /* USE_KEK */

  assert(name_len <= sizeof(k.name));
  memcpy(k.name, name, name_len);
  k.name_len = name_len;
  k.type = type;
  k.curve = curve;
  k.flags = flags;

  if ((err = hal_ks_set_keydb(&k, *hint, 0)) != HAL_OK)
    return err;

  return HAL_OK;
}

static int find(const hal_ks_keydb_t * const db,
                const hal_key_type_t type,
                const uint8_t * const name, const size_t name_len,
                int *hint)
{
  assert(db != NULL && name != NULL && acceptable_key_type(type));

  if (hint != NULL && *hint >= 0 && *hint < sizeof(db->keys)/sizeof(*db->keys) &&
      db->keys[*hint].in_use &&
      db->keys[*hint].type == type &&
      db->keys[*hint].name_len == name_len && memcmp(db->keys[*hint].name, name, name_len) == 0)
    return 1;

  for (int i = 0; i < sizeof(db->keys)/sizeof(*db->keys); i++) {
    if (!db->keys[i].in_use ||
        (hint != NULL && i == *hint) ||
        db->keys[i].type != type ||
        db->keys[i].name_len != name_len || memcmp(db->keys[i].name, name, name_len) != 0)
      continue;
    if (hint != NULL)
      *hint = i;
    return 1;
  }

  return 0;
}

hal_error_t hal_ks_exists(const hal_key_type_t type,
                          const uint8_t * const name, const size_t name_len,
                          int *hint)
{
  if (name == NULL || !acceptable_key_type(type))
    return HAL_ERROR_BAD_ARGUMENTS;

  const hal_ks_keydb_t * const db = hal_ks_get_keydb();

  if (db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if (find(db, type, name, name_len, hint))
    return HAL_OK;
  else
    return HAL_ERROR_KEY_NOT_FOUND;
}

hal_error_t hal_ks_fetch(const hal_key_type_t type,
                         const uint8_t * const name, const size_t name_len,
                         hal_curve_name_t *curve,
                         hal_key_flags_t *flags,
                         uint8_t *der, size_t *der_len, const size_t der_max,
                         int *hint)
{
  if (name == NULL || !acceptable_key_type(type))
    return HAL_ERROR_BAD_ARGUMENTS;

  const hal_ks_keydb_t * const db = hal_ks_get_keydb();
  int hint_ = -1;

  if (db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if (hint == NULL)
    hint = &hint_;

  if (!find(db, type, name, name_len, hint))
    return HAL_ERROR_KEY_NOT_FOUND;

  const hal_ks_key_t * const k = &db->keys[*hint];

  if (curve != NULL)
    *curve = k->curve;

  if (flags != NULL)
    *flags = k->flags;

  if (der == NULL && der_len != NULL)
    *der_len = k->der_len;

  if (der != NULL) {

#if USE_KEK

    uint8_t kek[KEK_LENGTH];
    size_t kek_len, der_len_;
    hal_error_t err;

    if (der_len == NULL)
      der_len = &der_len_;

    *der_len = der_max;

    if ((err = hal_ks_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
      err = hal_aes_keyunwrap(NULL, kek, kek_len, k->der, k->der_len, der, der_len);

    memset(kek, 0, sizeof(kek));

    if (err != HAL_OK)
      return err;

#else /* USE_KEK */

    if (k->der_len > der_max)
      return HAL_ERROR_RESULT_TOO_LONG;

    if (der_len != NULL)
      *der_len = k->der_len;

    memcpy(der, k->der, k->der_len);

#endif /* USE_KEK */
  }

  return HAL_OK;
}

hal_error_t hal_ks_delete(const hal_key_type_t type,
                          const uint8_t * const name, const size_t name_len,
                          int *hint)
{
  if (name == NULL || !acceptable_key_type(type))
    return HAL_ERROR_BAD_ARGUMENTS;

  const hal_ks_keydb_t * const db = hal_ks_get_keydb();
  int hint_ = -1;

  if (db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if (hint == NULL)
    hint = &hint_;

  if (!find(db, type, name, name_len, hint))
    return HAL_ERROR_KEY_NOT_FOUND;

  return hal_ks_del_keydb(*hint);
}

hal_error_t hal_ks_rename(const hal_key_type_t type,
                          const uint8_t * const old_name, const size_t old_name_len,
                          const uint8_t * const new_name, const size_t new_name_len,
                          int *hint)
{
  if (old_name == NULL || new_name == NULL || !acceptable_key_type(type))
    return HAL_ERROR_BAD_ARGUMENTS;

  if (new_name_len > HAL_RPC_PKEY_NAME_MAX)
    return HAL_ERROR_KEY_NAME_TOO_LONG;

  const hal_ks_keydb_t * const db = hal_ks_get_keydb();
  int hint_ = -1;

  if (db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if (find(db, type, new_name, new_name_len, NULL))
    return HAL_ERROR_KEY_NAME_IN_USE;

  if (hint == NULL)
    hint = &hint_;

  if (!find(db, type, old_name, old_name_len, hint))
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_ks_key_t k = db->keys[*hint];

  assert(new_name_len <= sizeof(k.name));
  memcpy(k.name, new_name, new_name_len);
  k.name_len = new_name_len;

  return hal_ks_set_keydb(&k, *hint, 1);
}

hal_error_t hal_ks_list(hal_pkey_info_t *result,
                        unsigned *result_len,
                        const unsigned result_max)
{
  if (result == NULL || result_len == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  const hal_ks_keydb_t * const db = hal_ks_get_keydb();

  if (db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  *result_len = 0;

  for (int i = 0; i < sizeof(db->keys)/sizeof(*db->keys); i++) {

    if (!db->keys[i].in_use)
      continue;

    if (*result_len == result_max)
      return HAL_ERROR_RESULT_TOO_LONG;

    result[*result_len].type = db->keys[i].type;
    result[*result_len].curve = db->keys[i].curve;
    result[*result_len].flags = db->keys[i].flags;
    result[*result_len].name_len = db->keys[i].name_len;
    memcpy(result[*result_len].name, db->keys[i].name, db->keys[i].name_len);
    ++ *result_len;
  }

  return HAL_OK;
}

hal_error_t hal_ks_get_pin(const hal_user_t user,
                           const hal_ks_pin_t **pin)
{
  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  const hal_ks_keydb_t * const db = hal_ks_get_keydb();

  if (db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  switch (user) {
  case HAL_USER_WHEEL:  *pin = &db->wheel_pin;  break;
  case HAL_USER_SO:	*pin = &db->so_pin;     break;
  case HAL_USER_NORMAL:	*pin = &db->user_pin;   break;
  default:		return HAL_ERROR_BAD_ARGUMENTS;
  }

#warning Need better "Have we been initialized yet?" test
  /*
   * If we were looking for the WHEEL PIN and it appears to be
   * completely unset, return the compiled-in last-gasp PIN.  This is
   * a terrible answer, but we need some kind of bootstrapping
   * mechanism.  Feel free to suggest something better.
   *
   * We probably need some more general "have we been initialized?"
   * state somewhere, and might want to refuse to do things like
   * storing keys until we've been initialized and the appropriate
   * PINs have been set.
   *
   * Just to make things more fun, some drivers return all zeros for
   * "this has never been set", some return all ones to indicate the
   * same thing.  REALLY need a flag somewhere.
   */

  uint8_t u00 = 0x00, uFF = 0xFF;
  for (int i = 0; i < sizeof((*pin)->pin); i++) {
    u00 |= (*pin)->pin[i];
    uFF &= (*pin)->pin[i];
  }
  for (int i = 0; i < sizeof((*pin)->salt); i++) {
    u00 |= (*pin)->salt[i];
    uFF &= (*pin)->salt[i];
  }
  if (user == HAL_USER_WHEEL && ((u00 == 0x00 && (*pin)->iterations == 0x00000000) ||
                                 (uFF == 0xFF && (*pin)->iterations == 0xFFFFFFFF)))
    *pin = &hal_last_gasp_pin;

  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
