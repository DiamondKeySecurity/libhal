/*
 * ks_volatile.c
 * -------------
 * Keystore implementation in normal volatile internal memory.
 *
 * NB: This is only suitable for cases where you do not want the keystore
 *     to survive library exit, eg, for storing PKCS #11 session keys.
 *
 * Authors: Rob Austein
 * Copyright (c) 2015-2016, NORDUnet A/S All rights reserved.
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

#define KEK_LENGTH (bitsToBytes(256))

#ifndef HAL_STATIC_PKEY_STATE_BLOCKS
#define HAL_STATIC_PKEY_STATE_BLOCKS 0
#endif

/*
 * Keystore database itself.  For the moment, we stick to the old
 * model where the entire database is wrapped in a C structure.  We
 * may want to change this, but if so, we'll need a replacement for
 * the length check.  If we do decide to replace it, we may want to
 * keep the C structure but replace the fixed size array with a C99
 * "flexible array", ie,
 *
 *   hal_ks_key_t keys[];
 *
 * which is like the old GCC zero-length array hack, and can only
 * go at the end of the structure.
 */

typedef struct {

  hal_ks_pin_t wheel_pin;
  hal_ks_pin_t so_pin;
  hal_ks_pin_t user_pin;

#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
  hal_ks_key_t keys[HAL_STATIC_PKEY_STATE_BLOCKS];
#else
#warning No keys in keydb
#endif

} db_t;

/*
 * "Subclass" (well, what one can do in C) of hal_ks_t.  This is
 * separate from db_t primarily to simplify things like rewriting the
 * old ks_mmap driver to piggy-back on the ks_volatile driver: we
 * wouldn't want the hal_ks_t into the mmap()ed file.
 */

typedef struct {
  hal_ks_t ks;              /* Must be first */
  db_t *db;                 /* Which memory-based keystore database */
} ks_t;

static db_t volatile_db;

static ks_t volatile_ks = { { hal_ks_volatile_driver }, &volatile_db };

static inline ks_t *ks_to_ksv(hal_ks_t *ks)
{
  return (ks_t *) ks;
}

static hal_error_t ks_volatile_open(const hal_ks_driver_t * const driver,
                                    hal_ks_t **ks)
{
  assert(driver != NULL && ks != NULL);
  *ks = &volatile_ks.ks;
  return HAL_OK;
}

static hal_error_t ks_volatile_close(hal_ks_t *ks)
{
  return HAL_OK;
}

static inline int acceptable_key_type(const hal_key_type_t type)
{
  switch (type) {
  case HAL_KEY_TYPE_RSA_PRIVATE:
  case HAL_KEY_TYPE_EC_PRIVATE:
  case HAL_KEY_TYPE_RSA_PUBLIC:
  case HAL_KEY_TYPE_EC_PUBLIC:
    return 1;
  default:
    return 0;
  }
}

static hal_error_t ks_store(hal_ks_t *ks,
                            const hal_pkey_slot_t * const slot,
                            const uint8_t * const der, const size_t der_len)
{
  if (ks == NULL || slot == NULL || der == NULL || der_len == 0 || !acceptable_key_type(slot->type))
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);
  hal_error_t err;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  int loc = -1;

  for (int i = 0; i < sizeof(ksv->db->keys)/sizeof(*ksv->db->keys); i++) {
    if (!ksv->db->keys[i].in_use && loc < 0)
      loc = i;
    if (ksv->db->keys[i].in_use &&
        ksv->db->keys[i].type == slot->type &&
        hal_uuid_cmp(&ksv->db->keys[i].name, &slot->name) == 0)
      return HAL_ERROR_KEY_NAME_IN_USE;
  }

  if (loc < 0)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  hal_ks_key_t k;
  memset(&k, 0, sizeof(k));
  k.der_len = sizeof(k.der);

  uint8_t kek[KEK_LENGTH];
  size_t kek_len;

  if ((err = hal_ks_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k.der, &k.der_len);

  memset(kek, 0, sizeof(kek));

  if (err != HAL_OK)
    return err;

  k.name  = slot->name;
  k.type  = slot->type;
  k.curve = slot->curve;
  k.flags = slot->flags;

  ksv->db->keys[loc] = k;
  ksv->db->keys[loc].in_use = 1;

  return HAL_OK;
}

static hal_ks_key_t *find(ks_t *ksv,
                          const hal_key_type_t type,
                          const hal_uuid_t * const name)
{
  assert(ksv != NULL && name != NULL && acceptable_key_type(type));

  for (int i = 0; i < sizeof(ksv->db->keys)/sizeof(*ksv->db->keys); i++)
    if (ksv->db->keys[i].in_use && ksv->db->keys[i].type == type && hal_uuid_cmp(&ksv->db->keys[i].name, name) == 0)
      return &ksv->db->keys[i];

  return NULL;
}

static hal_error_t ks_fetch(hal_ks_t *ks,
                            hal_pkey_slot_t *slot,
                            uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (ks == NULL || slot == NULL || !acceptable_key_type(slot->type))
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  const hal_ks_key_t * const k = find(ksv, slot->type, &slot->name);

  if (k == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  slot->curve = k->curve;
  slot->flags = k->flags;

  if (der == NULL && der_len != NULL)
    *der_len = k->der_len;

  if (der != NULL) {

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
  }

  return HAL_OK;
}

static hal_error_t ks_delete(hal_ks_t *ks,
                             const hal_pkey_slot_t * const slot)
{
  if (ks == NULL || slot == NULL || !acceptable_key_type(slot->type))
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  hal_ks_key_t *k = find(ksv, slot->type, &slot->name);

  if (k == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  memset(k, 0, sizeof(*k));

  return HAL_OK;
}

static hal_error_t ks_list(hal_ks_t *ks,
                           hal_pkey_info_t *result,
                           unsigned *result_len,
                           const unsigned result_max)
{
  if (ks == NULL || result == NULL || result_len == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  *result_len = 0;

  for (int i = 0; i < sizeof(ksv->db->keys)/sizeof(*ksv->db->keys); i++) {

    if (!ksv->db->keys[i].in_use)
      continue;

    if (*result_len == result_max)
      return HAL_ERROR_RESULT_TOO_LONG;

    result[*result_len].type  = ksv->db->keys[i].type;
    result[*result_len].curve = ksv->db->keys[i].curve;
    result[*result_len].flags = ksv->db->keys[i].flags;
    result[*result_len].name  = ksv->db->keys[i].name;
    ++ *result_len;
  }

  return HAL_OK;
}

const hal_ks_driver_t hal_ks_volatile_driver[1] = {{
  ks_volatile_open,
  ks_volatile_close,
  ks_store,
  ks_fetch,
  ks_delete,
  ks_list
}};

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
