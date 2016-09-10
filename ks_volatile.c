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

#ifndef HAL_STATIC_KS_VOLATILE_SLOTS
#define HAL_STATIC_KS_VOLATILE_SLOTS HAL_STATIC_PKEY_STATE_BLOCKS
#endif

#if HAL_STATIC_KS_VOLATILE_SLOTS > 0

/*
 * In-memory keystore database.  This should also be usable for
 * mmap(), if and when we get around to rewriting that driver (and in
 * which case this driver probably ought to be renamed ks_memory).
 */

typedef struct {
  hal_key_type_t        type;
  hal_curve_name_t      curve;
  hal_key_flags_t       flags;
  size_t                der_len;
  uint8_t               der[HAL_KS_WRAPPED_KEYSIZE];
} ks_key_t;

typedef struct {
  hal_ks_index_t        ksi;
  uint16_t              _index[HAL_STATIC_KS_VOLATILE_SLOTS];
  hal_uuid_t            _names[HAL_STATIC_KS_VOLATILE_SLOTS];
  ks_key_t              keys[HAL_STATIC_KS_VOLATILE_SLOTS];
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

static ks_t volatile_ks = {
  { hal_ks_volatile_driver },
  &volatile_db
};

static inline ks_t *ks_to_ksv(hal_ks_t *ks)
{
  return (ks_t *) ks;
}

static hal_error_t ks_init(db_t *db)
{
  assert(db != NULL);

  if (db->ksi.size)             /* Already initialized */
    return HAL_OK;

  /*
   * Set up keystore with empty index and full free list.
   * Since this driver doesn't care about wear leveling,
   * just populate the free list in block numerical order.
   */

  db->ksi.size  = HAL_STATIC_KS_VOLATILE_SLOTS;
  db->ksi.used  = 0;
  db->ksi.index = db->_index;
  db->ksi.names = db->_names;

  for (int i = 0; i < HAL_STATIC_KS_VOLATILE_SLOTS; i++)
    db->_index[i] = i;

  const hal_error_t err = hal_ks_index_setup(&db->ksi);

  if (err != HAL_OK)
    db->ksi.size = 0;           /* Mark uninitialized if setup failed */

  return err;
}

static hal_error_t ks_volatile_open(const hal_ks_driver_t * const driver,
                                    hal_ks_t **ks)
{
  assert(driver != NULL && ks != NULL);
  *ks = &volatile_ks.ks;
  return ks_init(volatile_ks.db);
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
  unsigned b;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if ((err = hal_ks_index_add(&ksv->db->ksi, &slot->name, &b)) != HAL_OK)
    return err;

  uint8_t kek[KEK_LENGTH];
  size_t kek_len;
  ks_key_t k;

  memset(&k, 0, sizeof(k));
  k.der_len = sizeof(k.der);
  k.type    = slot->type;
  k.curve   = slot->curve;
  k.flags   = slot->flags;

  if ((err = hal_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k.der, &k.der_len);

  memset(kek, 0, sizeof(kek));

  if (err == HAL_OK)
    ksv->db->keys[b] = k;
  else
    (void) hal_ks_index_delete(&ksv->db->ksi, &slot->name, NULL);

  return err;
}

static hal_error_t ks_fetch(hal_ks_t *ks,
                            hal_pkey_slot_t *slot,
                            uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (ks == NULL || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);
  hal_error_t err;
  unsigned b;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if ((err = hal_ks_index_find(&ksv->db->ksi, &slot->name, &b)) != HAL_OK)
    return err;

  const ks_key_t * const k = &ksv->db->keys[b];

  slot->type  = k->type;
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

    if ((err = hal_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
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
  if (ks == NULL || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);
  hal_error_t err;
  unsigned b;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if ((err = hal_ks_index_delete(&ksv->db->ksi, &slot->name, &b)) != HAL_OK)
    return err;

  memset(&ksv->db->keys[b], 0, sizeof(ksv->db->keys[b]));

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

  if (ksv->db->ksi.used > result_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  for (int i = 0; i < ksv->db->ksi.used; i++) {
    unsigned b      = ksv->db->ksi.index[i];
    result[i].name  = ksv->db->ksi.names[b];
    result[i].type  = ksv->db->keys[b].type;
    result[i].curve = ksv->db->keys[b].curve;
    result[i].flags = ksv->db->keys[b].flags;
  }

  *result_len = ksv->db->ksi.used;

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

#endif /* HAL_STATIC_KS_VOLATILE_SLOTS > 0 */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
