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

#ifndef STATIC_KS_VOLATILE_SLOTS
#define STATIC_KS_VOLATILE_SLOTS HAL_STATIC_PKEY_STATE_BLOCKS
#endif

#ifndef STATIC_KS_VOLATILE_ATTRIBUTE_SPACE
#define STATIC_KS_VOLATILE_ATTRIBUTE_SPACE 4096
#endif

/*
 * In-memory keystore database.  This should also be usable for
 * mmap(), if and when we get around to rewriting that driver (and in
 * which case this driver probably ought to be renamed ks_memory).
 */

typedef struct {
  hal_key_type_t        type;
  hal_curve_name_t      curve;
  hal_key_flags_t       flags;
  hal_client_handle_t   client;
  hal_session_handle_t  session;
  size_t                der_len;
  unsigned              attributes_len;
  uint8_t               der[HAL_KS_WRAPPED_KEYSIZE + STATIC_KS_VOLATILE_ATTRIBUTE_SPACE];
} ks_key_t;

typedef struct {
  hal_ks_index_t        ksi;
  ks_key_t              *keys;
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
  int per_session;          /* Whether objects are per-session */
} ks_t;

/*
 * If we also supported mmap, there would be a separate definition for
 * HAL_KS_MMAP_SLOTS above, and the bulk of the code would be under a
 * conditional testing whether either HAL_KS_*_SLOTS were nonzero.
 */

#if STATIC_KS_VOLATILE_SLOTS > 0

static ks_t volatile_ks;

static inline ks_t *ks_to_ksv(hal_ks_t *ks)
{
  return (ks_t *) ks;
}

/*
 * Check whether the current session can see a particular key.  One
 * might expect this to be based on whether the session matches, and
 * indeed it would be in a sane world, but in the world of PKCS #11,
 * keys belong to sessions, are visible to other sessions, and may
 * even be modifiable by other sessions, but softly and silently
 * vanish away when the original creating session is destroyed.
 *
 * In our terms, this means that visibility of session objects is
 * determined only by the client handle, so taking the session handle
 * as an argument here isn't really necessary, but we've flipflopped
 * on that enough times that at least for now I'd prefer to leave the
 * session handle here and not have to revise all the RPC calls again.
 * Remove it at some later date and redo the RPC calls if we manage to
 * avoid revising this yet again.
 */

static inline int key_visible_to_session(const ks_t * const ksv,
                                         const hal_client_handle_t client,
                                         const hal_session_handle_t session,
                                         const ks_key_t * const k)
{
  return !ksv->per_session || client.handle == HAL_HANDLE_NONE || k->client.handle  == client.handle;
}

static inline void *gnaw(uint8_t **mem, size_t *len, const size_t size)
{
  if (mem == NULL || *mem == NULL || len == NULL || size > *len)
    return NULL;
  void *ret = *mem;
  *mem += size;
  *len -= size;
  return ret;
}

static hal_error_t ks_init(const hal_ks_driver_t * const driver,
                           const int per_session,
                           ks_t *ksv,
                           uint8_t *mem,
                           size_t len)
{
  if (ksv == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if (mem != NULL) {
    memset(ksv, 0, sizeof(*ksv));
    memset(mem, 0, len);

    ksv->db            = gnaw(&mem, &len, sizeof(*ksv->db));
    ksv->db->ksi.index = gnaw(&mem, &len, sizeof(*ksv->db->ksi.index) * STATIC_KS_VOLATILE_SLOTS);
    ksv->db->ksi.names = gnaw(&mem, &len, sizeof(*ksv->db->ksi.names) * STATIC_KS_VOLATILE_SLOTS);
    ksv->db->keys      = gnaw(&mem, &len, sizeof(*ksv->db->keys)      * STATIC_KS_VOLATILE_SLOTS);
    ksv->db->ksi.size  = STATIC_KS_VOLATILE_SLOTS;
  }

  if (ksv->db            == NULL ||
      ksv->db->ksi.index == NULL ||
      ksv->db->ksi.names == NULL ||
      ksv->db->keys      == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if (mem == NULL) {
    memset(ksv->db->ksi.index, 0, sizeof(*ksv->db->ksi.index) * STATIC_KS_VOLATILE_SLOTS);
    memset(ksv->db->ksi.names, 0, sizeof(*ksv->db->ksi.names) * STATIC_KS_VOLATILE_SLOTS);
    memset(ksv->db->keys,      0, sizeof(*ksv->db->keys)      * STATIC_KS_VOLATILE_SLOTS);
  }

  ksv->ks.driver     = driver;
  ksv->per_session   = per_session;
  ksv->db->ksi.used  = 0;

  /*
   * Set up keystore with empty index and full free list.
   * Since this driver doesn't care about wear leveling,
   * just populate the free list in block numerical order.
   */

  for (int i = 0; i < STATIC_KS_VOLATILE_SLOTS; i++)
    ksv->db->ksi.index[i] = i;

  return hal_ks_index_setup(&ksv->db->ksi);
}

static hal_error_t ks_volatile_init(const hal_ks_driver_t * const driver, const int alloc)
{
  const size_t len = (sizeof(*volatile_ks.db) +
                      sizeof(*volatile_ks.db->ksi.index) * STATIC_KS_VOLATILE_SLOTS +
                      sizeof(*volatile_ks.db->ksi.names) * STATIC_KS_VOLATILE_SLOTS +
                      sizeof(*volatile_ks.db->keys)      * STATIC_KS_VOLATILE_SLOTS);

  uint8_t *mem = NULL;

  if (alloc && (mem = hal_allocate_static_memory(len)) == NULL)
    return HAL_ERROR_ALLOCATION_FAILURE;

  return ks_init(driver, 1, &volatile_ks, mem, len);
}

static hal_error_t ks_volatile_shutdown(const hal_ks_driver_t * const driver)
{
  if (volatile_ks.ks.driver != driver)
    return HAL_ERROR_KEYSTORE_ACCESS;
  return HAL_OK;
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
                            hal_pkey_slot_t *slot,
                            const uint8_t * const der, const size_t der_len)
{
  if (ks == NULL || slot == NULL || der == NULL || der_len == 0 || !acceptable_key_type(slot->type))
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);
  hal_error_t err;
  unsigned b;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if ((err = hal_ks_index_add(&ksv->db->ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK)
    return err;

  uint8_t kek[KEK_LENGTH];
  size_t kek_len;
  ks_key_t k;

  memset(&k, 0, sizeof(k));
  k.der_len = sizeof(k.der);
  k.type    = slot->type;
  k.curve   = slot->curve;
  k.flags   = slot->flags;
  k.client  = slot->client_handle;
  k.session = slot->session_handle;

  if ((err = hal_mkm_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k.der, &k.der_len);

  memset(kek, 0, sizeof(kek));

  if (err == HAL_OK)
    ksv->db->keys[b] = k;
  else
    (void) hal_ks_index_delete(&ksv->db->ksi, &slot->name, 0, NULL, &slot->hint);

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

  if ((err = hal_ks_index_find(&ksv->db->ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK)
    return err;

  const ks_key_t * const k = &ksv->db->keys[b];

  if (!key_visible_to_session(ksv, slot->client_handle, slot->session_handle, k))
    return HAL_ERROR_KEY_NOT_FOUND;

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

    if ((err = hal_mkm_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
      err = hal_aes_keyunwrap(NULL, kek, kek_len, k->der, k->der_len, der, der_len);

    memset(kek, 0, sizeof(kek));

    if (err != HAL_OK)
      return err;
  }

  return HAL_OK;
}

static hal_error_t ks_delete(hal_ks_t *ks,
                             hal_pkey_slot_t *slot)
{
  if (ks == NULL || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);
  hal_error_t err;
  unsigned b;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if ((err = hal_ks_index_find(&ksv->db->ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK)
    return err;

  if (!key_visible_to_session(ksv, slot->client_handle, slot->session_handle, &ksv->db->keys[b]))
    return HAL_ERROR_KEY_NOT_FOUND;

  if ((err = hal_ks_index_delete(&ksv->db->ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK)
    return err;

  memset(&ksv->db->keys[b], 0, sizeof(ksv->db->keys[b]));

  return HAL_OK;
}

static hal_error_t ks_match(hal_ks_t *ks,
                            hal_client_handle_t client,
                            hal_session_handle_t session,
                            const hal_key_type_t type,
                            const hal_curve_name_t curve,
                            const hal_key_flags_t flags,
                            const hal_rpc_pkey_attribute_t *attributes,
                            const unsigned attributes_len,
                            hal_uuid_t *result,
                            unsigned *result_len,
                            const unsigned result_max,
                            const hal_uuid_t * const previous_uuid)
{
  if (ks == NULL || (attributes == NULL && attributes_len > 0) ||
      result == NULL || result_len == NULL || previous_uuid == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  hal_error_t err;
  int i = -1;

  *result_len = 0;

  err = hal_ks_index_find(&ksv->db->ksi, previous_uuid, 0, NULL, &i);

  if (err == HAL_ERROR_KEY_NOT_FOUND)
    i--;
  else if (err != HAL_OK)
    return err;

  while (*result_len < result_max && ++i < ksv->db->ksi.used) {

    unsigned b = ksv->db->ksi.index[i];

    if (ksv->db->ksi.names[b].chunk > 0)
      continue;

    if (type != HAL_KEY_TYPE_NONE && type != ksv->db->keys[b].type)
      continue;

    if (curve != HAL_CURVE_NONE && curve != ksv->db->keys[b].curve)
      continue;

    if (!key_visible_to_session(ksv, client, session, &ksv->db->keys[b]))
      continue;

    if (attributes_len > 0) {
      const ks_key_t * const k = &ksv->db->keys[b];
      int ok = 1;

      if (k->attributes_len == 0)
        continue;

      hal_rpc_pkey_attribute_t key_attrs[k->attributes_len];

      if ((err = hal_ks_attribute_scan(k->der + k->der_len, sizeof(k->der) - k->der_len,
                                       key_attrs, k->attributes_len, NULL)) != HAL_OK)
        return err;

      for (const hal_rpc_pkey_attribute_t *required = attributes;
           ok && required < attributes + attributes_len; required++) {

        hal_rpc_pkey_attribute_t *present = key_attrs;
        while (ok && present->type != required->type)
          ok = ++present < key_attrs + k->attributes_len;

        if (ok)
          ok = (present->length == required->length &&
                !memcmp(present->value, required->value, present->length));
      }

      if (!ok)
        continue;
    }

    result[*result_len] = ksv->db->ksi.names[b].name;
    ++*result_len;
  }

  return HAL_OK;
}

static hal_error_t ks_set_attributes(hal_ks_t *ks,
                                     hal_pkey_slot_t *slot,
                                     const hal_rpc_pkey_attribute_t *attributes,
                                     const unsigned attributes_len)
{
  if (ks == NULL || slot == NULL || attributes == NULL || attributes_len == 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);
  hal_error_t err;
  unsigned b;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if ((err = hal_ks_index_find(&ksv->db->ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK)
    return err;

  ks_key_t * const k = &ksv->db->keys[b];

  if (!key_visible_to_session(ksv, slot->client_handle, slot->session_handle, k))
    return HAL_ERROR_KEY_NOT_FOUND;

  hal_rpc_pkey_attribute_t attrs[k->attributes_len + attributes_len];
  uint8_t *bytes = k->der + k->der_len;
  size_t bytes_len = sizeof(k->der) - k->der_len;
  size_t total_len;

  if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, k->attributes_len, &total_len)) != HAL_OK)
    return err;

  for (const hal_rpc_pkey_attribute_t *a = attributes; a < attributes + attributes_len; a++) {
    if (a->length > 0 && a->value != NULL)
      err =  hal_ks_attribute_insert(bytes, bytes_len, attrs, &k->attributes_len, &total_len,
                                     a->type, a->value, a->length);
    else
      err =  hal_ks_attribute_delete(bytes, bytes_len, attrs, &k->attributes_len, &total_len,
                                     a->type);
    if (err != HAL_OK)
      return err;
  }

  return HAL_OK;
}

static hal_error_t ks_get_attributes(hal_ks_t *ks,
                                     hal_pkey_slot_t *slot,
                                     hal_rpc_pkey_attribute_t *attributes,
                                     const unsigned attributes_len,
                                     uint8_t *attributes_buffer,
                                     const size_t attributes_buffer_len)
{
  if (ks == NULL || slot == NULL || attributes == NULL || attributes_len == 0 ||
      attributes_buffer == NULL || attributes_buffer_len == 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_t *ksv = ks_to_ksv(ks);
  hal_error_t err;
  unsigned b;

  if (ksv->db == NULL)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if ((err = hal_ks_index_find(&ksv->db->ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK)
    return err;

  const ks_key_t * const k = &ksv->db->keys[b];

  if (!key_visible_to_session(ksv, slot->client_handle, slot->session_handle, k))
    return HAL_ERROR_KEY_NOT_FOUND;

  if (k->attributes_len == 0)
    return HAL_ERROR_ATTRIBUTE_NOT_FOUND;

  hal_rpc_pkey_attribute_t attrs[k->attributes_len];

  if ((err = hal_ks_attribute_scan(k->der + k->der_len, sizeof(k->der) - k->der_len,
                                   attrs, k->attributes_len, NULL)) != HAL_OK)
    return err;

  uint8_t *abuf = attributes_buffer;

  for (int i = 0; i < attributes_len; i++) {

    int j = 0;
    while (attrs[j].type != attributes[i].type)
      if (++j >= k->attributes_len)
        return HAL_ERROR_ATTRIBUTE_NOT_FOUND;

    if (attrs[j].length > attributes_buffer + attributes_buffer_len - abuf)
      return HAL_ERROR_RESULT_TOO_LONG;

    memcpy(abuf, attrs[j].value, attrs[j].length);
    attributes[i].value  = abuf;
    attributes[i].length = attrs[j].length;
    abuf += attrs[j].length;
  }

  return HAL_OK;
}

const hal_ks_driver_t hal_ks_volatile_driver[1] = {{
  .init                 = ks_volatile_init,
  .shutdown             = ks_volatile_shutdown,
  .open                 = ks_volatile_open,
  .close                = ks_volatile_close,
  .store                = ks_store,
  .fetch                = ks_fetch,
  .delete               = ks_delete,
  .match                = ks_match,
  .set_attributes       = ks_set_attributes,
  .get_attributes       = ks_get_attributes
}};

#endif /* STATIC_KS_VOLATILE_SLOTS > 0 */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
