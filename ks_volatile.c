/*
 * ks_volatile.c
 * -------------
 * Keystore implementation in normal volatile internal memory.
 *
 * NB: This is only suitable for cases where you do not want the keystore
 *     to survive library exit, eg, for storing PKCS #11 session keys.
 *
 * Authors: Rob Austein
 * Copyright (c) 2015-2017, NORDUnet A/S All rights reserved.
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
#include "ks.h"

#ifndef STATIC_KS_VOLATILE_SLOTS
#define STATIC_KS_VOLATILE_SLOTS HAL_STATIC_PKEY_STATE_BLOCKS
#endif

#ifndef KS_VOLATILE_CACHE_SIZE
#define KS_VOLATILE_CACHE_SIZE 4
#endif

/*
 * Keystore database.
 */

typedef struct {
  hal_client_handle_t   client;
  hal_session_handle_t  session;
  hal_ks_block_t        block;
} ks_volatile_key_t;

typedef struct {
  hal_ks_t ks;              /* Must be first */
  ks_volatile_key_t *keys;
} ks_volatile_db_t;

/*
 * This is a bit silly, but it's safe enough, and it lets us avoid a
 * nasty mess of forward references.
 */

#define db      ((ks_volatile_db_t * const) hal_ks_volatile)

/*
 * Read a block.  CRC probably not necessary for RAM.
 */

static hal_error_t ks_volatile_read(hal_ks_t *ks, const unsigned blockno, hal_ks_block_t *block)
{
  if (ks != hal_ks_volatile || db->keys == NULL || block == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memcpy(block, &db->keys[blockno].block, sizeof(*block));

  return HAL_OK;
}

/*
 * Convert a live block into a tombstone.
 */

static hal_error_t ks_volatile_deprecate(hal_ks_t *ks, const unsigned blockno)
{
  if (ks != hal_ks_volatile || db->keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  db->keys[blockno].block.header.block_status = HAL_KS_BLOCK_STATUS_TOMBSTONE;

  return HAL_OK;
}

/*
 * Zero (not erase) a flash block.
 */

static hal_error_t ks_volatile_zero(hal_ks_t *ks, const unsigned blockno)
{
  if (ks != hal_ks_volatile || db->keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memset(&db->keys[blockno].block, 0x00, sizeof(db->keys[blockno].block));
  db->keys[blockno].client.handle = HAL_HANDLE_NONE;
  db->keys[blockno].session.handle = HAL_HANDLE_NONE;

  return HAL_OK;
}

/*
 * Erase a flash block.
 */

static hal_error_t ks_volatile_erase(hal_ks_t *ks, const unsigned blockno)
{
  if (ks != hal_ks_volatile || db->keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memset(&db->keys[blockno].block, 0xFF, sizeof(db->keys[blockno].block));
  db->keys[blockno].client.handle = HAL_HANDLE_NONE;
  db->keys[blockno].session.handle = HAL_HANDLE_NONE;

  return HAL_OK;
}

/*
 * Write a flash block.  CRC probably not necessary for RAM.
 */

static hal_error_t ks_volatile_write(hal_ks_t *ks, const unsigned blockno, hal_ks_block_t *block)
{
  if (ks != hal_ks_volatile || db->keys == NULL || block == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memcpy(&db->keys[blockno].block, block, sizeof(*block));

  return HAL_OK;
}

/*
 * Set key ownership.
 */

static hal_error_t ks_volatile_set_owner(hal_ks_t *ks,
                                         const unsigned blockno,
                                         const hal_client_handle_t client,
                                         const hal_session_handle_t session)
{
  if (ks != hal_ks_volatile || db->keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  db->keys[blockno].client = client;
  db->keys[blockno].session = session;

  return HAL_OK;
}

/*
 * Test key ownership.
 */

static hal_error_t ks_volatile_test_owner(hal_ks_t *ks,
                                          const unsigned blockno,
                                          const hal_client_handle_t client,
                                          const hal_session_handle_t session)
{
  if (ks != hal_ks_volatile || db->keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  if (db->keys[blockno].client.handle  == client.handle &&
      db->keys[blockno].session.handle == session.handle)
    return HAL_OK;
  else
    return HAL_ERROR_KEY_NOT_FOUND;
}

/*
 * Copy key ownership.
 */

static hal_error_t ks_volatile_copy_owner(hal_ks_t *ks,
                                          const unsigned source,
                                          const unsigned target)
{
  if (ks != hal_ks_volatile || db->keys == NULL || source >= ks->size || target >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  db->keys[target].client  = db->keys[source].client;
  db->keys[target].session = db->keys[source].session;
  return HAL_OK;
}

/*
 * Initialize keystore.
 */

static hal_error_t ks_volatile_init(hal_ks_t *ks, const int alloc)
{
  if (ks != hal_ks_volatile)
    return HAL_ERROR_IMPOSSIBLE;

  hal_error_t err = HAL_OK;
  void *mem = NULL;

  hal_ks_lock();

  if (alloc) {
    if ((err = hal_ks_alloc_common(ks, STATIC_KS_VOLATILE_SLOTS, KS_VOLATILE_CACHE_SIZE,
                                   &mem, sizeof(*db->keys) * STATIC_KS_VOLATILE_SLOTS)) != HAL_OK)
      goto done;
    db->keys = mem;
  }

  if (db->keys == NULL) {
    err = HAL_ERROR_IMPOSSIBLE;
    goto done;
  }

  for (unsigned b = 0; b < db->ks.size; b++)
    if ((err = hal_ks_block_erase(ks, b)) != HAL_OK)
      goto done;

  if ((err = hal_ks_init_common(ks)) != HAL_OK)
    goto done;

  ks->per_session = 1;

  err = HAL_OK;

 done:
  hal_ks_unlock();
  return err;
}

/*
 * Dispatch vector and keystore definition, now that we've defined all
 * the driver functions.
 */

static const hal_ks_driver_t ks_volatile_driver = {
  .init                 = ks_volatile_init,
  .read                 = ks_volatile_read,
  .write                = ks_volatile_write,
  .deprecate            = ks_volatile_deprecate,
  .zero                 = ks_volatile_zero,
  .erase                = ks_volatile_erase,
  .erase_maybe          = ks_volatile_erase, /* sic */
  .set_owner            = ks_volatile_set_owner,
  .test_owner           = ks_volatile_test_owner,
  .copy_owner           = ks_volatile_copy_owner
};

static ks_volatile_db_t _db = { .ks.driver = &ks_volatile_driver };

hal_ks_t * const hal_ks_volatile = &_db.ks;

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
