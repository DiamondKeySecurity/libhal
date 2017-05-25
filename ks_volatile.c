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

typedef struct {
  hal_client_handle_t   client;
  hal_session_handle_t  session;
  hal_ks_block_t	block;
} volatile_key_t;

static struct db {
  hal_ks_t ks;              /* Must be first */
  volatile_key_t *keys;
} db;

/*
 * Read a block.  CRC probably not necessary for RAM.
 */

static hal_error_t block_read(hal_k_t *ks, const unsigned blockno, ks_block_t *block)
{
  if (ks != &db.ks || db.keys == NULL || block == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memcpy(block, &db.keys[blockno].block, sizeof(*block));

  return HAL_OK;
}

/*
 * Convert a live block into a tombstone.
 */

static hal_error_t block_deprecate(hal_k_t *ks, const unsigned blockno)
{
  if (ks != &db.ks || db.keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  db.keys[blockno].block.header->block_status = BLOCK_STATUS_TOMBSTONE;

  return HAL_OK;
}

/*
 * Zero (not erase) a flash block.
 */

static hal_error_t block_zero(hal_k_t *ks, const unsigned blockno)
{
  if (ks != &db.ks || db.keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memset(db.keys[blockno].block, 0x00, sizeof(db.keys[blockno].block));
  db.keys[blockno].client.handle = HAL_HANDLE_NONE;
  db.keys[blockno].session.handle = HAL_HANDLE_NONE;

  return HAL_OK;
}

/*
 * Erase a flash block.
 */

static hal_error_t block_erase(hal_k_t *ks, const unsigned blockno)
{
  if (ks != &db.ks || db.keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memset(db.keys[blockno].block, 0xFF, sizeof(db.keys[blockno].block));
  db.keys[blockno].client.handle = HAL_HANDLE_NONE;
  db.keys[blockno].session.handle = HAL_HANDLE_NONE;

  return HAL_OK;
}

/*
 * Write a flash block.  CRC probably not necessary for RAM.
 */

static hal_error_t block_write(hal_k_t *ks, const unsigned blockno, ks_block_t *block)
{
  if (ks != &db.ks || db.keys == NULL || block == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  memcpy(&db.keys[blockno].block, block, sizeof(*block));

  return HAL_OK;
}

/*
 * Set key ownership.
 */

static hal_error_t block_set_owner(hal_ks_t *ks,
                                   const unsigned blockno,
                                   const hal_client_handle_t client,
                                   const hal_session_handle_t session)
{
  if (ks != &db.ks || db.keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  db.keys[blockno].client = client;
  db.keys[blockno].session = session;

  return HAL_OK;
}

/*
 * Test key ownership.
 */

static hal_error_t block_test_owner(hal_ks_t *ks, const
                                    unsigned blockno,
                                    const hal_client_handle_t client,
                                    const hal_session_handle_t session)
{
  if (ks != &db.ks || db.keys == NULL || blockno >= ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  if (db.keys[blockno].client.handle  == client.handle &&
      db.keys[blockno].session.handle == session.handle)
    return HAL_OK;
  else
    return HAL_ERROR_KEY_NOT_FOUND;
}

/*
 * Initialize keystore.
 */

static const hal_ks_driver_t hal_ks_volatile_driver[1] = {{
  .read               	= block_read,
  .write                = block_write,
  .deprecate		= block_deprecate,
  .zero                 = block_zero,
  .erase                = block_erase,
  .erase_maybe		= block_erase, /* sic */
  .set_owner            = block_set_owner,
  .test_owner           = block_test_owner
}};

 hal_error_t hal_ks_volatile_init(const int alloc)
{
  hal_error_t err = HAL_OK;

  hal_ks_lock();


  if (alloc && (err = hal_ks_alloc_common(&db.ks, STATIC_KS_VOLATILE_SLOTS, KS_VOLATILE_CACHE_SIZE)) != HAL_OK)
    goto done;

  if ((err = hal_ks_init_common(&db.ks, hal_ks_volatile_driver)) != HAL_OK)
    goto done;

  if (alloc && (db.keys = hal_allocate_static_memory(sizeof(*db.keys) * db.ks.size)) == NULL) {
    err = HAL_ERROR_ALLOCATION_FAILURE;
    goto done;
  }

  for (unsigned b = 0; b < db.ks.size; i++)
    if ((err = block_erase(&db.ks, b)) != HAL_OK)
      goto done;

  err = HAL_OK;

 done:
  hal_ks_unlock();
  return err;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
