/*
 * ks_flash.c
 * ----------
 * Keystore implementation in flash memory.
 *
 * Authors: Rob Austein, Fredrik Thulin
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

/*
 * This keystore driver operates over bare flash, versus over a flash file
 * system or flash translation layer. The block size is large enough to
 * hold an AES-keywrapped 4096-bit RSA key. Any remaining space in the key
 * block may be used to store attributes (opaque TLV blobs). If the
 * attributes overflow the key block, additional blocks may be added, but
 * no attribute may exceed the block size.
 */

#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "hal.h"
#include "hal_internal.h"
#include "ks.h"

#include "last_gasp_pin_internal.h"

#define HAL_OK CMIS_HAL_OK
#include "stm-keystore.h"
#undef HAL_OK

#ifndef KS_FLASH_CACHE_SIZE
#define KS_FLASH_CACHE_SIZE 4
#endif

#define NUM_FLASH_BLOCKS        KEYSTORE_NUM_SUBSECTORS

static struct db {
  hal_ks_t              ks;                  /* Must be first (C "subclassing") */
  hal_ks_pin_t          wheel_pin;
  hal_ks_pin_t          so_pin;
  hal_ks_pin_t          user_pin;
} db;

/*
 * PIN block gets the all-zeros UUID, which will never be returned by
 * the UUID generation code (by definition -- it's not a version 4 UUID).
 */

const static hal_uuid_t pin_uuid = {{0}};


/*
 * Calculate offset of the block in the flash address space.
 */

static inline uint32_t block_offset(const unsigned blockno)
{
  return blockno * KEYSTORE_SUBSECTOR_SIZE;
}

/*
 * Read a flash block.
 *
 * Flash read on the Alpha is slow enough that it pays to check the
 * first page before reading the rest of the block.
 */

static hal_error_t block_read(hal_k_t *ks, const unsigned blockno, ks_block_t *block)
{
  if (ks != &db.ks || block == NULL || blockno >= NUM_FLASH_BLOCKS || sizeof(*block) != KEYSTORE_SUBSECTOR_SIZE)
    return HAL_ERROR_IMPOSSIBLE;

  /* Sigh, magic numeric return codes */
  if (keystore_read_data(block_offset(blockno),
                         block->bytes,
                         KEYSTORE_PAGE_SIZE) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  switch (block_get_type(block)) {
  case BLOCK_TYPE_ERASED:
  case BLOCK_TYPE_ZEROED:
    return HAL_OK;
  case BLOCK_TYPE_KEY:
  case BLOCK_TYPE_PIN:
    break;
  default:
    return HAL_ERROR_KEYSTORE_BAD_BLOCK_TYPE;
  }

  switch (block_get_status(block)) {
  case BLOCK_STATUS_LIVE:
  case BLOCK_STATUS_TOMBSTONE:
    break;
  default:
    return HAL_ERROR_KEYSTORE_BAD_BLOCK_TYPE;
  }

  /* Sigh, magic numeric return codes */
  if (keystore_read_data(block_offset(blockno) + KEYSTORE_PAGE_SIZE,
                         block->bytes + KEYSTORE_PAGE_SIZE,
                         sizeof(*block) - KEYSTORE_PAGE_SIZE) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  if (calculate_block_crc(block) != block->header.crc)
    return HAL_ERROR_KEYSTORE_BAD_CRC;

  return HAL_OK;
}

/*
 * Convert a live block into a tombstone.  Caller is responsible for
 * making sure that the block being converted is valid; since we don't
 * need to update the CRC for this, we just modify the first page.
 */

static hal_error_t block_deprecate(hal_k_t *ks, const unsigned blockno)
{
  if (ks != &db.ks || blockno >= NUM_FLASH_BLOCKS)
    return HAL_ERROR_IMPOSSIBLE;

  uint8_t page[KEYSTORE_PAGE_SIZE];
  flash_block_header_t *header = (void *) page;
  uint32_t offset = block_offset(blockno);

  /* Sigh, magic numeric return codes */
  if (keystore_read_data(offset, page, sizeof(page)) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  header->block_status = BLOCK_STATUS_TOMBSTONE;

  /* Sigh, magic numeric return codes */
  if (keystore_write_data(offset, page, sizeof(page)) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  return HAL_OK;
}

/*
 * Zero (not erase) a flash block.  Just need to zero the first page.
 */

static hal_error_t block_zero(hal_k_t *ks, const unsigned blockno)
{
  if (ks != &db.ks || blockno >= NUM_FLASH_BLOCKS)
    return HAL_ERROR_IMPOSSIBLE;

  uint8_t page[KEYSTORE_PAGE_SIZE] = {0};

  /* Sigh, magic numeric return codes */
  if (keystore_write_data(block_offset(blockno), page, sizeof(page)) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  return HAL_OK;
}

/*
 * Erase a flash block.  Also see block_erase_maybe(), below.
 */

static hal_error_t block_erase(hal_k_t *ks, const unsigned blockno)
{
  if (ks != &db.ks || blockno >= NUM_FLASH_BLOCKS)
    return HAL_ERROR_IMPOSSIBLE;

  /* Sigh, magic numeric return codes */
  if (keystore_erase_subsector(blockno) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  return HAL_OK;
}

/*
 * Erase a flash block if it hasn't already been erased.
 * May not be necessary, trying to avoid unnecessary wear.
 *
 * Unclear whether there's any sane reason why this needs to be
 * constant time, given how slow erasure is.  But side channel attacks
 * can be tricky things, and it's theoretically possible that we could
 * leak information about, eg, key length, so we do constant time.
 */

static hal_error_t block_erase_maybe(hal_k_t *ks, const unsigned blockno)
{
  if (ks != &db.ks || blockno >= NUM_FLASH_BLOCKS)
    return HAL_ERROR_IMPOSSIBLE;

  uint8_t mask = 0xFF;

  for (uint32_t a = block_offset(blockno); a < block_offset(blockno + 1); a += KEYSTORE_PAGE_SIZE) {
    uint8_t page[KEYSTORE_PAGE_SIZE];
    if (keystore_read_data(a, page, sizeof(page)) != 1)
      return HAL_ERROR_KEYSTORE_ACCESS;
    for (int i = 0; i < KEYSTORE_PAGE_SIZE; i++)
      mask &= page[i];
  }

  return mask == 0xFF ? HAL_OK : block_erase(blockno);
}

/*
 * Write a flash block, calculating CRC when appropriate.
 */

static hal_error_t block_write(hal_k_t *ks, const unsigned blockno, ks_block_t *block)
{
  if (ks != &db.ks || block == NULL || blockno >= NUM_FLASH_BLOCKS || sizeof(*block) != KEYSTORE_SUBSECTOR_SIZE)
    return HAL_ERROR_IMPOSSIBLE;

  hal_error_t err = block_erase_maybe(blockno);

  if (err != HAL_OK)
    return err;

  switch (block_get_type(block)) {
  case BLOCK_TYPE_KEY:
  case BLOCK_TYPE_PIN:
    block->header.crc = calculate_block_crc(block);
    break;
  default:
    break;
  }

  /* Sigh, magic numeric return codes */
  if (keystore_write_data(block_offset(blockno), block->bytes, sizeof(*block)) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  return HAL_OK;
}

/*
 * The token keystore doesn't implement per-session objects, so these are no-ops.
 */

static hal_error_t block_set_owner(hal_ks_t *ks,
                                   const unsigned blockno,
                                   const hal_client_handle_t client,
                                   const hal_session_handle_t session)
{
  return HAL_OK;
}

static hal_error_t block_test_owner(hal_ks_t *ks, const
                                    unsigned blockno,
                                    const hal_client_handle_t client,
                                    const hal_session_handle_t session)
{
  return HAL_OK;
}

/*
 * Forward reference.
 */

static hal_error_t fetch_pin_block(unsigned *b, ks_block_t **block);

/*
 * Initialize keystore.
 */

static const hal_ks_driver_t hal_ks_token_driver[1] = {{
  .read               	= block_read,
  .write                = block_write,
  .deprecate		= block_deprecate,
  .zero                 = block_zero,
  .erase                = block_erase,
  .erase_maybe		= block_erase_maybe,
  .set_owner            = block_set_owner,
  .test_owner           = block_test_owner
}};

hal_error_t hal_ks_token_init(const int alloc)
{
  hal_error_t err = HAL_OK;

  hal_ks_lock();

  if (alloc && (err = hal_ks_alloc_common(&db.ks, NUM_FLASH_BLOCKS, KS_FLASH_CACHE_SIZE)) != HAL_OK)
    goto done;

  if ((err = hal_ks_init_common(ks, hal_ks_token_driver)) != HAL_OK)
    goto done;

  /*
   * Fetch or create the PIN block.
   */

  memset(&db.wheel_pin, 0, sizeof(db.wheel_pin));
  memset(&db.so_pin,    0, sizeof(db.so_pin));
  memset(&db.user_pin,  0, sizeof(db.user_pin));

  err = fetch_pin_block(NULL, &block);

  if (err == HAL_OK) {
    db.wheel_pin = block->pin.wheel_pin;
    db.so_pin    = block->pin.so_pin;
    db.user_pin  = block->pin.user_pin;
  }

  else if (err != HAL_ERROR_KEY_NOT_FOUND)
    goto done;

  else {
    /*
     * We found no PIN block, so create one, with the user and so PINs
     * cleared and the wheel PIN set to the last-gasp value.  The
     * last-gasp WHEEL PIN is a terrible answer, but we need some kind
     * of bootstrapping mechanism when all else fails.  If you have a
     * better suggestion, we'd love to hear it.
     */

    unsigned b;

    memset(block, 0xFF, sizeof(*block));

    block->header.block_type   = BLOCK_TYPE_PIN;
    block->header.block_status = BLOCK_STATUS_LIVE;

    block->pin.wheel_pin = db.wheel_pin = hal_last_gasp_pin;
    block->pin.so_pin    = db.so_pin;
    block->pin.user_pin  = db.user_pin;

    if ((err = hal_ks_index_add(&db.ksi, &pin_uuid, &b, NULL)) != HAL_OK)
      goto done;

    cache_mark_used(block, b);

    err = block_write(b, block);

    cache_release(block);

    if (err != HAL_OK)
      goto done;
  }

  err = HAL_OK;

 done:
  hal_ks_unlock();
  return err;
}

/*
 * The remaining functions aren't really part of the keystore API per se,
 * but they all involve non-key data which we keep in the keystore
 * because it's the flash we've got.
 */

/*
 * Special bonus init routine used only by the bootloader, so that it
 * can read PINs set by the main firmware.  Yes, this is a kludge.  We
 * could of course call the real ks_init() routine instead, but it's
 * slow, and we don't want to allow anything that would modify the
 * flash here, so having a special entry point for this kludge is
 * simplest, overall.  Sigh.
 */

void hal_ks_init_read_only_pins_only(void)
{
  unsigned b, best_seen = ~0;
  ks_block_t block[1];

  hal_ks_lock();

  for (b = 0; b < NUM_FLASH_BLOCKS; b++) {
    if (block_read(b, block) != HAL_OK || block_get_type(block) != BLOCK_TYPE_PIN)
      continue;
    best_seen = b;
    if (block_get_status(block) == BLOCK_STATUS_LIVE)
      break;
  }

  if (b != best_seen && best_seen != ~0 && block_read(best_seen, block) != HAL_OK)
    best_seen = ~0;

  if (best_seen == ~0) {
    memset(block, 0xFF, sizeof(*block));
    block->pin.wheel_pin = hal_last_gasp_pin;
  }

  db.wheel_pin = block->pin.wheel_pin;
  db.so_pin    = block->pin.so_pin;
  db.user_pin  = block->pin.user_pin;

  hal_ks_unlock();
}

/*
 * Fetch PIN.  This is always cached, so just returned cached value.
 */

hal_error_t hal_get_pin(const hal_user_t user,
                        const hal_ks_pin_t **pin)
{
  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err = HAL_OK;

  hal_ks_lock();

  switch (user) {
  case HAL_USER_WHEEL:  *pin = &db.wheel_pin;  break;
  case HAL_USER_SO:     *pin = &db.so_pin;     break;
  case HAL_USER_NORMAL: *pin = &db.user_pin;   break;
  default:               err = HAL_ERROR_BAD_ARGUMENTS;
  }

  hal_ks_unlock();

  return err;
}

/*
 * Fetch PIN block.  hint = 0 because we know that the all-zeros UUID
 * should always sort to first slot in the index.
 */

static hal_error_t fetch_pin_block(unsigned *b, ks_block_t **block)
{
  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  hal_error_t err;
  int hint = 0;
  unsigned b_;

  if (b == NULL)
    b = &b_;

  if ((err = hal_ks_index_find(&db.ksi, &pin_uuid, b, &hint))   != HAL_OK ||
      (err = block_read_cached(*b, block))                      != HAL_OK)
    return err;

  cache_mark_used(*block, *b);

  if (block_get_type(*block) != BLOCK_TYPE_PIN)
    return HAL_ERROR_IMPOSSIBLE;

  return HAL_OK;
}

/*
 * Update the PIN block.  This block should always be present, but we
 * have to do the zombie jamboree to make sure we write the new PIN
 * block before destroying the old one.  hint = 0 because we know that
 * the all-zeros UUID should always sort to first slot in the index.
 */

static hal_error_t update_pin_block(const unsigned b,
                                    ks_block_t *block,
                                    const flash_pin_block_t * const new_data)
{
  if (block == NULL || new_data == NULL || block_get_type(block) != BLOCK_TYPE_PIN)
    return HAL_ERROR_IMPOSSIBLE;

  int hint = 0;

  block->pin = *new_data;

  return block_update(b, block, &pin_uuid, &hint);
}

/*
 * Change a PIN.
 */

hal_error_t hal_set_pin(const hal_user_t user,
                        const hal_ks_pin_t * const pin)
{
  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_block_t *block;
  hal_error_t err;
  unsigned b;

  hal_ks_lock();

  if ((err = fetch_pin_block(&b, &block)) != HAL_OK)
    goto done;

  flash_pin_block_t new_data = block->pin;
  hal_ks_pin_t *dp, *bp;

  switch (user) {
  case HAL_USER_WHEEL:  bp = &new_data.wheel_pin; dp = &db.wheel_pin; break;
  case HAL_USER_SO:     bp = &new_data.so_pin;    dp = &db.so_pin;    break;
  case HAL_USER_NORMAL: bp = &new_data.user_pin;  dp = &db.user_pin;  break;
  default:              err = HAL_ERROR_BAD_ARGUMENTS;  goto done;
  }

  const hal_ks_pin_t old_pin = *dp;
  *dp = *bp = *pin;

  if ((err = update_pin_block(b, block, &new_data)) != HAL_OK)
    *dp = old_pin;

 done:
  hal_ks_unlock();
  return err;
}

#if HAL_MKM_FLASH_BACKUP_KLUDGE

/*
 * Horrible insecure kludge in lieu of a battery for the MKM.
 *
 * API here is a little strange: all calls pass a length parameter,
 * but any length other than the compiled in constant just returns an
 * immediate error, there's no notion of buffer max length vs buffer
 * used length, querying for the size of buffer really needed, or
 * anything like that.
 *
 * We might want to rewrite this some day, if we don't replace it with
 * a battery first.  For now we just preserve the API as we found it
 * while re-implementing it on top of the new keystore.
 */

hal_error_t hal_mkm_flash_read_no_lock(uint8_t *buf, const size_t len)
{
  if (buf != NULL && len != KEK_LENGTH)
    return HAL_ERROR_MASTERKEY_BAD_LENGTH;

  ks_block_t *block;
  hal_error_t err;
  unsigned b;

  if ((err = fetch_pin_block(&b, &block)) != HAL_OK)
    return err;

  if (block->pin.kek_set != FLASH_KEK_SET)
    return HAL_ERROR_MASTERKEY_NOT_SET;

  if (buf != NULL)
    memcpy(buf, block->pin.kek, len);

  return HAL_OK;
}

hal_error_t hal_mkm_flash_read(uint8_t *buf, const size_t len)
{
  hal_ks_lock();
  const hal_error_t err = hal_mkm_flash_read_no_lock(buf, len);
  hal_ks_unlock();
  return err;
}

hal_error_t hal_mkm_flash_write(const uint8_t * const buf, const size_t len)
{
  if (buf == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (len != KEK_LENGTH)
    return HAL_ERROR_MASTERKEY_BAD_LENGTH;

  ks_block_t *block;
  hal_error_t err;
  unsigned b;

  hal_ks_lock();

  if ((err = fetch_pin_block(&b, &block)) != HAL_OK)
    goto done;

  flash_pin_block_t new_data = block->pin;

  new_data.kek_set = FLASH_KEK_SET;
  memcpy(new_data.kek, buf, len);

  err = update_pin_block(b, block, &new_data);

 done:
  hal_ks_unlock();
  return err;
}

hal_error_t hal_mkm_flash_erase(const size_t len)
{
  if (len != KEK_LENGTH)
    return HAL_ERROR_MASTERKEY_BAD_LENGTH;

  ks_block_t *block;
  hal_error_t err;
  unsigned b;

  hal_ks_lock();

  if ((err = fetch_pin_block(&b, &block)) != HAL_OK)
    goto done;

  flash_pin_block_t new_data = block->pin;

  new_data.kek_set = FLASH_KEK_SET;
  memset(new_data.kek, 0, len);

  err = update_pin_block(b, block, &new_data);

 done:
  hal_ks_unlock();
  return err;
}

#endif /* HAL_MKM_FLASH_BACKUP_KLUDGE */


/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
