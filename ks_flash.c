/*
 * ks_flash.c
 * ----------
 * Keystore implementation in flash memory.
 *
 * Authors: Rob Austein, Fredrik Thulin
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

#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "hal.h"
#include "hal_internal.h"

#include "last_gasp_pin_internal.h"

#define HAL_OK CMIS_HAL_OK
#include "stm-keystore.h"
#undef HAL_OK

/*
 * Revised flash keystore database.  Work in progress.
 *
 * General consideration:
 *
 * - bits can only be cleared, not set, unless one wants to erase the
 *   sector.  This has some odd knock on effects in terms of
 *   things like values of enumerated constants used here.
 *
 * - This code assumes we're using ks_index.c, including its notion
 *   of a free list and its attempt at light-weight wear leveling.
 *
 * - This version takes a simplistic approach to updating existing
 *   blocks: write the modified contents to a new block regardless of
 *   whether they could have been made in-place.  The only in-place
 *   modifications we make are things like zeroing a block to mark it
 *   as having been used recently, so that it will go near the end of
 *   the free list.  We could allow many kinds of updates in place by
 *   making the crc field in the block header an array with some kind
 *   of counter (probably encoded as a mask given the constraints),
 *   but the code would be more complicated and it's not immediately
 *   obvious that it's worth it.  Maybe add that as a wear reduction
 *   feature later, but let's get the simpler version working first.
 *
 * Current theory for update logic:
 *
 * 1) Update-in-place of old block to deprecate;
 * 2) Write new block, including updating index;
 * 3) Update-in-place of old block to zero.
 */

/*
 * Known block states.
 *
 * Might want an additional state 0xDEADDEAD to mark blocks which
 * are known to be unusable, but the current hardware is NOR flash
 * so that may not be as important as it would be with NAND flash.
 *
 * C does not guarantee any particular representation for enums, so
 * including an enum directly in the block header isn't safe.
 */

typedef enum {
  FLASH_ERASED  = 0xFFFFFFFF, /* Pristine erased block (candidate for reuse) */
  FLASH_ZEROED  = 0x00000000, /* Zeroed block (recently used) */
  FLASH_KEYBLK  = 0x55555555, /* Block contains key material */
  FLASH_KEYOLD  = 0x41411414, /* Deprecated key block */
  FLASH_PINBLK  = 0xAAAAAAAA, /* Block contains PINs */
  FLASH_PINOLD  = 0x82822828, /* Deprecated PIN block */
  FLASH_UNKNOWN = 0x12345678, /* Internal code for "I have no clue what this is" */
} flash_block_type_t;

/*
 * Common header for all flash block types.  The crc fields should
 * remain at the end of the header to simplify the CRC calculation.
 */

typedef struct {
  uint32_t              block_type;
  hal_crc32_t           crc1, crc2;
} flash_block_header_t;

/*
 * We probably want some kind of TLV format for optional attributes
 * in key objects, and might want to put the DER key itself there to
 * save space.
 */

typedef struct {
  flash_block_header_t  header;
  hal_uuid_t            name;
  hal_key_type_t        type;
  hal_curve_name_t      curve;
  hal_key_flags_t       flags;
  size_t                der_len;
  uint8_t               der[HAL_KS_WRAPPED_KEYSIZE];
} flash_key_block_t;

/*
 * PIN block.  Also includes space for backing up the KEK when
 * HAL_MKM_FLASH_BACKUP_KLUDGE is enabled.
 */

typedef struct {
  flash_block_header_t  header;
  hal_ks_pin_t          wheel_pin;
  hal_ks_pin_t          so_pin;
  hal_ks_pin_t          user_pin;
#if HAL_MKM_FLASH_BACKUP_KLUDGE
  uint32_t              kek_set;
  uint8_t               kek[KEK_LENGTH];
#endif
} flash_pin_block_t;

#define FLASH_KEK_SET   0x33333333

/*
 * One flash block.
 */

typedef union {
  uint8_t               bytes[KEYSTORE_SUBSECTOR_SIZE];
  flash_block_header_t  header;
  flash_key_block_t     key;
  flash_pin_block_t     pin;
} flash_block_t;

/*
 * In-memory cache.
 */

typedef struct {
  unsigned            blockno;
  uint32_t            lru;
  flash_block_t       block;
} cache_block_t;

/*
 * In-memory database.
 *
 * The top-level structure is a static variable; the arrays are allocated at runtime
 * using hal_allocate_static_memory() because they can get kind of large.
 */

#ifndef KS_FLASH_CACHE_SIZE
#define KS_FLASH_CACHE_SIZE 4
#endif

#define NUM_FLASH_BLOCKS        KEYSTORE_NUM_SUBSECTORS

typedef struct {
  hal_ks_t              ks;                  /* Must be first (C "subclassing") */
  hal_ks_index_t        ksi;
  hal_ks_pin_t          wheel_pin;
  hal_ks_pin_t          so_pin;
  hal_ks_pin_t          user_pin;
  uint32_t              cache_lru;
  cache_block_t         *cache;
} db_t;

/*
 * PIN block gets the all-zeros UUID, which will never be returned by
 * the UUID generation code (by definition -- it's not a version 4 UUID).
 */

const static hal_uuid_t pin_uuid = {{0}};

/*
 * The in-memory database almost certainly should be a pointer to
 * allocated SDRAM rather than compile-time data space.  Well,
 * the arrays should be, anyway, it might be reasonable to keep
 * the top level structure here.  Worry about that later.
 */

static db_t db;

/*
 * Type safe cast.
 */

static inline flash_block_type_t block_get_type(const flash_block_t * const block)
{
  assert(block != NULL);
  return (flash_block_type_t) block->header.block_type;
}

/*
 * Pick unused or least-recently-used slot in our in-memory cache.
 *
 * Updating lru values is caller's problem: if caller is using cache
 * slot as a temporary buffer and there's no point in caching the
 * result, leave the lru values alone and the right thing will happen.
 */

static inline flash_block_t *cache_pick_lru(void)
{
  uint32_t best_delta = 0;
  int      best_index = 0;

  for (int i = 0; i < KS_FLASH_CACHE_SIZE; i++) {

    if (db.cache[i].blockno == ~0)
      return &db.cache[i].block;

    const uint32_t delta = db.cache_lru - db.cache[i].lru;
    if (delta > best_delta) {
      best_delta = delta;
      best_index = i;
    }

  }

  db.cache[best_index].blockno = ~0;
  return &db.cache[best_index].block;
}

/*
 * Find a block in our in-memory cache; return block or NULL if not present.
 */

static inline flash_block_t *cache_find_block(const unsigned blockno)
{
  for (int i = 0; i < KS_FLASH_CACHE_SIZE; i++)
    if (db.cache[i].blockno == blockno)
      return &db.cache[i].block;
  return NULL;
}

/*
 * Mark a block in our in-memory cache as being in current use.
 */

static inline void cache_mark_used(const flash_block_t * const block, const unsigned blockno)
{
  for (int i = 0; i < KS_FLASH_CACHE_SIZE; i++) {
    if (&db.cache[i].block == block) {
      db.cache[i].blockno = blockno;
      db.cache[i].lru = ++db.cache_lru;
      return;
    }
  }
}

/*
 * Release a block from the in-memory cache.
 */

static inline void cache_release(const flash_block_t * const block)
{
  if (block != NULL)
    cache_mark_used(block, ~0);
}

/*
 * Generate CRC-32 for a block.
 *
 * This function needs to understand the structure of
 * flash_block_header_t, so that it can skip over the crc field.
 */

static hal_crc32_t calculate_block_crc(const flash_block_t * const block)
{
  assert(block != NULL);

  hal_crc32_t crc = hal_crc32_init();

  crc = hal_crc32_update(crc,
                         block->bytes,
                         offsetof(flash_block_header_t, crc1));

  crc = hal_crc32_update(crc,
                         block->bytes + sizeof(flash_block_header_t),
                         sizeof(*block) - sizeof(flash_block_header_t));

  return hal_crc32_finalize(crc);
}

/*
 * Calculate block offset.
 */

static uint32_t block_offset(const unsigned blockno)
{
  return blockno * KEYSTORE_SUBSECTOR_SIZE;
}

/*
 * Read a flash block.
 *
 * Sadly, flash on the Alpha is slow enough that it pays to
 * check the first page before reading the rest of the block.
 */

static hal_error_t block_read(const unsigned blockno, flash_block_t *block)
{
  assert(block != NULL && blockno < NUM_FLASH_BLOCKS && sizeof(*block) == KEYSTORE_SUBSECTOR_SIZE);

  /* Sigh, magic numeric return codes */
  if (keystore_read_data(block_offset(blockno),
                         block->bytes,
                         KEYSTORE_PAGE_SIZE) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  flash_block_type_t block_type = block_get_type(block);
  hal_crc32_t crc = 0;

  switch (block_type) {
  case FLASH_KEYBLK:
  case FLASH_PINBLK:
    crc = block->header.crc1;
    break;
  case FLASH_KEYOLD:
  case FLASH_PINOLD:
    crc = block->header.crc2;
    break;
  case FLASH_ERASED:
  case FLASH_ZEROED:
    return HAL_OK;
  default:
    return HAL_ERROR_KEYSTORE_BAD_BLOCK_TYPE;
  }

  /* Sigh, magic numeric return codes */
  if (keystore_read_data(block_offset(blockno) + KEYSTORE_PAGE_SIZE,
                         block->bytes + KEYSTORE_PAGE_SIZE,
                         sizeof(*block) - KEYSTORE_PAGE_SIZE) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  switch (block_type) {
  default:
    if (calculate_block_crc(block) != crc)
      return HAL_ERROR_KEYSTORE_BAD_CRC;
  case FLASH_ERASED:
  case FLASH_ZEROED:
    return HAL_OK;
  }
}

/*
 * Read a block using the cache.  Marking the block as used is left
 * for the caller, so we can avoid blowing out the cache when we
 * perform a ks_list() operation.
 */

static hal_error_t block_read_cached(const unsigned blockno, flash_block_t **block)
{
  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if ((*block = cache_find_block(blockno)) != NULL)
    return HAL_OK;

  if ((*block = cache_pick_lru()) == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  return block_read(blockno, *block);
}

/*
 * Write a flash block, calculating CRC when appropriate.
 *
 * NB: This does NOT automatically erase the block prior to write,
 * because doing so would either mess up our wear leveling algorithm
 * (such as it is) or cause gratuitous erasures (increasing wear).
 */

static hal_error_t block_write(const unsigned blockno, flash_block_t *block)
{
  assert(block != NULL && blockno < NUM_FLASH_BLOCKS && sizeof(*block) == KEYSTORE_SUBSECTOR_SIZE);

  switch (block_get_type(block)) {
  case FLASH_KEYBLK:
  case FLASH_PINBLK:
    block->header.crc1 = calculate_block_crc(block);
    break;
  case FLASH_KEYOLD:
  case FLASH_PINOLD:
    block->header.crc2 = calculate_block_crc(block);
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
 * Zero (not erase) a flash block.  Just need to zero the first page.
 */

static hal_error_t block_zero(const unsigned blockno)
{
  uint8_t page[KEYSTORE_PAGE_SIZE] = {0};

  /* Sigh, magic numeric return codes */
  if (keystore_write_data(block_offset(blockno), page, sizeof(page)) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  return HAL_OK;
}

/*
 * Erase a flash block.  Also see block_erase_maybe(), below.
 */

static hal_error_t block_erase(const unsigned blockno)
{
  assert(blockno < NUM_FLASH_BLOCKS);

  /* Sigh, magic numeric return codes */
  if (keystore_erase_subsectors(blockno, blockno) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  return HAL_OK;
}

/*
 * Erase a flash block if it hasn't already been erased.
 * We have to disable fast read for this to work properly.
 * May not be necessary, trying to avoid unnecessary wear.
 *
 * Unclear whether there's any sane reason why this needs to be
 * constant time, given how slow erasure is.  But side channel attacks
 * can be tricky things, and it's theoretically possible that we could
 * leak information about, eg, key length, so we do constant time.
 */

static hal_error_t block_erase_maybe(const unsigned blockno)
{
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
 * Initialize keystore.  This includes some tricky bits that attempt
 * to preserve the free list ordering across reboots, to improve our
 * simplistic attempt at wear leveling.
 */

static hal_error_t ks_init(const hal_ks_driver_t * const driver)
{
  /*
   * Initialize the in-memory database.
   */

  const size_t len = (sizeof(*db.ksi.index) * NUM_FLASH_BLOCKS +
                      sizeof(*db.ksi.names) * NUM_FLASH_BLOCKS +
                      sizeof(*db.cache)     * KS_FLASH_CACHE_SIZE);

  uint8_t *mem = hal_allocate_static_memory(len);

  if (mem == NULL)
    return HAL_ERROR_ALLOCATION_FAILURE;

  memset(&db, 0, sizeof(db));
  memset(mem, 0, len);

  db.ksi.size  = NUM_FLASH_BLOCKS;
  db.ksi.index = (void *) mem; mem += sizeof(*db.ksi.index) * NUM_FLASH_BLOCKS;
  db.ksi.names = (void *) mem; mem += sizeof(*db.ksi.names) * NUM_FLASH_BLOCKS;
  db.cache     = (void *) mem;

  for (int i = 0; i < KS_FLASH_CACHE_SIZE; i++)
    db.cache[i].blockno = ~0;

  /*
   * Scan existing content of flash to figure out what we've got.
   * This gets a bit involved due to the need to recover from things
   * like power failures at inconvenient times.
   */

  flash_block_type_t block_types[NUM_FLASH_BLOCKS];
  flash_block_t *block = cache_pick_lru();
  int first_erased = -1;
  int saw_pins = 0;
  hal_error_t err;
  uint16_t n = 0;

  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  for (int i = 0; i < NUM_FLASH_BLOCKS; i++) {

    /*
     * Read one block.  If the CRC is bad or the block type is
     * unknown, it's old data we don't understand, something we were
     * writing when we crashed, or bad flash; in any of these cases,
     * we want the block to ends up near the end of the free list.
     */

    err = block_read(i, block);

    if (err == HAL_ERROR_KEYSTORE_BAD_CRC || err == HAL_ERROR_KEYSTORE_BAD_BLOCK_TYPE)
      block_types[i] = FLASH_UNKNOWN;

    else if (err == HAL_OK)
      block_types[i] = block_get_type(block);

    else
      return err;

    /*
     * First erased block we see is head of the free list.
     */

    if (block_types[i] == FLASH_ERASED && first_erased < 0)
      first_erased = i;

    /*
     * If it is or was a key block, remember its name.
     * PIN blocks get the all-zeros UUID for ks_index purposes.
     */

    if (block_types[i] == FLASH_KEYBLK || block_types[i] == FLASH_KEYOLD)
      db.ksi.names[i] = block->key.name;

    /*
     * If it is or was a PIN block, remember the PINs, but don't
     * overwrite PINs from a current PIN block with PINs from a
     * deprecated PIN block.
     */

    if (block_types[i] == FLASH_PINBLK || (block_types[i] == FLASH_PINOLD && !saw_pins)) {
      db.wheel_pin = block->pin.wheel_pin;
      db.so_pin    = block->pin.so_pin;
      db.user_pin  = block->pin.user_pin;
      saw_pins = 1;
    }

    /*
     * If it's a current block, include it in the index.
     */

    if (block_types[i] == FLASH_KEYBLK || block_types[i] == FLASH_PINBLK)
      db.ksi.index[n++] = i;
  }

  db.ksi.used = n;

  assert(db.ksi.used <= db.ksi.size);

  /*
   * At this point we've built the (unsorted) index from all the
   * current blocks.  Now we need to insert free, deprecated, and
   * unrecognized blocks into the free list in our preferred order.
   * There's probably a more efficient way to do this, but this is
   * just integer comparisons in a fairly small data set, so all of
   * these loops should be pretty fast.
   */

  if (n < db.ksi.size)
    for (int i = 0; i < NUM_FLASH_BLOCKS; i++)
      if (block_types[i] == FLASH_ERASED)
        db.ksi.index[n++] = i;

  if (n < db.ksi.size)
    for (int i = first_erased; i < NUM_FLASH_BLOCKS; i++)
      if (block_types[i] == FLASH_ZEROED)
        db.ksi.index[n++] = i;

  if (n < db.ksi.size)
    for (int i = 0; i < first_erased; i++)
      if (block_types[i] == FLASH_ZEROED)
        db.ksi.index[n++] = i;

  if (n < db.ksi.size)
    for (int i = 0; i < NUM_FLASH_BLOCKS; i++)
      if (block_types[i] == FLASH_KEYOLD || block_types[i] == FLASH_PINOLD)
        db.ksi.index[n++] = i;

  if (n < db.ksi.size)
    for (int i = 0; i < NUM_FLASH_BLOCKS; i++)
      if (block_types[i] == FLASH_UNKNOWN)
        db.ksi.index[n++] = i;

  assert(n == db.ksi.size);

  /*
   * Initialize the ks_index stuff.
   */

  if ((err = hal_ks_index_setup(&db.ksi)) != HAL_OK)
    return err;

  /*
   * Deal with deprecated blocks.  These are tombstones left behind
   * when something bad happened while we updating a block.  If write
   * of the updated block completed, we have nothing to do other than
   * cleaning up the tombstone, but if the write didn't complete, we
   * need to resurrect the data from the tombstone.
   */

  for (int i = 0; i < NUM_FLASH_BLOCKS; i++) {
    flash_block_type_t restore_type;

    switch (block_types[i]) {
    case FLASH_KEYOLD:  restore_type = FLASH_KEYBLK;    break;
    case FLASH_PINOLD:  restore_type = FLASH_PINBLK;    break;
    default:            continue;
    }

    err = hal_ks_index_find(&db.ksi, &db.ksi.names[i], NULL);

    if (err != HAL_OK && err != HAL_ERROR_KEY_NOT_FOUND)
      return err;

    unsigned b = ~0;

    if (err == HAL_ERROR_KEY_NOT_FOUND) {

      /*
       * Block did not exist, need to resurrect.
       */

      hal_uuid_t name = db.ksi.names[i]; /* Paranoia */

      if ((err = block_read(i, block)) != HAL_OK)
        return err;

      block->header.block_type = restore_type;

      if ((err = hal_ks_index_add(&db.ksi, &name, &b)) != HAL_OK ||
          (err = block_erase(b))                       != HAL_OK ||
          (err = block_write(b, block))                != HAL_OK)
        return err;

      if (restore_type == FLASH_PINBLK)
        saw_pins = 1;
    }

    /*
     * Done with the tombstone, zero it.
     */

    if ((unsigned) i != b && (err = block_zero(i)) != HAL_OK)
      return err;
  }

  /*
   * If we didn't see a PIN block, create one, with the user and so
   * PINs cleared and the wheel PIN set to the last-gasp value.  The
   * last-gasp WHEEL PIN is a terrible answer, but we need some kind
   * of bootstrapping mechanism when all else fails.  If you have a
   * better suggestion, we'd love to hear it.
   */

  if (!saw_pins) {
    unsigned b;

    memset(block, 0xFF, sizeof(*block));

    db.wheel_pin = hal_last_gasp_pin;

    block->header.block_type = FLASH_PINBLK;
    block->pin.wheel_pin = db.wheel_pin;
    block->pin.so_pin    = db.so_pin;
    block->pin.user_pin  = db.user_pin;

    if ((err = hal_ks_index_add(&db.ksi, &pin_uuid, &b)) != HAL_OK)
      return err;

    cache_mark_used(block, b);

    if ((err = block_erase_maybe(b)) == HAL_OK)
      err = block_write(b, block);

    cache_release(block);

    if (err != HAL_OK)
      return err;
  }

  /*
   * Erase first block on free list if it's not already erased.
   */

  if (db.ksi.used < db.ksi.size &&
      (err = block_erase_maybe(db.ksi.index[db.ksi.used])) != HAL_OK)
    return err;

  /*
   * And we're finally done.
   */

  db.ks.driver = driver;

  return HAL_OK;
}

static hal_error_t ks_shutdown(const hal_ks_driver_t * const driver)
{
  if (db.ks.driver != driver)
    return HAL_ERROR_KEYSTORE_ACCESS;
  return HAL_OK;
}

static hal_error_t ks_open(const hal_ks_driver_t * const driver,
                                    hal_ks_t **ks)
{
  if (driver != hal_ks_token_driver || ks == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  *ks = &db.ks;
  return HAL_OK;
}

static hal_error_t ks_close(hal_ks_t *ks)
{
  if (ks != NULL && ks != &db.ks)
    return HAL_ERROR_BAD_ARGUMENTS;

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
  if (ks != &db.ks || slot == NULL || der == NULL || der_len == 0 || !acceptable_key_type(slot->type))
    return HAL_ERROR_BAD_ARGUMENTS;

  flash_block_t *block = cache_pick_lru();
  flash_key_block_t *k = &block->key;
  uint8_t kek[KEK_LENGTH];
  size_t kek_len;
  hal_error_t err;
  unsigned b;

  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if ((err = hal_ks_index_add(&db.ksi, &slot->name, &b)) != HAL_OK)
    return err;

  cache_mark_used(block, b);

  memset(block, 0xFF, sizeof(*block));
  block->header.block_type = FLASH_KEYBLK;
  k->name    = slot->name;
  k->type    = slot->type;
  k->curve   = slot->curve;
  k->flags   = slot->flags;
  k->der_len = sizeof(k->der);

  if ((err = hal_mkm_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k->der, &k->der_len);

  memset(kek, 0, sizeof(kek));

  if (err == HAL_OK &&
      (err = block_erase_maybe(b)) == HAL_OK &&
      (err = block_write(b, block)) == HAL_OK)
    return HAL_OK;

  memset(block, 0, sizeof(*block));
  cache_release(block);
  (void) hal_ks_index_delete(&db.ksi, &slot->name, NULL);
  return err;
}

static hal_error_t ks_fetch(hal_ks_t *ks,
                            hal_pkey_slot_t *slot,
                            uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  flash_block_t *block;
  hal_error_t err;
  unsigned b;

  if ((err = hal_ks_index_find(&db.ksi, &slot->name, &b)) != HAL_OK ||
      (err = block_read_cached(b, &block)) != HAL_OK)
    return err;

  cache_mark_used(block, b);

  flash_key_block_t *k = &block->key;

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
                             const hal_pkey_slot_t * const slot)
{
  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err;
  unsigned b;

  if ((err = hal_ks_index_delete(&db.ksi, &slot->name, &b)) != HAL_OK)
    return err;

  /*
   * If we wanted to double-check the flash block itself against what
   * we got from the index, this is where we'd do it.
   */

  cache_release(cache_find_block(b));

  if ((err = block_zero(b)) != HAL_OK ||
      (err = block_erase_maybe(db.ksi.index[db.ksi.used])) != HAL_OK)
    return err;

  return HAL_OK;
}

static hal_error_t ks_list(hal_ks_t *ks,
                           hal_pkey_info_t *result,
                           unsigned *result_len,
                           const unsigned result_max)
{
  if (ks != &db.ks || result == NULL || result_len == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (db.ksi.used > result_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  flash_block_t *block;
  hal_error_t err;
  unsigned b;

  *result_len = 0;

  for (int i = 0; i < db.ksi.used; i++) {
    b = db.ksi.index[i];

    if ((err = block_read_cached(b, &block)) != HAL_OK)
      return err;

    if (block_get_type(block) != FLASH_KEYBLK)
      continue;

    result[*result_len].type  = block->key.type;
    result[*result_len].curve = block->key.curve;
    result[*result_len].flags = block->key.flags;
    result[*result_len].name  = block->key.name;
    ++ *result_len;
  }

  return HAL_OK;
}

const hal_ks_driver_t hal_ks_token_driver[1] = {{
  ks_init,
  ks_shutdown,
  ks_open,
  ks_close,
  ks_store,
  ks_fetch,
  ks_delete,
  ks_list
}};

/*
 * The remaining functions aren't really part of the keystore API per se,
 * but they all involve non-key data which we keep in the keystore
 * because it's the flash we've got.
 */

/*
 * Fetch PIN.  This is always cached, so just returned cached value.
 */

hal_error_t hal_get_pin(const hal_user_t user,
                        const hal_ks_pin_t **pin)
{
  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  switch (user) {
  case HAL_USER_WHEEL:  *pin = &db.wheel_pin;  break;
  case HAL_USER_SO:     *pin = &db.so_pin;     break;
  case HAL_USER_NORMAL: *pin = &db.user_pin;   break;
  default:              return HAL_ERROR_BAD_ARGUMENTS;
  }

  return HAL_OK;
}

/*
 * Fetch PIN block.
 */

static hal_error_t fetch_pin_block(unsigned *b, flash_block_t **block)
{
  assert(b != NULL && block != NULL);

  hal_error_t err;

  if ((err = hal_ks_index_find(&db.ksi, &pin_uuid, b)) != HAL_OK ||
      (err = block_read_cached(*b, block))             != HAL_OK)
    return err;

  cache_mark_used(*block, *b);

  if (block_get_type(*block) != FLASH_PINBLK)
    return HAL_ERROR_IMPOSSIBLE;

  return HAL_OK;
}

/*
 * Update the PIN block.  This block should always be present, but we
 * have to dance a bit to make sure we write the new PIN block before
 * destroying the old one.
 */

static hal_error_t update_pin_block(const unsigned b1,
                                    flash_block_t *block,
                                    const flash_pin_block_t * const new_data)
{
  assert(block != NULL && new_data != NULL && block_get_type(block) == FLASH_PINBLK);

  hal_error_t err;
  unsigned b2;

  block->header.block_type = FLASH_PINOLD;

  err = block_write(b1, block);

  cache_release(block);

  if (err != HAL_OK)
    return err;

  /*
   * We could simplify and speed this up a bit by taking advantage of
   * knowing that the PIN block is always db.ksi->index[0] (because of
   * the all-zeros UUID).  Maybe later.
   */

  if ((err = hal_ks_index_replace(&db.ksi, &pin_uuid, &b2)) != HAL_OK)
    return err;

  block->pin = *new_data;

  if (err == HAL_OK)
    cache_mark_used(block, b2);

  if (err == HAL_OK)
    err = block_erase_maybe(b2);

  if (err == HAL_OK)
    err = block_write(b2, block);

  if (err != HAL_OK)
    return err;

  if ((err = block_zero(b1)) != HAL_OK)
    return err;

  if (db.ksi.used < db.ksi.size)
    err = block_erase_maybe(db.ksi.index[db.ksi.used]);

  return err;
}

/*
 * Change a PIN.
 */

hal_error_t hal_set_pin(const hal_user_t user,
                        const hal_ks_pin_t * const pin)
{
  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  flash_block_t *block;
  hal_error_t err;
  unsigned b;

  if ((err = fetch_pin_block(&b, &block)) != HAL_OK)
    return err;

  flash_pin_block_t new_data = block->pin;
  hal_ks_pin_t *dp, *bp;

  switch (user) {
  case HAL_USER_WHEEL:  bp = &new_data.wheel_pin; dp = &db.wheel_pin; break;
  case HAL_USER_SO:     bp = &new_data.so_pin;    dp = &db.so_pin;    break;
  case HAL_USER_NORMAL: bp = &new_data.user_pin;  dp = &db.user_pin;  break;
  default:              return HAL_ERROR_BAD_ARGUMENTS;
  }

  const hal_ks_pin_t old_pin = *dp;
  *dp = *bp = *pin;

  if ((err = update_pin_block(b, block, &new_data)) != HAL_OK)
    *dp = old_pin;

  return err;
}

#if HAL_MKM_FLASH_BACKUP_KLUDGE

/*
 * Horrible insecure kludge in lieu of a battery for the MKM.
 *
 * API here is a little strange:
 *
 * - NULL buffer on read means do all the work without returning the
 *   value;
 *
 * - All calls pass a length parameter, but any length other than the
 *   compiled in constant just returns an immediate error, there's no
 *   notion of buffer max length vs buffer used length, querying for
 *   the size of buffer really needed, or anything like that.
 *
 * We might want to rewrite this some day, if we don't replace it with
 * a battery first.  For now we just preserve the API as we found it
 * while re-implementing it on top of the new keystore.
 */

hal_error_t hal_mkm_flash_read(uint8_t *buf, const size_t len)
{
  if (buf != NULL && len != KEK_LENGTH)
    return HAL_ERROR_MASTERKEY_BAD_LENGTH;

  flash_block_t *block;
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

hal_error_t hal_mkm_flash_write(const uint8_t * const buf, const size_t len)
{
  if (buf == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (len != KEK_LENGTH)
    return HAL_ERROR_MASTERKEY_BAD_LENGTH;

  flash_block_t *block;
  hal_error_t err;
  unsigned b;

  if ((err = fetch_pin_block(&b, &block)) != HAL_OK)
    return err;

  flash_pin_block_t new_data = block->pin;

  new_data.kek_set = FLASH_KEK_SET;
  memcpy(new_data.kek, buf, len);

  return update_pin_block(b, block, &new_data);
}

hal_error_t hal_mkm_flash_erase(const size_t len)
{
  if (len != KEK_LENGTH)
    return HAL_ERROR_MASTERKEY_BAD_LENGTH;

  flash_block_t *block;
  hal_error_t err;
  unsigned b;

  if ((err = fetch_pin_block(&b, &block)) != HAL_OK)
    return err;

  flash_pin_block_t new_data = block->pin;

  new_data.kek_set = FLASH_KEK_SET;
  memset(new_data.kek, 0, len);

  return update_pin_block(b, block, &new_data);
}

#endif /* HAL_MKM_FLASH_BACKUP_KLUDGE */


/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
