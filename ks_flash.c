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
 * Known block states.
 *
 * C does not guarantee any particular representation for enums, so
 * including enums directly in the block header isn't safe.  Instead,
 * we use an access method which casts when reading from the header.
 * Writing to the header isn't a problem, because C does guarantee
 * that enum is compatible with *some* integer type, it just doesn't
 * specify which one.
 */

typedef enum {
  BLOCK_TYPE_ERASED  = 0xFF, /* Pristine erased block (candidate for reuse) */
  BLOCK_TYPE_ZEROED  = 0x00, /* Zeroed block (recently used) */
  BLOCK_TYPE_KEY     = 0x55, /* Block contains key material */
  BLOCK_TYPE_ATTR    = 0x66, /* Block contains key attributes (overflow from key block) */
  BLOCK_TYPE_PIN     = 0xAA, /* Block contains PINs */
  BLOCK_TYPE_UNKNOWN = -1,   /* Internal code for "I have no clue what this is" */
} flash_block_type_t;

/*
 * Block status.
 */

typedef enum {
  BLOCK_STATUS_LIVE      = 0x66, /* This is a live flash block */
  BLOCK_STATUS_TOMBSTONE = 0x44, /* This is a tombstone left behind during an update  */
  BLOCK_STATUS_UNKNOWN   = -1,   /* Internal code for "I have no clue what this is" */
} flash_block_status_t;

/*
 * Common header for all flash block types.
 * A few of these fields are deliberately omitted from the CRC.
 */

typedef struct {
  uint8_t               block_type;
  uint8_t               block_status;
  uint8_t               total_chunks;
  uint8_t               this_chunk;
  hal_crc32_t           crc;
} flash_block_header_t;

/*
 * Key block.  Tail end of "der" field (after der_len) used for attributes.
 */

typedef struct {
  flash_block_header_t  header;
  hal_uuid_t            name;
  hal_key_type_t        type;
  hal_curve_name_t      curve;
  hal_key_flags_t       flags;
  size_t                der_len;
  unsigned              attributes_len;
  uint8_t               der[];  /* Must be last field -- C99 "flexible array member" */
} flash_key_block_t;

#define SIZEOF_FLASH_KEY_BLOCK_DER \
  (KEYSTORE_SUBSECTOR_SIZE - offsetof(flash_key_block_t, der))

/*
 * Key attribute overflow block (attributes which don't fit in der field of key block).
 */

typedef struct {
  flash_block_header_t  header;
  hal_uuid_t            name;
  unsigned              attributes_len;
  uint8_t               attributes[]; /* Must be last field -- C99 "flexible array member" */
} flash_attributes_block_t;

#define SIZEOF_FLASH_ATTRIBUTE_BLOCK_ATTRIBUTES \
  (KEYSTORE_SUBSECTOR_SIZE - offsetof(flash_attributes_block_t, attributes))

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
  uint8_t                       bytes[KEYSTORE_SUBSECTOR_SIZE];
  flash_block_header_t          header;
  flash_key_block_t             key;
  flash_attributes_block_t      attr;
  flash_pin_block_t             pin;
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
 * The in-memory database structure itself is small, but the arrays it
 * points to are large enough that they come from SDRAM allocated at
 * startup.
 */

static db_t db;

/*
 * Type safe casts.
 */

static inline flash_block_type_t block_get_type(const flash_block_t * const block)
{
  assert(block != NULL);
  return (flash_block_type_t) block->header.block_type;
}

static inline flash_block_status_t block_get_status(const flash_block_t * const block)
{
  assert(block != NULL);
  return (flash_block_status_t) block->header.block_status;
}

/*
 * Pick unused or least-recently-used slot in our in-memory cache.
 *
 * Updating lru values is caller's problem: if caller is using a cache
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
 * flash_block_header_t, so that it can skip over fields that
 * shouldn't be included in the CRC.
 */

static hal_crc32_t calculate_block_crc(const flash_block_t * const block)
{
  assert(block != NULL);

  hal_crc32_t crc = hal_crc32_init();

  crc = hal_crc32_update(crc, &block->header.block_type,
                         sizeof(block->header.block_type));

  crc = hal_crc32_update(crc, &block->header.total_chunks,
                         sizeof(block->header.total_chunks));

  crc = hal_crc32_update(crc, &block->header.this_chunk,
                         sizeof(block->header.this_chunk));

  crc = hal_crc32_update(crc, block->bytes + sizeof(flash_block_header_t),
                         sizeof(*block) - sizeof(flash_block_header_t));

  return hal_crc32_finalize(crc);
}

/*
 * Calculate block offset.
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

static hal_error_t block_read(const unsigned blockno, flash_block_t *block)
{
  if (block == NULL || blockno >= NUM_FLASH_BLOCKS || sizeof(*block) != KEYSTORE_SUBSECTOR_SIZE)
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
  case BLOCK_TYPE_ATTR:
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
 * Convert a live block into a tombstone.  Caller is responsible for
 * making sure that the block being converted is valid; since we don't
 * need to update the CRC for this, we just modify the first page.
 */

static hal_error_t block_deprecate(const unsigned blockno)
{
  if (blockno >= NUM_FLASH_BLOCKS)
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

static hal_error_t block_zero(const unsigned blockno)
{
  if (blockno >= NUM_FLASH_BLOCKS)
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

static hal_error_t block_erase(const unsigned blockno)
{
  if (blockno >= NUM_FLASH_BLOCKS)
    return HAL_ERROR_IMPOSSIBLE;

  /* Sigh, magic numeric return codes */
  if (keystore_erase_subsectors(blockno, blockno) != 1)
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

static hal_error_t block_erase_maybe(const unsigned blockno)
{
  if (blockno >= NUM_FLASH_BLOCKS)
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

static hal_error_t block_write(const unsigned blockno, flash_block_t *block)
{
  if (block == NULL || blockno >= NUM_FLASH_BLOCKS || sizeof(*block) != KEYSTORE_SUBSECTOR_SIZE)
    return HAL_ERROR_IMPOSSIBLE;

  hal_error_t err = block_erase_maybe(blockno);

  if (err != HAL_OK)
    return err;

  switch (block_get_type(block)) {
  case BLOCK_TYPE_KEY:
  case BLOCK_TYPE_PIN:
  case BLOCK_TYPE_ATTR:
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
 * Update one flash block, including zombie jamboree.
 */

static hal_error_t block_update(const unsigned b1, flash_block_t *block,
                                const hal_uuid_t * const uuid, const unsigned chunk, int *hint)
{
  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if (db.ksi.used == db.ksi.size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  cache_release(block);

  hal_error_t err;
  unsigned b2;

  if ((err = block_deprecate(b1))                                       != HAL_OK ||
      (err = hal_ks_index_replace(&db.ksi, uuid, chunk, &b2, hint))     != HAL_OK ||
      (err = block_write(b2, block))                                    != HAL_OK ||
      (err = block_zero(b1))                                            != HAL_OK)
    return err;

  cache_mark_used(block, b2);

  return block_erase_maybe(db.ksi.index[db.ksi.used]);
}

/*
 * Forward reference.
 */

static hal_error_t fetch_pin_block(unsigned *b, flash_block_t **block);

/*
 * Initialize keystore.  This includes various tricky bits, some of
 * which attempt to preserve the free list ordering across reboots, to
 * improve our simplistic attempt at wear leveling, others attempt to
 * recover from unclean shutdown.
 */

static inline void *gnaw(uint8_t **mem, size_t *len, const size_t size)
{
  if (mem == NULL || *mem == NULL || len == NULL || size > *len)
    return NULL;
  void *ret = *mem;
  *mem += size;
  *len -= size;
  return ret;
}

static hal_error_t ks_init(const hal_ks_driver_t * const driver)
{
  /*
   * Initialize the in-memory database.
   */

  size_t len = (sizeof(*db.ksi.index) * NUM_FLASH_BLOCKS +
                sizeof(*db.ksi.names) * NUM_FLASH_BLOCKS +
                sizeof(*db.cache)     * KS_FLASH_CACHE_SIZE);

  uint8_t *mem = hal_allocate_static_memory(len);

  if (mem == NULL)
    return HAL_ERROR_ALLOCATION_FAILURE;

  memset(&db, 0, sizeof(db));
  memset(mem, 0, len);

  db.ksi.index = gnaw(&mem, &len, sizeof(*db.ksi.index) * NUM_FLASH_BLOCKS);
  db.ksi.names = gnaw(&mem, &len, sizeof(*db.ksi.names) * NUM_FLASH_BLOCKS);
  db.cache     = gnaw(&mem, &len, sizeof(*db.cache)     * KS_FLASH_CACHE_SIZE);
  db.ksi.size  = NUM_FLASH_BLOCKS;
  db.ksi.used  = 0;

  if (db.ksi.index == NULL || db.ksi.names == NULL || db.cache == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  for (int i = 0; i < KS_FLASH_CACHE_SIZE; i++)
    db.cache[i].blockno = ~0;

  /*
   * Scan existing content of flash to figure out what we've got.
   * This gets a bit involved due to the need to recover from things
   * like power failures at inconvenient times.
   */

  flash_block_type_t   block_types[NUM_FLASH_BLOCKS];
  flash_block_status_t block_status[NUM_FLASH_BLOCKS];
  flash_block_t *block = cache_pick_lru();
  int first_erased = -1;
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
      block_types[i] = BLOCK_TYPE_UNKNOWN;

    else if (err == HAL_OK)
      block_types[i] = block_get_type(block);

    else
      return err;

    switch (block_types[i]) {
    case BLOCK_TYPE_KEY:
    case BLOCK_TYPE_PIN:
    case BLOCK_TYPE_ATTR:
      block_status[i] = block_get_status(block);
      break;
    default:
      block_status[i] = BLOCK_STATUS_UNKNOWN;
    }

    /*
     * First erased block we see is head of the free list.
     */

    if (block_types[i] == BLOCK_TYPE_ERASED && first_erased < 0)
      first_erased = i;

    /*
     * If it's a valid data block, include it in the index.  We remove
     * tombstones (if any) below, for now it's easiest to include them
     * in the index, so we can look them up by name if we must.
     */

    const hal_uuid_t *uuid = NULL;

    switch (block_types[i]) {
    case BLOCK_TYPE_KEY:        uuid = &block->key.name;        break;
    case BLOCK_TYPE_ATTR:       uuid = &block->attr.name;       break;
    case BLOCK_TYPE_PIN:        uuid = &pin_uuid;               break;
    default:                    /* Keep GCC happy */            break;
    }

    if (uuid != NULL) {
      db.ksi.names[i].name = *uuid;
      db.ksi.names[i].chunk = block->header.this_chunk;
      db.ksi.index[n++] = i;
    }
  }

  db.ksi.used = n;

  assert(db.ksi.used <= db.ksi.size);

  /*
   * At this point we've built the (unsorted) index from all the valid
   * blocks.  Now we need to insert free and unrecognized blocks into
   * the free list in our preferred order.  It's possible that there's
   * a better way to do this than linear scan, but this is just
   * integer comparisons in a fairly small data set, so it's probably
   * not worth trying to optimize.
   */

  if (n < db.ksi.size)
    for (int i = 0; i < NUM_FLASH_BLOCKS; i++)
      if (block_types[i] == BLOCK_TYPE_ERASED)
        db.ksi.index[n++] = i;

  if (n < db.ksi.size)
    for (int i = first_erased; i < NUM_FLASH_BLOCKS; i++)
      if (block_types[i] == BLOCK_TYPE_ZEROED)
        db.ksi.index[n++] = i;

  if (n < db.ksi.size)
    for (int i = 0; i < first_erased; i++)
      if (block_types[i] == BLOCK_TYPE_ZEROED)
        db.ksi.index[n++] = i;

  if (n < db.ksi.size)
    for (int i = 0; i < NUM_FLASH_BLOCKS; i++)
      if (block_types[i] == BLOCK_TYPE_UNKNOWN)
        db.ksi.index[n++] = i;

  assert(n == db.ksi.size);

  /*
   * Initialize the index.
   */

  if ((err = hal_ks_index_setup(&db.ksi)) != HAL_OK)
    return err;

  /*
   * We might want to call hal_ks_index_fsck() here, if we can figure
   * out some safe set of recovery actions we can take.
   */

  /*
   * Deal with tombstones.  These are blocks left behind when
   * something bad (like a power failure) happened while we updating.
   * The sequence of operations while updating is designed so that,
   * barring a bug or a hardware failure, we should never lose data.
   *
   * For any tombstone we find, we start by looking for all the blocks
   * with a matching UUID, then see what valid sequences we can
   * construct from what we found.
   *
   * If we can construct a valid sequence of live blocks, the complete
   * update was written out, and we just need to zero the tombstones.
   *
   * Otherwise, if we can construct a complete sequence of tombstone
   * blocks, the update failed before it was completely written, so we
   * have to zero the incomplete sequence of live blocks then restore
   * from the tombstones.
   *
   * Otherwise, if the live and tombstone blocks taken together form a
   * valid sequence, the update failed while deprecating the old live
   * blocks, and the update itself was not written, so we need to
   * restore the tombstones and leave the live blocks alone.
   *
   * If none of the above applies, we don't understand what happened,
   * which is a symptom of either a bug or a hardware failure more
   * serious than simple loss of power or reboot at an inconvenient
   * time, so we error out to avoid accidental loss of data.
   */

  for (int i = 0; i < NUM_FLASH_BLOCKS; i++) {

    if (block_status[i] != BLOCK_STATUS_TOMBSTONE)
      continue;

    hal_uuid_t name = db.ksi.names[i].name;
    unsigned n_blocks;
    int where = -1;

    if ((err = hal_ks_index_find_range(&db.ksi, &name, 0, &n_blocks, NULL, &where)) != HAL_OK)
      return err;

    while (where > 0 && !hal_uuid_cmp(&name, &db.ksi.names[db.ksi.index[where - 1]].name)) {
      where--;
      n_blocks++;
    }

    int live_ok = 1, tomb_ok = 1, join_ok = 1;
    unsigned n_live = 0, n_tomb = 0;
    unsigned i_live = 0, i_tomb = 0;

    for (int j = 0; j < n_blocks; j++) {
      unsigned b = db.ksi.index[where + j];
      switch (block_status[b]) {
      case BLOCK_STATUS_LIVE:           n_live++;       break;
      case BLOCK_STATUS_TOMBSTONE:      n_tomb++;       break;
      default:                          return HAL_ERROR_IMPOSSIBLE;
      }
    }

    uint16_t live_blocks[n_live], tomb_blocks[n_tomb];

    for (int j = 0; j < n_blocks; j++) {
      unsigned b = db.ksi.index[where + j];

      if ((err = block_read(b, block)) != HAL_OK)
        return err;

      join_ok &= block->header.this_chunk == j && block->header.total_chunks == n_blocks;

      switch (block_status[b]) {
      case BLOCK_STATUS_LIVE:
        live_blocks[i_live] = b;
        live_ok &= block->header.this_chunk == i_live++ && block->header.total_chunks == n_live;
        break;
      case BLOCK_STATUS_TOMBSTONE:
        tomb_blocks[i_tomb] = b;
        tomb_ok &= block->header.this_chunk == i_tomb++ && block->header.total_chunks == n_tomb;
        break;
      default:
        return HAL_ERROR_IMPOSSIBLE;
      }
    }

    if (!live_ok && !tomb_ok && !join_ok)
      return HAL_ERROR_KEYSTORE_LOST_DATA;

    if (live_ok) {
      for (int j = 0; j < n_tomb; j++) {
        const unsigned b = tomb_blocks[j];
        if ((err = block_zero(b)) != HAL_OK)
          return err;
        block_types[b]  = BLOCK_TYPE_ZEROED;
        block_status[b] = BLOCK_STATUS_UNKNOWN;
      }
    }

    else if (tomb_ok) {
      for (int j = 0; j < n_live; j++) {
        const unsigned b = live_blocks[j];
        if ((err = block_zero(b)) != HAL_OK)
          return err;
        block_types[b]  = BLOCK_TYPE_ZEROED;
        block_status[b] = BLOCK_STATUS_UNKNOWN;
      }
    }

    if (live_ok) {
      memcpy(&db.ksi.index[where], live_blocks, n_live * sizeof(*db.ksi.index));
      memmove(&db.ksi.index[where + n_live], &db.ksi.index[where + n_blocks],
              (db.ksi.size - where - n_blocks) * sizeof(*db.ksi.index));
      memcpy(&db.ksi.index[db.ksi.size - n_tomb], tomb_blocks, n_tomb * sizeof(*db.ksi.index));
      db.ksi.used -= n_tomb;
      n_blocks = n_live;
    }

    else if (tomb_ok) {
      memcpy(&db.ksi.index[where], tomb_blocks, n_tomb * sizeof(*db.ksi.index));
      memmove(&db.ksi.index[where + n_tomb], &db.ksi.index[where + n_blocks],
              (db.ksi.size - where - n_blocks) * sizeof(*db.ksi.index));
      memcpy(&db.ksi.index[db.ksi.size - n_live], live_blocks, n_live * sizeof(*db.ksi.index));
      db.ksi.used -= n_live;
      n_blocks = n_tomb;
    }

    for (int j = 0; j < n_blocks; j++) {
      int hint = where + j;
      unsigned b1 = db.ksi.index[hint], b2;
      if (block_status[b1] != BLOCK_STATUS_TOMBSTONE)
        continue;
      if ((err = block_read(b1, block)) != HAL_OK)
        return err;
      block->header.block_status = BLOCK_STATUS_LIVE;
      if ((err = hal_ks_index_replace(&db.ksi, &name, j, &b2, &hint)) != HAL_OK ||
          (err = block_write(b2, block)) != HAL_OK)
        return err;
      block_types[b1]  = BLOCK_TYPE_ZEROED;
      block_status[b1] = BLOCK_STATUS_UNKNOWN;
      block_status[b2] = BLOCK_STATUS_LIVE;
    }
  }

  err = fetch_pin_block(NULL, &block);

  if (err == HAL_OK) {
    db.wheel_pin = block->pin.wheel_pin;
    db.so_pin    = block->pin.so_pin;
    db.user_pin  = block->pin.user_pin;
  }

  else if (err != HAL_ERROR_KEY_NOT_FOUND)
    return err;

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
    block->header.total_chunks = 1;
    block->header.this_chunk   = 0;

    block->pin.wheel_pin = db.wheel_pin = hal_last_gasp_pin;
    block->pin.so_pin    = db.so_pin;
    block->pin.user_pin  = db.user_pin;

    if ((err = hal_ks_index_add(&db.ksi, &pin_uuid, 0, &b, NULL)) != HAL_OK)
      return err;

    cache_mark_used(block, b);

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
                            hal_pkey_slot_t *slot,
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

  if ((err = hal_ks_index_add(&db.ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK)
    return err;

  cache_mark_used(block, b);

  memset(block, 0xFF, sizeof(*block));

  block->header.block_type   = BLOCK_TYPE_KEY;
  block->header.block_status = BLOCK_STATUS_LIVE;
  block->header.total_chunks = 1;
  block->header.this_chunk   = 0;

  k->name    = slot->name;
  k->type    = slot->type;
  k->curve   = slot->curve;
  k->flags   = slot->flags;
  k->der_len = SIZEOF_FLASH_KEY_BLOCK_DER;
  k->attributes_len = 0;

  if ((err = hal_mkm_get_kek(kek, &kek_len, sizeof(kek))) == HAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k->der, &k->der_len);

  memset(kek, 0, sizeof(kek));

  if (err == HAL_OK &&
      (err = block_write(b, block)) == HAL_OK)
    return HAL_OK;

  memset(block, 0, sizeof(*block));
  cache_release(block);
  (void) hal_ks_index_delete(&db.ksi, &slot->name, 0, NULL, &slot->hint);
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

  if ((err = hal_ks_index_find(&db.ksi, &slot->name, 0, &b, &slot->hint)) != HAL_OK ||
      (err = block_read_cached(b, &block))                                != HAL_OK)
    return err;

  if (block_get_type(block) != BLOCK_TYPE_KEY)
    return HAL_ERROR_KEYSTORE_WRONG_BLOCK_TYPE; /* HAL_ERROR_KEY_NOT_FOUND */

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
                             hal_pkey_slot_t *slot)
{
  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err;
  unsigned n;

  if ((err = hal_ks_index_delete_range(&db.ksi, &slot->name, 0, &n, NULL, &slot->hint)) != HAL_OK)
    return err;

  unsigned b[n];

  if ((err = hal_ks_index_delete_range(&db.ksi, &slot->name, n, NULL, b, &slot->hint)) != HAL_OK)
    return err;

  for (int i = 0; i < n; i++)
    cache_release(cache_find_block(b[i]));

  for (int i = 0; i < n; i++)
    if ((err = block_zero(b[i])) != HAL_OK)
      return err;

  return block_erase_maybe(db.ksi.index[db.ksi.used]);
}

static hal_error_t ks_list(hal_ks_t *ks,
                           const hal_client_handle_t client,
                           const hal_session_handle_t session,
                           hal_pkey_info_t *result,
                           unsigned *result_len,
                           const unsigned result_max)
{
  if (ks != &db.ks || result == NULL || result_len == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  flash_block_t *block;
  hal_error_t err;

  *result_len = 0;

  for (int i = 0; i < db.ksi.used; i++) {
    unsigned b = db.ksi.index[i];

    if (*result_len >= result_max)
      return HAL_ERROR_RESULT_TOO_LONG;

    if ((err = block_read_cached(b, &block)) != HAL_OK)
      return err;

    if (block_get_type(block) != BLOCK_TYPE_KEY || block->header.this_chunk > 0)
      continue;

    result[*result_len].type  = block->key.type;
    result[*result_len].curve = block->key.curve;
    result[*result_len].flags = block->key.flags;
    result[*result_len].name  = block->key.name;
    ++ *result_len;
  }

  return HAL_OK;
}

static inline hal_error_t locate_attributes(flash_block_t *block, const unsigned chunk,
                                            uint8_t **bytes, size_t *bytes_len,
                                            unsigned **attrs_len)
{
  if (block == NULL || bytes == NULL || bytes_len == NULL || attrs_len == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if (chunk == 0) {
    if (block_get_type(block) != BLOCK_TYPE_KEY)
      return HAL_ERROR_KEYSTORE_WRONG_BLOCK_TYPE; /* HAL_ERROR_KEY_NOT_FOUND */
    *attrs_len = &block->key.attributes_len;
    *bytes = block->key.der + block->key.der_len;
    *bytes_len = SIZEOF_FLASH_KEY_BLOCK_DER - block->key.der_len;
  }

  else {
    if (block_get_type(block) != BLOCK_TYPE_ATTR)
      return HAL_ERROR_KEYSTORE_WRONG_BLOCK_TYPE; /* HAL_ERROR_KEY_NOT_FOUND */
    *attrs_len = &block->attr.attributes_len;
    *bytes = block->attr.attributes;
    *bytes_len = SIZEOF_FLASH_ATTRIBUTE_BLOCK_ATTRIBUTES;
  }

  return HAL_OK;
}

static hal_error_t ks_match(hal_ks_t *ks,
                            const hal_client_handle_t client,
                            const hal_session_handle_t session,
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
  if (ks == NULL || attributes == NULL ||
      result == NULL || result_len == NULL || previous_uuid == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  uint8_t need_attr[attributes_len > 0 ? attributes_len : 1];
  flash_block_t *block;
  int possible = 0;
  hal_error_t err;
  int i = -1;

  *result_len = 0;

  err = hal_ks_index_find(&db.ksi, previous_uuid, 0, NULL, &i);

  if (err == HAL_ERROR_KEY_NOT_FOUND)
    i--;
  else if (err != HAL_OK)
    return err;

  while (*result_len < result_max && ++i < db.ksi.used) {

    unsigned b = db.ksi.index[i];

    if (db.ksi.names[b].chunk == 0)
      possible = 1;

    if (!possible)
      continue;

    if ((err = block_read_cached(b, &block)) != HAL_OK)
      return err;

    if (db.ksi.names[b].chunk == 0) {
      memset(need_attr, 1, sizeof(need_attr));
      possible = ((type == HAL_KEY_TYPE_NONE || type  == block->key.type) &&
                  (curve == HAL_CURVE_NONE   || curve == block->key.curve));
    }

    if (!possible)
      continue;

    if (attributes_len > 0) {
      uint8_t *bytes = NULL;
      size_t bytes_len = 0;
      unsigned *attrs_len;

      if ((err = locate_attributes(block, db.ksi.names[b].chunk,
                                   &bytes, &bytes_len, &attrs_len)) != HAL_OK)
        return err;

      if (*attrs_len > 0) {
        hal_rpc_pkey_attribute_t attrs[*attrs_len];

        if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, NULL)) != HAL_OK)
          return err;

        for (int j = 0; possible && j < attributes_len; j++) {

          if (!need_attr[j])
            continue;

          for (hal_rpc_pkey_attribute_t *a = attrs; a < attrs + *attrs_len; a++) {
            if (a->type != attributes[j].type)
              continue;
            need_attr[j] = 0;
            possible = (a->length == attributes[j].length &&
                        !memcmp(a->value, attributes[j].value, a->length));
            break;
          }
        }
      }
    }

    if (!possible)
      continue;

    if (attributes_len > 0 && memchr(need_attr, 1, sizeof(need_attr)) != NULL)
      continue;

    result[*result_len] = db.ksi.names[b].name;
    ++*result_len;
    possible = 0;
  }

  return HAL_OK;
}

static  hal_error_t ks_set_attribute(hal_ks_t *ks,
                                     hal_pkey_slot_t *slot,
                                     const uint32_t type,
                                     const uint8_t * const value,
                                     const size_t value_len)
{
  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * Try to add new attribute as a single-block update.
   */

  flash_block_t *block;
  unsigned chunk = 0;
  hal_error_t err;

  do {
    int hint = slot->hint + chunk;
    unsigned b;

    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &b, &hint)) != HAL_OK ||
        (err = block_read_cached(b, &block))                              != HAL_OK)
      return err;

    if (block->header.this_chunk != chunk)
      return HAL_ERROR_IMPOSSIBLE;

    if (chunk == 0)
      slot->hint = hint;

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, chunk, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      return err;

    cache_mark_used(block, b);

    hal_rpc_pkey_attribute_t attrs[*attrs_len + 1];
    const unsigned old_attrs_len = *attrs_len;
    size_t total;

    if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, &total)) != HAL_OK)
      return err;

    err = hal_ks_attribute_insert(bytes, bytes_len, attrs, attrs_len, &total, type, value, value_len);

    if (*attrs_len != old_attrs_len && err != HAL_OK)
      cache_release(block);

    if (err == HAL_ERROR_RESULT_TOO_LONG)
      continue;

    if (err != HAL_OK)
      return err;

    return block_update(b, block, &slot->name, chunk, &hint);

  } while (++chunk < block->header.total_chunks);

  /*
   * If we get here, we have to add a new block, which requires
   * rewriting all the others to bump the total_blocks count.  We need
   * to keep track of all the old chunks so we can zero them at the
   * end, and because we can't zero them until we've written out the
   * new chunks, we need enough free blocks for the entire new object.
   */

  const unsigned total_chunks = block->header.total_chunks;
  unsigned b, blocks[total_chunks];

  if (db.ksi.used + total_chunks + 1 > db.ksi.size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  /*
   * Phase 1: Deprecate all the old chunks, remember where the were.
   */

  for (chunk = 0; chunk < total_chunks; chunk++) {
    int hint = slot->hint + chunk;
    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &blocks[chunk], &hint)) != HAL_OK ||
        (err = block_deprecate(blocks[chunk]))                                        != HAL_OK)
      return err;
  }

  /*
   * Phase 2: Rewrite all the existing chunks with the new total_chunks value.
   */

  for (chunk = 0; chunk < total_chunks; chunk++) {
    int hint = slot->hint + chunk;
    if ((err = block_read_cached(blocks[chunk], &block)) != HAL_OK)
      return err;
    if (block->header.this_chunk != chunk)
      return HAL_ERROR_IMPOSSIBLE;
    block->header.block_status = BLOCK_STATUS_LIVE;
    block->header.total_chunks = total_chunks + 1;

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;
    size_t total;

    if ((err = locate_attributes(block, chunk, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      return err;

    if (*attrs_len > 0) {
      hal_rpc_pkey_attribute_t attrs[*attrs_len];
      if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, &total)) != HAL_OK ||
          (err = hal_ks_attribute_delete(bytes, bytes_len, attrs, attrs_len, &total, type)) != HAL_OK)
        return err;
    }

    unsigned b;

    if ((err = hal_ks_index_replace(&db.ksi, &slot->name, chunk, &b, &hint))    != HAL_OK ||
        (err = block_write(b, block))                                           != HAL_OK)
      return err;
  }

  /*
   * Phase 3: Write the new chunk.
   */

  {
    block = cache_pick_lru();

    memset(block, 0xFF, sizeof(*block));

    block->header.block_type   = BLOCK_TYPE_ATTR;
    block->header.block_status = BLOCK_STATUS_LIVE;
    block->header.total_chunks = total_chunks + 1;
    block->header.this_chunk   = total_chunks;
    block->attr.name = slot->name;
    block->attr.attributes_len = 0;

    hal_rpc_pkey_attribute_t attrs[1];
    size_t total = 0;

    if ((err = hal_ks_attribute_insert(block->attr.attributes,
                                       SIZEOF_FLASH_ATTRIBUTE_BLOCK_ATTRIBUTES,
                                       attrs, &block->attr.attributes_len, &total,
                                       type, value, value_len))                         != HAL_OK ||
        (err = hal_ks_index_add(&db.ksi, &slot->name, total_chunks, &b, NULL))          != HAL_OK ||
        (err = block_write(b, block))                                                   != HAL_OK)
      return err;

    cache_mark_used(block, b);
  }

  /*
   * Phase 4: Zero the old chunks we deprecated in phase 1.
   */

  for (chunk = 0; chunk < total_chunks; chunk++)
    if ((err = block_zero(blocks[chunk])) != HAL_OK)
      return err;

  return HAL_OK;
}

static  hal_error_t ks_get_attribute(hal_ks_t *ks,
                                     hal_pkey_slot_t *slot,
                                     const uint32_t type,
                                     uint8_t *value,
                                     size_t *value_len,
                                     const size_t value_max)
{
  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  flash_block_t *block;
  hal_error_t err;
  unsigned b;

  hal_rpc_pkey_attribute_t a = {0, 0, NULL};
  unsigned chunk = 0;

  do {
    int hint = slot->hint + chunk;

    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &b, &hint)) != HAL_OK ||
        (err = block_read_cached(b, &block))                              != HAL_OK)
      return err;

    if (block->header.this_chunk != chunk)
      return HAL_ERROR_IMPOSSIBLE;

    if (chunk == 0)
      slot->hint = hint;

    cache_mark_used(block, b);

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, chunk, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      return err;

    if (*attrs_len == 0)
      continue;

    hal_rpc_pkey_attribute_t attrs[*attrs_len];

    if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, NULL)) != HAL_OK)
      return err;

    for (int i = 0; a.value == NULL && i < *attrs_len; ++i)
      if (attrs[i].type == type)
        a = attrs[i];

  } while (a.value == NULL && ++chunk < block->header.total_chunks);

  if (a.value == NULL)
    return HAL_ERROR_ATTRIBUTE_NOT_FOUND;

  if (a.length > value_max && value != NULL)
    return HAL_ERROR_RESULT_TOO_LONG;

  if (value != NULL)
    memcpy(value, a.value, a.length);

  if (value_len != NULL)
    *value_len = a.length;

  return HAL_OK;
}

static hal_error_t ks_delete_attribute(hal_ks_t *ks,
                                       hal_pkey_slot_t *slot,
                                       const uint32_t type)
{
  /*
   * For extra credit, we could handle attribute compaction here, but
   * in practice we expect attribute deletion without deleting the
   * entire object to be a rare enough event that it may not be worth
   * it.  Certainly it's not a high priority, so later, if ever.
   */

  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  flash_block_t *block;
  unsigned chunk = 0;

  do {
    int hint = slot->hint + chunk;
    hal_error_t err;
    unsigned b;

    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &b, &hint)) != HAL_OK ||
        (err = block_read_cached(b, &block))                              != HAL_OK)
      return err;

    if (block->header.this_chunk != chunk)
      return HAL_ERROR_IMPOSSIBLE;

    if (chunk == 0)
      slot->hint = hint;

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, chunk, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      return err;

    cache_mark_used(block, b);

    if (*attrs_len == 0)
      continue;

    hal_rpc_pkey_attribute_t attrs[*attrs_len];
    const unsigned old_attrs_len = *attrs_len;
    size_t total;

    if ((err = hal_ks_attribute_scan(  bytes, bytes_len, attrs, *attrs_len, &total))       != HAL_OK ||
        (err = hal_ks_attribute_delete(bytes, bytes_len, attrs,  attrs_len, &total, type)) != HAL_OK)
      return err;

    if (*attrs_len == old_attrs_len)
      continue;

    if ((err = block_update(b, block, &slot->name, chunk, &hint)) != HAL_OK)
      return err;

  } while (++chunk < block->header.total_chunks);

  return HAL_OK;
}

static  hal_error_t ks_set_attributes(hal_ks_t *ks,
                                      hal_pkey_slot_t *slot,
                                      const hal_rpc_pkey_attribute_t *attributes,
                                      const unsigned attributes_len)
{
#warning This function is much too long
  // Probably needs to be broken up into multiple sub-functions, or at least
  // into discrete blocks to scope most of the variables, but let's finish
  // writing the icky version before polishing the chrome.

  if (ks != &db.ks || slot == NULL || attributes == NULL || attributes_len == 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * Try to add new attribute as a single-block update.
   */

  unsigned updated_attributes_len = attributes_len;
  flash_block_t *block;
  unsigned chunk = 0;
  hal_error_t err;
  unsigned b;

  do {
    int hint = slot->hint + chunk;

    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &b, &hint)) != HAL_OK ||
        (err = block_read_cached(b, &block))                              != HAL_OK)
      return err;

    if (block->header.this_chunk != chunk)
      return HAL_ERROR_IMPOSSIBLE;

    cache_mark_used(block, b);

    if (chunk == 0)
      slot->hint = hint;

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, chunk, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      return err;

    updated_attributes_len += *attrs_len;

    hal_rpc_pkey_attribute_t attrs[*attrs_len + attributes_len];
    size_t total;

    if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, &total)) != HAL_OK)
      return err;

    for (int i = 0; err == HAL_OK && i < attributes_len; i++) {
      if (attributes[i].length == 0)
        err = hal_ks_attribute_delete(bytes, bytes_len, attrs, attrs_len, &total,
                                      attributes[i].type);
      else
        err = hal_ks_attribute_insert(bytes, bytes_len, attrs, attrs_len, &total,
                                      attributes[i].type,
                                      attributes[i].value,
                                      attributes[i].length);
      if (err != HAL_OK)
        cache_release(block);
    }

    if (err == HAL_ERROR_RESULT_TOO_LONG)
      continue;

    if (err != HAL_OK)
      return err;

    return block_update(b, block, &slot->name, chunk, &hint);

  } while (++chunk < block->header.total_chunks);

  /*
   * If we get here, we have to add a new block, which requires
   * rewriting all the others to bump the total_blocks count.  We need
   * to keep track of all the old chunks so we can zero them at the
   * end, and because we can't zero them until we've written out the
   * new chunks, we need enough free blocks for the entire new object.
   *
   * Calculating all of this is extremely tedious, but flash writes
   * are so much more expensive than anything else we do here that
   * it's almost certainly worth it.
   *
   * We don't need the attribute values to compute the sizes, just the
   * attribute sizes, so we scan all the existing blocks, build up a
   * structure with the current attribute types and sizes, modify that
   * according to our arguments, and compute the needed size.  Once we
   * have that, we can start rewriting existing blocks.  We put all
   * the new stuff at the end, which simplifies this slightly.
   *
   * In theory, this process never requires us to have more than two
   * blocks in memory at the same time (source and destination when
   * copying across chunk boundaries), but having enough cache buffers
   * to keep the whole set in memory will almost certainly make this
   * run faster.
   */

  hal_rpc_pkey_attribute_t updated_attributes[updated_attributes_len];
  const unsigned total_chunks_old = block->header.total_chunks;
  size_t bytes_available = 0;

  updated_attributes_len = 0;

  for (chunk = 0; chunk < total_chunks_old; chunk++) {
    int hint = slot->hint + chunk;

    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &b, &hint)) != HAL_OK ||
        (err = block_read_cached(b, &block))                              != HAL_OK)
      return err;

    if (block->header.this_chunk != chunk)
      return HAL_ERROR_IMPOSSIBLE;

    cache_mark_used(block, b);

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, chunk, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      return err;

    hal_rpc_pkey_attribute_t attrs[*attrs_len];
    size_t total;

    if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, &total)) != HAL_OK)
      return err;

    if (chunk == 0)
      bytes_available = bytes_len;

    for (int i = 0; i < *attrs_len; i++) {
      if (updated_attributes_len >= sizeof(updated_attributes)/sizeof(*updated_attributes))
        return HAL_ERROR_IMPOSSIBLE;
      updated_attributes[updated_attributes_len].type = attrs[i].type;
      updated_attributes[updated_attributes_len].length = attrs[i].length;
      updated_attributes[updated_attributes_len].value = NULL;
      updated_attributes_len++;
    }
  }

  for (int i = 0; i < attributes_len; i++) {

    for (int j = 0; j < updated_attributes_len; j++)
      if (updated_attributes[j].type == attributes[i].type)
        updated_attributes[j].length = 0;

    if (updated_attributes_len >= sizeof(updated_attributes)/sizeof(*updated_attributes))
      return HAL_ERROR_IMPOSSIBLE;
    updated_attributes[updated_attributes_len].type   = attributes[i].type;
    updated_attributes[updated_attributes_len].length = attributes[i].length;
    updated_attributes[updated_attributes_len].value  = attributes[i].value;
    updated_attributes_len++;
  }

  chunk = 0;

  for (int i = 0; i < updated_attributes_len; i++) {

    if (updated_attributes[i].length == 0) {
      memmove(&updated_attributes[i], &updated_attributes[i + 1], updated_attributes_len - i - 1);
      updated_attributes_len--;
      i--;
      continue;
    }

    const size_t needed = hal_ks_attribute_header_size + updated_attributes[i].length;

    if (needed > bytes_available) {
      bytes_available = SIZEOF_FLASH_ATTRIBUTE_BLOCK_ATTRIBUTES;
      chunk++;
    }

    if (needed > bytes_available)
      return HAL_ERROR_RESULT_TOO_LONG;

    bytes_available -= needed;
  }

  const unsigned total_chunks_new = chunk + 1;

  if (db.ksi.used + total_chunks_new > db.ksi.size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  /*
   * Phase 1: Deprecate all the old chunks, remember where they were.
   */

  unsigned old_blocks[total_chunks_old];

  for (chunk = 0; chunk < total_chunks_old; chunk++) {
    int hint = slot->hint + chunk;
    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &b, &hint)) != HAL_OK ||
        (err = block_deprecate(b))                                        != HAL_OK)
      return err;
    old_blocks[chunk] = b;
  }

  /*
   * Phase 2: Write new chunks, copying attributes from old chunks and attributes[]
   * as needed.  This is tedious.
   */

  {
    hal_rpc_pkey_attribute_t old_attrs[updated_attributes_len], new_attrs[updated_attributes_len];
    unsigned                *old_attrs_len = NULL,             *new_attrs_len = NULL;
    flash_block_t           *old_block     = NULL,             *new_block     = NULL;
    uint8_t                 *old_bytes     = NULL,             *new_bytes     = NULL;
    size_t                   old_bytes_len = 0,                 new_bytes_len = 0;
    unsigned                 old_chunk     = 0,                 new_chunk     = 0;
    size_t                   old_total     = 0,                 new_total     = 0;

    int updated_attributes_i = 0, old_attrs_i = 0;

    uint32_t       new_attr_type;
    size_t         new_attr_length;
    const uint8_t *new_attr_value;

    while (updated_attributes_i < updated_attributes_len) {

      if (old_chunk >= total_chunks_old || new_chunk >= total_chunks_new)
        return HAL_ERROR_IMPOSSIBLE;

      if (updated_attributes[updated_attributes_i].value != NULL) {
        new_attr_type   = updated_attributes[updated_attributes_i].type;
        new_attr_length = updated_attributes[updated_attributes_i].length;
        new_attr_value  = updated_attributes[updated_attributes_i].value;
      }

      else {

        if (old_block == NULL) {

          if ((err = block_read_cached(old_blocks[old_chunk], &old_block)) != HAL_OK)
            return err;

          if (old_block->header.this_chunk != old_chunk)
            return HAL_ERROR_IMPOSSIBLE;

          if ((err = locate_attributes(old_block, old_chunk,
                                       &old_bytes, &old_bytes_len, &old_attrs_len)) != HAL_OK ||
              (err = hal_ks_attribute_scan(old_bytes, old_bytes_len,
                                           old_attrs, *old_attrs_len, &old_total))  != HAL_OK)
            return err;

          old_attrs_i = 0;
        }

        while (old_attrs_i < *old_attrs_len &&
               old_attrs[old_attrs_i].type != updated_attributes[updated_attributes_i].type)
          old_attrs_i++;

        if (old_attrs_i >= *old_attrs_len) {
          old_chunk++;
          old_block = NULL;
          continue;
        }

        new_attr_type   = old_attrs[old_attrs_i].type;
        new_attr_length = old_attrs[old_attrs_i].length;
        new_attr_value  = old_attrs[old_attrs_i].value;
      }

      if (new_block == NULL) {

        new_block = cache_pick_lru();
        memset(new_block, 0xFF, sizeof(*new_block));

        if (new_chunk == 0) {
          flash_block_t *tmp_block;
          if ((err = block_read_cached(old_blocks[0], &tmp_block)) != HAL_OK)
            return err;
          if (tmp_block->header.this_chunk != 0)
            return HAL_ERROR_IMPOSSIBLE;
          new_block->header.block_type   = BLOCK_TYPE_KEY;
          new_block->key.name            = slot->name;
          new_block->key.type            = tmp_block->key.type;
          new_block->key.curve           = tmp_block->key.curve;
          new_block->key.flags           = tmp_block->key.flags;
          new_block->key.der_len         = tmp_block->key.der_len;
          new_block->key.attributes_len  = 0;
          memcpy(new_block->key.der, tmp_block->key.der, tmp_block->key.der_len);
        }
        else {
          new_block->header.block_type   = BLOCK_TYPE_ATTR;
          new_block->attr.name           = slot->name;
          new_block->attr.attributes_len = 0;
        }

        new_block->header.block_status = BLOCK_STATUS_LIVE;
        new_block->header.total_chunks = total_chunks_new;
        new_block->header.this_chunk   = new_chunk;

        if ((err = locate_attributes(new_block, new_chunk,
                                     &new_bytes, &new_bytes_len, &new_attrs_len)) != HAL_OK)
          return err;

        new_total = 0;
      }

      err = hal_ks_attribute_insert(new_bytes, new_bytes_len, new_attrs, new_attrs_len, &new_total,
                                    new_attr_type, new_attr_value, new_attr_length);

      switch (err) {
      case HAL_OK:
        if (++updated_attributes_i >= updated_attributes_len)
          continue;
        break;
      case HAL_ERROR_RESULT_TOO_LONG:
        if (new_chunk == 0 || new_attrs_len > 0)
          break;
      default:
        return err;
      }

      int hint = slot->hint + new_chunk;

      if (new_chunk < total_chunks_old)
        err = hal_ks_index_replace(&db.ksi, &slot->name, new_chunk, &b, &hint);
      else
        err = hal_ks_index_add(    &db.ksi, &slot->name, new_chunk, &b, &hint);

      if (err != HAL_OK || (err = block_write(b, new_block)) != HAL_OK)
        return err;

      cache_mark_used(new_block, b);

      new_block = NULL;
      new_chunk++;
    }
  }

  /*
   * Phase 3: Zero the old chunks we deprecated in phase 1.
   */

  for (chunk = 0; chunk < total_chunks_old; chunk++)
    if ((err = block_zero(old_blocks[chunk])) != HAL_OK)
      return err;

  return HAL_OK;
}

static  hal_error_t ks_get_attributes(hal_ks_t *ks,
                                      hal_pkey_slot_t *slot,
                                      hal_rpc_pkey_attribute_t *attributes,
                                      const unsigned attributes_len,
                                      uint8_t *attributes_buffer,
                                      const size_t attributes_buffer_len)
{
  if (ks != &db.ks || slot == NULL || attributes == NULL || attributes_len == 0 ||
      attributes_buffer == NULL || attributes_buffer_len == 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  for (int i = 0; i < attributes_len; i++) {
    attributes[i].length = 0;
    attributes[i].value  = NULL;
  }

  uint8_t *abuf = attributes_buffer;
  flash_block_t *block = NULL;
  unsigned chunk = 0;
  unsigned found = 0;
  hal_error_t err;
  unsigned b;

  do {
    int hint = slot->hint + chunk;

    if ((err = hal_ks_index_find(&db.ksi, &slot->name, chunk, &b, &hint)) != HAL_OK ||
        (err = block_read_cached(b, &block))                              != HAL_OK)
      return err;

    if (block->header.this_chunk != chunk)
      return HAL_ERROR_IMPOSSIBLE;

    if (chunk == 0)
      slot->hint = hint;

    cache_mark_used(block, b);

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, chunk, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      return err;

    if (*attrs_len == 0)
      continue;

    hal_rpc_pkey_attribute_t attrs[*attrs_len];

    if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, NULL)) != HAL_OK)
      return err;

    for (int i = 0; i < attributes_len; i++) {

      if (attributes[i].value != NULL)
        continue;

      int j = 0;
      while (j < *attrs_len && attrs[j].type != attributes[i].type)
        j++;
      if (j >= *attrs_len)
        continue;

      if (attrs[j].length > attributes_buffer + attributes_buffer_len - abuf)
        return HAL_ERROR_RESULT_TOO_LONG;

      memcpy(abuf, attrs[j].value, attrs[j].length);
      attributes[i].value  = abuf;
      attributes[i].length = attrs[j].length;
      abuf += attrs[j].length;
      found++;
    }

  } while (found < attributes_len && ++chunk < block->header.total_chunks);

  if (found < attributes_len)
    return HAL_ERROR_ATTRIBUTE_NOT_FOUND;

  return HAL_OK;
}

static hal_error_t ks_delete_attributes(hal_ks_t *ks,
                                        hal_pkey_slot_t *slot,
                                        const uint32_t *types,
                                        const unsigned types_len)
{
  // Most likely we will remove this function from the API entirely,
  // but for now implement it in terms of ks_set_attributes() to keep
  // all the horrid update logic in one place.

  if (ks != &db.ks || slot == NULL || types == NULL || types_len == 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_rpc_pkey_attribute_t attributes[types_len];

  for (int i = 0; i < types_len; i++) {
    attributes[i].type   = types[i];
    attributes[i].length = 0;
    attributes[i].value  = NULL;
  }

  return ks_set_attributes(ks, slot, attributes, types_len);
}

const hal_ks_driver_t hal_ks_token_driver[1] = {{
  ks_init,
  ks_shutdown,
  ks_open,
  ks_close,
  ks_store,
  ks_fetch,
  ks_delete,
  ks_list,
  ks_match,
  ks_set_attribute,
  ks_get_attribute,
  ks_delete_attribute,
  ks_set_attributes,
  ks_get_attributes,
  ks_delete_attributes
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
 * Fetch PIN block.  hint = 0 because we know that the all-zeros UUID
 * should always sort to first slot in the index.
 */

static hal_error_t fetch_pin_block(unsigned *b, flash_block_t **block)
{
  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  hal_error_t err;
  int hint = 0;
  unsigned b_;

  if (b == NULL)
    b = &b_;

  if ((err = hal_ks_index_find(&db.ksi, &pin_uuid, 0, b, &hint)) != HAL_OK ||
      (err = block_read_cached(*b, block))                       != HAL_OK)
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
                                    flash_block_t *block,
                                    const flash_pin_block_t * const new_data)
{
  if (block == NULL || new_data == NULL || block_get_type(block) != BLOCK_TYPE_PIN)
    return HAL_ERROR_IMPOSSIBLE;

  int hint = 0;

  block->pin = *new_data;

  return block_update(b, block, &pin_uuid, 0, &hint);
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
