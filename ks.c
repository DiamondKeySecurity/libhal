/*
 * ks.c
 * ----
 * Keystore, generic parts anyway.  This is internal within libhal.
 *
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

#include <stddef.h>
#include <string.h>

#include "hal.h"
#include "hal_internal.h"
#include "ks.h"

/*
 * Find a block in the index, return true (found) or false (not found).
 * "where" indicates the name's position, or the position of the first free block.
 *
 * NB: This does NOT return a block number, it returns an index into
 * ks->index[].
 */

static int ks_find(const hal_ks_t * const ks,
                   const hal_uuid_t * const uuid,
                   const int * const hint,
                   int *where)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL || uuid == NULL || where == NULL)
    return 0;

  if (hint != NULL && *hint >= 0 && *hint < ks->used &&
      hal_uuid_cmp(uuid, &ks->names[ks->index[*hint]]) == 0) {
    *where = *hint;
    return 1;
  }

  int lo = -1;
  int hi = ks->used;

  for (;;) {
    int m = (lo + hi) / 2;
    if (hi == 0 || m == lo) {
      *where = hi;
      return 0;
    }
    const int cmp = hal_uuid_cmp(uuid, &ks->names[ks->index[m]]);
    if (cmp < 0)
      hi = m;
    else if (cmp > 0)
      lo = m;
    else {
      *where = m;
      return 1;
    }
  }
}

/*
 * Heapsort the index.  We only need to do this on setup, for other
 * operations we're just inserting or deleting a single entry in an
 * already-ordered array, which is just a search problem.  If we were
 * really crunched for space, we could use an insertion sort here, but
 * heapsort is easy and works well with data already in place.
 */

static inline void ks_heapsift(hal_ks_t *ks, int parent, const int end)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL || parent < 0 || end < parent)
    return;
  for (;;) {
    const int left_child  = parent * 2 + 1;
    const int right_child = parent * 2 + 2;
    int biggest = parent;
    if (left_child  <= end && hal_uuid_cmp(&ks->names[ks->index[biggest]],
                                           &ks->names[ks->index[left_child]])  < 0)
      biggest = left_child;
    if (right_child <= end && hal_uuid_cmp(&ks->names[ks->index[biggest]],
                                           &ks->names[ks->index[right_child]]) < 0)
      biggest = right_child;
    if (biggest == parent)
      return;
    const uint16_t tmp = ks->index[biggest];
    ks->index[biggest] = ks->index[parent];
    ks->index[parent]  = tmp;
    parent = biggest;
  }
}

static inline void ks_heapsort(hal_ks_t *ks)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL)
    return;
  if (ks->used < 2)
    return;
  for (int i = (ks->used - 2) / 2; i >= 0; i--)
    ks_heapsift(ks, i, ks->used - 1);
  for (int i = ks->used - 1; i > 0; i--) {
    const uint16_t tmp = ks->index[i];
    ks->index[i]       = ks->index[0];
    ks->index[0]       = tmp;
    ks_heapsift(ks, 0, i - 1);
  }
}

/*
 * Perform a consistency check on the index.
 */

#define fsck(_ks) \
  do { hal_error_t _err = hal_ks_index_fsck(_ks); if (_err != HAL_OK) return _err; } while (0)


hal_error_t hal_ks_index_fsck(hal_ks_t *ks)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL ||
      ks->size == 0 || ks->used > ks->size)
    return HAL_ERROR_BAD_ARGUMENTS;

  for (int i = 1; i < ks->used; i++)
    if (hal_uuid_cmp(&ks->names[ks->index[i - 1]], &ks->names[ks->index[i]]) >= 0)
      return HAL_ERROR_KS_INDEX_UUID_MISORDERED;

  return HAL_OK;
}

/*
 * Find a single block by name.
 */

hal_error_t hal_ks_index_find(hal_ks_t *ks,
                              const hal_uuid_t * const name,
                              unsigned *blockno,
                              int *hint)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL ||
      ks->size == 0 || ks->used > ks->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  int where;

  fsck(ks);

  int ok = ks_find(ks, name, hint, &where);

  if (blockno != NULL)
    *blockno = ks->index[where];

  if (hint != NULL)
    *hint = where;

  return ok ? HAL_OK : HAL_ERROR_KEY_NOT_FOUND;
}

/*
 * Add a single block to the index.
 */

hal_error_t hal_ks_index_add(hal_ks_t *ks,
                             const hal_uuid_t * const name,
                             unsigned *blockno,
                             int *hint)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL ||
      ks->size == 0 || ks->used > ks->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (ks->used == ks->size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  int where;

  fsck(ks);

  if (ks_find(ks, name, hint, &where))
    return HAL_ERROR_KEY_NAME_IN_USE;

  /*
   * Grab first block on free list, which makes room to slide the
   * index up by one slot so we can insert the new block number.
   */

  const size_t len = (ks->used - where) * sizeof(*ks->index);
  const uint16_t b = ks->index[ks->used++];
  memmove(&ks->index[where + 1], &ks->index[where], len);
  ks->index[where] = b;
  ks->names[b] = *name;

  if (blockno != NULL)
    *blockno = b;

  if (hint != NULL)
    *hint = where;

  fsck(ks);

  return HAL_OK;
}

/*
 * Delete a single block from the index.
 */

hal_error_t hal_ks_index_delete(hal_ks_t *ks,
                                const hal_uuid_t * const name,
                                unsigned *blockno,
                                int *hint)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL ||
      ks->size == 0 || ks->used > ks->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  int where;

  fsck(ks);

  if (ks->used == 0 || !ks_find(ks, name, hint, &where))
    return HAL_ERROR_KEY_NOT_FOUND;

  /*
   * Free the block and stuff it at the end of the free list.
   */

  const size_t len = (ks->size - where - 1) * sizeof(*ks->index);
  const uint16_t b = ks->index[where];
  memmove(&ks->index[where], &ks->index[where + 1], len);
  ks->index[ks->size - 1] = b;
  ks->used--;
  memset(&ks->names[b], 0, sizeof(ks->names[b]));

  if (blockno != NULL)
    *blockno = b;

  if (hint != NULL)
    *hint = where;

  fsck(ks);

  return HAL_OK;
}

/*
 * Replace a single block in the index.
 */

hal_error_t hal_ks_index_replace(hal_ks_t *ks,
                                 const hal_uuid_t * const name,
                                 unsigned *blockno,
                                 int *hint)
{
  if (ks == NULL || ks->index == NULL || ks->names == NULL ||
      ks->size == 0 || ks->used > ks->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (ks->used == ks->size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  int where;

  fsck(ks);

  if (ks->used == 0 || !ks_find(ks, name, hint, &where))
    return HAL_ERROR_KEY_NOT_FOUND;

  /*
   * Grab first block from free list, slide free list down, put old
   * block at end of free list and replace old block with new block.
   */

  const size_t len = (ks->size - ks->used - 1) * sizeof(*ks->index);
  const uint16_t b1 = ks->index[where];
  const uint16_t b2 = ks->index[ks->used];
  memmove(&ks->index[ks->used], &ks->index[ks->used + 1], len);
  ks->index[ks->size - 1] = b1;
  ks->index[where] = b2;
  ks->names[b2] = *name;
  memset(&ks->names[b1], 0, sizeof(ks->names[b1]));

  if (blockno != NULL)
    *blockno = b2;

  if (hint != NULL)
    *hint = where;

  fsck(ks);

  return HAL_OK;
}

/*
 * Pick unused or least-recently-used slot in our in-memory cache.
 *
 * Updating lru values is caller's problem: if caller is using a cache
 * slot as a temporary buffer and there's no point in caching the
 * result, leave the lru values alone and the right thing will happen.
 */

static inline ks_block_t *cache_pick_lru(hal_ks_t *ks)
{
  uint32_t best_delta = 0;
  int      best_index = 0;

  for (int i = 0; i < ks->cache_size; i++) {

    if (ks->cache[i].blockno == ~0)
      return &ks->cache[i].block;

    const unsigned delta = ks->cache_lru - ks->cache[i].lru;
    if (delta > best_delta) {
      best_delta = delta;
      best_index = i;
    }

  }

  ks->cache[best_index].blockno = ~0;
  return &ks->cache[best_index].block;
}

/*
 * Find a block in our in-memory cache; return block or NULL if not present.
 */

static inline ks_block_t *cache_find_block(const hal_ks_t * const ks, const unsigned blockno)
{
  for (int i = 0; i < ks->cache_size; i++)
    if (ks->cache[i].blockno == blockno)
      return &ks->cache[i].block;
  return NULL;
}

/*
 * Mark a block in our in-memory cache as being in current use.
 */

static inline void cache_mark_used(hal_ks_t *ks, const ks_block_t * const block, const unsigned blockno)
{
  for (int i = 0; i < ks->cache_size; i++) {
    if (&ks->cache[i].block == block) {
      ks->cache[i].blockno = blockno;
      ks->cache[i].lru = ++ks->cache_lru;
      return;
    }
  }
}

/*
 * Release a block from the in-memory cache.
 */

static inline void cache_release(hal_ks_t *ks, const ks_block_t * const block)
{
  if (block != NULL)
    cache_mark_used(block, ~0);
}

/*
 * Generate CRC-32 for a block.
 *
 * This function needs to understand the structure of
 * ks_block_header_t, so that it can skip over fields that
 * shouldn't be included in the CRC.
 */

static hal_crc32_t calculate_block_crc(const ks_block_t * const block)
{
  hal_crc32_t crc = hal_crc32_init();

  if (block != NULL) {

    crc = hal_crc32_update(crc,  &block->header.block_type,
                           sizeof(block->header.block_type));

    crc = hal_crc32_update(crc,
                           block->bytes   + sizeof(ks_block_header_t),
                           sizeof(*block) - sizeof(ks_block_header_t));
  }

  return hal_crc32_finalize(crc);
}

/*
 * Read a block using the cache.  Marking the block as used is left
 * for the caller, so we can avoid blowing out the cache when we
 * perform a ks_match() operation.
 */

static hal_error_t block_read_cached(hal_ks_t *ks, const unsigned blockno, ks_block_t **block)
{
  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if ((*block = cache_find_block(ks, blockno)) != NULL)
    return HAL_OK;

  if ((*block = cache_pick_lru(ks)) == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  return block_read(ks, blockno, *block);
}

/*
 * Update one block, including zombie jamboree.
 */

static hal_error_t block_update(hal_ks_t *ks,
                                const unsigned b1,
                                ks_block_t *block,
                                const hal_uuid_t * const uuid,
                                int *hint)
{
  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if (ks->used == ks->size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  cache_release(block);

  hal_error_t err;
  unsigned b2;

  if ((err = block_deprecate(ks, b1))                   != HAL_OK ||
      (err = hal_ks_index_replace(ks, uuid, &b2, hint)) != HAL_OK ||
      (err = block_write(ks, b2, block))                != HAL_OK ||
      (err = block_zero(ks, b1))                        != HAL_OK)
    return err;

  cache_mark_used(ks, block, b2);

  /*
   * Erase the first block in the free list. In case of restart, this
   * puts the block back at the head of the free list.
   */

  return block_erase_maybe(ks, ks->index[ks->used]);
}

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

#warning Call ks_alloc_common() and ks_init_common() while holding hal_ks_lock(); !

hal_error_t ks_alloc_common(hal_ks_t *ks, const unsigned ks_blocks, const unsigned cache_blocks)
{
  /*
   * We allocate a single big chunk of memory rather than three
   * smaller chunks to make it atomic.  We need all three, so this way
   * either all succeed or all fail.
   */

  size_t len = (sizeof(*ks->index) * ks_blocks +
                sizeof(*ks->names) * ks_blocks +
                sizeof(*ks->cache) * cache_blocks);

  uint8_t *mem = hal_allocate_static_memory(len);

  if (mem == NULL)
    return HAL_ERROR_ALLOCATION_FAILURE;

  memset(ks,  0, sizeof(*ks));
  memset(mem, 0, len);

  ks->index = gnaw(&mem, &len, sizeof(*ks->index) * ks_blocks);
  ks->names = gnaw(&mem, &len, sizeof(*ks->names) * ks_blocks);
  ks->cache = gnaw(&mem, &len, sizeof(*ks->cache) * cache_blocks);

  ks->size       = ks_blocks;
  ks->cache_size = cache_blocks;

  return HAL_OK;
}

hal_error_t ks_init_common(hal_ks_t *ks, const hal_ks_driver_t * const driver)
{
  if (ks->index == NULL || ks->names == NULL || ks->cache == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  ks->used = 0;

  for (int i = 0; i < ks->cache_size; i++)
    ks->cache[i].blockno = ~0;

  /*
   * Scan existing content of keystore to figure out what we've got.
   * This gets a bit involved due to the need to recover from things
   * like power failures at inconvenient times.
   */

  ks_block_type_t   block_types[ks->size];
  ks_block_status_t block_status[ks->size];
  ks_block_t *block = cache_pick_lru(ks);
  int first_erased = -1;
  hal_error_t err;
  uint16_t n = 0;

  if (block == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  for (int i = 0; i < ks->size; i++) {

    /*
     * Read one block.  If the CRC is bad or the block type is
     * unknown, it's old data we don't understand, something we were
     * writing when we crashed, or bad flash; in any of these cases,
     * we want the block to end up near the end of the free list.
     */

    err = block_read(ks, i, block);

    if (err == HAL_ERROR_KEYSTORE_BAD_CRC || err == HAL_ERROR_KEYSTORE_BAD_BLOCK_TYPE)
      block_types[i] = BLOCK_TYPE_UNKNOWN;

    else if (err == HAL_OK)
      block_types[i] = block_get_type(block);

    else
      return err;

    switch (block_types[i]) {
    case BLOCK_TYPE_KEY:
    case BLOCK_TYPE_PIN:
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
    case BLOCK_TYPE_PIN:        uuid = &pin_uuid;               break;
    default:                    /* Keep GCC happy */            break;
    }

    if (uuid != NULL) {
      ks->names[i] = *uuid;
      ks->index[n++] = i;
    }
  }

  ks->used = n;

  if (ks->used > ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  /*
   * At this point we've built the (unsorted) index from all the valid
   * blocks.  Now we need to insert free and unrecognized blocks into
   * the free list in our preferred order.  It's possible that there's
   * a better way to do this than linear scan, but this is just
   * integer comparisons in a fairly small data set, so it's probably
   * not worth trying to optimize.
   */

  if (n < ks->size)
    for (int i = 0; i < ks->size; i++)
      if (block_types[i] == BLOCK_TYPE_ERASED)
        ks->index[n++] = i;

  if (n < ks->size)
    for (int i = first_erased; i < ks->size; i++)
      if (block_types[i] == BLOCK_TYPE_ZEROED)
        ks->index[n++] = i;

  if (n < ks->size)
    for (int i = 0; i < first_erased; i++)
      if (block_types[i] == BLOCK_TYPE_ZEROED)
        ks->index[n++] = i;

  if (n < ks->size)
    for (int i = 0; i < ks->size; i++)
      if (block_types[i] == BLOCK_TYPE_UNKNOWN)
        ks->index[n++] = i;

  if (ks->used > ks->size)
    return HAL_ERROR_IMPOSSIBLE;

  /*
   * Sort the index, then deal with tombstones.  Tombstones are blocks
   * left behind when something bad (like a power failure) happened
   * while we updating.  There can be at most one tombstone and one
   * live block for a given UUID.  If we find no live block, we need
   * to restore it from the tombstone, after which we need to zero the
   * tombstone in either case.  The sequence of operations while
   * updating is designed so that, barring a bug or a hardware
   * failure, we should never lose data.
   */

  ks_heapsort(ks);

  for (unsigned b_tomb = 0; b_tomb < ks->size; b_tomb++) {

    if (block_status[b_tomb] != BLOCK_STATUS_TOMBSTONE)
      continue;

    hal_uuid_t name = ks->names[b_tomb];

    int where = -1;

    if ((err = hal_ks_index_find(ks, &name, NULL, &where)) != HAL_OK)
      return err;

    if (b_tomb != ks->index[where]) {
      if (ks->used > where + 1 && b_tomb == ks->index[where + 1])
        where = where + 1;
      else if (0     <= where - 1 && b_tomb == ks->index[where - 1])
        where = where - 1;
      else
        return HAL_ERROR_IMPOSSIBLE;
    }

    const int matches_next = where + 1 < ks->used && !hal_uuid_cmp(&name, &ks->names[ks->index[where + 1]]);
    const int matches_prev = where - 1 >= 0       && !hal_uuid_cmp(&name, &ks->names[ks->index[where - 1]]);
    
    if ((matches_prev && matches_next) ||
        (matches_prev && block_status[ks->index[b_tomb - 1]] != BLOCK_STATUS_LIVE) ||
        (matches_next && block_status[ks->index[b_tomb + 1]] != BLOCK_STATUS_LIVE))
      return HAL_ERROR_IMPOSSIBLE;

    if (matches_prev || matches_next)  {
      memmove(&ks->index[where], &ks->index[where + 1], (ks->size - where - 1) * sizeof(*ks->index));
      ks->index[ks->size - 1] = b_tomb;
    }

    else {
      unsigned b_live;
      if ((err = block_read(ks, b_tomb, block)) != HAL_OK)
        return err;
      block->header.block_status = BLOCK_STATUS_LIVE;
      if ((err = hal_ks_index_replace(ks, &name, &b_live, &where)) != HAL_OK ||
          (err = block_write(ks, b_live, block)) != HAL_OK)
        return err;
      block_status[b_live] = BLOCK_STATUS_LIVE;
    }

    if ((err = block_zero(ks, b_tomb)) != HAL_OK)
      return err;
    block_types[ b_tomb] = BLOCK_TYPE_ZEROED;
    block_status[b_tomb] = BLOCK_STATUS_UNKNOWN;
  }

  /*
   * Erase first block on free list if it's not already erased.
   */

  if (ks->used < ks->size &&
      (err = block_erase_maybe(ks, ks->index[ks->used])) != HAL_OK)
    return err;

  /*
   * And we're finally done.
   */

  ks->driver = driver;

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

hal_error_t ks_store(hal_ks_t *ks,
                     hal_pkey_slot_t *slot,
                     const uint8_t * const der, const size_t der_len)
{
  if (ks == NULL || slot == NULL || der == NULL || der_len == 0 || !acceptable_key_type(slot->type))
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err = HAL_OK;
  ks_block_t *block;
  flash_key_block_t *k;
  uint8_t kek[KEK_LENGTH];
  size_t kek_len;
  unsigned b;

  hal_ks_lock();

  if ((block = cache_pick_lru(ks)) == NULL) {
    err = HAL_ERROR_IMPOSSIBLE;
    goto done;
  }

  k = &block->key;

  if ((err = hal_ks_index_add(ks, &slot->name, &b, &slot->hint)) != HAL_OK)
    goto done;

  cache_mark_used(ks, block, b);

  memset(block, 0xFF, sizeof(*block));

  block->header.block_type   = BLOCK_TYPE_KEY;
  block->header.block_status = BLOCK_STATUS_LIVE;

  k->name    = slot->name;
  k->type    = slot->type;
  k->curve   = slot->curve;
  k->flags   = slot->flags;
  k->der_len = SIZEOF_FLASH_KEY_BLOCK_DER;
  k->attributes_len = 0;

  if (ks->used < ks->size)
    err = block_erase_maybe(ks, ks->index[ks->used]);

  if (err == HAL_OK)
    err = hal_mkm_get_kek(kek, &kek_len, sizeof(kek));

  if (err == HAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k->der, &k->der_len);

  memset(kek, 0, sizeof(kek));

  if (err == HAL_OK)
    err = block_write(ks, b, block);

  if (err == HAL_OK)
    goto done;

  memset(block, 0, sizeof(*block));
  cache_release(ks, block);
  (void) hal_ks_index_delete(ks, &slot->name, NULL, &slot->hint);

 done:
  hal_ks_unlock();
  return err;
}

static hal_error_t ks_fetch(hal_ks_t *ks,
                            hal_pkey_slot_t *slot,
                            uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (ks == NULL || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err = HAL_OK;
  ks_block_t *block;
  unsigned b;

  hal_ks_lock();

  if ((err = hal_ks_index_find(ks, &slot->name, &b, &slot->hint)) != HAL_OK ||
      (err = block_read_cached(ks, b, &block))                    != HAL_OK)
    goto done;

  if (block_get_type(block) != BLOCK_TYPE_KEY) {
    err = HAL_ERROR_KEYSTORE_WRONG_BLOCK_TYPE; /* HAL_ERROR_KEY_NOT_FOUND */
    goto done;
  }

  cache_mark_used(ks, block, b);

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
  }

 done:
  hal_ks_unlock();
  return err;
}

static hal_error_t ks_delete(hal_ks_t *ks,
                             hal_pkey_slot_t *slot)
{
  if (ks == NULL || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err = HAL_OK;
  unsigned b;

  hal_ks_lock();

  if ((err = hal_ks_index_delete(ks, &slot->name, &b, &slot->hint)) != HAL_OK)
    goto done;

  cache_release(ks, cache_find_block(ks, b));

  if ((err = block_zero(ks, b)) != HAL_OK)
    goto done;

  err = block_erase_maybe(ks, ks->index[ks->used]);

 done:
  hal_ks_unlock();
  return err;
}

static inline hal_error_t locate_attributes(ks_block_t *block,
                                            uint8_t **bytes, size_t *bytes_len,
                                            unsigned **attrs_len)
{
  if (block == NULL || bytes == NULL || bytes_len == NULL || attrs_len == NULL)
    return HAL_ERROR_IMPOSSIBLE;


  if (block_get_type(block) != BLOCK_TYPE_KEY)
    return HAL_ERROR_KEYSTORE_WRONG_BLOCK_TYPE;
  *attrs_len = &block->key.attributes_len;
  *bytes = block->key.der + block->key.der_len;
  *bytes_len = SIZEOF_FLASH_KEY_BLOCK_DER - block->key.der_len;

  return HAL_OK;
}

static hal_error_t ks_match(hal_ks_t *ks,
                            const hal_client_handle_t client,
                            const hal_session_handle_t session,
                            const hal_key_type_t type,
                            const hal_curve_name_t curve,
                            const hal_key_flags_t mask,
                            const hal_key_flags_t flags,
                            const hal_pkey_attribute_t *attributes,
                            const unsigned attributes_len,
                            hal_uuid_t *result,
                            unsigned *result_len,
                            const unsigned result_max,
                            const hal_uuid_t * const previous_uuid)
{
  if (ks == NULL || (attributes == NULL && attributes_len > 0) ||
      result == NULL || result_len == NULL || previous_uuid == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err = HAL_OK;
  ks_block_t *block;
  int i = -1;

  hal_ks_lock();

  *result_len = 0;

  err = hal_ks_index_find(ks, previous_uuid, NULL, &i);

  if (err == HAL_ERROR_KEY_NOT_FOUND)
    i--;
  else if (err != HAL_OK)
    goto done;

  while (*result_len < result_max && ++i < ks->used) {

    unsigned b = ks->index[i];

    if ((err = block_read_cached(ks, b, &block)) != HAL_OK)
      goto done;

    if ((type  != HAL_KEY_TYPE_NONE && type  != block->key.type)  ||
        (curve != HAL_CURVE_NONE    && curve != block->key.curve) ||
        ((flags ^ block->key.flags) & mask)  != 0)
      continue;

    if (attributes_len > 0) {
      uint8_t need_attr[attributes_len];
      uint8_t *bytes = NULL;
      size_t bytes_len = 0;
      unsigned *attrs_len;
      int possible = 1;

      memset(need_attr, 1, sizeof(need_attr));

      if ((err = locate_attributes(block, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
        goto done;

      if (*attrs_len > 0) {
        hal_pkey_attribute_t attrs[*attrs_len];

        if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, NULL)) != HAL_OK)
          goto done;

        for (int j = 0; possible && j < attributes_len; j++) {

          if (!need_attr[j])
            continue;

          for (hal_pkey_attribute_t *a = attrs; a < attrs + *attrs_len; a++) {
            if (a->type != attributes[j].type)
              continue;
            need_attr[j] = 0;
            possible = (a->length == attributes[j].length &&
                        !memcmp(a->value, attributes[j].value, a->length));
            break;
          }
        }
      }

      if (!possible || memchr(need_attr, 1, sizeof(need_attr)) != NULL)
        continue;
    }

    result[*result_len] = ks->names[b];
    ++*result_len;
  }

  err = HAL_OK;

 done:
  hal_ks_unlock();
  return err;
}

static  hal_error_t ks_set_attributes(hal_ks_t *ks,
                                      hal_pkey_slot_t *slot,
                                      const hal_pkey_attribute_t *attributes,
                                      const unsigned attributes_len)
{
  if (ks == NULL || slot == NULL || attributes == NULL || attributes_len == 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err = HAL_OK;
  ks_block_t *block;
  unsigned b;

  hal_ks_lock();

  {
    if ((err = hal_ks_index_find(ks, &slot->name, &b, &slot->hint)) != HAL_OK ||
        (err = block_read_cached(ks, b, &block))                    != HAL_OK)
      goto done;

    cache_mark_used(ks, block, b);

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      goto done;

    hal_pkey_attribute_t attrs[*attrs_len + attributes_len];
    size_t total;

    if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, &total)) != HAL_OK)
      goto done;

    for (int i = 0; err == HAL_OK && i < attributes_len; i++)
      if (attributes[i].length == HAL_PKEY_ATTRIBUTE_NIL)
        err = hal_ks_attribute_delete(bytes, bytes_len, attrs, attrs_len, &total,
                                      attributes[i].type);
      else
        err = hal_ks_attribute_insert(bytes, bytes_len, attrs, attrs_len, &total,
                                      attributes[i].type,
                                      attributes[i].value,
                                      attributes[i].length);

    if (err == HAL_OK)
      err = block_update(ks, b, block, &slot->name, &slot->hint);
    else
      cache_release(ks, block);
  }

 done:
  hal_ks_unlock();
  return err;
}

static  hal_error_t ks_get_attributes(hal_ks_t *ks,
                                      hal_pkey_slot_t *slot,
                                      hal_pkey_attribute_t *attributes,
                                      const unsigned attributes_len,
                                      uint8_t *attributes_buffer,
                                      const size_t attributes_buffer_len)
{
  if (ks == NULL || slot == NULL || attributes == NULL || attributes_len == 0 ||
      attributes_buffer == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  for (int i = 0; i < attributes_len; i++) {
    attributes[i].length = 0;
    attributes[i].value  = NULL;
  }

  uint8_t *abuf = attributes_buffer;
  ks_block_t *block = NULL;
  hal_error_t err = HAL_OK;
  unsigned found = 0;
  unsigned b;

  hal_ks_lock();

  {
    if ((err = hal_ks_index_find(ks, &slot->name, &b, &slot->hint)) != HAL_OK ||
        (err = block_read_cached(ks, b, &block))                    != HAL_OK)
      goto done;

    cache_mark_used(ks, block, b);

    uint8_t *bytes = NULL;
    size_t bytes_len = 0;
    unsigned *attrs_len;

    if ((err = locate_attributes(block, &bytes, &bytes_len, &attrs_len)) != HAL_OK)
      goto done;

    if (*attrs_len == 0) {
      err = HAL_ERROR_ATTRIBUTE_NOT_FOUND;
      goto done;
    }

    hal_pkey_attribute_t attrs[*attrs_len];

    if ((err = hal_ks_attribute_scan(bytes, bytes_len, attrs, *attrs_len, NULL)) != HAL_OK)
      goto done;

    for (int i = 0; i < attributes_len; i++) {

      if (attributes[i].length > 0)
        continue;

      int j = 0;
      while (j < *attrs_len && attrs[j].type != attributes[i].type)
        j++;
      if (j >= *attrs_len)
        continue;
      found++;

      attributes[i].length = attrs[j].length;

      if (attributes_buffer_len == 0)
        continue;

      if (attrs[j].length > attributes_buffer + attributes_buffer_len - abuf) {
        err = HAL_ERROR_RESULT_TOO_LONG;
        goto done;
      }

      memcpy(abuf, attrs[j].value, attrs[j].length);
      attributes[i].value  = abuf;
      abuf += attrs[j].length;
    }

  };

  if (found < attributes_len && attributes_buffer_len > 0)
    err = HAL_ERROR_ATTRIBUTE_NOT_FOUND;
  else
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
