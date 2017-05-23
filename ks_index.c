/*
 * ks_index.c
 * ----------
 * Keystore index API.  This is internal within libhal.
 *
 * Copyright (c) 2016, NORDUnet A/S All rights reserved.
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

/*
 * Find a block in the index, return true (found) or false (not found).
 * "where" indicates the name's position, or the position of the first free block.
 *
 * NB: This does NOT return a block number, it returns an index into
 * ksi->index[].
 */

static int ks_find(const hal_ks_index_t * const ksi,
		   const hal_uuid_t * const uuid,
                   const int * const hint,
		   int *where)
{
  assert(ksi != NULL && ksi->index != NULL && ksi->names != NULL && uuid != NULL && where != NULL);

  if (hint != NULL && *hint >= 0 && *hint < ksi->used &&
      hal_uuid_cmp(uuid, &ksi->names[ksi->index[*hint]]) == 0) {
    *where = *hint;
    return 1;
  }

  int lo = -1;
  int hi = ksi->used;

  for (;;) {
    int m = (lo + hi) / 2;
    if (hi == 0 || m == lo) {
      *where = hi;
      return 0;
    }
    const int cmp = hal_uuid_cmp(uuid, &ksi->names[ksi->index[m]]);
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

static inline void ks_heapsift(hal_ks_index_t *ksi, int parent, const int end)
{
  assert(ksi != NULL && ksi->index != NULL && ksi->names != NULL &&
	 parent >= 0 && end >= parent);
  for (;;) {
    const int left_child  = parent * 2 + 1;
    const int right_child = parent * 2 + 2;
    int biggest = parent;
    if (left_child  <= end && hal_uuid_cmp(&ksi->names[ksi->index[biggest]],
                                           &ksi->names[ksi->index[left_child]])  < 0)
      biggest = left_child;
    if (right_child <= end && hal_uuid_cmp(&ksi->names[ksi->index[biggest]],
                                           &ksi->names[ksi->index[right_child]]) < 0)
      biggest = right_child;
    if (biggest == parent)
      return;
    const uint16_t tmp  = ksi->index[biggest];
    ksi->index[biggest] = ksi->index[parent];
    ksi->index[parent] = tmp;
    parent = biggest;
  }
}

static inline void ks_heapsort(hal_ks_index_t *ksi)
{
  assert(ksi != NULL && ksi->index != NULL && ksi->names != NULL);
  if (ksi->used < 2)
    return;
  for (int i = (ksi->used - 2) / 2; i >= 0; i--)
    ks_heapsift(ksi, i, ksi->used - 1);
  for (int i = ksi->used - 1; i > 0; i--) {
    const uint16_t tmp = ksi->index[i];
    ksi->index[i]      = ksi->index[0];
    ksi->index[0]      = tmp;
    ks_heapsift(ksi, 0, i - 1);
  }
}

/*
 * Perform a consistency check on the index.
 */

#define fsck(_ksi) \
  do { hal_error_t _err = hal_ks_index_fsck(_ksi); if (_err != HAL_OK) return _err; } while (0)


hal_error_t hal_ks_index_fsck(hal_ks_index_t *ksi)
{
  if (ksi == NULL || ksi->index == NULL || ksi->names == NULL ||
      ksi->size == 0 || ksi->used > ksi->size)
    return HAL_ERROR_BAD_ARGUMENTS;

  for (int i = 1; i < ksi->used; i++)
    if (hal_uuid_cmp(&ksi->names[ksi->index[i - 1]], &ksi->names[ksi->index[i]]) >= 0)
      return HAL_ERROR_KSI_INDEX_UUID_MISORDERED;

  return HAL_OK;
}

/*
 * Set up the index. Only setup task we have at the moment is sorting the index.
 */

hal_error_t hal_ks_index_setup(hal_ks_index_t *ksi)
{
  if (ksi == NULL || ksi->index == NULL || ksi->names == NULL ||
      ksi->size == 0 || ksi->used > ksi->size)
    return HAL_ERROR_BAD_ARGUMENTS;

  ks_heapsort(ksi);

  /*
   * One might think we should fsck here, but errors in the index
   * at this point probably relate to errors in the supplied data,
   * which only the driver knows how to clean up.
   */

  return HAL_OK;
}

/*
 * Find a single block by name.
 */

hal_error_t hal_ks_index_find(hal_ks_index_t *ksi,
			      const hal_uuid_t * const name,
			      unsigned *blockno,
                              int *hint)
{
  if (ksi == NULL || ksi->index == NULL || ksi->names == NULL ||
      ksi->size == 0 || ksi->used > ksi->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  int where;

  fsck(ksi);

  int ok = ks_find(ksi, name, hint, &where);

  if (blockno != NULL)
    *blockno = ksi->index[where];

  if (hint != NULL)
    *hint = where;

  return ok ? HAL_OK : HAL_ERROR_KEY_NOT_FOUND;
}

/*
 * Add a single block to the index.
 */

hal_error_t hal_ks_index_add(hal_ks_index_t *ksi,
			     const hal_uuid_t * const name,
			     unsigned *blockno,
                             int *hint)
{
  if (ksi == NULL || ksi->index == NULL || ksi->names == NULL ||
      ksi->size == 0 || ksi->used > ksi->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (ksi->used == ksi->size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  int where;

  fsck(ksi);

  if (ks_find(ksi, name, hint, &where))
    return HAL_ERROR_KEY_NAME_IN_USE;

  /*
   * Grab first block on free list, which makes room to slide the
   * index up by one slot so we can insert the new block number.
   */

  const size_t len = (ksi->used - where) * sizeof(*ksi->index);
  const uint16_t b = ksi->index[ksi->used++];
  memmove(&ksi->index[where + 1], &ksi->index[where], len);
  ksi->index[where] = b;
  ksi->names[b] = *name;

  if (blockno != NULL)
    *blockno = b;

  if (hint != NULL)
    *hint = where;

  fsck(ksi);

  return HAL_OK;
}

/*
 * Delete a single block from the index.
 */

hal_error_t hal_ks_index_delete(hal_ks_index_t *ksi,
				const hal_uuid_t * const name,
				unsigned *blockno,
                                int *hint)
{
  if (ksi == NULL || ksi->index == NULL || ksi->names == NULL ||
      ksi->size == 0 || ksi->used > ksi->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  int where;

  fsck(ksi);

  if (ksi->used == 0 || !ks_find(ksi, name, hint, &where))
    return HAL_ERROR_KEY_NOT_FOUND;

  /*
   * Free the block and stuff it at the end of the free list.
   */

  const size_t len = (ksi->size - where - 1) * sizeof(*ksi->index);
  const uint16_t b = ksi->index[where];
  memmove(&ksi->index[where], &ksi->index[where + 1], len);
  ksi->index[ksi->size - 1] = b;
  ksi->used--;
  memset(&ksi->names[b], 0, sizeof(ksi->names[b]));

  if (blockno != NULL)
    *blockno = b;

  if (hint != NULL)
    *hint = where;

  fsck(ksi);

  return HAL_OK;
}

/*
 * Replace a single block in the index.
 */

hal_error_t hal_ks_index_replace(hal_ks_index_t *ksi,
                                 const hal_uuid_t * const name,
                                 unsigned *blockno,
                                 int *hint)
{
  if (ksi == NULL || ksi->index == NULL || ksi->names == NULL ||
      ksi->size == 0 || ksi->used > ksi->size || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (ksi->used == ksi->size)
    return HAL_ERROR_NO_KEY_INDEX_SLOTS;

  int where;

  fsck(ksi);

  if (ksi->used == 0 || !ks_find(ksi, name, hint, &where))
    return HAL_ERROR_KEY_NOT_FOUND;

  /*
   * Grab first block from free list, slide free list down, put old
   * block at end of free list and replace old block with new block.
   */

  const size_t len = (ksi->size - ksi->used - 1) * sizeof(*ksi->index);
  const uint16_t b1 = ksi->index[where];
  const uint16_t b2 = ksi->index[ksi->used];
  memmove(&ksi->index[ksi->used], &ksi->index[ksi->used + 1], len);
  ksi->index[ksi->size - 1] = b1;
  ksi->index[where] = b2;
  ksi->names[b2] = *name;
  memset(&ksi->names[b1], 0, sizeof(ksi->names[b1]));

  if (blockno != NULL)
    *blockno = b2;

  if (hint != NULL)
    *hint = where;

  fsck(ksi);

  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
