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

#define HAL_OK LIBHAL_OK
#include "hal.h"
#include "hal_internal.h"
#undef HAL_OK

#define HAL_OK CMIS_HAL_OK
#include "stm-keystore.h"
#undef HAL_OK

#include <string.h>
#include <assert.h>

#include "last_gasp_pin_internal.h"

#define PAGE_SIZE_MASK          (KEYSTORE_PAGE_SIZE - 1)

#define KEK_LENGTH              (bitsToBytes(256))

/*
 * Revised flash keystore database.  Work in progress.
 *
 * General consideration:
 *
 * - bits can only be cleared, not set, unless one wants to erase the
 *   (sub)sector.  This has some odd knock on effects in terms of
 *   things like values of enumerated constants used here.
 *
 * - At the moment, all of hte the low-level flash code deals with
 *   sectors, not sub-sectors, so for the moment we only use the first
 *   sub-sector of each sector.  Fixing this should not involve any
 *   major changes to the code, just redefinition of some constants
 *   here once we figure out what effect this will have on the rest of
 *   the code that shares the same low-level flash code.  In either
 *   case we're dealing with "blocks", where a block is a sector now
 *   and will be a sub-sector later.
 *
 * - This code assumes we're using ks_index.c, including its notion
 *   of a free list and its attempt at light-weight wear leveling.
 */

/*
 * Known block states.
 *
 * This assumes that an enum is stored as a 32-bit unsigned integer,
 * which may be a bad assumption.  Might be better to use uint32_t (or
 * whatever) and inline functions for safe casting.
 *
 * Might want an additional state 0xDEADDEAD to mark blocks which
 * are known to be unusable, but the current hardware is NOR flash
 * so that may not be as important as it would be with NAND flash.
 */

typedef enum {
  FLASH_ERASED = 0xFFFFFFFF,    /* Pristine erased block (candidate for reuse) */
  FLASH_ZEROED = 0x00000000,    /* Zeroed block (recently used) */
  FLASH_KEYBLK = 0x55555555,    /* Block contains key material */
  FLASH_PINBLK = 0xAAAAAAAA,    /* Block contains PINs */
} flash_block_type_t;

typedef struct {

  /*
   * What kind of flash block this is
   */
  flash_block_type_t    block_type;

  /*
   * CRC-32 of block contents.  crc_mask width should be at least as
   * many bits as there are slots in the crc array.  Once all of the
   * slots have been used, we have to move to a new block.  Using 32
   * slots initially, adjust that up or down once we have some clue
   * how well this design works and how many slots we really want.
   */
  uint32_t              crc_mask;
  hal_crc32_t           crc[32];

  /*
   * Payload for key and PIN blocks.  Anonymous structures and unions
   * until and unless we have a reason to name them.
   *
   * Storing the KEK in a PIN block is a dangerous kludge and should
   * be removed as soon as we have a battery backup for the MKM.
   *
   * We probably want some kind of TLV format for optional attributes
   * in key objects, and might want to put the DER key itself there to
   * save space.
   */

  union {

    struct {
      hal_uuid_t        name;
      hal_key_type_t    type;
      hal_curve_name_t  curve;
      hal_key_flags_t   flags;
      size_t            der_len;
      uint8_t           der[HAL_KS_WRAPPED_KEYSIZE];
    }                   key;

    struct {
      struct {
        hal_user_t      user;
        hal_ks_pin_t    pin;
      }                 pins[40];
      uint8_t           kek[KEK_LENGTH];        /* Kludge */
    }                   pin;

  } payload;

} flash_block_t;


#warning Old keystore code below here
/*
 * Temporary hack: In-memory copy of entire (tiny) keystore database.
 * This is backwards compatability to let us debug without changing
 * too many moving parts at the same time, but will need to be
 * replaced by something that can handle a much larger number of keys,
 * which is one of the main points of the new keystore API.
 *
 * hal_ks_key_t is ordered such that all metadata appears before the
 * big buffers, in order for all metadata to be loaded with a single
 * page read.
 */

typedef struct {
  hal_key_type_t type;
  hal_curve_name_t curve;
  hal_key_flags_t flags;
  uint8_t in_use;
  size_t der_len;
  hal_uuid_t name;
  uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
} hal_ks_key_t;

typedef struct {
  hal_ks_t ks;                  /* Must be first (C "subclassing") */
  hal_ks_pin_t wheel_pin;
  hal_ks_pin_t so_pin;
  hal_ks_pin_t user_pin;

#if HAL_STATIC_PKEY_STATE_BLOCKS > 0
  hal_ks_key_t keys[HAL_STATIC_PKEY_STATE_BLOCKS];
#else
#warning No keys in keydb
#endif

} db_t;

static db_t db;

#define FLASH_SECTOR_1_OFFSET   (0 * KEYSTORE_SECTOR_SIZE)
#define FLASH_SECTOR_2_OFFSET   (1 * KEYSTORE_SECTOR_SIZE)

static inline uint32_t _active_sector_offset()
{
  /* XXX Load status bytes from both sectors and decide which is current. */
#warning Have not implemented two flash sectors yet
  return FLASH_SECTOR_1_OFFSET;
}

static inline uint32_t _get_key_offset(uint32_t num)
{
  /*
   * Reserve first two pages for flash sector state, PINs and future additions.
   * The three PINs alone currently occupy 3 * (64 + 16 + 4) bytes (252).
   */
  uint32_t offset = KEYSTORE_PAGE_SIZE * 2;
  uint32_t key_size = sizeof(*db.keys);
  uint32_t bytes_per_key = KEYSTORE_PAGE_SIZE * ((key_size / KEYSTORE_PAGE_SIZE) + 1);
  offset += num * bytes_per_key;
  return offset;
}

static hal_error_t ks_init(const hal_ks_driver_t * const driver)
{
  uint8_t page_buf[KEYSTORE_PAGE_SIZE];
  uint32_t idx = 0;             /* Current index into db.keys[] */

  memset(&db, 0, sizeof(db));

  if (keystore_check_id() != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  uint32_t active_sector_offset = _active_sector_offset();

  /*
   * The PINs are in the second page of the sector.
   * Caching all of these these makes some sense in any case.
   */

  uint32_t offset = active_sector_offset + KEYSTORE_PAGE_SIZE;
  if (keystore_read_data(offset, page_buf, sizeof(page_buf)) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  offset = 0;
  memcpy(&db.wheel_pin, page_buf + offset, sizeof(db.wheel_pin));

  offset += sizeof(db.wheel_pin);
  memcpy(&db.so_pin, page_buf + offset, sizeof(db.so_pin));

  offset += sizeof(db.so_pin);
  memcpy(&db.user_pin, page_buf + offset, sizeof(db.user_pin));

  /*
   * Now read out all the keys.  This is a temporary hack, in the long
   * run we want to pull these as they're needed, although depending
   * on how we organize the flash we might still need an initial scan
   * on startup to build some kind of in-memory index.
   */

  for (int i = 0; i < sizeof(db.keys) / sizeof(*db.keys); i++) {

    if ((offset = _get_key_offset(i)) > KEYSTORE_SECTOR_SIZE) {
      idx++;
      continue;
    }

    offset += active_sector_offset;

    if (keystore_read_data(offset, page_buf, sizeof(page_buf)) != 1)
      return HAL_ERROR_KEYSTORE_ACCESS;

    const hal_ks_key_t *key = (const hal_ks_key_t *) page_buf;

    if (key->in_use == 0xff) {
      /* unprogrammed data */
      idx++;
      continue;
    }

    if (key->in_use == 1) {
      uint8_t *dst = (uint8_t *) &db.keys[idx];
      uint32_t to_read = sizeof(*db.keys);

      /* We already have the first page in page_buf. Put it into place. */
      memcpy(dst, page_buf, sizeof(page_buf));
      to_read -= sizeof(page_buf);
      dst += sizeof(page_buf);

      /* Read as many more full pages as possible */
      if (keystore_read_data (offset + KEYSTORE_PAGE_SIZE, dst, to_read & ~PAGE_SIZE_MASK) != 1)
        return HAL_ERROR_KEYSTORE_ACCESS;
      dst += to_read & ~PAGE_SIZE_MASK;
      to_read &= PAGE_SIZE_MASK;

      if (to_read) {
        /* Partial last page. We can only read full pages so load it into page_buf. */
        if (keystore_read_data(offset + sizeof(*db.keys) - to_read, page_buf, sizeof(page_buf)) != 1)
          return HAL_ERROR_KEYSTORE_ACCESS;
        memcpy(dst, page_buf, to_read);
      }
    }
    idx++;
  }

  db.ks.driver = driver;

  return LIBHAL_OK;
}

static hal_error_t ks_shutdown(const hal_ks_driver_t * const driver)
{
  if (db.ks.driver != driver)
    return HAL_ERROR_KEYSTORE_ACCESS;
  memset(&db, 0, sizeof(db));
  return LIBHAL_OK;
}

static hal_error_t _write_data_to_flash(const uint32_t offset, const uint8_t *data, const size_t len)
{
  uint8_t page_buf[KEYSTORE_PAGE_SIZE];
  uint32_t to_write = len;

  if (keystore_write_data(offset, data, to_write & ~PAGE_SIZE_MASK) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  to_write &= PAGE_SIZE_MASK;
  if (to_write) {
    /*
     * Use page_buf to write the remaining bytes, since we must write a full page each time.
     */
    memset(page_buf, 0xff, sizeof(page_buf));
    memcpy(page_buf, data + len - to_write, to_write);
    if (keystore_write_data((offset + len) & ~PAGE_SIZE_MASK, page_buf, sizeof(page_buf)) != 1)
      return HAL_ERROR_KEYSTORE_ACCESS;
  }

  return LIBHAL_OK;
}

/*
 * Write the full DB to flash, PINs and all.
 */

static hal_error_t _write_db_to_flash(const uint32_t sector_offset)
{
  hal_error_t status;
  uint8_t page_buf[KEYSTORE_PAGE_SIZE];
  uint32_t i, offset;

  if (sizeof(db.wheel_pin) + sizeof(db.so_pin) + sizeof(db.user_pin) > sizeof(page_buf))
    return HAL_ERROR_BAD_ARGUMENTS;

  /* Put the three PINs into page_buf */
  offset = 0;
  memcpy(page_buf + offset, &db.wheel_pin, sizeof(db.wheel_pin));
  offset += sizeof(db.wheel_pin);
  memcpy(page_buf + offset, &db.so_pin, sizeof(db.so_pin));
  offset += sizeof(db.so_pin);
  memcpy(page_buf + offset, &db.user_pin, sizeof(db.user_pin));

  /* Write PINs into the second of the two reserved pages at the start of the sector. */
  offset = sector_offset + KEYSTORE_PAGE_SIZE;
  if ((status = _write_data_to_flash(offset, page_buf, sizeof(page_buf))) != LIBHAL_OK)
    return status;

  for (i = 0; i < sizeof(db.keys) / sizeof(*db.keys); i++) {
    offset = _get_key_offset(i);
    if (offset > KEYSTORE_SECTOR_SIZE)
      return HAL_ERROR_BAD_ARGUMENTS;

    offset += sector_offset;

    if ((status =_write_data_to_flash(offset, (uint8_t *) &db.keys[i], sizeof(*db.keys))) != LIBHAL_OK)
      return status;
  }

  return LIBHAL_OK;
}

static hal_error_t ks_open(const hal_ks_driver_t * const driver,
                                    hal_ks_t **ks)
{
  if (driver != hal_ks_token_driver || ks == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  *ks = &db.ks;
  return LIBHAL_OK;
}

static hal_error_t ks_close(hal_ks_t *ks)
{
  if (ks != NULL && ks != &db.ks)
    return HAL_ERROR_BAD_ARGUMENTS;

  return LIBHAL_OK;
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

static inline hal_ks_key_t *find(const hal_uuid_t * const name)
{
  assert(name != NULL);

  for (int i = 0; i < sizeof(db.keys)/sizeof(*db.keys); i++)
    if (db.keys[i].in_use && hal_uuid_cmp(&db.keys[i].name, name) == 0)
      return &db.keys[i];

  return NULL;
}

static hal_error_t ks_fetch(hal_ks_t *ks,
                            hal_pkey_slot_t *slot,
                            uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  const hal_ks_key_t * const k = find(&slot->name);

  if (k == NULL)
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

    if ((err = hal_mkm_get_kek(kek, &kek_len, sizeof(kek))) == LIBHAL_OK)
      err = hal_aes_keyunwrap(NULL, kek, kek_len, k->der, k->der_len, der, der_len);

    memset(kek, 0, sizeof(kek));

    if (err != LIBHAL_OK)
      return err;
  }

  return LIBHAL_OK;
}

static hal_error_t ks_list(hal_ks_t *ks,
                           hal_pkey_info_t *result,
                           unsigned *result_len,
                           const unsigned result_max)
{
  if (ks != &db.ks || result == NULL || result_len == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  *result_len = 0;

  for (int i = 0; i < sizeof(db.keys)/sizeof(*db.keys); i++) {

    if (!db.keys[i].in_use)
      continue;

    if (*result_len == result_max)
      return HAL_ERROR_RESULT_TOO_LONG;

    result[*result_len].type  = db.keys[i].type;
    result[*result_len].curve = db.keys[i].curve;
    result[*result_len].flags = db.keys[i].flags;
    result[*result_len].name  = db.keys[i].name;
    ++ *result_len;
  }

  return LIBHAL_OK;
}

/*
 * This function in particular really needs to be rewritten to take
 * advantage of the new keystore API.
 */

static hal_error_t ks_store(hal_ks_t *ks,
                            const hal_pkey_slot_t * const slot,
                            const uint8_t * const der, const size_t der_len)
{
  if (ks != &db.ks || slot == NULL || der == NULL || der_len == 0 || !acceptable_key_type(slot->type))
    return HAL_ERROR_BAD_ARGUMENTS;

  if (find(&slot->name) != NULL)
    return HAL_ERROR_KEY_NAME_IN_USE;

  int loc = -1;

  for (int i = 0; i < sizeof(db.keys)/sizeof(*db.keys); i++)
    if (!db.keys[i].in_use && loc < 0)
      loc = i;

  if (loc < 0)
    return HAL_ERROR_NO_KEY_SLOTS_AVAILABLE;

  hal_ks_key_t k;
  memset(&k, 0, sizeof(k));
  k.der_len = sizeof(k.der);

  uint8_t kek[KEK_LENGTH];
  size_t kek_len;

  hal_error_t err;

  if ((err = hal_mkm_get_kek(kek, &kek_len, sizeof(kek))) == LIBHAL_OK)
    err = hal_aes_keywrap(NULL, kek, kek_len, der, der_len, k.der, &k.der_len);

  memset(kek, 0, sizeof(kek));

  if (err != LIBHAL_OK)
    return err;

  k.name  = slot->name;
  k.type  = slot->type;
  k.curve = slot->curve;
  k.flags = slot->flags;

  uint8_t page_buf[KEYSTORE_PAGE_SIZE];

  uint32_t offset = _get_key_offset(loc);

  if (offset > KEYSTORE_SECTOR_SIZE)
    return HAL_ERROR_BAD_ARGUMENTS;

  uint32_t active_sector_offset = _active_sector_offset();

  offset += active_sector_offset;

  if (keystore_check_id() != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  /*
   * Check if there is a key occupying this slot in the flash already.
   * This includes the case where we've zeroed a former key without
   * erasing the flash sector, so we have to check the flash itself,
   * we can't just look at the in-memory representation.
   */

  if (keystore_read_data(offset, page_buf, sizeof(page_buf)) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  const int unused_since_erasure = ((hal_ks_key_t *) page_buf)->in_use == 0xFF;

  db.keys[loc] = k;
  db.keys[loc].in_use = 1;

  if (unused_since_erasure) {

    /*
     * Key slot was unused in flash, so we can just write the new key there.
     */

    if ((err = _write_data_to_flash(offset, (uint8_t *) &k, sizeof(k))) != LIBHAL_OK)
      return err;

  } else {

    /*
     * Key slot in flash has been used.  We should be more clever than
     * this, but for now we just rewrite the whole freaking keystore.
     */

    /* TODO: Erase and write the database to the inactive sector, and then toggle active sector. */

    if (keystore_erase_sectors(active_sector_offset / KEYSTORE_SECTOR_SIZE,
                               active_sector_offset / KEYSTORE_SECTOR_SIZE) != 1)
      return HAL_ERROR_KEYSTORE_ACCESS;

    if ((err =_write_db_to_flash(active_sector_offset)) != LIBHAL_OK)
      return err;
  }

  return LIBHAL_OK;
}

static hal_error_t ks_delete(hal_ks_t *ks,
                             const hal_pkey_slot_t * const slot)
{
  if (ks != &db.ks || slot == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_ks_key_t *k = find(&slot->name);

  if (k == NULL)
    return HAL_ERROR_KEY_NOT_FOUND;

  const int loc = k - db.keys;
  uint32_t offset = _get_key_offset(loc);

  if (loc < 0 || offset > KEYSTORE_SECTOR_SIZE)
    return HAL_ERROR_IMPOSSIBLE;

  offset += _active_sector_offset();

  memset(k, 0, sizeof(*k));

  /*
   * Setting bits to 0 never requires erasing flash. Just write it.
   */

  return _write_data_to_flash(offset, (uint8_t *) k, sizeof(*k));
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

  /*
   * If we were looking for the WHEEL PIN and it appears to be
   * completely unset, return the compiled-in last-gasp PIN.  This is
   * a terrible answer, but we need some kind of bootstrapping
   * mechanism.  Feel free to suggest something better.
   */

  uint8_t u00 = 0x00, uFF = 0xFF;
  for (int i = 0; i < sizeof((*pin)->pin); i++) {
    u00 |= (*pin)->pin[i];
    uFF &= (*pin)->pin[i];
  }
  for (int i = 0; i < sizeof((*pin)->salt); i++) {
    u00 |= (*pin)->salt[i];
    uFF &= (*pin)->salt[i];
  }
  if (user == HAL_USER_WHEEL && ((u00 == 0x00 && (*pin)->iterations == 0x00000000) ||
                                 (uFF == 0xFF && (*pin)->iterations == 0xFFFFFFFF)))
    *pin = &hal_last_gasp_pin;

  return LIBHAL_OK;
}

hal_error_t hal_set_pin(const hal_user_t user,
                        const hal_ks_pin_t * const pin)
{
  uint32_t active_sector_offset;

  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_ks_pin_t *p = NULL;

  switch (user) {
  case HAL_USER_WHEEL:  p = &db.wheel_pin;  break;
  case HAL_USER_SO:     p = &db.so_pin;     break;
  case HAL_USER_NORMAL: p = &db.user_pin;   break;
  default:              return HAL_ERROR_BAD_ARGUMENTS;
  }

  memcpy(p, pin, sizeof(*p));

  active_sector_offset = _active_sector_offset();

  /* TODO: Could check if the PIN is currently all 0xff, in which case we wouldn't have to
   * erase and re-write the whole DB.
   */

  /* TODO: Erase and write the database to the inactive sector, and then toggle active sector. */
  if (keystore_erase_sectors(active_sector_offset / KEYSTORE_SECTOR_SIZE,
                             active_sector_offset / KEYSTORE_SECTOR_SIZE) != 1)
    return HAL_ERROR_KEYSTORE_ACCESS;

  return _write_db_to_flash(active_sector_offset);
}

#warning MKM flash kludge support needed here
/*
 * Need functions to handle lower level stuff we want
 * hal_mkm_flash_read() and hal_mkm_flash_write() to call, since we're
 * stuffing that data into the PIN block.
 */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
