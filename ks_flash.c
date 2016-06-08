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

#include "hal.h"
#include "hal_internal.h"

#include <string.h>

#define _SAVE_OUR_HAL_OK	HAL_OK
#undef HAL_OK

#warning Unmaintainable workaround for two different HAL_OKs used here
/* Don't #include "stm-keystore.h" to avoid conflicting definitions of HAL_OK
 * as well as circular dependencies I guess.
 */
#define N25Q128_PAGE_SIZE		0x100		// 256
#define N25Q128_SECTOR_SIZE		0x10000		// 65536
#define N25Q128_NUM_SECTORS		0x100		// 256
#define KEYSTORE_PAGE_SIZE		   N25Q128_PAGE_SIZE
#define KEYSTORE_SECTOR_SIZE		   N25Q128_SECTOR_SIZE
#define KEYSTORE_NUM_SECTORS		   N25Q128_NUM_SECTORS
extern int keystore_check_id(void);
extern int keystore_read_data(uint32_t offset, uint8_t *buf, const uint32_t len);
extern int keystore_write_data(uint32_t offset, const uint8_t *buf, const uint32_t len);
extern int keystore_erase_sectors(uint32_t start, uint32_t stop);

#define PAGE_SIZE_MASK			(KEYSTORE_PAGE_SIZE - 1)

/*
 * Use a one-element array here so that references can be pointer-based
 * as in the other implementations, to ease re-merge at some later date.
 */

static hal_ks_keydb_t db[1];
volatile uint32_t num_keys = 0;

/* Offsets where we found the entrys */


#define FLASH_SECTOR_1_OFFSET	(0 * KEYSTORE_SECTOR_SIZE)
#define FLASH_SECTOR_2_OFFSET	(1 * KEYSTORE_SECTOR_SIZE)

uint32_t _active_sector_offset()
{
    /* XXX Load status bytes from both sectors and decide which is current. */
    #warning Have not implemented two flash sectors yet
    return FLASH_SECTOR_1_OFFSET;
}

uint32_t _get_key_offset(uint32_t num, size_t elem_size)
{
    /* Reserve first two pages for flash sector state, PINs and future additions.
     * The three PINs alone currently occupy 3 * (64 + 16 + 4) bytes (252).
     */
    uint32_t offset = KEYSTORE_PAGE_SIZE * 2;
    uint32_t bytes_per_elem = KEYSTORE_PAGE_SIZE * ((elem_size / KEYSTORE_PAGE_SIZE) + 1);
    offset += num * bytes_per_elem;
    return offset;
}

const hal_ks_keydb_t *hal_ks_get_keydb(void)
{
    uint32_t offset, i, idx = 0, active_sector_offset;
    hal_ks_key_t *key;
    uint8_t page_buf[KEYSTORE_PAGE_SIZE];

    if (keystore_check_id() != 1) return NULL;

    active_sector_offset = _active_sector_offset();

    /* The PINs are in the second page of the sector. */
    offset = active_sector_offset + KEYSTORE_PAGE_SIZE;
    if (keystore_read_data(offset, page_buf, sizeof(page_buf)) != 1) return NULL;
    offset = 0;
    memcpy(&db->wheel_pin, page_buf + offset, sizeof(db->wheel_pin));
    offset += sizeof(db->wheel_pin);
    memcpy(&db->so_pin, page_buf + offset, sizeof(db->so_pin));
    offset += sizeof(db->so_pin);
    memcpy(&db->user_pin, page_buf + offset, sizeof(db->user_pin));

    for (i = 0; i < sizeof(db->keys) / sizeof(*db->keys); i++) {
        offset = _get_key_offset(i, sizeof(*key));
        if (offset > KEYSTORE_SECTOR_SIZE) {
            memset(&db->keys[idx], 0, sizeof(*db->keys));
            db->keys[idx].ks_internal = offset;
            idx++;
            continue;
        }

        offset += active_sector_offset;

        if (keystore_read_data(offset, page_buf, sizeof(page_buf)) != 1) return NULL;

        key = (hal_ks_key_t *) page_buf;
        if (key->in_use == 0xff) {
            /* unprogrammed data */
            memset(&db->keys[idx], 0, sizeof(*db->keys));
            db->keys[idx].ks_internal = offset;
            idx++;
            continue;
        }

        if (key->in_use == 1) {
            key = &db->keys[idx++];
            uint8_t *dst = (uint8_t *) key;
            uint32_t to_read = sizeof(*key);

            /* Put first page into place */
            memcpy(dst, page_buf, sizeof(page_buf));
            to_read -= KEYSTORE_PAGE_SIZE;
            dst += sizeof(page_buf);

            /* Read as many more full pages as possible */
            if (keystore_read_data (offset + KEYSTORE_PAGE_SIZE, dst, to_read & ~PAGE_SIZE_MASK) != 1) return NULL;
            dst += to_read & ~PAGE_SIZE_MASK;
            to_read &= PAGE_SIZE_MASK;

            if (to_read) {
                /* Partial last sector. We can only read full sectors so load it into page_buf. */
                if (keystore_read_data(offset + sizeof(*key) - to_read, page_buf, sizeof(page_buf)) != 1) return NULL;
                memcpy(dst, page_buf, to_read);
            }
            key->ks_internal = offset;
        }
    }

    return db;
}

hal_error_t _write_data_to_flash(const uint32_t offset, const uint8_t *data, const size_t len)
{
    uint8_t page_buf[KEYSTORE_PAGE_SIZE];
    uint32_t to_write = len;

    if (keystore_write_data(offset, data, to_write & ~PAGE_SIZE_MASK) != 1) {
        return HAL_ERROR_KEYSTORE_ACCESS;
    }
    to_write &= PAGE_SIZE_MASK;
    if (to_write) {
        /* Use page_buf to write the remaining bytes, since we must write a full page each time. */
        memset(page_buf, 0xff, sizeof(page_buf));
        memcpy(page_buf, data + len - to_write, to_write);
        if (keystore_write_data((offset + len) & ~PAGE_SIZE_MASK, page_buf, sizeof(page_buf)) != 1) {
            return HAL_ERROR_KEYSTORE_ACCESS;
        }
    }

    return HAL_OK;
}

/*
 * Write the full DB to flash, PINs and all.
 */
hal_error_t _write_db_to_flash(const uint32_t sector_offset)
{
    hal_error_t status;
    uint8_t page_buf[KEYSTORE_PAGE_SIZE];
    uint32_t i, offset = sector_offset;

    if (sizeof(db->wheel_pin) + sizeof(db->so_pin) + sizeof(db->user_pin) > sizeof(page_buf)) {
        return HAL_ERROR_BAD_ARGUMENTS;
    }

    /* Write PINs into the second of the two reserved pages at the start of the sector. */
    offset += KEYSTORE_PAGE_SIZE;
    memcpy(page_buf + offset, &db->wheel_pin, sizeof(db->wheel_pin));
    offset += sizeof(db->wheel_pin);
    memcpy(page_buf + offset, &db->so_pin, sizeof(db->so_pin));
    offset += sizeof(db->so_pin);
    memcpy(page_buf + offset, &db->user_pin, sizeof(db->user_pin));

    if ((status = _write_data_to_flash(offset, page_buf, sizeof(page_buf))) != HAL_OK) {
        return status;
    }

    for (i = 0; i < sizeof(db->keys) / sizeof(*db->keys); i++) {
        offset = _get_key_offset(i, sizeof(*db->keys));
        if (offset > KEYSTORE_SECTOR_SIZE) {
            return HAL_ERROR_BAD_ARGUMENTS;
        }

        offset += sector_offset;

        if ((status =_write_data_to_flash(offset, (uint8_t *) &db->keys[i], sizeof(*db->keys))) != HAL_OK) {
            return status;
        }
    }

    return HAL_OK;
}

hal_error_t hal_ks_set_keydb(const hal_ks_key_t * const key,
                             const int loc,
                             const int updating)
{
    hal_error_t status;
    uint32_t offset, active_sector_offset;
    hal_ks_key_t *tmp_key;
    uint8_t page_buf[KEYSTORE_PAGE_SIZE];

    if (key == NULL || loc < 0 || loc >= sizeof(db->keys)/sizeof(*db->keys) || (!key->in_use != !updating))
        return HAL_ERROR_BAD_ARGUMENTS;

    offset = _get_key_offset(loc, sizeof(*key));
    if (offset > KEYSTORE_SECTOR_SIZE) return HAL_ERROR_BAD_ARGUMENTS;

    active_sector_offset = _active_sector_offset();

    offset += active_sector_offset;

    if (keystore_check_id() != 1) return HAL_ERROR_KEYSTORE_ACCESS;

    /* Check if there is a key occupying this slot in the flash already.
     * Don't trust the in-memory representation since it would mean data
     * corruption in flash if it had been altered.
     */
    if (keystore_read_data(offset, page_buf, sizeof(page_buf)) != 1) {
        return HAL_ERROR_KEYSTORE_ACCESS;
    }
    tmp_key = (hal_ks_key_t *) page_buf;

    if (tmp_key->in_use == 0xff) {
        /* Key slot was unused in flash. Write the new key there. */
        if ((status = _write_data_to_flash(offset, (uint8_t *) key, sizeof(*db->keys))) != HAL_OK) {
            return status;
        }
    } else {
        /* TODO: Erase and write the database to the inactive sector, and then toggle active sector. */
        if (keystore_erase_sectors(active_sector_offset / KEYSTORE_SECTOR_SIZE,
                                   active_sector_offset / KEYSTORE_SECTOR_SIZE) != 1) {
            return HAL_ERROR_KEYSTORE_ACCESS;
        }
        if ((status =_write_db_to_flash(active_sector_offset)) != HAL_OK) {
            return status;
        }
    }

    return HAL_OK;
}

hal_error_t hal_ks_del_keydb(const int loc)
{
    uint32_t offset;

  if (loc < 0 || loc >= sizeof(db->keys)/sizeof(*db->keys))
    return HAL_ERROR_BAD_ARGUMENTS;

  offset = _get_key_offset(loc, sizeof(*db->keys));
  if (offset > KEYSTORE_SECTOR_SIZE) {
      return HAL_ERROR_BAD_ARGUMENTS;
  }

  offset += _active_sector_offset();

  memset(&db->keys[loc], 0, sizeof(*db->keys));

  /* Setting bits to 0 never requires erasing flash. Just write it. */
  return _write_data_to_flash(offset, (uint8_t *) &db->keys[loc], sizeof(*db->keys));
}

hal_error_t hal_ks_set_pin(const hal_user_t user,
                           const hal_ks_pin_t * const pin)
{
  uint32_t active_sector_offset;

  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_ks_pin_t *p = NULL;

  switch (user) {
  case HAL_USER_WHEEL:  p = &db->wheel_pin;  break;
  case HAL_USER_SO:	p = &db->so_pin;     break;
  case HAL_USER_NORMAL:	p = &db->user_pin;   break;
  default:		return HAL_ERROR_BAD_ARGUMENTS;
  }

  memcpy(p, pin, sizeof(*p));

  active_sector_offset = _active_sector_offset();

  /* TODO: Could check if the PIN is currently all 0xff, in which case we wouldn't have to
   * erase and re-write the whole DB.
   */

  /* TODO: Erase and write the database to the inactive sector, and then toggle active sector. */
  if (keystore_erase_sectors(active_sector_offset / KEYSTORE_SECTOR_SIZE,
                             active_sector_offset / KEYSTORE_SECTOR_SIZE) != 1) {
      return HAL_ERROR_KEYSTORE_ACCESS;
  }
  return _write_db_to_flash(active_sector_offset);
}


hal_error_t hal_ks_get_kek(uint8_t *kek,
                           size_t *kek_len,
                           const size_t kek_max)
{
  if (kek == NULL || kek_len == NULL || kek_max < bitsToBytes(128))
    return HAL_ERROR_BAD_ARGUMENTS;

  const size_t len = ((kek_max < bitsToBytes(192)) ? bitsToBytes(128) :
                      (kek_max < bitsToBytes(256)) ? bitsToBytes(192) :
                      bitsToBytes(256));

  #warning Faking the Key Encryption Key
  memset(kek, 4, len);

  return HAL_OK;
}



/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
