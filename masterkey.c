/*
 * masterkey.c
 * -----------
 * Masterkey set/get functions.
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

#define HAL_OK CMIS_HAL_OK
#include "stm-init.h"
#include "stm-keystore.h"
#undef HAL_OK

#define HAL_OK LIBHAL_OK
#include "hal.h"
#include "masterkey.h"
#undef HAL_OK

#include <string.h>


static int volatile_init = 0, flash_init = 0;
static const hal_core_t *core = NULL;

#define MKM_VOLATILE_STATUS_ADDRESS	0
#define SCLK_DIV			0x20
#define MKM_FLASH_STATUS_ADDRESS	(KEYSTORE_SECTOR_SIZE * (KEYSTORE_NUM_SECTORS - 1))
#define MKM_FLASH_STATUS_IN_USE		0x0000ffff
#define KEK_LENGTH (256 / 8)


hal_error_t masterkey_volatile_init()
{
    hal_error_t err;
    uint32_t status;

    if (! volatile_init) {
	if ((core = hal_core_find(MKMIF_NAME, NULL)) == NULL) {
	    return HAL_ERROR_CORE_NOT_FOUND;
	}

	err =
	    hal_mkmif_set_clockspeed(core, SCLK_DIV) ||
	    hal_mkmif_init(core) ||
	    hal_mkmif_read_word(core, MKM_VOLATILE_STATUS_ADDRESS, &status);

	if (err != LIBHAL_OK) return err;

	if (status != HSM_MASTERKEY_SET &&
	    status != HSM_MASTERKEY_NOT_SET) {
	    if ((err = hal_mkmif_write_word(core, MKM_VOLATILE_STATUS_ADDRESS, HSM_MASTERKEY_NOT_SET)) != LIBHAL_OK) {
		return err;
	    }
	}

	volatile_init = 1;
    }
    return LIBHAL_OK;
}

masterkey_status_t masterkey_volatile_read(uint8_t *buf, size_t len)
{
    hal_error_t err;
    uint32_t status;

    err =
	masterkey_volatile_init() ||
	hal_mkmif_read_word(core, MKM_VOLATILE_STATUS_ADDRESS, &status);

    if (err != LIBHAL_OK) return HSM_MASTERKEY_FAIL;

    if (buf != NULL && status == HSM_MASTERKEY_SET) {
	if ((err = hal_mkmif_read(core, MKM_VOLATILE_STATUS_ADDRESS + 4, buf, len)) == LIBHAL_OK) {
	    return HSM_MASTERKEY_SET;
	}
    }

    if (status == HSM_MASTERKEY_SET || status == HSM_MASTERKEY_NOT_SET) {
	return (masterkey_status_t) status;
    }

    return HSM_MASTERKEY_FAIL;
}

masterkey_status_t masterkey_volatile_write(uint8_t *buf, size_t len)
{
    hal_error_t err;

    if (len != KEK_LENGTH) return HSM_MASTERKEY_FAIL;
    if (! buf) return HSM_MASTERKEY_FAIL;

    err =
	masterkey_volatile_init() ||
	hal_mkmif_write(core, MKM_VOLATILE_STATUS_ADDRESS + 4, buf, len) ||
	hal_mkmif_write_word(core, MKM_VOLATILE_STATUS_ADDRESS, HSM_MASTERKEY_SET);

    if (err != LIBHAL_OK) return HSM_MASTERKEY_FAIL;

    return HSM_MASTERKEY_OK;
}

masterkey_status_t masterkey_volatile_erase(size_t len)
{
    uint8_t buf[KEK_LENGTH] = {0};
    hal_error_t err;

    if (len != KEK_LENGTH) return HSM_MASTERKEY_FAIL;

    err =
	masterkey_volatile_init() ||
	hal_mkmif_write(core, MKM_VOLATILE_STATUS_ADDRESS + 4, buf, sizeof(buf)) ||
	hal_mkmif_write_word(core, MKM_VOLATILE_STATUS_ADDRESS, HSM_MASTERKEY_NOT_SET);

    if (err != LIBHAL_OK) return HSM_MASTERKEY_FAIL;

    return HSM_MASTERKEY_OK;
}

/* Storing the master key in flash is a pretty Bad Idea, but since the Alpha board
 * doesn't have a battery mounted (only pin headers for attaching one), it might
 * help in non-production use where one doesn't have tamper protection anyways.
 *
 * For production use on the Alpha, one option is to have the Master Key on paper
 * and enter it into volatile RAM after each power on.
 */
hal_error_t masterkey_flash_init()
{
    if (! flash_init) {
	if (! keystore_check_id()) return HAL_ERROR_IO_UNEXPECTED;
	flash_init = 1;
    }
    return LIBHAL_OK;
}

masterkey_status_t masterkey_flash_read(uint8_t *buf, size_t len)
{
    uint8_t page[KEYSTORE_PAGE_SIZE];
    uint32_t *status = (uint32_t *) page;

    if (len > sizeof(page) - 4) return HSM_MASTERKEY_FAIL;

    if (masterkey_flash_init() != LIBHAL_OK) return HSM_MASTERKEY_FAIL;

    if (! keystore_read_data(MKM_FLASH_STATUS_ADDRESS, page, sizeof(page))) {
	memset(page, 0, sizeof(page));
	return HSM_MASTERKEY_FAIL;
    }

    if (buf != NULL && len) memcpy(buf, page + 4, len);

    memset(page + 4, 0, sizeof(page) - 4);

    if (*status == MKM_FLASH_STATUS_IN_USE) return HSM_MASTERKEY_SET;
    if (*status == 0x0 || *status == 0xffffffff) return HSM_MASTERKEY_NOT_SET;

    return HSM_MASTERKEY_FAIL;
}

masterkey_status_t masterkey_flash_write(uint8_t *buf, size_t len)
{
    uint8_t page[KEYSTORE_PAGE_SIZE] = {0xff};
    uint32_t *status = (uint32_t *) page;
    int res;

    if (len > sizeof(page) - 4) return HSM_MASTERKEY_FAIL;
    if (buf == NULL) return HSM_MASTERKEY_FAIL;

    if (masterkey_flash_init() != LIBHAL_OK) return HSM_MASTERKEY_FAIL;

    *status = MKM_FLASH_STATUS_IN_USE;
    memcpy(page + 4, buf, len);

    res = keystore_write_data(MKM_FLASH_STATUS_ADDRESS, page, sizeof(page));
    memset(page, 0, sizeof(page));
    if (res != 1) {
	return HSM_MASTERKEY_FAIL;
    }

    return HSM_MASTERKEY_OK;
}

masterkey_status_t masterkey_flash_erase(size_t len)
{
    if (len > KEYSTORE_PAGE_SIZE - 4) return HSM_MASTERKEY_FAIL;

    if (keystore_erase_sectors(MKM_FLASH_STATUS_ADDRESS / KEYSTORE_SECTOR_SIZE,
			       MKM_FLASH_STATUS_ADDRESS / KEYSTORE_SECTOR_SIZE) != 1) {
	return HSM_MASTERKEY_FAIL;
    }

    return HSM_MASTERKEY_OK;
}
