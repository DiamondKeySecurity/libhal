/*
 * hal_io_fmc.c
 * ------------
 * This module contains common code to talk to the FPGA over the FMC bus.
 *
 * Author: Paul Selkirk
 * Copyright (c) 2014-2016, NORDUnet A/S All rights reserved.
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

#include <stdio.h>
#include <stdint.h>

#include "stm-fmc.h"

/* stm32f4xx_hal_def.h and hal.h both define HAL_OK as an enum value */
#define HAL_OK HAL_OKAY

#include "hal.h"
#include "hal_internal.h"

/*
 * Even no-op debugging code shows up in profiling if it's in an inner
 * loop which runs often enough, so we leave now this off by default
 * at compile time.
 */
#ifndef HAL_IO_FMC_DEBUG
#define HAL_IO_FMC_DEBUG        0
#endif

static int inited = 0;

#if HAL_IO_FMC_DEBUG

static int debug = 0;

void hal_io_set_debug(int onoff)
{
  debug = onoff;
}

static inline void dump(const char *label, const hal_addr_t offset, const uint8_t * const buf, const size_t len)
{
  if (debug) {
    char hex[len * 3 + 1];
    for (size_t i = 0; i < len; ++i)
      sprintf(hex + 3 * i, " %02x", buf[i]);
    hal_log(HAL_LOG_DEBUG, "%s %04x [%s ]", label, (unsigned int) offset, hex);
  }
}

#else

#define dump(...)

#endif

/*
 * Translate cryptech register number to FMC address.
 */
static inline hal_addr_t fmc_offset(hal_addr_t offset)
{
  return offset << 2;
}

/*
 * Minimal version of memcpy, where we know the addresses and length are
 * word-aligned.
 */
static inline void fmc_fpga_memcpy(uint32_t *dst, uint32_t *src, size_t nword)
{
    while (nword >= 4) {
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        nword -= 4;
    }
    while (nword > 0) {
        *dst++ = *src++;
        nword--;
    }
}

hal_error_t hal_io_write(const hal_core_t *core, hal_addr_t offset, const uint8_t *buf, size_t len)
{
  if (core == NULL)
    return HAL_ERROR_CORE_NOT_FOUND;

  if (len % 4 != 0)
    return HAL_ERROR_IO_BAD_COUNT;

  if (!inited) {
    fmc_init();
    inited = 1;
  }

  dump("write ", offset + hal_core_base(core), buf, len);

  offset = fmc_offset(offset + hal_core_base(core));
  fmc_fpga_memcpy((uint32_t *)fmc_fpga_addr(offset), (uint32_t *)buf, len/4);

  return HAL_OK;
}

hal_error_t hal_io_read(const hal_core_t *core, hal_addr_t offset, uint8_t *buf, size_t len)
{
  if (core == NULL)
    return HAL_ERROR_CORE_NOT_FOUND;

  if (len % 4 != 0)
    return HAL_ERROR_IO_BAD_COUNT;

  if (!inited) {
    fmc_init();
    inited = 1;
  }

  dump("read  ", offset + hal_core_base(core), buf, len);

  offset = fmc_offset(offset + hal_core_base(core));
  fmc_fpga_memcpy((uint32_t *)buf, (uint32_t *)fmc_fpga_addr(offset), len/4);

  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 2
 * End:
 */
