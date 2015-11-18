/*
 * csprng.c
 * --------
 * HAL interface to Cryptech CSPRNG.
 *
 * Authors: Joachim Strömbergson, Paul Selkirk, Rob Austein
 * Copyright (c) 2014-2015, SUNET
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>

#include "hal.h"
#include "verilog_constants.h"

#ifndef WAIT_FOR_CSPRNG_VALID
#define WAIT_FOR_CSPRNG_VALID   1
#endif

hal_error_t hal_get_random(const hal_core_t *core, void *buffer, const size_t length)
{
  uint8_t temp[4], *buf = buffer;
  hal_error_t err;
  size_t i;

  if ((err = hal_core_check_name(&core, CSPRNG_NAME)) != HAL_OK)
    return err;

  for (i = 0; i < length; i += 4) {
    const int last = (length - i) < 4;

    if (WAIT_FOR_CSPRNG_VALID && (err = hal_io_wait_valid(core)) != HAL_OK)
      return err;

    if ((err = hal_io_read(core, CSPRNG_ADDR_RANDOM, (last ? temp : &buf[i]), 4)) != HAL_OK)
      return err;

    if (last)
      for (; i < length; i++)
        buf[i] = temp[i&3];
  }

  for (i = 0, buf = buffer; i < length; i++, buf++)
    if (*buf != 0)
      return HAL_OK;

  return HAL_ERROR_CSPRNG_BROKEN;
}

/*
 * "Any programmer who fails to comply with the standard naming, formatting,
 *  or commenting conventions should be shot.  If it so happens that it is
 *  inconvenient to shoot him, then he is to be politely requested to recode
 *  his program in adherence to the above standard."
 *                      -- Michael Spier, Digital Equipment Corporation
 *
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
