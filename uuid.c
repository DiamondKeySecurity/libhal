/*
 * uuid.c
 * ------
 * UUID support for keystore database.
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

#include <assert.h>

#include "hal.h"
#include "hal_internal.h"

hal_error_t hal_uuid_gen(hal_uuid_t *uuid)
{
  hal_error_t err;

  if (uuid == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * Generate a version 4 UUID as specified in RFC 4122.
   * This is basically a 122-bit random number.
   */

  if ((err = hal_rpc_get_random(uuid->uuid, sizeof(uuid->uuid))) != HAL_OK)
    return err;

  /*
   * Set high order bits of clock_seq_hi_and_reserved and
   * time_hi_and_version fields to magic values as specified by RFC
   * 4122 section 4.4.
   *
   * Not recommended reading if you've eaten recently.
   */

  uuid->uuid[6] &= 0x0f;
  uuid->uuid[6] |= 0x40;
  uuid->uuid[8] &= 0x3f;
  uuid->uuid[8] |= 0x80;

  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
