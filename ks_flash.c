/*
 * ks_flash.c
 * ----------
 * Keystore implementation in flash memory.
 *
 * Authors: Rob Austein
 * Copyright (c) 2015, NORDUnet A/S All rights reserved.
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

static hal_ks_keydb_t *db;

const hal_ks_keydb_t *hal_ks_get_keydb(void)
{

#error Not sure what goes here yet

}

hal_error_t hal_ks_set_keydb(const hal_ks_key_t * const key,
                             const int loc)
{
  if (key == NULL || loc < 0 || loc >= sizeof(db.keys)/sizeof(*db.keys) || key->in_use)
    return HAL_ERROR_BAD_ARGUMENTS;

#error Not sure what goes here yet either

}

hal_error_t hal_ks_del_keydb(const int loc)
{
  if (loc < 0 || loc >= sizeof(db.keys)/sizeof(*db.keys))
    return HAL_ERROR_BAD_ARGUMENTS;

#error Or what goes here

}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
