/*
 * ks_volatile.c
 * -------------
 * Keystore implementation in normal volatile internal memory.
 *
 * NB: This is only suitable for cases where you do not want the keystore
 *     to survive library exit, eg, for storing PKCS #11 session keys.
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

#include <string.h>

#include "hal.h"
#include "hal_internal.h"

/*
 * Splitting the different keystore backends out into separate files
 * seemed like a good idea at the time, but the code is getting
 * somewhat repetitive.  Might want to re-merge and conditionalize in
 * some other way.  Deferred until we sort out ks_flash.c.
 */

/*
 * Use a one-element array here so that references can be pointer-based
 * as in the other implementations, to ease re-merge at some later date.
 */

static hal_ks_keydb_t db[1];

const hal_ks_keydb_t *hal_ks_get_keydb(void)
{
  return db;
}

hal_error_t hal_ks_set_keydb(const hal_ks_key_t * const key,
                             const int loc)
{
  if (key == NULL || loc < 0 || loc >= sizeof(db->keys)/sizeof(*db->keys) || key->in_use)
    return HAL_ERROR_BAD_ARGUMENTS;

  db->keys[loc] = *key;
  db->keys[loc].in_use = 1;
  return HAL_OK;
}

hal_error_t hal_ks_del_keydb(const int loc)
{
  if (loc < 0 || loc >= sizeof(db->keys)/sizeof(*db->keys))
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(&db->keys[loc], 0, sizeof(db->keys[loc]));
  return HAL_OK;
}

hal_error_t hal_ks_set_pin(const hal_user_t user,
                           const hal_ks_pin_t * const pin)
{
  if (pin == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_ks_pin_t *p = NULL;

  switch (user) {
  case HAL_USER_WHEEL:  p = &db->wheel_pin;  break;
  case HAL_USER_SO:	p = &db->so_pin;     break;
  case HAL_USER_NORMAL:	p = &db->user_pin;   break;
  default:		return HAL_ERROR_BAD_ARGUMENTS;
  }

  *p = *pin;
  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
