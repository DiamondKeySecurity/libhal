/*
 * ks_mmap.c
 * ---------
 * Keystore implementation over POSIX mmap().
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

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>

#include "hal.h"
#include "hal_internal.h"

#ifndef HAL_KS_MMAP_FILE
#define HAL_KS_MMAP_FILE ".cryptech_hal_keystore"
#endif

#ifndef MAP_FILE
#define MAP_FILE 0
#endif

/*
 * Storing the KEK in with the keys it's protecting is a bad idea, but we have no better
 * place to put it (real protection requires dedicated hardware, which we don't have here).
 */

#define KEKBUF_LEN (bitsToBytes(256))

static hal_ks_keydb_t *db;
static uint8_t *kekbuf;

const hal_ks_keydb_t *hal_ks_get_keydb(void)
{
  if (db != NULL)
    return db;

  const char * const env  = getenv("CRYPTECH_KEYSTORE");
  const char * const home = getenv("HOME");
  const char * const base = HAL_KS_MMAP_FILE;
  const long pagemask = sysconf(_SC_PAGESIZE) - 1;
  const size_t len = (sizeof(hal_ks_keydb_t) + KEKBUF_LEN + pagemask) & ~pagemask;

  char fn_[strlen(base) + (home == NULL ? 0 : strlen(home)) + 2];
  const char *fn = fn_;
  int fd;

  if (pagemask < 0)
    return NULL;

  if (env != NULL)
    fn = env;
  else if (home == NULL)
    fn = base;
  else
    strcat(strcat(strcpy(fn_, home), "/"), base);

  if ((fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600)) >= 0) {
    uint8_t zeros[len];
    memset(zeros, 0, sizeof(zeros));
    (void) write(fd, zeros, sizeof(zeros));
  }
  else if (errno == EEXIST) {
    fd = open(fn, O_RDWR | O_CREAT, 0600);
  }

  if (fd >= 0 && (db = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0)) != NULL)
    kekbuf = (uint8_t *) (db + 1);

  (void) close(fd);

  return db;
}

hal_error_t hal_ks_set_keydb(const hal_ks_key_t * const key,
                             const int loc,
                             const int updating)
{
  if (key == NULL || loc < 0 || loc >= sizeof(db->keys)/sizeof(*db->keys) || (!key->in_use != !updating))
    return HAL_ERROR_BAD_ARGUMENTS;

  db->keys[loc] = *key;
  db->keys[loc].in_use = 1;
  return HAL_OK;
}

hal_error_t hal_ks_del_keydb(const int loc)
{
  if (loc < 0 || loc >= sizeof(db->keys)/sizeof(*db->keys))
    return HAL_ERROR_BAD_ARGUMENTS;

  db->keys[loc].in_use = 0;
  memset(&db->keys[loc], 0, sizeof(db->keys[loc]));
  return HAL_OK;
}

hal_error_t hal_set_pin(const hal_user_t user,
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

hal_error_t hal_mkm_get_kek(uint8_t *kek,
                           size_t *kek_len,
                           const size_t kek_max)
{
  if (kek == NULL || kek_len == NULL || kek_max < bitsToBytes(128))
    return HAL_ERROR_BAD_ARGUMENTS;

  if (kekbuf == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  hal_error_t err;

  const size_t len = ((kek_max < bitsToBytes(192)) ? bitsToBytes(128) :
                      (kek_max < bitsToBytes(256)) ? bitsToBytes(192) :
                      bitsToBytes(256));

  uint8_t t = 0;

  for (int i = 0; i < KEKBUF_LEN; i++)
    t |= kekbuf[i];

  if (t == 0 && (err = hal_rpc_get_random(kekbuf, sizeof(KEKBUF_LEN))) != HAL_OK)
    return err;

  memcpy(kek, kekbuf, len);
  *kek_len = len;
  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
