/*
 * modexp.c
 * ----------
 * Wrapper around Cryptech ModExp core.
 *
 * This doesn't do full RSA, that's another module.  This module's job
 * is just the I/O to get bits in and out of the ModExp core, including
 * compensating for a few known bugs that haven't been resolved yet.
 *
 * If at some point the interface to the ModExp core becomes simple
 * enough that this module is no longer needed, it will go away.
 *
 * Authors: Rob Austein
 * Copyright (c) 2015, SUNET
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cryptech.h"

/*
 * Whether we want debug output.
 */

static int debug = 0;

void hal_modexp_set_debug(const int onoff)
{
  debug = onoff;
}

/*
 * Check a result, report on failure if debugging, pass failures up
 * the chain.
 */

#define check(_expr_)                                                   \
  do {                                                                  \
    hal_error_t _err = (_expr_);                                        \
    if (_err != HAL_OK && debug)                                        \
      printf("%s failed: %s\n", #_expr_, hal_error_string(_err));       \
    if (_err != HAL_OK)                                                 \
      return _err;                                                      \
  } while (0)

/*
 * Set an ordinary register.
 */

static hal_error_t set_register(const off_t addr,
                                uint32_t value)
{
  uint8_t w[4];
  int i;

  for (i = 3; i >= 0; i--) {
    w[i] = value & 0xFF;
    value >>= 8;
  }

  return hal_io_write(addr, w, sizeof(w));
}

/*
 * Get value of a block memory.
 */

static hal_error_t get_blockmem(const off_t reset_addr,
                                const off_t data_addr,
                                uint8_t *value,
                                const size_t length,
                                const size_t io_len)
{
  uint8_t discard[4];
  size_t i;

  assert(value != NULL && length % 4 == 0);

  assert(io_len >= length && io_len % 4 == 0);

  check(set_register(reset_addr, 1));

  for (i = 0; i < io_len - length; i += 4) {
    check(hal_io_read(data_addr, discard, 4));
    if (discard[0] != 0 || discard[1] != 0 || discard[2] != 0 || discard[3] != 0)
      return HAL_ERROR_IO_UNEXPECTED;
  }

  for (i = 0; i < length; i += 4)
    check(hal_io_read(data_addr, &value[i], 4));

  return HAL_OK;
}

/*
 * Set value of a block memory.
 */

static hal_error_t set_blockmem(const off_t reset_addr,
                                const off_t data_addr,
                                const uint8_t * const value,
                                const size_t length,
                                const size_t io_len)
{
  const uint8_t zero[4] = { 0, 0, 0, 0 };
  size_t i;

  assert(value != NULL && length % 4 == 0);

  assert(io_len >= length && io_len % 4 == 0);

  check(set_register(reset_addr, 1));

  for (i = 0; i < io_len - length; i += 4)
    check(hal_io_write(data_addr, zero, 4));

  for (i = 0; i < length; i += 4)
    check(hal_io_write(data_addr, &value[i], 4));

  return HAL_OK;
}

/*
 * Run one modexp operation.
 */

hal_error_t hal_modexp(const uint8_t * const msg, const size_t msg_len, /* Message */
                       const uint8_t * const exp, const size_t exp_len, /* Exponent */
                       const uint8_t * const mod, const size_t mod_len, /* Modulus */
                       uint8_t *result, const size_t result_len)
{
  /*
   * All pointers must be set, neither message nor exponent may be
   * longer than modulus, result buffer must not be shorter than
   * modulus, and all input lengths must be a multiple of four.
   *
   * The multiple-of-four restriction is a pain, but the rest of the
   * HAL code currently enforces the same restriction, and allowing
   * arbitrary lengths would require some tedious shuffling to deal
   * with alignment issues, so it's not worth trying to fix only here.
   */

  if (msg == NULL || exp == NULL || mod == NULL || result == NULL ||
      msg_len > mod_len || exp_len > mod_len || result_len < mod_len ||
      ((msg_len | exp_len | mod_len) & 3) != 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * This insanity is a work-around for a current bug in the ModExp
   * core: we have to zero-pad everything out to the size of the
   * modulus plus 32-bits.  Some kind of overflow issue.  All of this
   * "io_len" nonsense can go away once that's fixed.
   */

  const size_t io_len = mod_len + 4;
  assert((io_len & 3) == 0);

  check(set_blockmem(MODEXP_MODULUS_PTR_RST, MODEXP_MODULUS_DATA, mod, mod_len, io_len));
  check(set_blockmem(MODEXP_MESSAGE_PTR_RST, MODEXP_MESSAGE_DATA, msg, msg_len, io_len));
  check(set_register(MODEXP_MODULUS_LENGTH, /* mod_len */ io_len / 4));

  check(set_blockmem(MODEXP_EXPONENT_PTR_RST, MODEXP_EXPONENT_DATA, exp, exp_len, io_len));
  check(set_register(MODEXP_EXPONENT_LENGTH, /* exp_len */ io_len / 4));

  check(hal_io_wait_ready(MODEXP_ADDR_STATUS));

  check(set_register(MODEXP_ADDR_CTRL, 1));

  /*
   * ModExp core is not very fast (yet), so wait a long time for a
   * response, but not forever.
   */

  int timeout = 0x7FFFFFFF;
  check(hal_io_wait(MODEXP_ADDR_STATUS, STATUS_READY, &timeout));

  check(get_blockmem(MODEXP_RESULT_PTR_RST, MODEXP_RESULT_DATA, result, mod_len, io_len));

  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
