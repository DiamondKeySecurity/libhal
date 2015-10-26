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
#include <assert.h>

#include "hal.h"

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
 * Get value of a data buffer.  We reverse the order of 32-bit words
 * in the buffer during the transfer to match what the modexps6 core
 * expects.
 */

static hal_error_t get_buffer(const off_t data_addr,
                              uint8_t *value,
                              const size_t length)
{
  size_t i;

  assert(value != NULL && length % 4 == 0);

  for (i = 0; i < length; i += 4)
    check(hal_io_read(data_addr + i/4, &value[length - 4 - i], 4));

  return HAL_OK;
}

/*
 * Set value of a data buffer.  We reverse the order of 32-bit words
 * in the buffer during the transfer to match what the modexps6 core
 * expects.
 */

static hal_error_t set_buffer(const off_t data_addr,
                              const uint8_t * const value,
                              const size_t length)
{
  size_t i;

  assert(value != NULL && length % 4 == 0);

  for (i = 0; i < length; i += 4)
    check(hal_io_write(data_addr + i/4, &value[length - 4 - i], 4));

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
   * We probably ought to take the mode (fast vs constant-time) as an
   * argument, but for the moment we just guess that really short
   * exponent means we're using the public key and can use fast mode,
   * all other cases are something to do with the private key and
   * therefore must use constant-time mode.
   *
   * Unclear whether it's worth trying to figure out exactly how long
   * the operands are: assuming a multiple of eight is safe, but makes
   * a bit more work for the core; checking to see how many bits are
   * really set leaves the core sitting idle while the main CPU does
   * these checks.  No way to know which is faster without testing;
   * take simple approach for the moment.
   */

  /* Select mode (1 = fast, 0 = safe) */
  check(set_register(MODEXPS6_ADDR_MODE, (exp_len <= 4)));

  /* Set modulus size in bits */
  check(set_register(MODEXPS6_ADDR_MODULUS_WIDTH, mod_len * 8));

  /* Write new modulus */
  check(set_buffer(MODEXPS6_ADDR_MODULUS, mod, mod_len));

  /* Pre-calcuate speed-up coefficient */
  check(hal_io_init(MODEXPS6_ADDR_CTRL));

  /* Wait for calculation to complete */
  check(hal_io_wait_ready(MODEXPS6_ADDR_STATUS));

  /* Write new message */
  check(set_buffer(MODEXPS6_ADDR_MESSAGE, msg, msg_len));

  /* Set new exponent length in bits */
  check(set_register(MODEXPS6_ADDR_EXPONENT_WIDTH, exp_len * 8));

  /* Set new exponent */
  check(set_buffer(MODEXPS6_ADDR_EXPONENT, exp, exp_len));

  /* Start calculation */
  check(hal_io_next(MODEXPS6_ADDR_CTRL));

  /* Wait for result */
  check(hal_io_wait_valid(MODEXPS6_ADDR_STATUS));

  /* Extract result */
  check(get_buffer(MODEXPS6_ADDR_RESULT, result, mod_len));

  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
