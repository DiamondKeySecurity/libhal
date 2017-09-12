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
 * Copyright (c) 2015, NORDUnet A/S
 * All rights reserved.
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

#include "hal.h"
#include "hal_internal.h"

/*
 * Whether we want debug output.
 */

static int debug = 0;

void hal_modexp_set_debug(const int onoff)
{
  debug = onoff;
}

/*
 * Get value of an ordinary register.
 */

static hal_error_t inline get_register(const hal_core_t *core,
                                       const hal_addr_t addr,
                                       uint32_t *value)
{
  hal_error_t err;
  uint8_t w[4];

  if (value == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if ((err = hal_io_read(core, addr, w, sizeof(w))) != HAL_OK)
    return err;

  *value = (w[0] << 0) | (w[1] << 8) | (w[2] << 16) | (w[3] << 24);

  return HAL_OK;
}

/*
 * Set value of an ordinary register.
 */

static hal_error_t inline set_register(const hal_core_t *core,
                                       const hal_addr_t addr,
                                       const uint32_t value)
{
  const uint8_t w[4] = {
    ((value >> 24) & 0xFF),
    ((value >> 16) & 0xFF),
    ((value >>  8) & 0xFF),
    ((value >>  0) & 0xFF)
  };

  return hal_io_write(core, addr, w, sizeof(w));
}

/*
 * Get value of a data buffer.  We reverse the order of 32-bit words
 * in the buffer during the transfer to match what the modexpa7 core
 * expects.
 */

static inline hal_error_t get_buffer(const hal_core_t *core,
                                     const hal_addr_t data_addr,
                                     uint8_t *value,
                                     const size_t length)
{
  hal_error_t err;
  size_t i;

  if (value == NULL || length % 4 != 0)
    return HAL_ERROR_IMPOSSIBLE;

  for (i = 0; i < length; i += 4)
    if ((err = hal_io_read(core, data_addr + i/4, &value[length - 4 - i], 4)) != HAL_OK)
      return err;

  return HAL_OK;
}

/*
 * Set value of a data buffer.  We reverse the order of 32-bit words
 * in the buffer during the transfer to match what the modexpa7 core
 * expects.
 *
 * Do we need to zero the portion of the buffer we're not using
 * explictly (that is, the portion between `length` and the value of
 * the core's MODEXPA7_ADDR_BUFFER_BITS register)?  We've gotten away
 * without doing this so far, but the core doesn't take an explicit
 * length parameter for the message itself, instead it assumes that
 * the message is either as long as or twice as long as the exponent,
 * depending on the setting of the CRT mode bit.  Maybe initializing
 * the core clears the excess bits so there's no issue?  Dunno.  Have
 * never seen a problem with this yet, just dont' know why not.
 */

static inline hal_error_t set_buffer(const hal_core_t *core,
                                     const hal_addr_t data_addr,
                                     const uint8_t * const value,
                                     const size_t length)
{
  hal_error_t err;
  size_t i;

  if (value == NULL || length % 4 != 0)
    return HAL_ERROR_IMPOSSIBLE;

  for (i = 0; i < length; i += 4)
    if ((err = hal_io_write(core, data_addr + i/4, &value[length - 4 - i], 4)) != HAL_OK)
      return err;

  return HAL_OK;
}

/*
 * Check a result, report on failure if debugging, pass failures up
 * the chain.
 */

#define check(_expr_)                                                                   \
  do {                                                                                  \
    hal_error_t _err = (_expr_);                                                        \
    if (_err != HAL_OK && debug)                                                        \
      hal_log(HAL_LOG_WARN, "%s failed: %s\n", #_expr_, hal_error_string(_err));        \
    if (_err != HAL_OK) {                                                               \
      hal_core_free(core);                                                              \
      return _err;                                                                      \
    }                                                                                   \
  } while (0)

/*
 * Run one modexp operation.
 */

hal_error_t hal_modexp(hal_core_t *core,
                       const int precalc,
                       const uint8_t * const msg, const size_t msg_len,         /* Message */
                       const uint8_t * const exp, const size_t exp_len,         /* Exponent */
                       const uint8_t * const mod, const size_t mod_len,         /* Modulus */
                       uint8_t *result,           const size_t result_len,      /* Result of exponentiation */
                       uint8_t *coeff,            const size_t coeff_len,       /* Modulus coefficient (r/w) */
                       uint8_t *mont,             const size_t mont_len)        /* Montgomery factor (r/w)*/
{
  hal_error_t err;

  /*
   * All pointers must be set, exponent may not be longer than
   * modulus, message may not be longer than twice the modulus (CRT
   * mode), result buffer must not be shorter than modulus, and all
   * input lengths must be a multiple of four bytes (the core is all
   * about 32-bit words).
   */

  if (msg    == NULL || msg_len    > MODEXPA7_OPERAND_BYTES || msg_len    >  mod_len * 2 ||
      exp    == NULL || exp_len    > MODEXPA7_OPERAND_BYTES || exp_len    >  mod_len     ||
      mod    == NULL || mod_len    > MODEXPA7_OPERAND_BYTES ||
      result == NULL || result_len > MODEXPA7_OPERAND_BYTES || result_len <  mod_len     ||
      coeff  == NULL || coeff_len  > MODEXPA7_OPERAND_BYTES ||
      mont   == NULL || mont_len   > MODEXPA7_OPERAND_BYTES ||
      ((msg_len | exp_len | mod_len) & 3) != 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * Gonna need to think about running two modexpa7 cores in parallel
   * in CRT mode for full speed signature.
   */

  if (((err = hal_core_alloc(MODEXPA7_NAME, &core)) != HAL_OK))
    return err;

  /*
   * Now that we have the core, check operand length against what it
   * says it can handle.
   */

  uint32_t operand_max = 0;
  check(get_register(core, MODEXPA7_ADDR_BUFFER_BITS, &operand_max));
  operand_max /= 8;

  if (msg_len   > operand_max ||
      exp_len   > operand_max ||
      mod_len   > operand_max ||
      coeff_len > operand_max ||
      mont_len  > operand_max) {
    hal_core_free(core);
    return HAL_ERROR_BAD_ARGUMENTS;
  }

  /* Set modulus */

  check(set_register(core, MODEXPA7_ADDR_MODULUS_BITS, mod_len * 8));
  check(set_buffer(core, MODEXPA7_ADDR_MODULUS, mod, mod_len));

  /*
   * Calculate modulus-dependent speedup factors if needed.  Buffer
   * space is always caller's problem (because caller almost certainly
   * wants to stash these values in the keystore anyway).  Calculation
   * is edge-triggered by "init" bit going from zero to one.
   */

  if (precalc) {
    check(hal_io_zero(core));
    check(hal_io_init(core));
    check(hal_io_wait_ready(core));
    check(get_buffer(core, MODEXPA7_ADDR_MODULUS_COEFF_OUT,     coeff, coeff_len));
    check(get_buffer(core, MODEXPA7_ADDR_MONTGOMERY_FACTOR_OUT, mont,  mont_len));
  }

  /* Load modulus-dependent speedup factors (even if we just calculated them) */
  check(set_buffer(core, MODEXPA7_ADDR_MODULUS_COEFF_IN,     coeff, coeff_len));
  check(set_buffer(core, MODEXPA7_ADDR_MONTGOMERY_FACTOR_IN, mont,  mont_len));

  /* Select CRT mode if and only if message is longer than exponent */
  check(set_register(core, MODEXPA7_ADDR_MODE,
                     (msg_len > mod_len
                      ? MODEXPA7_MODE_CRT
                      : MODEXPA7_MODE_PLAIN)));

  /* Set message and exponent */
  check(set_buffer(core, MODEXPA7_ADDR_MESSAGE, msg, msg_len));
  check(set_buffer(core, MODEXPA7_ADDR_EXPONENT, exp, exp_len));
  check(set_register(core, MODEXPA7_ADDR_EXPONENT_BITS, exp_len * 8));

  /* Edge-trigger the "next" bit to start calculation, then wait for the result */
  check(hal_io_zero(core));
  check(hal_io_next(core));
  check(hal_io_wait_valid(core));

  /* Extract result, clean up, then done */
  check(get_buffer(core, MODEXPA7_ADDR_RESULT, result, mod_len));
  hal_core_free(core);
  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
