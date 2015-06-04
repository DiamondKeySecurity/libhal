/*
 * test-rsa.c
 * ----------
 * First stumblings towards a test harness for RSA using Cryptech
 * ModExp core.
 *
 * For the moment this just does modular exponentiation tests using
 * RSA keys and pre-formatted data-to-be-signed, without attempting
 * CRT or any of the other clever stuff we should be doing.  This is
 * not usable for any sane purpose other than testing.
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
#include "test-rsa.h"

/*
 * Constant value to use with hal_io_write() when we don't want
 * a read-back check thus aren't using set_register().
 */

static const uint8_t one[] = { 0, 0, 0, 1 };

/*
 * Debugging aid: check a result, report on failure.
 */

#define check(_expr_)                           \
  do {                                          \
    if ((_expr_) != 0)                          \
      return printf("%s failed\n", #_expr_), 1; \
  } while (0)

/*
 * Set an ordinary register, with read-back check.
 */

static int _set_register(const off_t addr,
                         const char * const name,
                         uint32_t value)
{
  uint8_t w1[4], w2[4];
  int i;
  assert(name != NULL);
  for (i = 3; i >= 0; i--) {
    w1[i] = value & 0xFF;
    value >>= 8;
  }
  printf("Setting register %#lx %s...\n", (unsigned long) addr, name);
  check(hal_io_write(addr, w1, sizeof(w1)));
  check(hal_io_read(addr,  w2, sizeof(w2)));
  if (memcmp(w1, w2, sizeof(w1)) != 0)
    printf("MISMATCH\n");
  return 0;
}

/*
 * Get value of a block memory.
 */

static int _get_blockmem(const off_t reset_addr,
                         const char * const reset_name,
                         const off_t data_addr,
                         const char * const data_name,
                         uint8_t *value,
                         const size_t length)
{
  size_t i;
  assert(reset_name != NULL && data_name != NULL && value != NULL && length % 4 == 0);
  printf("Setting register %#lx %s...\n", (unsigned long) reset_addr, reset_name);
  check(hal_io_write(reset_addr, one, sizeof(one)));
  printf("Getting blockmem %#lx %s...\n", (unsigned long) data_addr, data_name);
  for (i = 0; i < length; i += 4)
    check(hal_io_read(data_addr, &value[i], 4));
  return 0;
}

/*
 * Set value of a block memory, with read-back check.
 */

static int _set_blockmem(const off_t reset_addr,
                         const char * const reset_name,
                         const off_t data_addr,
                         const char * const data_name,
                         const uint8_t * const value,
                         const size_t value_length,
                         uint8_t *buffer,
                         const size_t buffer_length)
{
  size_t i;
  assert(reset_name != NULL && data_name != NULL && value != NULL && buffer_length >= value_length && value_length % 4 == 0);
  printf("Setting register %#lx %s...\n", (unsigned long) reset_addr, reset_name);
  check(hal_io_write(reset_addr, one, sizeof(one)));
  printf("Setting blockmem %#lx %s...\n", (unsigned long) data_addr, data_name);
  for (i = 0; i < value_length; i += 4)
    check(hal_io_write(data_addr, &value[i], 4));
  check(_get_blockmem(reset_addr, reset_name, data_addr, data_name, buffer, value_length));
  if (memcmp(value, buffer, value_length))
    printf("MISMATCH\n");
  printf("\n");
  return 0;
}

/*
 * Syntactic sugar.
 */

#define set_register(_field_, _value_) \
  _set_register(_field_, #_field_, _value_)

#define get_blockmem(_field_, _value_, _length_) \
  _get_blockmem(_field_##_PTR_RST, #_field_ "_PTR_RST", _field_##_DATA, #_field_ "_DATA", _value_, _length_)

#define set_blockmem(_field_, _value_, _buffer_) \
  _set_blockmem(_field_##_PTR_RST, #_field_ "_PTR_RST", _field_##_DATA, #_field_ "_DATA", (_value_).val, (_value_).len, _buffer_, sizeof(_buffer_))

/*
 * Run one modexp test.
 */

static int test_modexp(const char * const kind,
                       const rsa_tc_t * const tc,
                       const rsa_tc_bn_t * const msg, /* Input message */
                       const rsa_tc_bn_t * const exp, /* Exponent */
                       const rsa_tc_bn_t * const val) /* Expected result */
{
  uint8_t b[4096];

  hal_io_set_debug(1);

  printf("%s test for %lu-bit RSA key\n", kind, (unsigned long) tc->size);

  check(set_blockmem(MODEXP_MODULUS, tc->n, b));
  check(set_blockmem(MODEXP_MESSAGE, (*msg), b));
  check(set_register(MODEXP_MODULUS_LENGTH, tc->n.len / 4));

  check(set_blockmem(MODEXP_EXPONENT, (*exp), b));
  check(set_register(MODEXP_EXPONENT_LENGTH, val->len / 4));

  printf("Checking ready status\n");
  check(hal_io_wait_ready(MODEXP_ADDR_STATUS));
  printf("\n");

  check(set_register(MODEXP_ADDR_CTRL, 1));

  hal_io_set_debug(0);

  printf("Waiting for ready\n");
  check(hal_io_wait(MODEXP_ADDR_STATUS, STATUS_READY, NULL));
  printf("\n");

  hal_io_set_debug(1);

  check(get_blockmem(MODEXP_RESULT, b, tc->n.len));

  printf("Comparing results with known value...");
  if (memcmp(b, val->val, val->len))
    printf("MISMATCH\n");
  else
    printf("OK\n");
  printf("\n");

  return 0;
}

/*
 * Test signature and exponentiation for one RSA keypair.
 */

static int test_rsa(const rsa_tc_t * const tc)
{
  return (test_modexp("Signature",    tc, &tc->m, &tc->d, &tc->s) || /* RSA decryption */
          test_modexp("Verification", tc, &tc->s, &tc->e, &tc->m));  /* RSA encryption */
}

int main(int argc, char *argv[])
{
  uint8_t name[8], version[4];
  int i;

  /*
   * Initialize EIM and report what core we're running.
   */

  check(hal_io_read(MODEXP_ADDR_NAME0,   name,    sizeof(name)));
  check(hal_io_read(MODEXP_ADDR_VERSION, version, sizeof(version)));
  printf("\"%8.8s\"  \"%4.4s\"\n\n", name, version);

  /*
   * Run the test cases.
   */

  for (i = 0; i < (sizeof(rsa_tc)/sizeof(*rsa_tc)); i++)
    if (test_rsa(&rsa_tc[i]))
      return 1;

  return 0;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
