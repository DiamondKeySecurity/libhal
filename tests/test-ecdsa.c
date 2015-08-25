/*
 * test-ecdsa.c
 * ------------
 * Test harness for Cryptech ECDSA code.
 *
 * At the moment, the ECDSA code is a pure software implementation,
 * Verilog will be along eventually.
 *
 * Testing ECDSA is a bit tricky because ECDSA depends heavily on
 * using a new random secret for each signature.  So we can test some
 * things against the normal ECDSA implemenation, but some tests
 * require a side door replacement of the random number generator so
 * that we can use a known values from our test vector in place of the
 * random secret that would be used in real operation.  Test code for
 * the latter mode depends on the library having been compiled with
 * the testing hook enable, which it should not be for production use.
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
#include <errno.h>

#include <sys/time.h>

#include <hal.h>

#include "test-ecdsa.h"

/*
 * Supplied test vectors don't use ASN.1 encoding.  Don't want to
 * trust our own ASN.1 code for this (it's one of the things we're
 * testing) so use Python pyasn1 or ecdsa.der code to build what we
 * need and supply them as test vector data too.  This is probably
 * also the right way to test our encoding and decoding of private
 * keys too.
 */

#if HAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM

/*
 * Code to let us replace ECDSA's random numbers with test data, if
 * the ECDSA library code has been compiled with support for this.
 */

typedef hal_error_t (*rng_override_test_function_t)(void *, const size_t);

extern rng_override_test_function_t hal_ecdsa_set_rng_override_test_function(rng_override_test_function_t new_func);

static const uint8_t               *next_random_value = NULL;
static size_t                       next_random_length = 0;

static hal_error_t next_random_handler(void *data, const size_t length)
{
  if (data == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (next_random_value == NULL || length < next_random_length)
    return HAL_ERROR_IMPOSSIBLE;

  memset(data, 0, length);
  memcpy(data + length - next_random_length, next_random_value, next_random_length);

  next_random_value  = NULL;
  next_random_length = 0;

  (void) hal_ecdsa_set_rng_override_test_function(0);

  return HAL_OK;
}

static void set_next_random(const uint8_t * const data, const size_t length)
{
  (void) hal_ecdsa_set_rng_override_test_function(next_random_handler);
  next_random_value  = data;
  next_random_length = length;
}

/*
 * Run one keygen test from test vectors.
 */

static int test_keygen_static(const hal_ecdsa_curve_t curve)

{
  uint8_t keybuf[hal_ecdsa_key_t_size];
  hal_ecdsa_key_t *key = NULL;
  hal_error_t err;
  const uint8_t *d, *Qx, *Qy;
  size_t d_len, Qx_len, Qy_len;

  switch (curve) {

  case HAL_ECDSA_CURVE_P256:
    printf("ECDSA P-256 key generation test\n");
    d  = p256_d;  d_len  = sizeof(p256_d);
    Qx = p256_Qx; Qx_len = sizeof(p256_Qx);
    Qy = p256_Qy; Qy_len = sizeof(p256_Qy);
    break;

  case HAL_ECDSA_CURVE_P384:
    printf("ECDSA P-384 key generation test\n");
    d  = p384_d;  d_len  = sizeof(p384_d);
    Qx = p384_Qx; Qx_len = sizeof(p384_Qx);
    Qy = p384_Qy; Qy_len = sizeof(p384_Qy);
    break;

  default:
    printf("Unsupported ECDSA curve type\n");
    return 0;
  }

  set_next_random(d, d_len);

  if ((err =  hal_ecdsa_key_gen(&key, keybuf, sizeof(keybuf), curve)) != HAL_OK)
    return printf("hal_ecdsa_key_gen() failed: %s\n", hal_error_string(err)), 0;

  uint8_t Rx[Qx_len], Ry[Qy_len];
  size_t Rx_len, Ry_len;

  if ((err = hal_ecdsa_key_get_public(key, Rx, &Rx_len, sizeof(Rx), Ry, &Ry_len, sizeof(Ry))) != HAL_OK)
    return printf("hal_ecdsa_key_get_public() failed: %s\n", hal_error_string(err)), 0;

  if (Qx_len != Rx_len || memcmp(Qx, Rx, Rx_len) != 0)
    return printf("Qx mismatch\n"), 0;

  if (Qy_len != Ry_len || memcmp(Qy, Ry, Ry_len) != 0)
    return printf("Qy mismatch\n"), 0;

  return 1;
}

#endif /* HAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM */

/*
 * Time a test.
 */

static void _time_check(const struct timeval t0, const int ok)
{
  struct timeval t;
  gettimeofday(&t, NULL);
  t.tv_sec -= t0.tv_sec;
  t.tv_usec = t0.tv_usec;
  if (t.tv_usec < 0) {
    t.tv_usec += 1000000;
    t.tv_sec  -= 1;
  }
  printf("Elapsed time %lu.%06lu seconds, %s\n",
         (unsigned long) t.tv_sec,
         (unsigned long) t.tv_usec,
         ok ? "OK" : "FAILED");
}

#define time_check(_expr_)                      \
  do {                                          \
    struct timeval _t;                          \
    gettimeofday(&_t, NULL);                    \
    int _ok = (_expr_);                         \
    _time_check(_t, _ok);                       \
    ok &= _ok;                                  \
  } while (0)

/*
 * Run tests for one ECDSA curve.
 */

static int test_ecdsa(const hal_ecdsa_curve_t curve)

{
  int ok = 1;

  time_check(test_keygen_static(curve));

  return ok;
}

int main(int argc, char *argv[])
{
  uint8_t name[8], version[4];
  hal_error_t err;

  /*
   * Initialize EIM and report what core we're running.
   */

  if ((err = hal_io_read(CSPRNG_ADDR_NAME0,   name,    sizeof(name)))    != HAL_OK ||
      (err = hal_io_read(CSPRNG_ADDR_VERSION, version, sizeof(version))) != HAL_OK) {
    printf("Initialization failed: %s\n", hal_error_string(err));
    return 1;
  }

  printf("\"%8.8s\"  \"%4.4s\"\n\n", name, version);

  return !test_ecdsa(HAL_ECDSA_CURVE_P256) || !test_ecdsa(HAL_ECDSA_CURVE_P384);
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
