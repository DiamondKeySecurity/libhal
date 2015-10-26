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
#include <string.h>
#include <errno.h>

#include <sys/time.h>

#include <hal.h>

#include "test-rsa.h"

/*
 * Run one modexp test.
 */

static int test_modexp(const char * const kind,
                       const rsa_tc_t * const tc,
                       const rsa_tc_bn_t * const msg, /* Input message */
                       const rsa_tc_bn_t * const exp, /* Exponent */
                       const rsa_tc_bn_t * const val) /* Expected result */
{
  uint8_t result[tc->n.len];

  printf("%s test for %lu-bit RSA key\n", kind, (unsigned long) tc->size);

  if (hal_modexp(msg->val, msg->len, exp->val, exp->len,
                 tc->n.val, tc->n.len, result, sizeof(result)) != HAL_OK) {
    printf("ModExp failed\n");
    return 0;
  }

  if (memcmp(result, val->val, val->len)) {
    printf("MISMATCH\n");
    return 0;
  }

  return 1;
}

/*
 * Run one RSA CRT test.
 */

static int test_decrypt(const char * const kind, const rsa_tc_t * const tc)
{
  printf("%s test for %lu-bit RSA key\n", kind, (unsigned long) tc->size);

  uint8_t keybuf[hal_rsa_key_t_size];
  hal_rsa_key_t *key = NULL;
  hal_error_t err = HAL_OK;

  if ((err = hal_rsa_key_load_private(&key,
                                      keybuf, sizeof(keybuf),
                                      tc->n.val,  tc->n.len,
                                      tc->e.val,  tc->e.len,
                                      tc->d.val,  tc->d.len,
                                      tc->p.val,  tc->p.len,
                                      tc->q.val,  tc->q.len,
                                      tc->u.val,  tc->u.len,
                                      tc->dP.val, tc->dP.len,
                                      tc->dQ.val, tc->dQ.len)) != HAL_OK) {
    printf("RSA CRT key load failed: %s\n", hal_error_string(err));
    return 0;
  }

  uint8_t result[tc->n.len];

  if ((err = hal_rsa_decrypt(key, tc->m.val, tc->m.len, result, sizeof(result))) != HAL_OK)
    printf("RSA CRT failed: %s\n", hal_error_string(err));

  const int mismatch = (err == HAL_OK && memcmp(result, tc->s.val, tc->s.len) != 0);

  if (mismatch)
    printf("MISMATCH\n");

  hal_rsa_key_clear(key);

  return err == HAL_OK && !mismatch;
}

/*
 * Run one RSA key generation + CRT test.
 */

static int test_gen(const char * const kind, const rsa_tc_t * const tc)
{
  printf("%s test for %lu-bit RSA key\n", kind, (unsigned long) tc->size);

  char fn[sizeof("test-rsa-key-xxxxxx.der")];
  uint8_t keybuf1[hal_rsa_key_t_size], keybuf2[hal_rsa_key_t_size];
  hal_rsa_key_t *key1 = NULL, *key2 = NULL;
  hal_error_t err = HAL_OK;
  FILE *f;

  const uint8_t f4[] = { 0x01, 0x00, 0x01 };

  if ((err = hal_rsa_key_gen(&key1, keybuf1, sizeof(keybuf1), bitsToBytes(tc->size), f4, sizeof(f4))) != HAL_OK) {
    printf("RSA key generation failed: %s\n", hal_error_string(err));
    return 0;
  }

  size_t der_len = 0;

  if ((err = hal_rsa_key_to_der(key1, NULL, &der_len, 0)) != HAL_OK) {
    printf("Getting DER length of RSA key failed: %s\n", hal_error_string(err));
    return 0;
  }

  uint8_t der[der_len];

  if ((err = hal_rsa_key_to_der(key1, der, &der_len, sizeof(der))) != HAL_OK) {
    printf("Converting RSA key to DER failed: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hal_rsa_key_from_der(&key2, keybuf2, sizeof(keybuf2), der, sizeof(der))) != HAL_OK) {
    printf("Converting RSA key back from DER failed: %s\n", hal_error_string(err));
    return 0;
  }

  if (memcmp(keybuf1, keybuf2, hal_rsa_key_t_size) != 0) {
    printf("RSA key mismatch after conversion to and back from DER\n");
    return 0;
  }

  snprintf(fn, sizeof(fn), "test-rsa-key-%04lu.der", (unsigned long) tc->size);
  printf("Writing %s\n", fn);

  if ((f = fopen(fn, "wb")) == NULL) {
    printf("Couldn't open %s: %s\n", fn, strerror(errno));
    return 0;
  }

  if (fwrite(der, der_len, 1, f) != 1) {
    printf("Length mismatch writing %s\n", fn);
    return 0;
  }

  if (fclose(f) == EOF) {
    printf("Couldn't close %s: %s\n", fn, strerror(errno));
    return 0;
  }

  uint8_t result[tc->n.len];

  if ((err = hal_rsa_decrypt(key1, tc->m.val, tc->m.len, result, sizeof(result))) != HAL_OK)
    printf("RSA CRT failed: %s\n", hal_error_string(err));

  snprintf(fn, sizeof(fn), "test-rsa-sig-%04lu.der", (unsigned long) tc->size);
  printf("Writing %s\n", fn);

  if ((f = fopen(fn, "wb")) == NULL) {
    printf("Couldn't open %s: %s\n", fn, strerror(errno));
    return 0;
  }

  if (fwrite(result, sizeof(result), 1, f) != 1) {
    printf("Length mismatch writing %s key\n", fn);
    return 0;
  }

  if (fclose(f) == EOF) {
    printf("Couldn't close %s: %s\n", fn, strerror(errno));
    return 0;
  }

  if (err != HAL_OK)            /* Deferred failure from hal_rsa_decrypt(), above */
    return 0;

  if ((err = hal_rsa_encrypt(key1, result, sizeof(result), result, sizeof(result))) != HAL_OK)
    printf("RSA signature check failed: %s\n", hal_error_string(err));

  const int mismatch = (err == HAL_OK && memcmp(result, tc->m.val, tc->m.len) != 0);

  if (mismatch)
    printf("MISMATCH\n");

  hal_rsa_key_clear(key1);
  hal_rsa_key_clear(key2);

  return err == HAL_OK && !mismatch;
}

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
 * Test signature and exponentiation for one RSA keypair using
 * precompiled test vectors, then generate a key of the same length
 * and try generating a signature with that.
 */

static int test_rsa(const rsa_tc_t * const tc)
{
  int ok = 1;

  /* RSA encryption */
  time_check(test_modexp("Verification", tc, &tc->s, &tc->e, &tc->m));

  /* Brute force RSA decryption */
  time_check(test_modexp("Signature (ModExp)", tc, &tc->m, &tc->d, &tc->s));

  /* RSA decyrption using CRT */
  time_check(test_decrypt("Signature (CRT)", tc));

  /* Key generation and CRT -- not test vector, so writes key and sig to file */
  time_check(test_gen("Generation and CRT", tc));

  return ok;
}

int main(int argc, char *argv[])
{
  uint8_t name[8], version[4];
  hal_error_t err;
  int i;

  /*
   * Initialize EIM and report what core we're running.
   */

  if ((err = hal_io_read(MODEXPS6_ADDR_NAME0,   name,    sizeof(name)))    != HAL_OK ||
      (err = hal_io_read(MODEXPS6_ADDR_VERSION, version, sizeof(version))) != HAL_OK) {
    printf("Initialization failed: %s\n", hal_error_string(err));
    return 1;
  }

  printf("\"%8.8s\"  \"%4.4s\"\n\n", name, version);

  /*
   * Run the test cases.
   */

  hal_modexp_set_debug(1);

  /* Normal test */

  for (i = 0; i < (sizeof(rsa_tc)/sizeof(*rsa_tc)); i++)
    if (!test_rsa(&rsa_tc[i]))
      return 1;

  return 0;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
