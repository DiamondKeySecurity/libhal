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

  printf("OK\n");
  return 1;
}

/*
 * Test signature and exponentiation for one RSA keypair.
 */

static int test_rsa(const rsa_tc_t * const tc)
{
  return (test_modexp("Signature",    tc, &tc->m, &tc->d, &tc->s) && /* RSA decryption */
          test_modexp("Verification", tc, &tc->s, &tc->e, &tc->m));  /* RSA encryption */
}

int main(int argc, char *argv[])
{
  uint8_t name[8], version[4];
  hal_error_t err;
  int i;

  /*
   * Initialize EIM and report what core we're running.
   */

  if ((err = hal_io_read(MODEXP_ADDR_NAME0,   name,    sizeof(name)))    != HAL_OK ||
      (err = hal_io_read(MODEXP_ADDR_VERSION, version, sizeof(version))) != HAL_OK) {
    printf("Initialization failed: %s\n", hal_error_string(err));
    return 1;
  }

  printf("\"%8.8s\"  \"%4.4s\"\n\n", name, version);

  /*
   * Run the test cases.
   */

  hal_modexp_set_debug(1);

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
