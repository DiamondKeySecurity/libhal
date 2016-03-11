/*
 * test-rpc_pkey.c
 * ---------------
 * Test code for RPC interface to Cryptech public key operations.
 *
 * Authors: Rob Austein, Paul Selkirk
 * Copyright (c) 2015-2016, NORDUnet A/S
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
#include <string.h>
#include <assert.h>

#include <hal.h>

#warning This is wrong, nothing outside libhal itself should include hal_internal.h
#include <hal_internal.h>

#include "test-rsa.h"
#include "test-ecdsa.h"

static int test_rsa_testvec(const rsa_tc_t * const tc)
{
  const hal_client_handle_t client = {0};
  const hal_session_handle_t session = {0};
  hal_pkey_handle_t private_key, public_key;
  hal_error_t err;
  size_t len;

  assert(tc != NULL);

  printf("Starting %lu-bit RSA test vector tests\n", (unsigned long) tc->size);

  uint8_t tc_keybuf[hal_rsa_key_t_size];
  hal_rsa_key_t *tc_key = NULL;

  if ((err = hal_rsa_key_load_private(&tc_key,
                                      tc_keybuf, sizeof(tc_keybuf),
                                      tc->n.val,  tc->n.len,
                                      tc->e.val,  tc->e.len,
                                      tc->d.val,  tc->d.len,
                                      tc->p.val,  tc->p.len,
                                      tc->q.val,  tc->q.len,
                                      tc->u.val,  tc->u.len,
                                      tc->dP.val, tc->dP.len,
                                      tc->dQ.val, tc->dQ.len)) != HAL_OK)
    return printf("Could not load RSA private key from test vector: %s\n", hal_error_string(err)), 0;

  const uint8_t private_label[] = "private key", public_label[] = "private key";

  uint8_t private_der[hal_rsa_private_key_to_der_len(tc_key)];
  uint8_t public_der[hal_rsa_public_key_to_der_len(tc_key)];

  if ((err = hal_rsa_private_key_to_der(tc_key, private_der, &len, sizeof(private_der))) != HAL_OK)
    return printf("Could not DER encode private key from test vector: %s\n", hal_error_string(err)), 0;

  assert(len == sizeof(private_der));

  if ((err = hal_rpc_pkey_load(client, session, &private_key, HAL_KEY_TYPE_RSA_PRIVATE, HAL_CURVE_NONE,
                               private_label, sizeof(private_label), private_der, sizeof(private_der),
                               HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)) != HAL_OK)
    return printf("Could not load private key into RPC: %s\n", hal_error_string(err)), 0;

  if ((err = hal_rsa_public_key_to_der(tc_key, public_der, &len, sizeof(public_der))) != HAL_OK)
    return printf("Could not DER encode public key from test vector: %s\n", hal_error_string(err)), 0;

  assert(len == sizeof(public_der));

  if ((err = hal_rpc_pkey_load(client, session, &public_key, HAL_KEY_TYPE_RSA_PUBLIC, HAL_CURVE_NONE,
                               public_label, sizeof(public_label), public_der, sizeof(public_der),
                               HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)) != HAL_OK)
    return printf("Could not load public key into RPC: %s\n", hal_error_string(err)), 0;

  uint8_t m_buf[tc->m.len], s_buf[tc->s.len];

  if ((err = hal_rpc_pkey_sign(session, private_key, hal_hash_handle_none, tc->m.val, tc->m.len,
                               s_buf, &len, sizeof(s_buf))) != HAL_OK)
    return printf("Could not sign: %s\n", hal_error_string(err)), 0;

  if (tc->s.len != len || memcmp(s_buf, tc->s.val, tc->s.len) != 0)
    return printf("MISMATCH\n"), 0;

  if ((err = hal_rpc_pkey_verify(session, public_key, hal_hash_handle_none, tc->s.val, tc->s.len,
                                 m_buf, sizeof(m_buf))) != HAL_OK)
    return printf("Could not verify: %s\n", hal_error_string(err)), 0;

  if ((err = hal_rpc_pkey_delete(private_key)) != HAL_OK)
    return printf("Could not delete private key: %s\n", hal_error_string(err)), 0;

  if ((err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
    return printf("Could not delete public key: %s\n", hal_error_string(err)), 0;

  printf("OK\n");
  return 1;
}

int main (int argc, char *argv[])
{
  rpc_client_init(RPC_LOCAL);
  // rpc_client_init(RPC_REMOTE);

  int ok = 1;

  for (int i = 0; i < (sizeof(rsa_tc)/sizeof(*rsa_tc)); i++)
    ok &= test_rsa_testvec(&rsa_tc[i]);

  return !ok;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
