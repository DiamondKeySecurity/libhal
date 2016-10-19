/*
 * rpc_client.c
 * ------------
 * Remote procedure call client-side private API implementation.
 *
 * Authors: Rob Austein, Paul Selkirk
 * Copyright (c) 2015-2016, NORDUnet A/S All rights reserved.
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

#include <assert.h>

#include "hal.h"
#include "hal_internal.h"
#include "xdr_internal.h"

#ifndef HAL_RPC_CLIENT_DEBUG
#define HAL_RPC_CLIENT_DEBUG 0
#endif

#if HAL_RPC_CLIENT_DEBUG
#include <stdio.h>
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) { printf("%s returned %d (%s)\n", #op, _err_, hal_error_string(_err_)); return _err_; } } while (0)
#else
#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) {                                                                       return _err_; } } while (0)
#endif

#define pad(n) (((n) + 3) & ~3)

#define nargs(n) ((n) * 4)

#if RPC_CLIENT != RPC_CLIENT_LOCAL

/*
 * Consolidate a bit of the repetitive code from the packet receive loop.
 * We're looking for a packet which is a response to the packet we sent,
 * so if the opcode is wrong, we discard and wait for another packet.
 */

static hal_error_t read_matching_packet(const rpc_func_num_t expected_func,
                                        uint8_t *inbuf,
                                        const size_t inbuf_max,
                                        const uint8_t **iptr,
                                        const uint8_t **ilimit)
{
  hal_client_handle_t dummy_client;
  uint32_t received_func;
  size_t ilen = inbuf_max;
  hal_error_t err;

  assert(inbuf != NULL && iptr != NULL && ilimit != NULL);

  do {

    if ((err = hal_rpc_recv(inbuf, &ilen)) != HAL_OK)
      return err;

    assert(ilen <= inbuf_max);
    *iptr = inbuf;
    *ilimit = inbuf + ilen;

    if ((err = hal_xdr_decode_int(iptr, *ilimit, &received_func))       == HAL_ERROR_XDR_BUFFER_OVERFLOW)
      continue;
    if (err != HAL_OK)
      return err;

    if ((err = hal_xdr_decode_int(iptr, *ilimit, &dummy_client.handle)) == HAL_ERROR_XDR_BUFFER_OVERFLOW)
      continue;
    if (err != HAL_OK)
      return err;

  } while (received_func != expected_func);

  return HAL_OK;
}

/*
 * RPC calls.
 */

static hal_error_t get_version(uint32_t *version)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_GET_VERSION));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_GET_VERSION, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, version));
  }
  return rpc_ret;
}

static hal_error_t get_random(void *buffer, const size_t length)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4) + pad(length)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t rcvlen = length;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_GET_RANDOM));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, (uint32_t)length));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_GET_RANDOM, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, buffer, &rcvlen));
    // XXX check rcvlen vs length
  }
  return rpc_ret;
}

static hal_error_t set_pin(const hal_client_handle_t client,
                           const hal_user_t user,
                           const char * const pin, const size_t pin_len)
{
  uint8_t outbuf[nargs(4) + pad(pin_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_SET_PIN));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, user));
  check(hal_xdr_encode_buffer(&optr, olimit, (const uint8_t *)pin, pin_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_SET_PIN, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

/*
 * We may end up wanting to wrap a client-side cache around the
 * login()/logout()/logout_all() calls and reimplement is_logged_in()
 * on the client side using that cache, so that access checks don't
 * need to cross the RPC boundary.  Then again, we might not, if the
 * RPC call is fast enough, so implementing all before the RPC would
 * qualify as premature optimization.  There aren't all that many
 * things on the client side that would use this anyway, so the whole
 * question may be moot.
 *
 * For now, we leave all of these as plain RPC calls, but we may want
 * to revisit this if the is_logged_in() call turns into a bottleneck.
 */

static hal_error_t login(const hal_client_handle_t client,
                         const hal_user_t user,
                         const char * const pin, const size_t pin_len)
{
  uint8_t outbuf[nargs(4) + pad(pin_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGIN));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, user));
  check(hal_xdr_encode_buffer(&optr, olimit, (const uint8_t *)pin, pin_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_LOGIN, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t logout(const hal_client_handle_t client)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGOUT));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_LOGOUT, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t logout_all(void)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGOUT_ALL));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_LOGOUT_ALL, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t is_logged_in(const hal_client_handle_t client,
                                const hal_user_t user)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_IS_LOGGED_IN));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, user));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_IS_LOGGED_IN, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t hash_get_digest_len(const hal_digest_algorithm_t alg, size_t *length)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t len32;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_DIGEST_LEN));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, alg));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_HASH_GET_DIGEST_LEN, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &len32));
    *length = (size_t)len32;
  }
  return rpc_ret;
}

static hal_error_t hash_get_digest_algorithm_id(const hal_digest_algorithm_t alg,
                                                uint8_t *id, size_t *len, const size_t len_max)
{
  uint8_t outbuf[nargs(4)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4) + pad(len_max)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t len32 = len_max;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, alg));
  check(hal_xdr_encode_int(&optr, olimit, len_max));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID,
                             inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, id, &len32));
    *len = len32;
  }
  return rpc_ret;
}

static hal_error_t hash_get_algorithm(const hal_hash_handle_t hash, hal_digest_algorithm_t *alg)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t alg32;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_ALGORITHM));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_HASH_GET_ALGORITHM, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &alg32));
    *alg = (hal_digest_algorithm_t) alg32;
  }
  return rpc_ret;
}

static hal_error_t hash_initialize(const hal_client_handle_t client,
                                   const hal_session_handle_t session,
                                   hal_hash_handle_t *hash,
                                   const hal_digest_algorithm_t alg,
                                   const uint8_t * const key, const size_t key_len)
{
  uint8_t outbuf[nargs(5) + pad(key_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_INITIALIZE));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, alg));
  check(hal_xdr_encode_buffer(&optr, olimit, key, key_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_HASH_INITIALIZE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &hash->handle));
  }
  return rpc_ret;
}

static hal_error_t hash_update(const hal_hash_handle_t hash,
                               const uint8_t * data, const size_t length)
{
  uint8_t outbuf[nargs(4) + pad(length)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_UPDATE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, data, length));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_HASH_UPDATE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t hash_finalize(const hal_hash_handle_t hash,
                                 uint8_t *digest, const size_t length)
{
  uint8_t outbuf[nargs(4)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4) + pad(length)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t digest_len = length;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_FINALIZE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_int(&optr, olimit, length));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_HASH_FINALIZE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, digest, &digest_len));
    /* XXX check digest_len vs length */
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_load(const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    hal_pkey_handle_t *pkey,
                                    const hal_key_type_t type,
                                    const hal_curve_name_t curve,
                                    hal_uuid_t *name,
                                    const uint8_t * const der, const size_t der_len,
                                    const hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(7) + pad(der_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t name_len = sizeof(name->uuid);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_LOAD));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, type));
  check(hal_xdr_encode_int(&optr, olimit, curve));
  check(hal_xdr_encode_buffer(&optr, olimit, der, der_len));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_LOAD, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
    check(hal_xdr_decode_buffer(&iptr, ilimit, name->uuid, &name_len));
    if (name_len != sizeof(name->uuid))
      return HAL_ERROR_KEY_NAME_TOO_LONG;
  }

  return rpc_ret;
}

static hal_error_t pkey_remote_find(const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    hal_pkey_handle_t *pkey,
                                    const hal_uuid_t * const name,
                                    const hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(5) + pad(sizeof(name->uuid))], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_FIND));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, name->uuid, sizeof(name->uuid)));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_FIND, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

  if (rpc_ret == HAL_OK)
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));

  return rpc_ret;
}

static hal_error_t pkey_remote_generate_rsa(const hal_client_handle_t client,
                                            const hal_session_handle_t session,
                                            hal_pkey_handle_t *pkey,
                                            hal_uuid_t *name,
                                            const unsigned key_len,
                                            const uint8_t * const exp, const size_t exp_len,
                                            const hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(6) + pad(exp_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t name_len = sizeof(name->uuid);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GENERATE_RSA));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, key_len));
  check(hal_xdr_encode_buffer(&optr, olimit, exp, exp_len));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_GENERATE_RSA, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
    check(hal_xdr_decode_buffer(&iptr, ilimit, name->uuid, &name_len));
    if (name_len != sizeof(name->uuid))
      return HAL_ERROR_KEY_NAME_TOO_LONG;
  }

  return rpc_ret;
}

static hal_error_t pkey_remote_generate_ec(const hal_client_handle_t client,
                                           const hal_session_handle_t session,
                                           hal_pkey_handle_t *pkey,
                                           hal_uuid_t *name,
                                           const hal_curve_name_t curve,
                                           const hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(5)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(5) + pad(sizeof(name->uuid))];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t name_len = sizeof(name->uuid);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GENERATE_EC));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, curve));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_GENERATE_EC, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));

  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));
    check(hal_xdr_decode_buffer(&iptr, ilimit, name->uuid, &name_len));
    if (name_len != sizeof(name->uuid))
      return HAL_ERROR_KEY_NAME_TOO_LONG;
  }

  return rpc_ret;
}

static hal_error_t pkey_remote_close(const hal_pkey_handle_t pkey)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_CLOSE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_CLOSE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t pkey_remote_delete(const hal_pkey_handle_t pkey)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_DELETE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_DELETE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t pkey_remote_get_key_type(const hal_pkey_handle_t pkey,
                                            hal_key_type_t *type)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t type32;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_KEY_TYPE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_GET_KEY_TYPE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &type32));
    *type = (hal_key_type_t)type32;
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_get_key_flags(const hal_pkey_handle_t pkey,
                                             hal_key_flags_t *flags)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t flags32;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_KEY_FLAGS));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_GET_KEY_FLAGS, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &flags32));
    *flags = (hal_key_flags_t)flags32;
  }
  return rpc_ret;
}

static size_t pkey_remote_get_public_key_len(const hal_pkey_handle_t pkey)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t len32;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &len32));
    return (size_t)len32;
  }
  else
    return 0;
}

static hal_error_t pkey_remote_get_public_key(const hal_pkey_handle_t pkey,
                                              uint8_t *der, size_t *der_len, const size_t der_max)
{
  uint8_t outbuf[nargs(4)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4) + pad(der_max)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t dlen32 = der_max;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_PUBLIC_KEY));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, der_max));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_GET_PUBLIC_KEY, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, der, &dlen32));
    *der_len = (size_t)dlen32;
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_sign(const hal_pkey_handle_t pkey,
                                    const hal_hash_handle_t hash,
                                    const uint8_t * const input, const size_t input_len,
                                    uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  uint8_t outbuf[nargs(6) + pad(input_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4) + pad(signature_max)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t slen32 = signature_max;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_SIGN));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, input, input_len));
  check(hal_xdr_encode_int(&optr, olimit, signature_max));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_SIGN, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, signature, &slen32));
    *signature_len = (size_t)slen32;
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_verify(const hal_pkey_handle_t pkey,
                                      const hal_hash_handle_t hash,
                                      const uint8_t * const input, const size_t input_len,
                                      const uint8_t * const signature, const size_t signature_len)
{
  uint8_t outbuf[nargs(6) + pad(input_len) + pad(signature_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_VERIFY));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, input, input_len));
  check(hal_xdr_encode_buffer(&optr, olimit, signature, signature_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_VERIFY, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t hal_xdr_decode_pkey_info(const uint8_t **iptr, const uint8_t * const ilimit,
                                            hal_pkey_info_t *info)
{
  uint32_t u32;

  check(hal_xdr_decode_int(iptr, ilimit, &u32)); info->type  = u32;
  check(hal_xdr_decode_int(iptr, ilimit, &u32)); info->curve = u32;
  check(hal_xdr_decode_int(iptr, ilimit, &u32)); info->flags = u32;

  u32 = sizeof(info->name.uuid);
  check(hal_xdr_decode_buffer(iptr, ilimit, info->name.uuid, &u32));
  if (u32 != sizeof(info->name.uuid))
    return HAL_ERROR_KEY_NAME_TOO_LONG;

  return HAL_OK;
}

static hal_error_t pkey_remote_list(const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    hal_pkey_info_t *result,
                                    unsigned *result_len,
                                    const unsigned result_max,
                                    hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(5)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4) + pad(result_max * sizeof(hal_pkey_info_t))];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t len;
  hal_error_t ret, rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_LIST));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, result_max));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_LIST, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &len));
    *result_len = len;
    for (int i = 0; i < len; ++i) {
      if ((ret = hal_xdr_decode_pkey_info(&iptr, ilimit, &result[i])) != HAL_OK) {
        *result_len = 0;
        return ret;
      }
    }
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_match(const hal_client_handle_t client,
                                     const hal_session_handle_t session,
                                     const hal_key_type_t type,
                                     const hal_curve_name_t curve,
                                     const hal_key_flags_t flags,
                                     hal_rpc_pkey_attribute_t *attributes,
                                     const unsigned attributes_len,
                                     hal_uuid_t *result,
                                     unsigned *result_len,
                                     const unsigned result_max,
                                     hal_uuid_t *previous_uuid)
{
  size_t attributes_buffer_len = 0;
  if (attributes != NULL)
    for (int i = 0; i < attributes_len; i++)
      attributes_buffer_len += attributes[i].length;

  uint8_t outbuf[nargs(9 + attributes_len * 2) + pad(attributes_buffer_len) + pad(sizeof(hal_uuid_t))];
  uint8_t *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(5) + pad(result_max * sizeof(hal_uuid_t)) + pad(sizeof(hal_uuid_t))];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_MATCH));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, type));
  check(hal_xdr_encode_int(&optr, olimit, curve));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_xdr_encode_int(&optr, olimit, attributes_len));
  if (attributes != NULL) {
    for (int i = 0; i < attributes_len; i++) {
      check(hal_xdr_encode_int(&optr, olimit, attributes[i].type));
      check(hal_xdr_encode_buffer(&optr, olimit, attributes[i].value, attributes[i].length));
    }
  }
  check(hal_xdr_encode_int(&optr, olimit, result_max));
  check(hal_xdr_encode_buffer(&optr, olimit, previous_uuid->uuid, sizeof(previous_uuid->uuid)));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_MATCH, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    uint32_t array_len, uuid_len;
    *result_len = 0;
    check(hal_xdr_decode_int(&iptr, ilimit, &array_len));
    for (int i = 0; i < array_len; ++i) {
      check(hal_xdr_decode_buffer(&iptr, ilimit, result[i].uuid, &uuid_len));
      if (uuid_len != sizeof(result[i].uuid))
        return HAL_ERROR_KEY_NAME_TOO_LONG;
    }
    check(hal_xdr_decode_buffer(&iptr, ilimit, previous_uuid->uuid, &uuid_len));
    if (uuid_len != sizeof(previous_uuid->uuid))
      return HAL_ERROR_KEY_NAME_TOO_LONG;
    *result_len = array_len;
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_set_attribute(const hal_pkey_handle_t pkey,
                                             const uint32_t type,
                                             const uint8_t * const value,
                                             const size_t value_len)
{
  uint8_t outbuf[nargs(5) + pad(value_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_SET_ATTRIBUTE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, type));
  check(hal_xdr_encode_buffer(&optr, olimit, value, value_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_SET_ATTRIBUTE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t pkey_remote_get_attribute(const hal_pkey_handle_t pkey,
                                             const uint32_t type,
                                             uint8_t *value,
                                             size_t *value_len,
                                             const size_t value_max)
{
  uint8_t outbuf[nargs(5)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(4) + pad(value_max)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  uint32_t vlen32 = value_max;
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_ATTRIBUTE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, type));
  check(hal_xdr_encode_int(&optr, olimit, vlen32));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_GET_ATTRIBUTE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, value, &vlen32));
    *value_len = (size_t) vlen32;
  }

  return rpc_ret;
}

static hal_error_t pkey_remote_delete_attribute(const hal_pkey_handle_t pkey,
                                                const uint32_t type)
{
  uint8_t outbuf[nargs(4)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(3)];
  const uint8_t *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  hal_client_handle_t dummy_client = {0};
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_DELETE_ATTRIBUTE));
  check(hal_xdr_encode_int(&optr, olimit, dummy_client.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, type));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(read_matching_packet(RPC_FUNC_PKEY_DELETE_ATTRIBUTE, inbuf, sizeof(inbuf), &iptr, &ilimit));

  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

#if RPC_CLIENT == RPC_CLIENT_MIXED

/*
 * "Mixed" mode pkey operations, where the public key operation itself
 * takes place on the HSM but the hashing takes place locally.  If
 * we're given a hash context in this case, it's local, so we have to
 * pull the digest from the hash context and send that to the HSM.
 */

static hal_error_t pkey_mixed_sign(const hal_pkey_handle_t pkey,
                                   const hal_hash_handle_t hash,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  if (input != NULL)
    return hal_rpc_remote_pkey_dispatch.sign(pkey, hash, input, input_len,
                                             signature, signature_len, signature_max);

  hal_digest_algorithm_t alg;
  hal_key_type_t pkey_type;
  size_t digest_len;
  hal_error_t err;

  if ((err = hal_rpc_hash_get_algorithm(hash, &alg))           != HAL_OK ||
      (err = hal_rpc_hash_get_digest_length(alg, &digest_len)) != HAL_OK ||
      (err = hal_rpc_pkey_get_key_type(pkey, &pkey_type))      != HAL_OK)
    return err;

  uint8_t digest[digest_len > signature_max ? digest_len : signature_max];

  switch (pkey_type) {

  case HAL_KEY_TYPE_RSA_PRIVATE:
  case HAL_KEY_TYPE_RSA_PUBLIC:
    if ((err = hal_rpc_pkcs1_construct_digestinfo(hash, digest, &digest_len, sizeof(digest))) != HAL_OK)
      return err;
    break;

  default:
    if ((err = hal_rpc_hash_finalize(hash, digest, digest_len)) != HAL_OK)
      return err;

  }

  return hal_rpc_remote_pkey_dispatch.sign(pkey, hal_hash_handle_none, digest, digest_len,
                                           signature, signature_len, signature_max);
}

static hal_error_t pkey_mixed_verify(const hal_pkey_handle_t pkey,
                                     const hal_hash_handle_t hash,
                                     const uint8_t * const input, const size_t input_len,
                                     const uint8_t * const signature, const size_t signature_len)
{
  if (input != NULL)
    return hal_rpc_remote_pkey_dispatch.verify(pkey, hash, input, input_len,
                                               signature, signature_len);

  hal_digest_algorithm_t alg;
  hal_key_type_t pkey_type;
  size_t digest_len;
  hal_error_t err;

  if ((err = hal_rpc_hash_get_algorithm(hash, &alg))           != HAL_OK ||
      (err = hal_rpc_hash_get_digest_length(alg, &digest_len)) != HAL_OK ||
      (err = hal_rpc_pkey_get_key_type(pkey, &pkey_type))      != HAL_OK)
    return err;

  uint8_t digest[digest_len > signature_len ? digest_len : signature_len];

  switch (pkey_type) {

  case HAL_KEY_TYPE_RSA_PRIVATE:
  case HAL_KEY_TYPE_RSA_PUBLIC:
    if ((err = hal_rpc_pkcs1_construct_digestinfo(hash, digest, &digest_len, sizeof(digest))) != HAL_OK)
      return err;
    break;

  default:
    if ((err = hal_rpc_hash_finalize(hash, digest, digest_len)) != HAL_OK)
      return err;

  }

  return hal_rpc_remote_pkey_dispatch.verify(pkey, hal_hash_handle_none,
                                             digest, digest_len, signature, signature_len);
}

#endif /* RPC_CLIENT == RPC_CLIENT_MIXED */

/*
 * Dispatch vectors.
 */

const hal_rpc_misc_dispatch_t hal_rpc_remote_misc_dispatch = {
  set_pin,
  login,
  logout,
  logout_all,
  is_logged_in,
  get_random,
  get_version
};

const hal_rpc_hash_dispatch_t hal_rpc_remote_hash_dispatch = {
  hash_get_digest_len,
  hash_get_digest_algorithm_id,
  hash_get_algorithm,
  hash_initialize,
  hash_update,
  hash_finalize
};

const hal_rpc_pkey_dispatch_t hal_rpc_remote_pkey_dispatch = {
  pkey_remote_load,
  pkey_remote_find,
  pkey_remote_generate_rsa,
  pkey_remote_generate_ec,
  pkey_remote_close,
  pkey_remote_delete,
  pkey_remote_get_key_type,
  pkey_remote_get_key_flags,
  pkey_remote_get_public_key_len,
  pkey_remote_get_public_key,
  pkey_remote_sign,
  pkey_remote_verify,
  pkey_remote_list,
  pkey_remote_match,
  pkey_remote_set_attribute,
  pkey_remote_get_attribute,
  pkey_remote_delete_attribute
};

#if RPC_CLIENT == RPC_CLIENT_MIXED
const hal_rpc_pkey_dispatch_t hal_rpc_mixed_pkey_dispatch = {
  pkey_remote_load,
  pkey_remote_find,
  pkey_remote_generate_rsa,
  pkey_remote_generate_ec,
  pkey_remote_close,
  pkey_remote_delete,
  pkey_remote_get_key_type,
  pkey_remote_get_key_flags,
  pkey_remote_get_public_key_len,
  pkey_remote_get_public_key,
  pkey_mixed_sign,
  pkey_mixed_verify,
  pkey_remote_list,
  pkey_remote_match,
  pkey_remote_set_attribute,
  pkey_remote_get_attribute,
  pkey_remote_delete_attribute
};
#endif /* RPC_CLIENT == RPC_CLIENT_MIXED */

#endif /* RPC_CLIENT != RPC_CLIENT_LOCAL */


#if RPC_CLIENT == RPC_CLIENT_REMOTE
const hal_rpc_misc_dispatch_t * hal_rpc_misc_dispatch = &hal_rpc_remote_misc_dispatch;
const hal_rpc_hash_dispatch_t * hal_rpc_hash_dispatch = &hal_rpc_remote_hash_dispatch;
const hal_rpc_pkey_dispatch_t * hal_rpc_pkey_dispatch = &hal_rpc_remote_pkey_dispatch;
#endif

#if RPC_CLIENT == RPC_CLIENT_MIXED
const hal_rpc_misc_dispatch_t * hal_rpc_misc_dispatch = &hal_rpc_remote_misc_dispatch;
const hal_rpc_hash_dispatch_t * hal_rpc_hash_dispatch = &hal_rpc_local_hash_dispatch;
const hal_rpc_pkey_dispatch_t * hal_rpc_pkey_dispatch = &hal_rpc_mixed_pkey_dispatch;
#endif

hal_error_t hal_rpc_client_init(void)
{
#if RPC_CLIENT == RPC_CLIENT_LOCAL
  return HAL_OK;
#else
  return hal_rpc_client_transport_init();
#endif
}

hal_error_t hal_rpc_client_close(void)
{
#if RPC_CLIENT == RPC_CLIENT_LOCAL
  return HAL_OK;
#else
  return hal_rpc_client_transport_close();
#endif
}


/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
