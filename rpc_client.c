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

/*
 * RPC calls.
 */

#define check(op) do { const hal_error_t _err_ = (op); if (_err_ != HAL_OK) return _err_; } while (0)

#define pad(n) (((n) + 3) & ~3)

#define nargs(n) ((n) * 4)

#if RPC_CLIENT != RPC_CLIENT_LOCAL

static hal_error_t get_version(uint32_t *version)
{
  uint8_t outbuf[nargs(1)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_GET_VERSION));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, version));
  }
  return rpc_ret;
}

static hal_error_t get_random(void *buffer, const size_t length)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2) + pad(length)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t rcvlen = length;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_GET_RANDOM));
  check(hal_xdr_encode_int(&optr, olimit, (uint32_t)length));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
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
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_SET_PIN));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, user));
  check(hal_xdr_encode_buffer(&optr, olimit, (const uint8_t *)pin, pin_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
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
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGIN));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, user));
  check(hal_xdr_encode_buffer(&optr, olimit, (const uint8_t *)pin, pin_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t logout(const hal_client_handle_t client)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGOUT));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t logout_all(void)
{
  uint8_t outbuf[nargs(1)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_LOGOUT_ALL));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t is_logged_in(const hal_client_handle_t client,
                                const hal_user_t user)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_IS_LOGGED_IN));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, user));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t hash_get_digest_len(const hal_digest_algorithm_t alg, size_t *length)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t len32;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_DIGEST_LEN));
  check(hal_xdr_encode_int(&optr, olimit, alg));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
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
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2) + pad(len_max)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t len32 = len_max;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_DIGEST_LEN));
  check(hal_xdr_encode_int(&optr, olimit, alg));
  check(hal_xdr_encode_int(&optr, olimit, len_max));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, id, &len32));
    *len = len32;
  }
  return rpc_ret;
}

static hal_error_t hash_get_algorithm(const hal_hash_handle_t hash, hal_digest_algorithm_t *alg)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t alg32;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_GET_ALGORITHM));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &alg32));
    *alg = (hal_digest_algorithm_t)alg32;
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
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_INITIALIZE));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, alg));
  check(hal_xdr_encode_buffer(&optr, olimit, key, key_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &hash->handle));
  }
  return rpc_ret;
}

static hal_error_t hash_update(const hal_hash_handle_t hash,
                               const uint8_t * data, const size_t length)
{
  uint8_t outbuf[nargs(3) + pad(length)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_UPDATE));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, data, length));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t hash_finalize(const hal_hash_handle_t hash,
                                 uint8_t *digest, const size_t length)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2) + pad(length)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t digest_len = length;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_HASH_FINALIZE));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_int(&optr, olimit, length));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, digest, &digest_len));
    /* XXX check digest_len vs length */
  }
  return rpc_ret;
}

static hal_error_t pkey_load(const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             hal_pkey_handle_t *pkey,
                             const hal_key_type_t type,
                             const hal_curve_name_t curve,
                             const uint8_t * const name, const size_t name_len,
                             const uint8_t * const der, const size_t der_len,
                             const hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(8) + pad(name_len) + pad(der_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_LOAD));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, type));
  check(hal_xdr_encode_int(&optr, olimit, curve));
  check(hal_xdr_encode_buffer(&optr, olimit, name, name_len));
  check(hal_xdr_encode_buffer(&optr, olimit, der, der_len));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK)
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));

  return rpc_ret;
}

static hal_error_t pkey_find(const hal_client_handle_t client,
                             const hal_session_handle_t session,
                             hal_pkey_handle_t *pkey,
                             const hal_key_type_t type,
                             const uint8_t * const name, const size_t name_len)
{
  uint8_t outbuf[nargs(5) + pad(name_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_FIND));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, type));
  check(hal_xdr_encode_buffer(&optr, olimit, name, name_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK)
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));

  return rpc_ret;
}

static hal_error_t pkey_generate_rsa(const hal_client_handle_t client,
                                     const hal_session_handle_t session,
                                     hal_pkey_handle_t *pkey,
                                     const uint8_t * const name, const size_t name_len,
                                     const unsigned key_len,
                                     const uint8_t * const exp, const size_t exp_len,
                                     const hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(7) + pad(name_len) + pad(exp_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GENERATE_RSA));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, name, name_len));
  check(hal_xdr_encode_int(&optr, olimit, key_len));
  check(hal_xdr_encode_buffer(&optr, olimit, exp, exp_len));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK)
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));

  return rpc_ret;
}

static hal_error_t pkey_generate_ec(const hal_client_handle_t client,
                                    const hal_session_handle_t session,
                                    hal_pkey_handle_t *pkey,
                                    const uint8_t * const name, const size_t name_len,
                                    const hal_curve_name_t curve,
                                    const hal_key_flags_t flags)
{
  uint8_t outbuf[nargs(6) + pad(name_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GENERATE_EC));
  check(hal_xdr_encode_int(&optr, olimit, client.handle));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, name, name_len));
  check(hal_xdr_encode_int(&optr, olimit, curve));
  check(hal_xdr_encode_int(&optr, olimit, flags));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK)
    check(hal_xdr_decode_int(&iptr, ilimit, &pkey->handle));

  return rpc_ret;
}

static hal_error_t pkey_close(const hal_pkey_handle_t pkey)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_CLOSE));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t pkey_delete(const hal_pkey_handle_t pkey)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_DELETE));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t pkey_get_key_type(const hal_pkey_handle_t pkey,
                                     hal_key_type_t *type)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t type32;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_KEY_TYPE));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &type32));
    *type = (hal_key_type_t)type32;
  }
  return rpc_ret;
}

static hal_error_t pkey_get_key_flags(const hal_pkey_handle_t pkey,
                                      hal_key_flags_t *flags)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t flags32;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_KEY_FLAGS));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &flags32));
    *flags = (hal_key_flags_t)flags32;
  }
  return rpc_ret;
}

static size_t pkey_get_public_key_len(const hal_pkey_handle_t pkey)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t len32;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_int(&iptr, ilimit, &len32));
    return (size_t)len32;
  }
  else
    return 0;
}

static hal_error_t pkey_get_public_key(const hal_pkey_handle_t pkey,
                                       uint8_t *der, size_t *der_len, const size_t der_max)
{
  uint8_t outbuf[nargs(3)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2) + pad(der_max)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t dlen32 = der_max;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_GET_PUBLIC_KEY));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, der_max));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, der, &dlen32));
    *der_len = (size_t)dlen32;
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_sign(const hal_session_handle_t session,
                                    const hal_pkey_handle_t pkey,
                                    const hal_hash_handle_t hash,
                                    const uint8_t * const input,  const size_t input_len,
                                    uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  uint8_t outbuf[nargs(6) + pad(input_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2) + pad(signature_max)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t slen32 = signature_max;
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_REMOTE_SIGN));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, input, input_len));
  check(hal_xdr_encode_int(&optr, olimit, signature_max));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    check(hal_xdr_decode_buffer(&iptr, ilimit, signature, &slen32));
    *signature_len = (size_t)slen32;
  }
  return rpc_ret;
}

static hal_error_t pkey_remote_verify(const hal_session_handle_t session,
                                      const hal_pkey_handle_t pkey,
                                      const hal_hash_handle_t hash,
                                      const uint8_t * const input, const size_t input_len,
                                      const uint8_t * const signature, const size_t signature_len)
{
  uint8_t outbuf[nargs(6) + pad(input_len) + pad(signature_len)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(1)], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  hal_error_t rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_REMOTE_VERIFY));
  check(hal_xdr_encode_int(&optr, olimit, session.handle));
  check(hal_xdr_encode_int(&optr, olimit, pkey.handle));
  check(hal_xdr_encode_int(&optr, olimit, hash.handle));
  check(hal_xdr_encode_buffer(&optr, olimit, input, input_len));
  check(hal_xdr_encode_buffer(&optr, olimit, signature, signature_len));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  return rpc_ret;
}

static hal_error_t hal_xdr_decode_pkey_info(uint8_t **iptr, const uint8_t * const ilimit, hal_pkey_info_t *info)
{
  uint32_t i32;

  check(hal_xdr_decode_int(iptr, ilimit, &i32)); info->type = i32;
  check(hal_xdr_decode_int(iptr, ilimit, &i32)); info->curve = i32;
  check(hal_xdr_decode_int(iptr, ilimit, &i32)); info->flags = i32;
  check(hal_xdr_decode_buffer(iptr, ilimit, (uint8_t *)&info->name[0], &i32)); info->name_len = i32;
  return HAL_OK;
}

static hal_error_t pkey_list(hal_pkey_info_t *result,
                             unsigned *result_len,
                             const unsigned result_max)
{
  uint8_t outbuf[nargs(2)], *optr = outbuf, *olimit = outbuf + sizeof(outbuf);
  uint8_t inbuf[nargs(2) + pad(result_max * sizeof(hal_pkey_info_t))], *iptr = inbuf, *ilimit = inbuf + sizeof(inbuf);
  size_t ilen = sizeof(inbuf);
  uint32_t len;
  hal_error_t ret, rpc_ret;

  check(hal_xdr_encode_int(&optr, olimit, RPC_FUNC_PKEY_LIST));
  check(hal_xdr_encode_int(&optr, olimit, result_max));
  check(hal_rpc_send(outbuf, optr - outbuf));

  check(hal_rpc_recv(inbuf, &ilen));
  assert(ilen <= sizeof(inbuf));
  check(hal_xdr_decode_int(&iptr, ilimit, &rpc_ret));
  if (rpc_ret == HAL_OK) {
    int i;
    check(hal_xdr_decode_int(&iptr, ilimit, &len));
    *result_len = len;
    for (i = 0; i < len; ++i) {
      if ((ret = hal_xdr_decode_pkey_info(&iptr, ilimit, &result[i])) != HAL_OK) {
        *result_len = 0;
        return ret;
      }
    }
  }
  return rpc_ret;
}


/*
 * "Mixed" mode pkey operations, where the public key operation itself
 * takes place on the HSM but the hashing takes place locally.  If
 * we're given a hash context in this case, it's local, so we have to
 * pull the digest from the hash context and send that to the HSM.
 */

static hal_error_t pkey_mixed_sign(const hal_session_handle_t session,
                                   const hal_pkey_handle_t pkey,
                                   const hal_hash_handle_t hash,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * signature, size_t *signature_len, const size_t signature_max)
{
  if (input != NULL)
    return pkey_remote_sign(session, pkey, hash, input, input_len,
                            signature, signature_len, signature_max);

  hal_digest_algorithm_t alg;
  size_t digest_len;
  hal_error_t err;

  if ((err = hal_rpc_hash_get_algorithm(hash, &alg))           != HAL_OK ||
      (err = hal_rpc_hash_get_digest_length(alg, &digest_len)) != HAL_OK)
    return err;

  uint8_t digest[digest_len];

  if ((err = hal_rpc_hash_finalize(hash, digest, digest_len)) != HAL_OK)
    return err;

  return pkey_remote_sign(session, pkey, hal_hash_handle_none, digest, digest_len,
                          signature, signature_len, signature_max);
}

static hal_error_t pkey_mixed_verify(const hal_session_handle_t session,
                                     const hal_pkey_handle_t pkey,
                                     const hal_hash_handle_t hash,
                                     const uint8_t * const input, const size_t input_len,
                                     const uint8_t * const signature, const size_t signature_len)
{
  if (input != NULL)
    return pkey_remote_verify(session, pkey, hash, input, input_len,
                              signature, signature_len);

  hal_digest_algorithm_t alg;
  size_t digest_len;
  hal_error_t err;

  if ((err = hal_rpc_hash_get_algorithm(hash, &alg))           != HAL_OK ||
      (err = hal_rpc_hash_get_digest_length(alg, &digest_len)) != HAL_OK)
    return err;

  uint8_t digest[digest_len];

  if ((err = hal_rpc_hash_finalize(hash, digest, digest_len)) != HAL_OK)
    return err;

  return pkey_remote_verify(session, pkey, hal_hash_handle_none, digest, digest_len,
                            signature, signature_len);
}

/*
 * Dispatch vectors.
 */

const hal_rpc_misc_dispatch_t hal_rpc_remote_misc_dispatch = {
  set_pin, login, logout, logout_all, is_logged_in, get_random, get_version
};

const hal_rpc_hash_dispatch_t hal_rpc_remote_hash_dispatch = {
  hash_get_digest_len, hash_get_digest_algorithm_id, hash_get_algorithm,
  hash_initialize, hash_update, hash_finalize
};

const hal_rpc_pkey_dispatch_t hal_rpc_remote_pkey_dispatch = {
  pkey_load, pkey_find, pkey_generate_rsa, pkey_generate_ec, pkey_close, pkey_delete,
  pkey_get_key_type, pkey_get_key_flags, pkey_get_public_key_len, pkey_get_public_key,
  pkey_remote_sign, pkey_remote_verify,
  pkey_list
};

const hal_rpc_pkey_dispatch_t hal_rpc_mixed_pkey_dispatch = {
  pkey_load, pkey_find, pkey_generate_rsa, pkey_generate_ec, pkey_close, pkey_delete,
  pkey_get_key_type, pkey_get_key_flags, pkey_get_public_key_len, pkey_get_public_key,
  pkey_mixed_sign, pkey_mixed_verify,
  pkey_list
};

#endif /* RPC_CLIENT != RPC_CLIENT_LOCAL */

#if RPC_CLIENT == RPC_CLIENT_LOCAL
const hal_rpc_misc_dispatch_t * hal_rpc_misc_dispatch = &hal_rpc_local_misc_dispatch;
const hal_rpc_hash_dispatch_t * hal_rpc_hash_dispatch = &hal_rpc_local_hash_dispatch;
const hal_rpc_pkey_dispatch_t * hal_rpc_pkey_dispatch = &hal_rpc_local_pkey_dispatch;
#elif RPC_CLIENT == RPC_CLIENT_REMOTE
const hal_rpc_misc_dispatch_t * hal_rpc_misc_dispatch = &hal_rpc_remote_misc_dispatch;
const hal_rpc_hash_dispatch_t * hal_rpc_hash_dispatch = &hal_rpc_remote_hash_dispatch;
const hal_rpc_pkey_dispatch_t * hal_rpc_pkey_dispatch = &hal_rpc_remote_pkey_dispatch;
#elif RPC_CLIENT == RPC_CLIENT_MIXED
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
