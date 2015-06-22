/*
 * rsa.c
 * -----
 * Basic RSA functions based on Cryptech ModExp core.
 *
 * The mix of what we're doing in software vs what we're doing on the
 * FPGA is a moving target.  Goal for now is to have the bits we need
 * to do in C be straightforward to review and as simple as possible
 * (but no simpler).
 *
 * Much of the code in this module is based, at least loosely, on Tom
 * St Denis's libtomcrypt code.  
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
#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "cryptech.h"

/*
 * Whether to use ModExp core.  It works, but at the moment it's so
 * slow that a full test run can take more than an hour.
 */

#ifndef HAL_RSA_USE_MODEXP
#define HAL_RSA_USE_MODEXP 1
#endif

/*
 * Use "Tom's Fast Math" library for our bignum implementation.  This
 * particular implementation has a couple of nice features:
 *
 * - The code is relatively readable, thus reviewable.
 *
 * - The bignum representation doesn't use dynamic memory, which
 *   simplifies things for us.
 *
 * The price tag for not using dynamic memory is that libtfm has to be
 * configured to know about the largest bignum one wants it to be able
 * to support at compile time.  This should not be a serious problem.
 */

#include <tfm.h>

/*
 * Whether we want debug output.
 */

static int debug = 0;

void hal_rsa_set_debug(const int onoff)
{
  debug = onoff;
}

/*
 * Whether we want RSA blinding.
 */

static int blinding = 1;

void hal_rsa_set_blinding(const int onoff)
{
  blinding = onoff;
}

/*
 * RSA key implementation.  This structure type is private to this
 * module, anything else that needs to touch one of these just gets a
 * typed opaque pointer.  We do, however, export the size, so that we
 * can make memory allocation the caller's problem.
 */

struct rsa_key {
  hal_rsa_key_type_t type;      /* What kind of key this is */
  fp_int n;                     /* The modulus */
  fp_int e;                     /* Public exponent */
  fp_int d;                     /* Private exponent */
  fp_int p;                     /* 1st prime factor */
  fp_int q;                     /* 2nd prime factor */
  fp_int u;                     /* 1/q mod p */
  fp_int dP;                    /* d mod (p - 1) */
  fp_int dQ;                    /* d mod (q - 1) */
};

const size_t hal_rsa_key_t_size = sizeof(struct rsa_key);

/*
 * Error handling.
 */

#define lose(_code_)                                    \
  do { err = _code_; goto fail; } while (0)

#define FP_CHECK(_expr_)                                \
  do {                                                  \
    switch (_expr_) {                                   \
    case FP_OKAY: break;                                \
    case FP_VAL:  lose(HAL_ERROR_BAD_ARGUMENTS);        \
    case FP_MEM:  lose(HAL_ERROR_ALLOCATION_FAILURE);   \
    default:      lose(HAL_ERROR_IMPOSSIBLE);  		\
    }                                                   \
  } while (0)


/*
 * Unpack a bignum into a byte array, with length check.
 */

static hal_error_t unpack_fp(fp_int *bn, uint8_t *buffer, const size_t length)
{
  hal_error_t err = HAL_OK;

  assert(bn != NULL && buffer != NULL);

  const size_t bytes = fp_unsigned_bin_size(bn);

  if (bytes > length)
    lose(HAL_ERROR_RESULT_TOO_LONG);

  memset(buffer, 0, length);
  fp_to_unsigned_bin(bn, buffer + length - bytes);

 fail:
  return err;
}

#if HAL_RSA_USE_MODEXP

/*
 * Unwrap bignums into byte arrays, feed them into hal_modexp(), and
 * wrap result back up as a bignum.
 */

static hal_error_t modexp(fp_int *msg, fp_int *exp, fp_int *mod, fp_int *res)
{
  hal_error_t err = HAL_OK;

  assert(msg != NULL && exp != NULL && mod != NULL && res != NULL);

  const size_t msg_len = fp_unsigned_bin_size(msg);
  const size_t exp_len = fp_unsigned_bin_size(exp);
  const size_t mod_len = fp_unsigned_bin_size(mod);

  const size_t len = (MAX(MAX(msg_len, exp_len), mod_len) + 3) & ~3;

  uint8_t msgbuf[len], expbuf[len], modbuf[len], resbuf[len];

  if ((err = unpack_fp(msg, msgbuf, sizeof(msgbuf))) != HAL_OK ||
      (err = unpack_fp(exp, expbuf, sizeof(expbuf))) != HAL_OK ||
      (err = unpack_fp(mod, modbuf, sizeof(modbuf))) != HAL_OK ||
      (err = hal_modexp(msgbuf, sizeof(msgbuf),
                        expbuf, sizeof(expbuf),
                        modbuf, sizeof(modbuf),
                        resbuf, sizeof(resbuf))) != HAL_OK)
    goto fail;

  fp_read_unsigned_bin(res, resbuf, sizeof(resbuf));

 fail:
  memset(msgbuf, 0, sizeof(msgbuf));
  memset(expbuf, 0, sizeof(expbuf));
  memset(modbuf, 0, sizeof(modbuf));
  return err;
}

/*
 * Wrapper to let us export our modexp function as a replacement for
 * TFM's, to avoid dragging in all of the TFM montgomery code when we
 * use TFM's Miller-Rabin test code.
 *
 * This code is here rather than in a separate module because of the
 * error handling: TFM's error codes aren't really capable of
 * expressing all the things that could go wrong here.
 */

int fp_exptmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  return modexp(a, b, c, d) == HAL_OK ? FP_OKAY : FP_VAL;
}

#else /* HAL_RSA_USE_MODEXP */

/*
 * Workaround to let us use TFM's software implementation of modular
 * exponentiation when we want to test other things and don't want to
 * wait for the slow FPGA implementation.
 */

static hal_error_t modexp(fp_int *msg, fp_int *exp, fp_int *mod, fp_int *res)
{
  hal_error_t err = HAL_OK;
  FP_CHECK(fp_exptmod(msg, exp, mod, res));
 fail:
  return err;
}

#endif /* HAL_RSA_USE_MODEXP */

/*
 * Create blinding factors.  There are various schemes for amortizing
 * the cost of this over multiple RSA operations, at present we don't
 * try.  Come back to this if it looks like a bottleneck.
 */

static hal_error_t create_blinding_factors(struct rsa_key *key, fp_int *bf, fp_int *ubf)
{
  assert(key != NULL && bf != NULL && ubf != NULL);

  uint8_t rnd[fp_unsigned_bin_size(&key->n)];
  hal_error_t err = HAL_OK;

  if ((err = hal_get_random(rnd, sizeof(rnd))) != HAL_OK)
    goto fail;

  fp_init(bf);
  fp_read_unsigned_bin(bf,  rnd, sizeof(rnd));
  fp_copy(bf, ubf);

  if ((err = modexp(bf, &key->e, &key->n, bf)) != HAL_OK)
    goto fail;

  FP_CHECK(fp_invmod(ubf, &key->n, ubf));

 fail:
  memset(rnd, 0, sizeof(rnd));
  return err;
}

/*
 * RSA decryption via Chinese Remainder Theorem (Garner's formula).
 */

static hal_error_t rsa_crt(struct rsa_key *key, fp_int *msg, fp_int *sig)
{
  assert(key != NULL && msg != NULL && sig != NULL);

  hal_error_t err = HAL_OK;
  fp_int t, m1, m2, bf, ubf;

  fp_init(&t);
  fp_init(&m1);
  fp_init(&m2);

  /*
   * Handle blinding if requested.
   */
  if (blinding) {
    if ((err = create_blinding_factors(key, &bf, &ubf)) != HAL_OK)
      goto fail;
    FP_CHECK(fp_mulmod(msg, &bf, &key->n, msg));
  }

  /*
   * m1 = msg ** dP mod p
   * m2 = msg ** dQ mod q
   */
  if ((err = modexp(msg, &key->dP, &key->p, &m1)) != HAL_OK ||
      (err = modexp(msg, &key->dQ, &key->q, &m2)) != HAL_OK)
    goto fail;

  /*
   * t = m1 - m2.
   */
  fp_sub(&m1, &m2, &t);

  /*
   * Add zero (mod p) if needed to make t positive.  If doing this
   * once or twice doesn't help, something is very wrong.
   */
  if (fp_cmp_d(&t, 0) == FP_LT)
    fp_add(&t, &key->p, &t);
  if (fp_cmp_d(&t, 0) == FP_LT)
    fp_add(&t, &key->p, &t);
  if (fp_cmp_d(&t, 0) == FP_LT)
    lose(HAL_ERROR_IMPOSSIBLE);

  /*
   * sig = (t * u mod p) * q + m2
   */
  FP_CHECK(fp_mulmod(&t, &key->u, &key->p, &t));
  fp_mul(&t, &key->q, &t);
  fp_add(&t, &m2, sig);

  /*
   * Unblind if necessary.
   */
  if (blinding)
    FP_CHECK(fp_mulmod(sig, &ubf, &key->n, sig));

 fail:
  fp_zero(&t);
  fp_zero(&m1);
  fp_zero(&m2);
  return err;
}

/*
 * Public API for raw RSA encryption and decryption.
 *
 * NB: This does not handle PKCS #1.5 padding, at the moment that's up
 * to the caller.
 */

hal_error_t hal_rsa_encrypt(hal_rsa_key_t key_,
                            const uint8_t * const input,  const size_t input_len,
                            uint8_t * output, const size_t output_len)
{
  struct rsa_key *key = key_.key;
  hal_error_t err = HAL_OK;

  if (key == NULL || input == NULL || output == NULL || input_len > output_len)
    return HAL_ERROR_BAD_ARGUMENTS;

  fp_int i, o;
  fp_init(&i);
  fp_init(&o);

  fp_read_unsigned_bin(&i, (uint8_t *) input, input_len);

  if ((err = modexp(&i, &key->e, &key->n, &o)) != HAL_OK ||
      (err = unpack_fp(&o, output, output_len))   != HAL_OK)
    goto fail;

 fail:
  fp_zero(&i);
  fp_zero(&o);
  return err;
}

hal_error_t hal_rsa_decrypt(hal_rsa_key_t key_,
                            const uint8_t * const input,  const size_t input_len,
                            uint8_t * output, const size_t output_len)
{
  struct rsa_key *key = key_.key;
  hal_error_t err = HAL_OK;

  if (key == NULL || input == NULL || output == NULL || input_len > output_len)
    return HAL_ERROR_BAD_ARGUMENTS;

  fp_int i, o;
  fp_init(&i);
  fp_init(&o);

  fp_read_unsigned_bin(&i, (uint8_t *) input, input_len);

  /*
   * Do CRT if we have all the necessary key components, otherwise
   * just do brute force ModExp.
   */

  if (fp_iszero(&key->p) || fp_iszero(&key->q) || fp_iszero(&key->u) || fp_iszero(&key->dP) || fp_iszero(&key->dQ))
    err = modexp(&i, &key->d, &key->n, &o);
  else
    err = rsa_crt(key, &i, &o);
  
  if (err != HAL_OK || (err = unpack_fp(&o, output, output_len)) != HAL_OK)
    goto fail;

 fail:
  fp_zero(&i);
  fp_zero(&o);
  return err;
}

/*
 * Clear a key.  We might want to do something a bit more energetic
 * than plain old memset() eventually.
 */

void hal_rsa_key_clear(hal_rsa_key_t key)
{
  if (key.key != NULL)
    memset(key.key, 0, sizeof(struct rsa_key));
}

/*
 * Load a key from raw components.  This is a simplistic version: we
 * don't attempt to generate missing private key components, we just
 * reject the key if it doesn't have everything we expect.
 *
 * In theory, the only things we'd really need for the private key if
 * we were being nicer about this would be e, p, and q, as we could
 * calculate everything else from them.
 */

hal_error_t hal_rsa_key_load(const hal_rsa_key_type_t type,
                             hal_rsa_key_t *key_,
                             void *keybuf, const size_t keybuf_len,
                             const uint8_t * const n,  const size_t n_len,
                             const uint8_t * const e,  const size_t e_len,
                             const uint8_t * const d,  const size_t d_len,
                             const uint8_t * const p,  const size_t p_len,
                             const uint8_t * const q,  const size_t q_len,
                             const uint8_t * const u,  const size_t u_len,
                             const uint8_t * const dP, const size_t dP_len,
                             const uint8_t * const dQ, const size_t dQ_len)
{
  if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(struct rsa_key))
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(keybuf, 0, keybuf_len);

  struct rsa_key *key = keybuf;

  key->type = type;

#define _(x) do { fp_init(&key->x); if (x == NULL) goto fail; fp_read_unsigned_bin(&key->x, (uint8_t *) x, x##_len); } while (0)
  switch (type) {
  case HAL_RSA_PRIVATE:
    _(d); _(p); _(q); _(u); _(dP); _(dQ);
  case HAL_RSA_PUBLIC:
    _(n); _(e);
    key_->key = key;
    return HAL_OK;
  }
#undef _

 fail:
  memset(key, 0, sizeof(*key));
  return HAL_ERROR_BAD_ARGUMENTS;
}

/*
 * Extract public key components.
 */

static hal_error_t extract_component(hal_rsa_key_t key_, const size_t offset,
                                     uint8_t *res, size_t *res_len, const size_t res_max)
{
  if (key_.key == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  fp_int *bn = (fp_int *) (((uint8_t *) key_.key) + offset);

  const size_t len = fp_unsigned_bin_size(bn);

  if (res_len != NULL)
    *res_len = len;

  if (res == NULL)
    return HAL_OK;

  if (len > res_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  memset(res, 0, res_max);
  fp_to_unsigned_bin(bn, res);
  return HAL_OK;
}

hal_error_t hal_rsa_key_get_modulus(hal_rsa_key_t key_,
                                    uint8_t *res, size_t *res_len, const size_t res_max)
{
  return extract_component(key_, offsetof(struct rsa_key, n), res, res_len, res_max);
}

hal_error_t hal_rsa_key_get_public_exponent(hal_rsa_key_t key_,
                                            uint8_t *res, size_t *res_len, const size_t res_max)
{
  return extract_component(key_, offsetof(struct rsa_key, e), res, res_len, res_max);
}

/*
 * Generate a prime factor for an RSA keypair.
 * 
 * Get random bytes, munge a few bits, and stuff into a bignum.  Keep
 * doing this until we find a result that's (probably) prime and for
 * which result - 1 is relatively prime with respect to e.
 */

static hal_error_t find_prime(unsigned prime_length, fp_int *e, fp_int *result)
{
  uint8_t buffer[prime_length];
  hal_error_t err;
  fp_int t;

  fp_init(&t);

  do {
    if ((err = hal_get_random(buffer, sizeof(buffer))) != HAL_OK)
      return err;
    buffer[0                 ] |= 0xc0;
    buffer[sizeof(buffer) - 1] |= 0x01;
    fp_read_unsigned_bin(result, buffer, sizeof(buffer));

  } while (!fp_isprime(result) ||
           (fp_sub_d(result, 1, &t), fp_gcd(&t, e, &t), fp_cmp_d(&t, 1) != FP_EQ));

  fp_zero(&t);
  return HAL_OK;
}

/*
 * Generate a new RSA keypair.
 */

hal_error_t hal_rsa_key_gen(hal_rsa_key_t *key_,
                            void *keybuf, const size_t keybuf_len,
                            const unsigned key_length,
                            const uint8_t * const public_exponent, const size_t public_exponent_len)
{
  struct rsa_key *key = keybuf;
  hal_error_t err = HAL_OK;
  fp_int p_1, q_1;

  if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(struct rsa_key))
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(keybuf, 0, keybuf_len);
  key->type = HAL_RSA_PRIVATE;
  fp_read_unsigned_bin(&key->e, (uint8_t *) public_exponent, public_exponent_len);

  if (key_length != bitsToBytes(1024) && key_length != bitsToBytes(2048) &&
      key_length != bitsToBytes(4096) && key_length != bitsToBytes(8192))
    return HAL_ERROR_UNSUPPORTED_KEY;

  if (fp_cmp_d(&key->e, 0x010001) != FP_EQ)
    return HAL_ERROR_UNSUPPORTED_KEY;

  /*
   * Find a good pair of prime numbers.
   */

  if ((err = find_prime(key_length / 2, &key->e, &key->p)) != HAL_OK ||
      (err = find_prime(key_length / 2, &key->e, &key->q)) != HAL_OK)
    return err;

  /*
   * Calculate remaining key components.
   */

  fp_init(&p_1); fp_sub_d(&key->p, 1, &p_1);
  fp_init(&q_1); fp_sub_d(&key->q, 1, &q_1);
  fp_mul(&key->p, &key->q, &key->n);                    /* n = p * q */
  fp_lcm(&p_1, &q_1, &key->d);
  FP_CHECK(fp_invmod(&key->e, &key->d, &key->d));       /* d = (1/e) % lcm(p-1, q-1) */
  FP_CHECK(fp_mod(&key->d, &p_1, &key->dP));            /* dP = d % (p-1) */
  FP_CHECK(fp_mod(&key->d, &q_1, &key->dQ));            /* dQ = d % (q-1) */
  FP_CHECK(fp_invmod(&key->q, &key->p, &key->u));       /* u = (1/q) % p */

  key_->key = key;

  /* Fall through to cleanup */

 fail:
  if (err != HAL_OK)
    memset(keybuf, 0, keybuf_len);
  fp_zero(&p_1);
  fp_zero(&q_1);
  return err;
}

/*
 * Minimal ASN.1 encoding and decoding for private keys.  This is NOT
 * a general-purpose ASN.1 implementation, just enough to read and
 * write PKCS #1.5 RSAPrivateKey syntax (RFC 2313 section 7.2).
 *
 * If at some later date we need a full ASN.1 implementation we'll add
 * it as (a) separate library module(s), but for now the goal is just
 * to let us serialize private keys for internal use and debugging.
 */

#define	ASN1_INTEGER	0x02
#define	ASN1_SEQUENCE	0x30

/*
 * RSAPrivateKey fields in the required order.
 */

#define RSAPrivateKey_fields    \
  _(&version);                  \
  _(&key->n);                   \
  _(&key->e);                   \
  _(&key->d);                   \
  _(&key->p);                   \
  _(&key->q);                   \
  _(&key->dP);                  \
  _(&key->dQ);                  \
  _(&key->u);

static size_t count_length(size_t length)
{
  size_t result = 1;

  if (length >= 128)
    for (; length > 0; length >>= 8)
      result++;

  return result;
}

static void encode_length(size_t length, size_t length_len, uint8_t *der)
{
  assert(der != NULL && length_len > 0 && length_len < 128);

  if (length < 128) {
    assert(length_len == 1);
    *der = (uint8_t) length;
  }

  else {
    *der = 0x80 | (uint8_t) --length_len;
    while (length > 0 && length_len > 0) {
      der[length_len--] = (uint8_t) (length & 0xFF);
      length >>= 8;
    }
    assert(length == 0 && length_len == 0);
  }
}

static hal_error_t decode_header(const uint8_t tag,
                                 const uint8_t * const der, size_t der_max,
                                 size_t *hlen, size_t *vlen)
{
  assert(der != NULL && hlen != NULL && vlen != NULL);

  if (der_max < 2 || der[0] != tag)
    return HAL_ERROR_ASN1_PARSE_FAILED;

  if ((der[1] & 0x80) == 0) {
    *hlen = 2;
    *vlen = der[1];
  }

  else {
    *hlen = 2 + (der[1] & 0x7F);
    *vlen = 0;

    if (*hlen > der_max)
      return HAL_ERROR_ASN1_PARSE_FAILED;

    for (size_t i = 2; i < *hlen; i++)
      *vlen = (*vlen << 8) + der[i];
  }

  if (*hlen + *vlen > der_max)
    return HAL_ERROR_ASN1_PARSE_FAILED;

  return HAL_OK;
}

static hal_error_t encode_integer(fp_int *bn,
                                  uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (bn == NULL || der_len == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * Calculate length.  Need to pad data with a leading zero if most
   * significant bit is set, to avoid flipping ASN.1 sign bit.  If
   * caller didn't supply a buffer, just return the total length.
   */

  const int cmp = fp_cmp_d(bn, 0);

  if (cmp != FP_EQ && cmp != FP_GT)
    return HAL_ERROR_BAD_ARGUMENTS;

  const int leading_zero  = (cmp == FP_EQ || (fp_count_bits(bn) & 7) == 0);
  const size_t data_len   = fp_unsigned_bin_size(bn) + leading_zero;
  const size_t tag_len    = 1;
  const size_t length_len = count_length(data_len);
  const size_t total_len  = tag_len + length_len + data_len;

  *der_len = total_len;

  if (der == NULL)
    return HAL_OK;

  if (total_len > der_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  /*
   * Now encode.
   */

  *der++ = ASN1_INTEGER;
  encode_length(data_len, length_len, der);
  der += length_len;
  if (leading_zero)
    *der++ = 0x00;
  fp_to_unsigned_bin(bn, der);

  return HAL_OK;
}

static hal_error_t decode_integer(fp_int *bn,
                                  const uint8_t * const der, size_t *der_len, const size_t der_max)
{
  if (bn == NULL || der == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err;
  size_t hlen, vlen;

  if ((err = decode_header(ASN1_INTEGER, der, der_max, &hlen, &vlen)) != HAL_OK)
    return err;

  if (der_len != NULL)
    *der_len = hlen + vlen;

  if (vlen < 1 || (der[hlen] & 0x80) != 0x00)
    return HAL_ERROR_ASN1_PARSE_FAILED;

  fp_init(bn);
  fp_read_unsigned_bin(bn, (uint8_t *) der + hlen, vlen);
  return HAL_OK;
}

hal_error_t hal_rsa_key_to_der(hal_rsa_key_t key_,
                               uint8_t *der, size_t *der_len, const size_t der_max)
{
  struct rsa_key *key = key_.key;
  hal_error_t err = HAL_OK;

  if (key == NULL || der_len == NULL || key->type != HAL_RSA_PRIVATE)
    return HAL_ERROR_BAD_ARGUMENTS;

  fp_int version;
  fp_zero(&version);

  /*
   * Calculate length.
   */

  size_t data_len = 0;

#define _(x) { size_t i; if ((err = encode_integer(x, NULL, &i, der_max - data_len)) != HAL_OK) return err; data_len += i; }
  RSAPrivateKey_fields;
#undef _

  const size_t tag_len    = 1;
  const size_t length_len = count_length(data_len);
  const size_t total_len  = tag_len + length_len + data_len;

  *der_len = total_len;

  if (der == NULL)
    return HAL_OK;

  if (total_len > der_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  /*
   * Now encode.
   */

  *der++ = ASN1_SEQUENCE;
  encode_length(data_len, length_len, der);
  der += length_len;
  
#define _(x) { size_t i; if ((err = encode_integer(x, der, &i, data_len)) != HAL_OK) return err; der += i; data_len -= i; }
  RSAPrivateKey_fields;
#undef _

  return HAL_OK;
}

size_t hal_rsa_key_to_der_len(hal_rsa_key_t key_)
{
  size_t len = 0;
  return hal_rsa_key_to_der(key_, NULL, &len, 0) == HAL_OK ? len : 0;
}

hal_error_t hal_rsa_key_from_der(hal_rsa_key_t *key_,
                                 void *keybuf, const size_t keybuf_len,
                                 const uint8_t *der, const size_t der_len)
{
  if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(struct rsa_key) || der == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(keybuf, 0, keybuf_len);

  struct rsa_key *key = keybuf;

  key->type = HAL_RSA_PRIVATE;

  hal_error_t err = HAL_OK;
  size_t hlen, vlen;

  if ((err = decode_header(ASN1_SEQUENCE, der, der_len, &hlen, &vlen)) != HAL_OK)
    return err;

  der += hlen;

  fp_int version;
  fp_init(&version);

#define _(x) { size_t i; if ((err = decode_integer(x, der, &i, vlen)) != HAL_OK) return err; der += i; vlen -= i; }
  RSAPrivateKey_fields;
#undef _

  if (fp_cmp_d(&version, 0) != FP_EQ)
    return HAL_ERROR_ASN1_PARSE_FAILED;

  key_->key = key;

  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
