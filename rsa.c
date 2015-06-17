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
#include <string.h>
#include <assert.h>

#include "cryptech.h"

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

#include "tfm.h"

/*
 * Whether we want debug output.
 */

static int debug = 0;

void hal_rsa_set_debug(const int onoff)
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
 * RSA key implementation.  This structure type is private to this
 * module, anything else that needs to touch one of these just gets a
 * typed opaque pointer.  We do, however, export the size, so that we
 * can make memory allocation the caller's problem (well, maybe).
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
 * In the long run we want a full RSA implementation, or enough of one
 * to cover what we need in PKCS #11.  For the moment, though, the
 * most urgent thing is to see whether this approach to performing the
 * CRT calculation works (and is any faster), followed by whether we
 * can use this approach for key generation.
 *
 * So don't worry about whether the following functions are what we
 * want in the long run, they'll probably evolve as we go.
 */

#warning Should do RSA blinding, skipping for now

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

/*
 * Unwrap bignums into byte arrays, feeds them into hal_modexp(), and
 * wrap result back up as a bignum.
 */

static hal_error_t modexp_fp(fp_int *msg, fp_int *exp, fp_int *mod, fp_int *res)
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
 * RSA decyrption/signature using the Chinese Remainder Theorem
 * (Garner's formula).
 */

hal_error_t hal_rsa_crt(hal_rsa_key_t key_,
                        const uint8_t * const m,  const size_t m_len,
                        uint8_t * result, const size_t result_len)
{
  hal_error_t err = HAL_OK;
  struct rsa_key *key = key_.key;
  struct { fp_int t, msg, m1, m2; } tmp;

  fp_init(&tmp.t);
  fp_init(&tmp.msg);
  fp_init(&tmp.m1);
  fp_init(&tmp.m2);

  fp_read_unsigned_bin(&tmp.msg, (uint8_t *) m, m_len);

  /*
   * m1 = msg ** dP mod p
   * m2 = msg ** dQ mod q
   */
  if ((err = modexp_fp(&tmp.msg, &key->dP, &key->p, &tmp.m1)) != HAL_OK ||
      (err = modexp_fp(&tmp.msg, &key->dQ, &key->q, &tmp.m2)) != HAL_OK)
    goto fail;

  /*
   * t = m1 - m2.
   * Add zero (mod p) once or twice if necessary to get positive result.
   */
  fp_sub(&tmp.m1, &tmp.m2, &tmp.t);
  if (fp_cmp_d(&tmp.t, 0) == FP_LT)
    fp_add(&tmp.t, &key->p, &tmp.t);
  if (fp_cmp_d(&tmp.t, 0) == FP_LT)
    fp_add(&tmp.t, &key->p, &tmp.t);
  if (fp_cmp_d(&tmp.t, 0) == FP_LT)
    lose(HAL_ERROR_IMPOSSIBLE);

  /*
   * t = (t * u mod p) * q + m2
   */
  FP_CHECK(fp_mulmod(&tmp.t, &key->u, &key->p, &tmp.t));
  fp_mul(&tmp.t, &key->q, &tmp.t);
  fp_add(&tmp.t, &tmp.m2, &tmp.t);

  /*
   * t now holds result, write it back to caller
   */
  if ((err = unpack_fp(&tmp.t, result, result_len)) != HAL_OK)
    goto fail;

  /*
   * Done, fall through into cleanup.
   */

 fail:
  memset(&tmp, 0, sizeof(tmp));
  return err;
}

static hal_error_t find_prime(unsigned prime_length, fp_int *e, fp_int *result)
{
  uint8_t buffer[prime_length];
  hal_error_t err;
  fp_int t;

  /*
   * Get random bytes, munge a few bits, and stuff into a bignum.
   * Keep doing this until we find a result that's (probably) prime
   * and for which result - 1 is relatively prime with respect to e.
   */

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

hal_error_t hal_rsa_gen(hal_rsa_key_t *key_,
                        void *keybuf, const size_t keybuf_len,
                        const unsigned key_length,
                        const unsigned long public_exponent)
{
  struct rsa_key *key = keybuf;
  hal_error_t err = HAL_OK;
  fp_int p_1, q_1;

  if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(struct rsa_key))
    return HAL_ERROR_BAD_ARGUMENTS;

  switch (key_length) {
  case bitsToBytes(1024):
  case bitsToBytes(2048):
  case bitsToBytes(4096):
  case bitsToBytes(8192):
    break;
  default:
    return HAL_ERROR_UNSUPPORTED_KEY;
  }

  switch (public_exponent) {
  case 0x010001:
    break;
  default:
    return HAL_ERROR_UNSUPPORTED_KEY;
  }

  /*
   * Initialize key
   */

  memset(keybuf, 0, keybuf_len);
  key->type = HAL_RSA_PRIVATE;
  fp_set(&key->e, public_exponent);

  /*
   * Find a good pair of prime numbers.
   */

  if ((err = find_prime(key_length / 2, &key->e, &key->p)) != HAL_OK ||
      (err = find_prime(key_length / 2, &key->e, &key->q)) != HAL_OK)
    return err;

  /*
   * Calculate remaining key components.
   */

  fp_sub_d(&key->p, 1, &p_1);
  fp_sub_d(&key->q, 1, &q_1);
  fp_mul(&key->p, &key->q, &key->n);                    /* n = p * q */
  fp_lcm(&p_1, &q_1, &key->d);
  FP_CHECK(fp_invmod(&key->e, &key->d, &key->d));       /* d = (1/e) % lcm(p-1, q-1) */
  FP_CHECK(fp_mod(&key->d, &p_1, &key->dP));            /* dP = d % (p-1) */
  FP_CHECK(fp_mod(&key->d, &q_1, &key->dQ));            /* dQ = d % (q-1) */
  FP_CHECK(fp_invmod(&key->q, &key->p, &key->u));       /* u = (1/q) % p */

  /* Fall through to cleanup */

 fail:
  fp_zero(&p_1);
  fp_zero(&q_1);
  return err;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
