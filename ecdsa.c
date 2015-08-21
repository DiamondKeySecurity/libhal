/*
 * ecdsa.c
 * -------
 * Basic ECDSA functions.
 *
 * At some point we may want to refactor this to separate
 * functionality that appiles to all elliptic curve cryptography from
 * functions specific to ECDSA over the NIST Suite B prime curves, but
 * it's simplest to keep this all in one place initially.
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

/*
 * We use "Tom's Fast Math" library for our bignum implementation.
 * This particular implementation has a couple of nice features:
 *
 * - The code is relatively readable, thus reviewable.
 *
 * - The bignum representation doesn't use dynamic memory, which
 *   simplifies things for us.
 *
 * The price tag for not using dynamic memory is that libtfm has to be
 * configured to know about the largest bignum one wants it to be able
 * to support at compile time.  This should not be a serious problem.
 *
 * We use a lot of one-element arrays (fp_int[1] instead of plain
 * fp_int) to avoid having to prefix every use of an fp_int with "&".
 *
 * Unfortunately, libtfm is bad about const-ification, but we want to
 * hide that from our users, so our public API uses const as
 * appropriate and we use inline functions to remove const constraints
 * in a relatively type-safe manner before calling libtom.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "hal.h"
#include <tfm.h>
#include "asn1_internal.h"

/*
 * Whether we want debug output.
 */

static int debug = 0;

void hal_ecdsa_set_debug(const int onoff)
{
  debug = onoff;
}

/*
 * ECDSA curve descriptor.  We only deal with named curves; at the
 * moment, we only deal with NIST prime curves where the elliptic
 * curve's "a" parameter is always -3 and its "h" value (order of
 * elliptic curve group divided by order of base point) is always 1.
 *
 * Since the Montgomery parameters we need for the point arithmetic
 * depend only on the underlying field prime, we precompute them when
 * we load the curve and store them in the field descriptor, even
 * though they aren't really curve parameters per se.
 *
 * For similar reasons, we also include the ASN.1 OBJECT IDENTIFIERs
 * used to name these curves.
 */

typedef struct {
  fp_int q[1];                          /* Modulus of underlying prime field */
  fp_int b[1];                          /* Curve's "b" parameter */
  fp_int Gx[1];                         /* x component of base point G */
  fp_int Gy[1];                         /* y component of base point G */
  fp_int n[1];                          /* Order of base point G */
  fp_int mu[1];                         /* Montgomery normalization factor */
  fp_digit rho;                         /* Montgomery reduction value */
  const uint8_t *oid;                   /* OBJECT IDENTIFIER */
  size_t oid_len;                       /* Length of OBJECT IDENTIFIER */
} ecdsa_curve_t;

/*
 * ECDSA key implementation.  This structure type is private to this
 * module, anything else that needs to touch one of these just gets a
 * typed opaque pointer.  We do, however, export the size, so that we
 * can make memory allocation the caller's problem.
 *
 * EC points are stored in Jacobian format such that (x, y, z) =>
 * (x/z**2, y/z**3, 1) when interpretted as affine coordinates.
 */

typedef struct {
  fp_int x[1], y[1], z[1];
} ec_point_t;

struct hal_ecdsa_key {
  hal_ecdsa_key_type_t type;            /* Public or private is */
  hal_ecdsa_curve_t curve;              /* Curve descriptor */
  ec_point_t Q[1];                      /* Public key */
  fp_int d[1];                          /* Private key */
};

const size_t hal_ecdsa_key_t_size = sizeof(struct hal_ecdsa_key);

/*
 * Error handling.
 */

#define lose(_code_) do { err = _code_; goto fail; } while (0)

/*
 * Functions to strip const qualifiers from arguments to libtfm calls
 * in a relatively type-safe manner.
 */

static inline fp_int *unconst_fp_int(const fp_int * const arg)
{
  return (fp_int *) arg;
}

static inline uint8_t *unconst_uint8_t(const uint8_t * const arg)
{
  return (uint8_t *) arg;
}

/*
 * We can't (usefully) initialize fp_int variables at compile time, so
 * instead we load all the curve parameters the first time anything
 * asks for any of them.
 */

static const ecdsa_curve_t * const get_curve(const hal_ecdsa_curve_t curve)
{
  static ecdsa_curve_t curve_p256, curve_p384, curve_p521;
  static int initialized = 0;

  if (!initialized) {

#include "ecdsa_curves.h"

    fp_read_unsigned_bin(curve_p256.q,  unconst_uint8_t(p256_q),  sizeof(p256_q));
    fp_read_unsigned_bin(curve_p256.b,  unconst_uint8_t(p256_b),  sizeof(p256_b));
    fp_read_unsigned_bin(curve_p256.Gx, unconst_uint8_t(p256_Gx), sizeof(p256_Gx));
    fp_read_unsigned_bin(curve_p256.Gy, unconst_uint8_t(p256_Gy), sizeof(p256_Gy));
    fp_read_unsigned_bin(curve_p256.n,  unconst_uint8_t(p256_n),  sizeof(p256_n));
    if (fp_montgomery_setup(curve_p256.q, &curve_p256.rho) != FP_OKAY)
      return NULL;
    fp_zero(curve_p256.mu);
    fp_montgomery_calc_normalization(curve_p256.mu, curve_p256.q);
    curve_p256.oid = p256_oid;
    curve_p256.oid_len = sizeof(p256_oid);

    fp_read_unsigned_bin(curve_p384.q,  unconst_uint8_t(p384_q),  sizeof(p384_q));
    fp_read_unsigned_bin(curve_p384.b,  unconst_uint8_t(p384_b),  sizeof(p384_b));
    fp_read_unsigned_bin(curve_p384.Gx, unconst_uint8_t(p384_Gx), sizeof(p384_Gx));
    fp_read_unsigned_bin(curve_p384.Gy, unconst_uint8_t(p384_Gy), sizeof(p384_Gy));
    fp_read_unsigned_bin(curve_p384.n,  unconst_uint8_t(p384_n),  sizeof(p384_n));
    if (fp_montgomery_setup(curve_p384.q, &curve_p384.rho) != FP_OKAY)
      return NULL;
    fp_zero(curve_p384.mu);
    fp_montgomery_calc_normalization(curve_p384.mu, curve_p384.q);
    curve_p384.oid = p384_oid;
    curve_p384.oid_len = sizeof(p384_oid);

    fp_read_unsigned_bin(curve_p521.q,  unconst_uint8_t(p521_q),  sizeof(p521_q));
    fp_read_unsigned_bin(curve_p521.b,  unconst_uint8_t(p521_b),  sizeof(p521_b));
    fp_read_unsigned_bin(curve_p521.Gx, unconst_uint8_t(p521_Gx), sizeof(p521_Gx));
    fp_read_unsigned_bin(curve_p521.Gy, unconst_uint8_t(p521_Gy), sizeof(p521_Gy));
    fp_read_unsigned_bin(curve_p521.n,  unconst_uint8_t(p521_n),  sizeof(p521_n));
    if (fp_montgomery_setup(curve_p521.q, &curve_p521.rho) != FP_OKAY)
      return NULL;
    fp_zero(curve_p521.mu);
    fp_montgomery_calc_normalization(curve_p521.mu, curve_p521.q);
    curve_p521.oid = p521_oid;
    curve_p521.oid_len = sizeof(p521_oid);

    initialized = 1;
  }

  switch (curve) {
  case HAL_ECDSA_CURVE_P256: return &curve_p256;
  case HAL_ECDSA_CURVE_P384: return &curve_p384;
  case HAL_ECDSA_CURVE_P521: return &curve_p521;
  default:                   return NULL;
  }
}

/*
 * Test whether two points are equal: x and z coordinates identical, y
 * coordinates either identical or negated.
 */

static inline int point_equal(const ec_point_t * const P,
                              const ec_point_t * const Q,
                              const ecdsa_curve_t * const curve)
{
  assert(P != NULL && Q != NULL && curve != NULL);

  if (fp_cmp(unconst_fp_int(P->x), unconst_fp_int(Q->x)) != FP_EQ ||
      fp_cmp(unconst_fp_int(P->z), unconst_fp_int(Q->z)) != FP_EQ)
    return 0;

  if (fp_cmp(unconst_fp_int(P->y), unconst_fp_int(Q->y)) == FP_EQ)
    return 1;

  fp_int Qy_neg[1];

  fp_sub(unconst_fp_int(curve->q), unconst_fp_int(Q->y), Qy_neg);

  const int result = fp_cmp(unconst_fp_int(P->y), Qy_neg) == FP_EQ;

  fp_zero(Qy_neg);

  return result;
}

/*
 * Finite field operations (hence "ff_").  These are basically just
 * the usual bignum operations, constrained by the field modulus.
 *
 * All of these are operations in the field underlying the specified
 * curve, and assume that operands are already in Montgomery form.
 *
 * Several of these are written a bit oddly, in an attempt to make
 * them run in constant time.  Be warned that an optimizing compiler
 * may be clever enough to defeat this.  In the long run, the real
 * solution is probably to perform these field operations in Verilog.
 */

static inline void ff_add(const ecdsa_curve_t * const curve,
                          const fp_int * const a,
                          const fp_int * const b,
                          fp_int *c)
{
  fp_int t[2][1];
  memset(t, 0, sizeof(t));
  fp_add(unconst_fp_int(a), unconst_fp_int(b), t[0]);
  fp_sub(t[0], unconst_fp_int(curve->q), t[1]);
  fp_copy(t[fp_cmp(t[0], unconst_fp_int(curve->q)) != FP_LT], c);
  memset(t, 0, sizeof(t));
}

static inline void ff_sub(const ecdsa_curve_t * const curve,
                          const fp_int * const a, 
                          const fp_int * const b,
                          fp_int *c)
{
  fp_int t[2][1];
  memset(t, 0, sizeof(t));
  fp_sub(unconst_fp_int(a), unconst_fp_int(b), t[0]);
  fp_add(t[0], unconst_fp_int(curve->q), t[1]);
  fp_copy(t[fp_cmp_d(c, 0) == FP_LT], c);
  memset(t, 0, sizeof(t));
}

static inline void ff_div2(const ecdsa_curve_t * const curve,
                           const fp_int * const a, 
                           fp_int *b)
{
  fp_int t[2][1];
  memset(t, 0, sizeof(t));
  fp_copy(unconst_fp_int(a), t[0]);
  fp_add(t[0], unconst_fp_int(curve->q), t[1]);
  fp_div_2(t[fp_isodd(unconst_fp_int(a))], b);
  memset(t, 0, sizeof(t));
}

static inline void ff_mul(const ecdsa_curve_t * const curve,
                          const fp_int * const a,
                          const fp_int * const b,
                          fp_int *c)
{
  fp_mul(unconst_fp_int(a), unconst_fp_int(b), c);
  fp_montgomery_reduce(c, unconst_fp_int(curve->q), curve->rho);
}

static inline void ff_sqr(const ecdsa_curve_t * const curve,
                          const fp_int * const a,
                          fp_int *b)
{
  fp_sqr(unconst_fp_int(a), b);
  fp_montgomery_reduce(b, unconst_fp_int(curve->q), curve->rho);
}

#warning Change point arithmetic algorithms?
/*
 * The point doubling and addition algorithms we use here are from
 * libtomcrypt.  The formula database at hyperelliptic.org lists
 * faster algorithms satisfying the same preconditions, perhaps we
 * should use those instead?
 *
 * Labels in the following refer to entries on the page:
 *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
 *
 * The libtomcrypt doubling algorithm looks like a trivial variation
 * on dbl-2004-hmv.  We might want to use dbl-2001-b instead.
 *
 * The libtomcrypt addition algorithm doesn't match up exactly with
 * any listed algorithm, but I suspect it's a variation on
 * add-1998-cmo-2.  We might want to use add-2007-bl instead.
 *
 * There are faster algorithms listed, but all of them appear to
 * require whacking one or both points back into affine
 * representation, which has its own costs, so, at least for now, it'd
 * probably be best to stick with algorithms that don't require this.
 */

/**
 * Double an EC point.
 * @param P             The point to double
 * @param R             [out] The destination of the double
 * @param curve         The curve parameters structure
 *
 * Algorithm is a minor variation on algorithm 3.21 from Guide to
 * Elliptic Curve Cryptography.
 */

static inline void point_double(const ec_point_t * const P,
                                ec_point_t *R,
                                const ecdsa_curve_t * const curve)
{
  assert(P != NULL && R != NULL && curve != NULL);

  fp_int t1[1]; fp_init(t1); 
  fp_int t2[1]; fp_init(t2);

  if (P != R)
    *R = *P;

  ff_sqr  (curve,  R->z,  t1);                /* t1 = Pz ** 2                                   */
  ff_sub  (curve,  R->x,  t1,    t2);         /* t2 = Px - Pz ** 2                              */
  ff_add  (curve,  R->x,  t1,    t1);         /* t1 = Px + Pz ** 2                              */
  ff_mul  (curve,  t1,    t2,    t2);         /* t2 = 1 * (Px - Pz ** 2) * (Px + Pz ** 2)       */
  ff_add  (curve,  t2,    t2,    t1);         /* t1 = 2 * (Px - Pz ** 2) * (Px + Pz ** 2)       */
  ff_add  (curve,  t1,    t2,    t1);         /* t1 = 3 * (Px - Pz ** 2) * (Px + Pz ** 2) = A   */

  ff_add  (curve,  R->y,  R->y,  R->y);       /* Ry = 2 * Py = B                                */
  ff_mul  (curve,  R->z,  R->y,  R->z);       /* Rz = B * Pz                                    */

  ff_sqr  (curve,  R->y,  R->y);              /* Ry = B ** 2 = C                                */
  ff_sqr  (curve,  R->y,  t2);                /* t2 = C ** 2                                    */
  ff_div2 (curve,  t2,    t2);                /* t2 = C ** 2 / 2                                */
  ff_mul  (curve,  R->y,  R->x,  R->y);       /* Ry = C * Px = D                                */

  ff_sqr  (curve,  t1,    R->x);              /* Rx = A ** 2                                    */
  ff_sub  (curve,  R->x,  R->y,  R->x);       /* Rx = A ** 2 - D                                */
  ff_sub  (curve,  R->x,  R->y,  R->x);       /* Rx = A ** 2 - 2 * D                            */

  ff_sub  (curve,  R->y,  R->x,  R->y);       /* Ry = D - Rx                                    */
  ff_mul  (curve,  R->y,  t1,    R->y);       /* Ry = (D - Rx) * A                              */
  ff_sub  (curve,  R->y,  t2,    R->y);       /* Ry = (D - Rx) * A - C ** 2 / 2                 */

  fp_zero(t1); fp_zero(t2);
}

/**
 * Add two EC points
 * @param P             The point to add
 * @param Q             The point to add
 * @param R             [out] The destination of the double
 * @param curve         The curve parameters structure
*/

static inline void point_add(const ec_point_t * const P,
                             const ec_point_t * const Q,
                             ec_point_t *R,
                             const ecdsa_curve_t * const curve)
{
  assert(P != NULL && Q != NULL && R != NULL && curve != NULL);

  if (point_equal(P, Q, curve))
    return point_double(P, R, curve);

  fp_int t1[1]; fp_init(t1);
  fp_int t2[1]; fp_init(t2);

  if (P != R)
    *R = *P;

  /*
   * Operations marked {@} are no-ops when Q.z == 1, but probably
   * don't save us enough in the long run for optimizing them out to
   * be worth even a low-probability risk of a timing channel attack.
   */

  ff_sqr  (curve,  Q->z,   t1);                      /* t1 = z' ** 2       {@} */
  ff_mul  (curve,  t1,     R->x,   R->x);            /* x  = x  *  z' ** 2 {@} */
  ff_mul  (curve,  Q->z,   t1,     t1);              /* t1 = z' ** 3       {@} */
  ff_mul  (curve,  t1,     R->y,   R->y);            /* y  = y  *  z' ** 3 {@} */

  ff_sqr  (curve,  R->z,  t1);                       /* t1 = z  * z  */
  ff_mul  (curve,  Q->x,  t1,    t2);                /* t2 = x' * t1 */
  ff_mul  (curve,  R->z,  t1,    t1);                /* t1 = z  * t1 */
  ff_mul  (curve,  Q->y,  t1,    t1);                /* t1 = y' * t1 */

  ff_sub  (curve,  R->y,  t1,    R->y);              /* y  = y  - t1 */
  ff_add  (curve,  t1,    t1,    t1);                /* t1 = 2  * t1 */
  ff_add  (curve,  t1,    R->y,  t1);                /* t1 = y  + t1 */
  ff_sub  (curve,  R->x,  t2,    R->x);              /* x  = x  - t2 */
  ff_add  (curve,  t2,    t2,    t2);                /* t2 = 2  * t2 */
  ff_add  (curve,  t2,    R->x,  t2);                /* t2 = x  + t2 */

  ff_mul  (curve,  R->z,  Q->z,  R->z);              /* z  = z * z' {@} */

  ff_mul  (curve,  R->z,  R->x,  R->z);              /* z  = z  * x  */

  ff_mul  (curve,  t1,    R->x,  t1);                /* t1 = t1 * x  */
  ff_sqr  (curve,  R->x,  R->x);                     /* x  = x  * x  */
  ff_mul  (curve,  t2,    R->x,  t2);                /* t2 = t2 * x  */
  ff_mul  (curve,  t1,    R->x,  t1);                /* t1 = t1 * x  */

  ff_sqr  (curve,  R->y,  R->x);                     /* x  = y  * y  */
  ff_sub  (curve,  R->x,  t2,    R->x);              /* x  = x  - t2 */

  ff_sub  (curve,  t2,    R->x,  t2);                /* t2 = t2 - x  */
  ff_sub  (curve,  t2,    R->x,  t2);                /* t2 = t2 - x  */
  ff_mul  (curve,  t2,    R->y,  t2);                /* t2 = t2 * y  */
  ff_sub  (curve,  t2,    t1,    R->y);              /* y  = t2 - t1 */
  ff_div2 (curve,  R->y,  R->y);                     /* y  = y  / 2  */

  fp_zero(t1); fp_zero(t2);
}

/**
 * Map a projective jacbobian point back to affine space
 * @param P        [in/out] The point to map
 * @param curve    The curve parameters structure
 */

static inline hal_error_t point_to_affine(ec_point_t *P,
                                          const ecdsa_curve_t * const curve)
{
  assert(P != NULL && curve != NULL);

  hal_error_t err = HAL_ERROR_IMPOSSIBLE;

  fp_int t1[1]; fp_init(t1);
  fp_int t2[1]; fp_init(t2);

  fp_int * const q = unconst_fp_int(curve->q);

  fp_montgomery_reduce(P->z, q, curve->rho);

  if (fp_invmod (P->z,   q, t1) != FP_OKAY ||    /* t1 = 1 / z    */
      fp_sqrmod (t1,     q, t2) != FP_OKAY ||    /* t2 = 1 / z**2 */
      fp_mulmod (t1, t2, q, t1) != FP_OKAY)      /* t1 = 1 / z**3 */
    goto fail;

  fp_mul (P->x,  t2,  P->x);                     /* x = x / z**2 */
  fp_mul (P->y,  t1,  P->y);                     /* y = y / z**3 */
  fp_set (P->z,  1);                             /* z = 1        */

  fp_montgomery_reduce(P->x, q, curve->rho);
  fp_montgomery_reduce(P->y, q, curve->rho);

  err = HAL_OK;

 fail:
  fp_zero(t1);
  fp_zero(t2);
  return err;
}

/**
 * Perform a point multiplication.
 * @param k             The scalar to multiply by
 * @param P             The base point
 * @param R             [out] Destination for kP
 * @param curve         Curve parameters
 * @param map           Boolean whether to map back to affine (1: map, 0: leave projective)
 * @return HAL_OK on success
 *
 * This implementation uses the "Montgomery Ladder" approach, which is
 * relatively robust against timing channel attacks if nothing else
 * goes wrong, but many other things can indeed go wrong.
 */

static hal_error_t point_scalar_multiply(const fp_int * const k,
                                         const ec_point_t * const P,
                                         ec_point_t *R,
                                         const ecdsa_curve_t * const curve,
                                         const int map)
{
  assert(k != NULL && P != NULL && R != NULL &&  curve != NULL);

  if (fp_iszero(k))
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * Convert to Montgomery form and initialize table.  Initial values:
   *
   * M[0] = 1P
   * M[1] = 2P
   * M[2] = don't care, only used for timing-attack resistance
   */

  ec_point_t M[3][1];
  memset(M, 0, sizeof(M));

  if (fp_mulmod(unconst_fp_int(P->x), unconst_fp_int(curve->mu), unconst_fp_int(curve->q), M[0]->x) != FP_OKAY ||
      fp_mulmod(unconst_fp_int(P->y), unconst_fp_int(curve->mu), unconst_fp_int(curve->q), M[0]->y) != FP_OKAY ||
      fp_mulmod(unconst_fp_int(P->z), unconst_fp_int(curve->mu), unconst_fp_int(curve->q), M[0]->z) != FP_OKAY) {
    memset(M, 0, sizeof(M));
    return HAL_ERROR_IMPOSSIBLE;
  }

  point_double(M[0], M[1], curve);

  /*
   * Walk down bits of the scalar, performing dummy operations to mask
   * timing while hunting for the most significant bit.
   */

  int dummy_mode = 1;

  for (int digit_index = k->used - 1; digit_index >= 0; digit_index--) {

    fp_digit digit = k->dp[digit_index];

    for (int bits_left = DIGIT_BIT; bits_left > 0; bits_left--) {

      const int bit = (digit >> (DIGIT_BIT - 1)) & 1;
      digit <<= 1;

      if (dummy_mode) {
        point_add    (M[0], M[1], M[2], curve);
        point_double (M[1], M[2],       curve);
        dummy_mode = !bit;                              /* Dummy until we find MSB */
      }

      else {
        point_add    (M[0],   M[1],  M[bit^1], curve);
        point_double (M[bit], M[bit],          curve);
      }
    }
  }

  /*
   * Copy result out, map back to affine if requested, then done.
   */

  *R = *M[0];
  hal_error_t err = map ? point_to_affine(R, curve) : HAL_OK;
  memset(M, 0, sizeof(M));
  return err;
}

/*
 * Pick a random point on the curve, return random scalar and
 * resulting point.
 */

static hal_error_t point_pick_random(const ecdsa_curve_t * const curve,
                                     fp_int *k,
                                     ec_point_t *P)
{
  hal_error_t err;

  assert(curve != NULL && k != NULL && P != NULL);

  /*
   * Pick a random scalar corresponding to a point on the curve.  Per
   * the NSA (gulp) Suite B guidelines, we ask the CSPRNG for 64 more
   * bits than we need, which should be enough to mask any bias
   * induced by the modular reduction.
   *
   * We're picking a point out of the subgroup generated by the base
   * point on the elliptic curve, so the modulus for this calculation
   * is order of the base point.
   *
   * Zero is an excluded value, but the chance of a non-broken CSPRNG
   * returning zero is so low that it would almost certainly indicate
   * an undiagnosed bug in the CSPRNG.
   */
  uint8_t k_buf[fp_unsigned_bin_size(unconst_fp_int(curve->n)) + 8];

  do {
    if ((err = hal_get_random(k_buf, sizeof(k_buf))) != HAL_OK)
      return err;
    fp_read_unsigned_bin(k, k_buf, sizeof(k_buf));
    if (fp_iszero(k) || fp_mod(k, unconst_fp_int(curve->n), k) != FP_OKAY)
      return HAL_ERROR_IMPOSSIBLE;
  } while (fp_iszero(k));

  memset(k_buf, 0, sizeof(k_buf));

  /*
   * Calculate P = kG and return.
   */

  fp_copy(curve->Gx, P->x);
  fp_copy(curve->Gy, P->y);
  fp_set(P->z, 1);

  return point_scalar_multiply(k, P, P, curve, 1);
}

/*
 * Test whether a point really is on a particular curve (sometimes
 * called "validation when applied to a public key").
 */

static int point_is_on_curve(const ec_point_t * const P,
                             const ecdsa_curve_t * const curve)
{
  assert(P != NULL && curve != NULL);

  fp_int t1[1]; fp_init(t1); 
  fp_int t2[1]; fp_init(t2);

  /*
   * Compute y**2 - x**3 + 3*x.
   */

  fp_sqr(unconst_fp_int(P->y), t1);             /* t1 = y**2 */
  fp_sqr(unconst_fp_int(P->x), t2);             /* t2 = x**2 */
  if (fp_mod(t2, unconst_fp_int(curve->q), t2) != FP_OKAY)
    return 0;
  fp_mul(unconst_fp_int(P->x), t2, t2);         /* t2 = x**3 */
  fp_sub(t1, t2, t1);                           /* t1 = y**2 - x**3 */
  fp_add(t1, unconst_fp_int(P->x), t1);         /* t1 = y**2 - x**3 + 1*x */
  fp_add(t1, unconst_fp_int(P->x), t1);         /* t1 = y**2 - x**3 + 2*x */
  fp_add(t1, unconst_fp_int(P->x), t1);         /* t1 = y**2 - x**3 + 3*x */

  /*
   * Normalize and test whether computed value matches b.
   */

  if (fp_mod(t1, unconst_fp_int(curve->q), t1) != FP_OKAY)
    return 0;
  while (fp_cmp_d(t1, 0) == FP_LT)
    fp_add(t1, unconst_fp_int(curve->q), t1);
  while (fp_cmp(t1, unconst_fp_int(curve->q)) != FP_LT)
    fp_sub(t1, unconst_fp_int(curve->q), t1);

  return fp_cmp(t1, unconst_fp_int(curve->b)) == FP_EQ;
}

/*
 * Generate a new ECDSA key.
 */

hal_error_t hal_ecdsa_key_gen(hal_ecdsa_key_t **key_,
                              void *keybuf, const size_t keybuf_len,
                              const hal_ecdsa_curve_t curve_)
{
  const ecdsa_curve_t * const curve = get_curve(curve_);
  hal_ecdsa_key_t *key = keybuf;
  hal_error_t err;

  if (key_ == NULL || key == NULL || keybuf_len < sizeof(*key) || curve == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(keybuf, 0, keybuf_len);

  key->type = HAL_ECDSA_PRIVATE;
  key->curve = curve_;

  if ((err = point_pick_random(curve, key->d, key->Q)) != HAL_OK)
    return err;

  assert(point_is_on_curve(key->Q, curve));

  *key_ = key;
  return HAL_OK;
}

/*
 * Extract key type (public or private).
 */

hal_error_t hal_ecdsa_key_get_type(const hal_ecdsa_key_t * const key,
                                   hal_ecdsa_key_type_t *key_type)
{
  if (key == NULL || key_type == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  *key_type = key->type;
  return HAL_OK;
}

/*
 * Extract name of curve underlying a key.
 */

hal_error_t hal_ecdsa_key_get_curve(const hal_ecdsa_key_t * const key,
                                    hal_ecdsa_curve_t *curve)
{
  if (key == NULL || curve == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  *curve = key->curve;
  return HAL_OK;
}

/*
 * Extract public key components.
 */

hal_error_t hal_ecdsa_key_get_public(const hal_ecdsa_key_t * const key,
                                     uint8_t *x, size_t *x_len, const size_t x_max,
                                     uint8_t *y, size_t *y_len, const size_t y_max)
{
  if (key == NULL || (x_len == NULL && x != NULL) || (y_len == NULL && y != NULL))
    return HAL_ERROR_BAD_ARGUMENTS;

  if (x_len != NULL)
    *x_len = fp_unsigned_bin_size(unconst_fp_int(key->Q->x));

  if (y_len != NULL)
    *y_len = fp_unsigned_bin_size(unconst_fp_int(key->Q->y));

  if ((x != NULL && *x_len > x_max) ||
      (y != NULL && *y_len > y_max))
    return HAL_ERROR_RESULT_TOO_LONG;

  if (x != NULL)
    fp_to_unsigned_bin(unconst_fp_int(key->Q->x), x);

  if (y != NULL)
    fp_to_unsigned_bin(unconst_fp_int(key->Q->y), y);

  return HAL_OK;
}

/*
 * Clear a key.
 */

void hal_ecdsa_key_clear(hal_ecdsa_key_t *key)
{
  if (key != NULL)
    memset(key, 0, sizeof(*key));
}

/*
 * Load a public key from components, and validate that the public key
 * really is on the named curve.
 */

hal_error_t hal_ecdsa_key_load_public(hal_ecdsa_key_t **key_,
                                      void *keybuf, const size_t keybuf_len,
                                      const hal_ecdsa_curve_t curve_,
                                      const uint8_t * const x, const size_t x_len,
                                      const uint8_t * const y, const size_t y_len)
{
  const ecdsa_curve_t * const curve = get_curve(curve_);
  hal_ecdsa_key_t *key = keybuf;

  if (key_ == NULL || key == NULL || keybuf_len < sizeof(*key) || curve == NULL || x == NULL || y == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(keybuf, 0, keybuf_len);

  key->type = HAL_ECDSA_PUBLIC;
  key->curve = curve_;

  fp_read_unsigned_bin(key->Q->x, unconst_uint8_t(x), x_len);
  fp_read_unsigned_bin(key->Q->y, unconst_uint8_t(y), y_len);
  fp_set(key->Q->z, 1);

  if (!point_is_on_curve(key->Q, curve))
    return HAL_ERROR_KEY_NOT_ON_CURVE;

  *key_ = key;

  return HAL_OK;
}

/*
 * Load a private key from components.
 *
 * For extra paranoia, we could check Q == dG.
 */

hal_error_t hal_ecdsa_key_load_private(hal_ecdsa_key_t **key_,
                                       void *keybuf, const size_t keybuf_len,
                                       const hal_ecdsa_curve_t curve_,
                                       const uint8_t * const x, const size_t x_len,
                                       const uint8_t * const y, const size_t y_len,
                                       const uint8_t * const d, const size_t d_len)
{
  hal_ecdsa_key_t *key = keybuf;
  hal_error_t err;

  if (d == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if ((err = hal_ecdsa_key_load_public(key_, keybuf, keybuf_len, curve_, x, x_len, y, y_len)) != HAL_OK)
    return err;

  key->type = HAL_ECDSA_PRIVATE;
  fp_read_unsigned_bin(key->d, unconst_uint8_t(d), d_len);
  return HAL_OK;
}

/*
 * Write private key in RFC 5915 ASN.1 DER format.
 */

hal_error_t hal_ecdsa_key_to_der(const hal_ecdsa_key_t * const key,
                                 uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (key == NULL || key->type != HAL_ECDSA_PRIVATE)
    return HAL_ERROR_BAD_ARGUMENTS;

  const ecdsa_curve_t * const curve = get_curve(key->curve);
  if (curve == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  const size_t q_len  = fp_unsigned_bin_size(unconst_fp_int(curve->q));
  const size_t d_len  = fp_unsigned_bin_size(unconst_fp_int(key->d));
  const size_t Qx_len = fp_unsigned_bin_size(unconst_fp_int(key->Q->x));
  const size_t Qy_len = fp_unsigned_bin_size(unconst_fp_int(key->Q->y));
  assert(q_len >= d_len && q_len >= Qx_len && q_len >= Qy_len);

  fp_int version[1];
  fp_set(version, 1);

  hal_error_t err;

  size_t version_len, hlen, hlen2, hlen3, hlen4;

  if ((err = hal_asn1_encode_integer(version,                           NULL, &version_len, 0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_OCTET_STRING, q_len,           NULL, &hlen2,       0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_EXPLICIT_0,   curve->oid_len,  NULL, &hlen3,       0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_EXPLICIT_1,   (q_len + 1) * 2, NULL, &hlen4,       0)) != HAL_OK)
    return err;
  
  const size_t vlen = (version_len    +
                       hlen2 + q_len +
                       hlen3 + curve->oid_len +
                       hlen4  + (q_len + 1) * 2);

  if ((err = hal_asn1_encode_header(ASN1_SEQUENCE, vlen, der, &hlen, der_max)) != HAL_OK)
    return err;

  if (der_len != NULL)
    *der_len = hlen + vlen;

  if (der == NULL)
    return HAL_OK;

  uint8_t *d = der + hlen;
  memset(d, 0, vlen);

  if ((err = hal_asn1_encode_integer(version, d, NULL, der + der_max - d)) != HAL_OK)
    return err;
  d += version_len;

  if ((err = hal_asn1_encode_header(ASN1_OCTET_STRING, q_len, d, NULL, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen2;
  fp_to_unsigned_bin(unconst_fp_int(key->d), d + q_len - d_len);
  d += q_len;

  if ((err = hal_asn1_encode_header(ASN1_EXPLICIT_0, curve->oid_len, d, NULL, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen3;
  memcpy(d, curve->oid, curve->oid_len);
  d += curve->oid_len;

  if ((err = hal_asn1_encode_header(ASN1_EXPLICIT_1, (q_len + 1) * 2, d, NULL, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen4;
  *d++ = 0x00;
  *d++ = 0x04;
  fp_to_unsigned_bin(unconst_fp_int(key->d), d + q_len - Qx_len);
  d += q_len;
  fp_to_unsigned_bin(unconst_fp_int(key->d), d + q_len - Qy_len);
  d += q_len;

  assert(d == der + der_max);

  return HAL_OK;
}

size_t hal_ecdsa_key_to_der_len(const hal_ecdsa_key_t * const key)
{
  size_t len;
  return hal_ecdsa_key_to_der(key, NULL, &len, 0) == HAL_OK ? len : 0;
}

/*
 * Read private key in RFC 5915 ASN.1 DER format.
 */

hal_error_t hal_ecdsa_key_from_der(hal_ecdsa_key_t **key_,
                                   void *keybuf, const size_t keybuf_len,
                                   const uint8_t * const der, const size_t der_len)
{
  hal_ecdsa_key_t *key = keybuf;

  if (key_ == NULL || key == NULL || keybuf_len < sizeof(*key))
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(keybuf, 0, keybuf_len);
  key->type = HAL_ECDSA_PRIVATE;

  size_t hlen, vlen;
  hal_error_t err;

  if ((err = hal_asn1_decode_header(ASN1_SEQUENCE, der, der_len, &hlen, &vlen)) != HAL_OK)
    return err;

  const uint8_t * const der_end = der + hlen + vlen;
  const uint8_t *d = der + hlen;
  const ecdsa_curve_t *curve = NULL;
  fp_int version[1];

  if ((err = hal_asn1_decode_integer(version, d, &hlen, vlen)) != HAL_OK)
    goto fail;
  if (fp_cmp_d(version, 1) != FP_EQ)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);
  d += hlen;

  if ((err = hal_asn1_decode_header(ASN1_OCTET_STRING, d, der_end - d, &hlen, &vlen)) != HAL_OK)
    return err;
  d += hlen;
  fp_read_unsigned_bin(key->d, unconst_uint8_t(d), vlen);
  d += vlen;

  if ((err = hal_asn1_decode_header(ASN1_EXPLICIT_0, d, der_end - d, &hlen, &vlen)) != HAL_OK)
    return err;
  d += hlen;
  for (key->curve = (hal_ecdsa_curve_t) 0; (curve = get_curve(key->curve)) != NULL; key->curve++)
    if (vlen == curve->oid_len && memcmp(d, curve->oid, vlen) == 0)
      break;
  if (curve == NULL)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);
  d += vlen;
  
  if ((err = hal_asn1_decode_header(ASN1_EXPLICIT_1, d, der_end - d, &hlen, &vlen)) != HAL_OK)
    return err;
  d += hlen;
  if (vlen < 4 || (vlen & 1) != 0 || *d++ != 0x00 || *d++ != 0x04)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);
  vlen = vlen/2 - 1;
  fp_read_unsigned_bin(key->Q->x, unconst_uint8_t(d), vlen);
  d += vlen;
  fp_read_unsigned_bin(key->Q->x, unconst_uint8_t(d), vlen);
  d += vlen;

  if (d != der_end)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);

  return HAL_OK;

 fail:
  memset(keybuf, 0, keybuf_len);
  return err;
}

hal_error_t hal_ecdsa_sign(const hal_ecdsa_key_t * const key,
                           const hal_hash_descriptor_t * const hash_descriptor,
                           const uint8_t * const input, const size_t input_len,
                           uint8_t *output, size_t *output_len, const size_t output_max)
{
  if (key == NULL || hash_descriptor == NULL || input == NULL ||
      output == NULL || output_len == NULL || key->type != HAL_ECDSA_PRIVATE)
    return HAL_ERROR_BAD_ARGUMENTS;

  const ecdsa_curve_t * const curve = get_curve(key->curve);
  if (curve == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  fp_int k[1]; fp_init(k);
  fp_int r[1]; fp_init(r);
  fp_int s[1]; fp_init(s);
  fp_int e[1]; fp_init(e);

  fp_int * const n = unconst_fp_int(curve->n);
  fp_int * const d = unconst_fp_int(key->d);

  ec_point_t R[1];
  memset(R, 0, sizeof(R));

  hal_error_t err;

#warning Should we be hashing here, or should API have caller do it?  What does PKCS 11 do for ECDSA?

  /*
   * Hash the input and load result into e.
   */

  {
    uint8_t statebuf[hash_descriptor->hash_state_length];
    uint8_t hashbuf[hash_descriptor->digest_length];
    hal_hash_state_t state = { NULL };

    if ((err = hal_hash_initialize(hash_descriptor, &state,
                                   statebuf, sizeof(statebuf)))    != HAL_OK ||
        (err = hal_hash_update(state, input, input_len))           != HAL_OK ||
        (err = hal_hash_finalize(state, hashbuf, sizeof(hashbuf))) != HAL_OK)
      return err;

    fp_read_unsigned_bin(e, hashbuf, sizeof(hashbuf));
  }

  do {

    /*
     * Pick random curve point R, then calculate r = R.x % n.
     * If r == 0, we can't use this point, so go try again.
     */

    if ((err = point_pick_random(curve, k, R)) != HAL_OK)
      goto fail;

    assert(point_is_on_curve(R, curve));

    if (fp_mod(R->x, n, r) != FP_OKAY)
      lose(HAL_ERROR_IMPOSSIBLE);

    if (fp_iszero(r))
      continue;

    /*
     * Calculate s = ((e + dr)/k) % n.
     * If s == 0, we can't use this point, so go try again.
     */

    if (fp_mulmod (d, r, n, s) != FP_OKAY)
      lose(HAL_ERROR_IMPOSSIBLE);

    fp_add        (e, s, s);

    if (fp_mod    (s, n, s)    != FP_OKAY ||
        fp_invmod (k, n, k)    != FP_OKAY ||
        fp_mulmod (s, k, n, s) != FP_OKAY)
      lose(HAL_ERROR_IMPOSSIBLE);

  } while (fp_iszero(s));

  /*
   * Final signature is ASN.1 DER encoding of SEQUENCE { INTEGER r, INTEGER s }.
   */

  size_t r_len, s_len;

  if ((err = hal_asn1_encode_integer(r, NULL, &r_len, 0)) != HAL_OK ||
      (err = hal_asn1_encode_integer(s, NULL, &s_len, 0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_SEQUENCE, r_len + s_len, output, output_len, output_max)) != HAL_OK)
    goto fail;

  uint8_t * const r_out = output + *output_len;
  uint8_t * const s_out = r_out + r_len;
  output_len += r_len + s_len;
  assert(*output_len <= output_max);

  if ((err = hal_asn1_encode_integer(r, r_out, NULL, output_max - (r_out - output))) != HAL_OK ||
      (err = hal_asn1_encode_integer(s, s_out, NULL, output_max - (s_out - output))) != HAL_OK)
    goto fail;

  err = HAL_OK;

 fail:
  fp_zero(k); fp_zero(r); fp_zero(s); fp_zero(e);
  memset(R, 0, sizeof(R));
  return err;
}

hal_error_t hal_ecdsa_verify(const hal_ecdsa_key_t * const key,
                             const hal_hash_descriptor_t * const hash_descriptor,
                             const uint8_t * const input, const size_t input_len)
{
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
