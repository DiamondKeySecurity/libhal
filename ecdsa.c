/*
 * ecdsa.c
 * -------
 * Elliptic Curve Digital Signature Algorithm for NIST prime curves.
 *
 * At some point we may want to refactor this code to separate
 * functionality that applies to all elliptic curve cryptography into
 * a separate module from functions specific to ECDSA over the NIST
 * prime curves, but it's simplest to keep this all in one place
 * initially.
 *
 * Much of the code in this module is based, at least loosely, on Tom
 * St Denis's libtomcrypt code.  Algorithms for point addition and
 * point doubling courtesy of the hyperelliptic.org formula database.
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
 * Perhaps we should encapsulate this idiom in a typedef.
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
 * Whether we're using static test vectors instead of the random
 * number generator.  Do NOT enable this in production (doh).
 */

#ifndef HAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM
#define HAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM 0
#endif

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
 * Finite field operations (hence "ff_").  These are basically just
 * the usual bignum operations, constrained by the field modulus.
 *
 * All of these are operations in the field underlying the specified
 * curve, and assume that operands are already in Montgomery form.
 *
 * The ff_add() and ff_sub() are written a bit oddly, in an attempt to
 * make them run in constant time.  An optimizing compiler may be
 * clever enough to defeat this.  In the long run, we probably want to
 * perform these field operations in Verilog anyway.
 *
 * We might be able to squeeze a bit more speed out of the point
 * arithmetic by making using fp_mul_2d() when multiplying by a power
 * of two.  Skipping for now as a premature optimization, but if we do
 * need this, it'd probably be simplest to add a ff_dbl() function
 * which handles overflow in the same way that ff_add() does.
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

  fp_copy(t[fp_cmp_d(t[1], 0) != FP_LT], c);

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

  fp_copy(t[fp_cmp_d(t[0], 0) == FP_LT], c);

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

/*
 * Test whether a point is the point at infinity.
 *
 * In Jacobian projective coordinate, any point of the form
 *
 *   (j ** 2, j **3, 0) for j in [1..q-1]
 *
 * is on the line at infinity, but for practical purposes simply
 * checking the z coordinate is probably sufficient.
 */

static inline int point_is_infinite(const ec_point_t * const P)
{
  assert(P != NULL);
  return fp_iszero(P->z);
}

/*
 * Set a point to be the point at infinity.  For Jacobian projective
 * coordinates, it's customary to use (1 : 1 : 0) as the
 * representitive value.
 */

static inline void point_set_infinite(ec_point_t *P)
{
  assert(P != NULL);
  fp_set(P->x, 1);
  fp_set(P->y, 1);
  fp_set(P->z, 0);
}

/*
 * Copy a point.
 */

static inline void point_copy(const ec_point_t * const P, ec_point_t *R)
{
  if (P != NULL && R != NULL && P != R)
    *R = *P;
}

/**
 * Double an EC point.
 * @param P             The point to double
 * @param R             [out] The destination of the double
 * @param curve         The curve parameters structure
 *
 * Algorithm is dbl-2001-b from
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
 */

static inline void point_double(const ec_point_t * const P,
                                ec_point_t *R,
                                const ecdsa_curve_t * const curve)
{
  assert(P != NULL && R != NULL && curve != NULL);

  assert(!point_is_infinite(P));

  fp_int alpha[1], beta[1], gamma[1], delta[1],  t1[1], t2[1];

  fp_init(alpha); fp_init(beta); fp_init(gamma); fp_init(delta); fp_init(t1); fp_init(t2);

  ff_sqr  (curve,  P->z,          delta);       /* delta = Pz ** 2 */
  ff_sqr  (curve,  P->y,          gamma);       /* gamma = Py ** 2 */
  ff_mul  (curve,  P->x,  gamma,  beta);        /* beta  = Px * gamma */
  ff_sub  (curve,  P->x,  delta,  t1);          /* alpha = 3 * (Px - delta) * (Px + delta) */
  ff_add  (curve,  P->x,  delta,  t2);
  ff_mul  (curve,  t1,    t2,     t1);
  ff_add  (curve,  t1,    t1,     t2);
  ff_add  (curve,  t1,    t2,     alpha);

  ff_sqr  (curve,  alpha,         t1);          /* Rx = (alpha ** 2) - (8 * beta) */
  ff_add  (curve,  beta,  beta,   t2);
  ff_add  (curve,  t2,    t2,     t2);
  ff_add  (curve,  t2,    t2,     t2);
  ff_sub  (curve,  t1,    t2,     R->x);

  ff_add  (curve,  P->y,  P->z,   t1);          /* Rz = ((Py + Pz) ** 2) - gamma - delta */
  ff_sqr  (curve,  t1,            t1);
  ff_sub  (curve,  t1,    gamma,  t1);
  ff_sub  (curve,  t1,    delta,  R->z);

  ff_add  (curve,  beta,  beta,   t1);          /* Ry = (((4 * beta) - Rx) * alpha) - (8 * (gamma ** 2)) */
  ff_add  (curve,  t1,    t1,     t1);
  ff_sub  (curve,  t1,    R->x,   t1);
  ff_mul  (curve,  t1,    alpha,  t1);
  ff_sqr  (curve,  gamma,         t2);
  ff_add  (curve,  t2,    t2,     t2);
  ff_add  (curve,  t2,    t2,     t2);
  ff_add  (curve,  t2,    t2,     t2);
  ff_sub  (curve,  t1,    t2,     R->y);

  fp_zero(alpha); fp_zero(beta); fp_zero(gamma); fp_zero(delta); fp_zero(t1); fp_zero(t2);
}

/**
 * Add two EC points
 * @param P             The point to add
 * @param Q             The point to add
 * @param R             [out] The destination of the double
 * @param curve         The curve parameters structure
 *
 * Algorithm is add-2007-bl from
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
 *
 * The special cases for P == Q and P == -Q are unfortunate, but are
 * probably unavoidable for this type of curve.
 */

static inline void point_add(const ec_point_t * const P,
                             const ec_point_t * const Q,
                             ec_point_t *R,
                             const ecdsa_curve_t * const curve)
{
  assert(P != NULL && Q != NULL && R != NULL && curve != NULL);

  if (fp_cmp(unconst_fp_int(P->x), unconst_fp_int(Q->x)) == FP_EQ &&
      fp_cmp(unconst_fp_int(P->z), unconst_fp_int(Q->z)) == FP_EQ) {

    /*
     * If P == Q, we have to use the doubling algorithm instead.
     */

    if (fp_cmp(unconst_fp_int(P->y), unconst_fp_int(Q->y)) == FP_EQ)
      return point_double(P, R, curve);

    fp_int Qy_neg[1];
    fp_sub(unconst_fp_int(curve->q), unconst_fp_int(Q->y), Qy_neg);
    const int zero_sum = fp_cmp(unconst_fp_int(P->y), Qy_neg) == FP_EQ;
    fp_zero(Qy_neg);

    /*
     * If P == -Q, P + Q is the point at infinity.  Which can't be
     * expressed in affine coordinates, but that's not this function's
     * problem.
     */

    if (zero_sum)
      return point_set_infinite(R);
  }

  fp_int Z1Z1[1], Z2Z2[1], U1[1], U2[1], S1[1], S2[1], H[1], I[1], J[1], r[1], V[1], t[1];

  fp_init(Z1Z1), fp_init(Z2Z2), fp_init(U1), fp_init(U2), fp_init(S1), fp_init(S2);
  fp_init(H), fp_init(I), fp_init(J), fp_init(r), fp_init(V), fp_init(t);

  ff_sqr  (curve,  P->z,           Z1Z1);       /* Z1Z1 = Pz ** 2 */

  ff_sqr  (curve,  Q->z,           Z2Z2);       /* Z2Z1 = Qz ** 2 */

  ff_mul  (curve,  P->x,   Z2Z2,   U1);         /* U1   = Px * Z2Z2 */

  ff_mul  (curve,  Q->x,   Z1Z1,   U2);         /* U2   = Qx * Z1Z1 */

  ff_mul  (curve,  Q->z,   Z2Z2,   S1);         /* S1 = Py * (Qz ** 3) */
  ff_mul  (curve,  P->y,   S1,     S1);

  ff_mul  (curve,  P->z,   Z1Z1,   S2);         /* S2 = Qy * (Pz ** 3) */
  ff_mul  (curve,  Q->y,   S2,     S2);

  ff_sub  (curve,  U2,     U1,     H);          /* H = U2 - U1 */

  ff_add  (curve,  H,      H,      I);          /* I = (2 * H) ** 2 */
  ff_sqr  (curve,  I,      I);

  ff_mul  (curve,  H,      I,      J);          /* J = H * I */

  ff_sub  (curve,  S2,     S1,     r);          /* r = 2 * (S2 - S1) */
  ff_add  (curve,  r,      r,      r);

  ff_mul  (curve,  U1,     I,      V);          /* V = U1 * I */

  ff_sqr  (curve,  r,              R->x);       /* Rx = (r ** 2) - J - (2 * V) */
  ff_sub  (curve,  R->x,   J,      R->x);
  ff_sub  (curve,  R->x,   V,      R->x);
  ff_sub  (curve,  R->x,   V,      R->x);

  ff_sub  (curve,  V,      R->x,   R->y);       /* Ry = (r * (V - Rx)) - (2 * S1 * J) */
  ff_mul  (curve,  r,      R->y,   R->y);
  ff_mul  (curve,  S1,     J,      t);
  ff_sub  (curve,  R->y,   t,      R->y);
  ff_sub  (curve,  R->y,   t,      R->y);

  ff_add  (curve,  P->z,   Q->z,   R->z);       /* Rz = (((Pz + Qz) ** 2) - Z1Z1 - Z2Z2) * H */
  ff_sqr  (curve,  R->z,           R->z);
  ff_sub  (curve,  R->z,   Z1Z1,   R->z);
  ff_sub  (curve,  R->z,   Z2Z2,   R->z);
  ff_mul  (curve,  R->z,   H,      R->z);

  fp_zero(Z1Z1), fp_zero(Z2Z2), fp_zero(U1), fp_zero(U2), fp_zero(S1), fp_zero(S2);
  fp_zero(H), fp_zero(I), fp_zero(J), fp_zero(r), fp_zero(V), fp_zero(t);
}

/**
 * Map a point in projective Jacbobian coordinates back to affine space
 * @param P        [in/out] The point to map
 * @param curve    The curve parameters structure
 *
 * It's not possible to represent the point at infinity in affine
 * coordinates, and the calling function will have to handle this
 * specially in any case, so we declare this to be the calling
 * function's problem.
 */

static inline hal_error_t point_to_affine(ec_point_t *P,
                                          const ecdsa_curve_t * const curve)
{
  assert(P != NULL && curve != NULL);

  if (point_is_infinite(P))
    return HAL_ERROR_IMPOSSIBLE;

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
   * timing while hunting for the most significant bit of the scalar.
   *
   * Note that, in order for this timing protection to work, the
   * number of iterations in the loop has to depend on the order of
   * the base point rather than on the scalar.
   */

  int dummy_mode = 1;

  for (int bit_index = fp_count_bits(unconst_fp_int(curve->n)) - 1; bit_index >= 0; bit_index--) {

    const int digit_index = bit_index / DIGIT_BIT;
    const fp_digit  digit = digit_index < k->used ? k->dp[digit_index] : 0;
    const fp_digit   mask = ((fp_digit) 1) << (bit_index % DIGIT_BIT);
    const int         bit = (digit & mask) != 0;

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

  /*
   * Copy result out, map back to affine if requested, then done.
   */

  point_copy(M[0], R);
  hal_error_t err = map ? point_to_affine(R, curve) : HAL_OK;
  memset(M, 0, sizeof(M));
  return err;
}

/*
 * Testing only: ECDSA key generation and signature both have a
 * critical dependency on random numbers, but we can't use the random
 * number generator when testing against static test vectors. So add a
 * wrapper around the random number generator calls, with a hook to
 * let us override the generator for test purposes.  Do NOT use this
 * in production, kids.
 */

#if HAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM

#warning hal_ecdsa random number generator overridden for test purposes
#warning DO NOT USE THIS IN PRODUCTION

typedef hal_error_t (*rng_override_test_function_t)(void *, const size_t);

static rng_override_test_function_t rng_test_override_function = 0;

rng_override_test_function_t hal_ecdsa_set_rng_override_test_function(rng_override_test_function_t new_func)
{
  rng_override_test_function_t old_func = rng_test_override_function;
  rng_test_override_function = new_func;
  return old_func;
}

static inline hal_error_t get_random(void *buffer, const size_t length)
{
  if (rng_test_override_function)
    return rng_test_override_function(buffer, length);
  else
    return hal_get_random(buffer, length);
}

#else /* HAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM */

static inline hal_error_t get_random(void *buffer, const size_t length)
{
  return hal_get_random(buffer, length);
}

#endif /* HAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM */

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
   * is the order of the base point.
   *
   * Zero is an excluded value, but the chance of a non-broken CSPRNG
   * returning zero is so low that it would almost certainly indicate
   * an undiagnosed bug in the CSPRNG.
   */

  uint8_t k_buf[fp_unsigned_bin_size(unconst_fp_int(curve->n)) + 8];

  do {

    if ((err = get_random(k_buf, sizeof(k_buf))) != HAL_OK)
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
 * Test whether a point really is on a particular curve.  This is
 * called "validation" when applied to a public key, and is required
 * before verifying a signature.
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
 * Load a private key from components; does all the same things as
 * hal_ecdsa_key_load_public(), then loads the private key itself and
 * adjusts the key type.
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
 * Write public key in X9.62 ECPoint format (ASN.1 OCTET STRING, first octet is compression flag).
 */

hal_error_t hal_ecdsa_key_to_ecpoint(const hal_ecdsa_key_t * const key,
                                     uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (key == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  const ecdsa_curve_t * const curve = get_curve(key->curve);
  if (curve == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  const size_t q_len  = fp_unsigned_bin_size(unconst_fp_int(curve->q));
  const size_t Qx_len = fp_unsigned_bin_size(unconst_fp_int(key->Q->x));
  const size_t Qy_len = fp_unsigned_bin_size(unconst_fp_int(key->Q->y));
  assert(q_len >= Qx_len && q_len >= Qy_len);

  const size_t vlen = q_len * 2 + 1;
  size_t hlen;

  hal_error_t err = hal_asn1_encode_header(ASN1_OCTET_STRING, vlen, der, &hlen, der_max);

  if (der_len != NULL)
    *der_len = hlen + vlen;

  if (der == NULL || err != HAL_OK)
    return err;

  assert(hlen + vlen <= der_max);

  uint8_t *d = der + hlen;
  memset(d, 0, vlen);

  *d++ = 0x04;                  /* uncompressed */

  fp_to_unsigned_bin(unconst_fp_int(key->Q->x), d + q_len - Qx_len);
  d += q_len;

  fp_to_unsigned_bin(unconst_fp_int(key->Q->y), d + q_len - Qy_len);
  d += q_len;

  assert(d <= der + der_max);

  return HAL_OK;
}

/*
 * Convenience wrapper to return how many bytes a key would take if
 * encoded as an ECPoint.
 */

size_t hal_ecdsa_key_to_ecpoint_len(const hal_ecdsa_key_t * const key)
{
  size_t len;
  return hal_ecdsa_key_to_ecpoint(key, NULL, &len, 0) == HAL_OK ? len : 0;
}

/*
 * Read public key in X9.62 ECPoint format (ASN.1 OCTET STRING, first octet is compression flag).
 * ECPoint format doesn't include a curve identifier, so caller has to supply one.
 */

hal_error_t hal_ecdsa_key_from_ecpoint(hal_ecdsa_key_t **key_,
                                       void *keybuf, const size_t keybuf_len,
                                       const uint8_t * const der, const size_t der_len,
                                       const hal_ecdsa_curve_t curve)
{
  hal_ecdsa_key_t *key = keybuf;

  if (key_ == NULL || key == NULL || keybuf_len < sizeof(*key) || get_curve(curve) == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(keybuf, 0, keybuf_len);
  key->type = HAL_ECDSA_PUBLIC;
  key->curve = curve;

  size_t hlen, vlen;
  hal_error_t err;

  if ((err = hal_asn1_decode_header(ASN1_OCTET_STRING, der, der_len, &hlen, &vlen)) != HAL_OK)
    return err;

  const uint8_t * const der_end = der + hlen + vlen;
  const uint8_t *d = der + hlen;

  if (vlen < 3 || (vlen & 1) == 0 || *d++ != 0x04)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);

  vlen = vlen/2 - 1;

  fp_read_unsigned_bin(key->Q->x, unconst_uint8_t(d), vlen);
  d += vlen;

  fp_read_unsigned_bin(key->Q->y, unconst_uint8_t(d), vlen);
  d += vlen;

  fp_set(key->Q->z, 1);

  if (d != der_end)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);

  *key_ = key;
  return HAL_OK;

 fail:
  memset(keybuf, 0, keybuf_len);
  return err;
}

/*
 * Write private key in RFC 5915 ASN.1 DER format.
 *
 * This is hand-coded, and is approaching the limit where one should
 * probably be using an ASN.1 compiler like asn1c instead.
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

  size_t version_len, hlen, hlen_oct, hlen_oid, hlen_exp0, hlen_bit, hlen_exp1;

  if ((err = hal_asn1_encode_integer(version,                                    NULL, &version_len, 0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_OCTET_STRING,          q_len,           NULL, &hlen_oct,    0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_OBJECT_IDENTIFIER,     curve->oid_len,  NULL, &hlen_oid,    0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_EXPLICIT_0, hlen_oid + curve->oid_len,  NULL, &hlen_exp0,   0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_BIT_STRING,            (q_len + 1) * 2, NULL, &hlen_bit,    0)) != HAL_OK ||
      (err = hal_asn1_encode_header(ASN1_EXPLICIT_1, hlen_bit + (q_len + 1) * 2, NULL, &hlen_exp1,   0)) != HAL_OK)
    return err;

  const size_t vlen = (version_len   +
                       hlen_oct + q_len +
                       hlen_oid + hlen_exp0 + curve->oid_len +
                       hlen_bit + hlen_exp1 + (q_len + 1) * 2);

  err = hal_asn1_encode_header(ASN1_SEQUENCE, vlen, der, &hlen, der_max);

  if (der_len != NULL)
    *der_len = hlen + vlen;

  if (der == NULL || err != HAL_OK)
    return err;

  uint8_t *d = der + hlen;
  memset(d, 0, vlen);

  if ((err = hal_asn1_encode_integer(version, d, NULL, der + der_max - d)) != HAL_OK)
    return err;
  d += version_len;

  if ((err = hal_asn1_encode_header(ASN1_OCTET_STRING, q_len, d, &hlen, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen;
  fp_to_unsigned_bin(unconst_fp_int(key->d), d + q_len - d_len);
  d += q_len;

  if ((err = hal_asn1_encode_header(ASN1_EXPLICIT_0, hlen_oid + curve->oid_len, d, &hlen, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen;
  if ((err = hal_asn1_encode_header(ASN1_OBJECT_IDENTIFIER, curve->oid_len, d, &hlen, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen;
  memcpy(d, curve->oid, curve->oid_len);
  d += curve->oid_len;

  if ((err = hal_asn1_encode_header(ASN1_EXPLICIT_1, hlen_bit + (q_len + 1) * 2, d, &hlen, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen;
  if ((err = hal_asn1_encode_header(ASN1_BIT_STRING, (q_len + 1) * 2, d, &hlen, der + der_max - d)) != HAL_OK)
    return err;
  d += hlen;
  *d++ = 0x00;
  *d++ = 0x04;
  fp_to_unsigned_bin(unconst_fp_int(key->Q->x), d + q_len - Qx_len);
  d += q_len;
  fp_to_unsigned_bin(unconst_fp_int(key->Q->y), d + q_len - Qy_len);
  d += q_len;

  assert(d == der + der_max);

  return HAL_OK;
}

/*
 * Convenience wrapper to return how many bytes a private key would
 * take if encoded as DER.
 */

size_t hal_ecdsa_key_to_der_len(const hal_ecdsa_key_t * const key)
{
  size_t len;
  return hal_ecdsa_key_to_der(key, NULL, &len, 0) == HAL_OK ? len : 0;
}

/*
 * Read private key in RFC 5915 ASN.1 DER format.
 *
 * This is hand-coded, and is approaching the limit where one should
 * probably be using an ASN.1 compiler like asn1c instead.
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
  if (vlen > der_end - d)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);
  if ((err = hal_asn1_decode_header(ASN1_OBJECT_IDENTIFIER, d, vlen, &hlen, &vlen)) != HAL_OK)
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
  if (vlen > der_end - d)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);
  if ((err = hal_asn1_decode_header(ASN1_BIT_STRING, d, vlen, &hlen, &vlen)) != HAL_OK)
    return err;
  d += hlen;
  if (vlen < 4 || (vlen & 1) != 0 || *d++ != 0x00 || *d++ != 0x04)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);
  vlen = vlen/2 - 1;
  fp_read_unsigned_bin(key->Q->x, unconst_uint8_t(d), vlen);
  d += vlen;
  fp_read_unsigned_bin(key->Q->y, unconst_uint8_t(d), vlen);
  d += vlen;
  fp_set(key->Q->z, 1);

  if (d != der_end)
    lose(HAL_ERROR_ASN1_PARSE_FAILED);

  *key_ = key;
  return HAL_OK;

 fail:
  memset(keybuf, 0, keybuf_len);
  return err;
}

/*
 * Encode a signature in PKCS #11 format: an octet string consisting
 * of concatenated values for r and s, each padded (if necessary) out
 * to the byte length of the order of the base point.
 */

static hal_error_t encode_signature_pkcs11(const ecdsa_curve_t * const curve,
                                           const fp_int * const r, const fp_int * const s,
                                           uint8_t *signature, size_t *signature_len, const size_t signature_max)
{
  assert(curve != NULL && r != NULL && s != NULL);

  const size_t n_len = fp_unsigned_bin_size(unconst_fp_int(curve->n));
  const size_t r_len = fp_unsigned_bin_size(unconst_fp_int(r));
  const size_t s_len = fp_unsigned_bin_size(unconst_fp_int(s));

  if (n_len < r_len || n_len < s_len)
    return HAL_ERROR_IMPOSSIBLE;

  if (signature_len != NULL)
    *signature_len = n_len * 2;

  if (signature == NULL)
    return HAL_OK;

  if (signature_max < n_len * 2)
    return HAL_ERROR_RESULT_TOO_LONG;

  memset(signature, 0, n_len * 2);
  fp_to_unsigned_bin(unconst_fp_int(r), signature + 1 * n_len - r_len);
  fp_to_unsigned_bin(unconst_fp_int(s), signature + 2 * n_len - s_len);

  return HAL_OK;
}

/*
 * Decode a signature from PKCS #11 format: an octet string consisting
 * of concatenated values for r and s, each of which occupies half of
 * the octet string (which must therefore be of even length).
 */

static hal_error_t decode_signature_pkcs11(const ecdsa_curve_t * const curve,
                                           fp_int *r, fp_int *s,
                                           const uint8_t * const signature, const size_t signature_len)
{
  assert(curve != NULL && r != NULL && s != NULL);

  if (signature == NULL || (signature_len & 1) != 0)
    return HAL_ERROR_BAD_ARGUMENTS;

  const size_t n_len = signature_len / 2;

  if (n_len > fp_unsigned_bin_size(unconst_fp_int(curve->n)))
    return HAL_ERROR_BAD_ARGUMENTS;

  fp_read_unsigned_bin(r, unconst_uint8_t(signature) + 0 * n_len, n_len);
  fp_read_unsigned_bin(s, unconst_uint8_t(signature) + 1 * n_len, n_len);

  return HAL_OK;
}

/*
 * Encode a signature in ASN.1 format SEQUENCE { INTEGER r, INTEGER s }.
 */

static hal_error_t encode_signature_asn1(const ecdsa_curve_t * const curve,
                                         const fp_int * const r, const fp_int * const s,
                                         uint8_t *signature, size_t *signature_len, const size_t signature_max)
{
  assert(curve != NULL && r != NULL && s != NULL);

  size_t hlen, r_len, s_len;
  hal_error_t err;

  if ((err = hal_asn1_encode_integer(r, NULL, &r_len, 0)) != HAL_OK ||
      (err = hal_asn1_encode_integer(s, NULL, &s_len, 0)) != HAL_OK)
    return err;

  const size_t vlen = r_len + s_len;

  err = hal_asn1_encode_header(ASN1_SEQUENCE, vlen, signature, &hlen, signature_max);

  if (signature_len != NULL)
    *signature_len = hlen + vlen;

  if (signature == NULL || err != HAL_OK)
    return err;

  uint8_t * const r_out = signature + hlen;
  uint8_t * const s_out = r_out + r_len;

  if ((err = hal_asn1_encode_integer(r, r_out, NULL, signature_max - (r_out - signature))) != HAL_OK ||
      (err = hal_asn1_encode_integer(s, s_out, NULL, signature_max - (s_out - signature))) != HAL_OK)
    return err;

  return HAL_OK;
}

/*
 * Decode a signature from ASN.1 format SEQUENCE { INTEGER r, INTEGER s }.
 */

static hal_error_t decode_signature_asn1(const ecdsa_curve_t * const curve,
                                         fp_int *r, fp_int *s,
                                         const uint8_t * const signature, const size_t signature_len)
{
  assert(curve != NULL && r != NULL && s != NULL);

  if (signature == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  size_t len1, len2;
  hal_error_t err;

  if ((err = hal_asn1_decode_header(ASN1_SEQUENCE, signature, signature_len, &len1, &len2)) != HAL_OK)
    return err;

  const uint8_t *       der     = signature + len1;
  const uint8_t * const der_end = der       + len2;

  if ((err = hal_asn1_decode_integer(r, der, &len1, der_end - der)) != HAL_OK)
    return err;
  der += len1;

  if ((err = hal_asn1_decode_integer(s, der, &len1, der_end - der)) != HAL_OK)
    return err;
  der += len1;

  if (der != der_end)
    return HAL_ERROR_ASN1_PARSE_FAILED;

  return HAL_OK;
}

/*
 * Sign a caller-supplied hash.
 */

hal_error_t hal_ecdsa_sign(const hal_ecdsa_key_t * const key,
                           const uint8_t * const hash, const size_t hash_len,
                           uint8_t *signature, size_t *signature_len, const size_t signature_max,
                           const hal_ecdsa_signature_format_t signature_format)
{
  if (key == NULL || hash == NULL || signature == NULL || signature_len == NULL || key->type != HAL_ECDSA_PRIVATE)
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

  fp_read_unsigned_bin(e, unconst_uint8_t(hash), hash_len);

  do {

    /*
     * Pick random curve point R, then calculate r = Rx % n.
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
   * Encode the signature, then we're done.
   */

  switch (signature_format) {

  case HAL_ECDSA_SIGNATURE_FORMAT_ASN1:
    if ((err = encode_signature_asn1(curve, r, s, signature, signature_len, signature_max)) != HAL_OK)
      goto fail;
    break;

  case HAL_ECDSA_SIGNATURE_FORMAT_PKCS11:
    if ((err = encode_signature_pkcs11(curve, r, s, signature, signature_len, signature_max)) != HAL_OK)
      goto fail;
    break;

  default:
    lose(HAL_ERROR_BAD_ARGUMENTS);
  }

  err = HAL_OK;

 fail:
  fp_zero(k); fp_zero(r); fp_zero(s); fp_zero(e);
  memset(R, 0, sizeof(R));
  return err;
}

/*
 * Verify a signature using a caller-supplied hash.
 */

hal_error_t hal_ecdsa_verify(const hal_ecdsa_key_t * const key,
                             const uint8_t * const hash, const size_t hash_len,
                             const uint8_t * const signature, const size_t signature_len,
                             const hal_ecdsa_signature_format_t signature_format)
{
  assert(key != NULL && hash != NULL && signature != NULL);

  const ecdsa_curve_t * const curve = get_curve(key->curve);

  if (curve == NULL)
    return HAL_ERROR_IMPOSSIBLE;

  if (!point_is_on_curve(key->Q, curve))
    return HAL_ERROR_KEY_NOT_ON_CURVE;

  fp_int * const n = unconst_fp_int(curve->n);

  hal_error_t err;
  fp_int r[1], s[1], e[1], w[1], u1[1], u2[1], v[1];
  ec_point_t u1G[1], u2Q[1], R[1];

  fp_init(w); fp_init(u1); fp_init(u2); fp_init(v);
  memset(u1G, 0, sizeof(u1G));
  memset(u2Q, 0, sizeof(u2Q));
  memset(R,   0, sizeof(R));

  /*
   * Start by decoding the signature.
   */

  switch (signature_format) {

  case HAL_ECDSA_SIGNATURE_FORMAT_ASN1:
    if ((err = decode_signature_asn1(curve, r, s, signature, signature_len)) != HAL_OK)
      return err;
    break;

  case HAL_ECDSA_SIGNATURE_FORMAT_PKCS11:
    if ((err = decode_signature_pkcs11(curve, r, s, signature, signature_len)) != HAL_OK)
      return err;
    break;

  default:
    return HAL_ERROR_BAD_ARGUMENTS;
  }

  /*
   * Check that r and s are in the allowed range, read the hash, then
   * compute:
   *
   * w  = 1 / s
   * u1 = e * w
   * u2 = r * w
   * R  = u1 * G + u2 * Q.
   */

  if (fp_cmp_d(r, 1) == FP_LT || fp_cmp(r, n) != FP_LT ||
      fp_cmp_d(s, 1) == FP_LT || fp_cmp(s, n) != FP_LT)
    return HAL_ERROR_INVALID_SIGNATURE;

  fp_read_unsigned_bin(e, unconst_uint8_t(hash), hash_len);

  if (fp_invmod(s, n, w)     != FP_OKAY ||
      fp_mulmod(e, w, n, u1) != FP_OKAY ||
      fp_mulmod(r, w, n, u2) != FP_OKAY)
    return HAL_ERROR_IMPOSSIBLE;

  fp_copy(unconst_fp_int(curve->Gx), u1G->x);
  fp_copy(unconst_fp_int(curve->Gy), u1G->y);
  fp_set(u1G->z, 1);

  if ((err = point_scalar_multiply(u1, u1G,    u1G, curve, 0)) != HAL_OK ||
      (err = point_scalar_multiply(u2, key->Q, u2Q, curve, 0)) != HAL_OK)
    return err;

  if (point_is_infinite(u1G))
    point_copy(u2Q, R);
  else if (point_is_infinite(u2Q))
    point_copy(u1G, R);
  else
    point_add(u1G, u2Q, R, curve);

  /*
   * Signature is OK if
   *   R is not the point at infinity, and
   *   Rx is congruent to r mod n.
   */

  if (point_is_infinite(R))
    return HAL_ERROR_INVALID_SIGNATURE;

  if ((err = point_to_affine(R, curve)) != HAL_OK)
    return err;

  if (fp_mod(R->x, n, v) != FP_OKAY)
    return HAL_ERROR_IMPOSSIBLE;

  return fp_cmp(v, r) == FP_EQ ? HAL_OK : HAL_ERROR_INVALID_SIGNATURE;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
