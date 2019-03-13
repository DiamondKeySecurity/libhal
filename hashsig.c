/*
 * hashsig.c
 * ---------
 * Implementation of draft-mcgrew-hash-sigs-15.txt
 *
 * Copyright (c) 2018, NORDUnet A/S All rights reserved.
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

#include "hal.h"
#include "hashsig.h"
#include "ks.h"
#include "asn1_internal.h"
#include "xdr_internal.h"

typedef struct { uint8_t bytes[32]; } bytestring32;
typedef struct { uint8_t bytes[16]; } bytestring16;

#define D_PBLC 0x8080
#define D_MESG 0x8181
#define D_LEAF 0x8282
#define D_INTR 0x8383

#define u32str(X) htonl(X)
#define u16str(X) htons(X)
#define u8str(X) ((X) & 0xff)

#define check(op) do { hal_error_t _err = (op); if (_err != HAL_OK) return _err; } while (0)

/* ---------------------------------------------------------------- */

/*
 * XDR extensions
 */

static inline hal_error_t hal_xdr_encode_bytestring32(uint8_t ** const outbuf, const uint8_t * const limit, const bytestring32 * const value)
{
    return hal_xdr_encode_fixed_opaque(outbuf, limit, (const uint8_t *)value, sizeof(bytestring32));
}

static inline hal_error_t hal_xdr_decode_bytestring32_ptr(const uint8_t ** const inbuf, const uint8_t * const limit, bytestring32 **value)
{
    return hal_xdr_decode_fixed_opaque_ptr(inbuf, limit, (const uint8_t ** const)value, sizeof(bytestring32));
}

static inline hal_error_t hal_xdr_decode_bytestring32(const uint8_t ** const inbuf, const uint8_t * const limit, bytestring32 * const value)
{
    return hal_xdr_decode_fixed_opaque(inbuf, limit, (uint8_t * const)value, sizeof(bytestring32));
}

static inline hal_error_t hal_xdr_encode_bytestring16(uint8_t ** const outbuf, const uint8_t * const limit, const bytestring16 *value)
{
    return hal_xdr_encode_fixed_opaque(outbuf, limit, (const uint8_t *)value, sizeof(bytestring16));
}

static inline hal_error_t hal_xdr_decode_bytestring16_ptr(const uint8_t ** const inbuf, const uint8_t * const limit, bytestring16 **value)
{
    return hal_xdr_decode_fixed_opaque_ptr(inbuf, limit, (const uint8_t ** const)value, sizeof(bytestring16));
}

static inline hal_error_t hal_xdr_decode_bytestring16(const uint8_t ** const inbuf, const uint8_t * const limit, bytestring16 * const value)
{
    return hal_xdr_decode_fixed_opaque(inbuf, limit, (uint8_t * const)value, sizeof(bytestring16));
}

/* ---------------------------------------------------------------- */

/*
 * ASN.1 extensions
 */

static inline hal_error_t hal_asn1_encode_size_t(const size_t n, uint8_t *der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_encode_uint32((const uint32_t)n, der, der_len, der_max);
}

static inline hal_error_t hal_asn1_decode_size_t(size_t *np, const uint8_t * const der, size_t *der_len, const size_t der_max)
{
    /* trust the compiler to optimize out the unused code path */
    if (sizeof(size_t) == sizeof(uint32_t)) {
        return hal_asn1_decode_uint32((uint32_t *)np, der, der_len, der_max);
    }
    else {
        uint32_t n;
        hal_error_t err;

        if ((err = hal_asn1_decode_uint32(&n, der, der_len, der_max)) == HAL_OK)
            *np = (size_t)n;

        return err;
    }
}

static inline hal_error_t hal_asn1_encode_lms_algorithm(const hal_lms_algorithm_t type, uint8_t *der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_encode_uint32((const uint32_t)type, der, der_len, der_max);
}

static inline hal_error_t hal_asn1_decode_lms_algorithm(hal_lms_algorithm_t *type, const uint8_t * const der, size_t *der_len, const size_t der_max)
{
    uint32_t n;
    hal_error_t err;

    if ((err = hal_asn1_decode_uint32(&n, der, der_len, der_max)) == HAL_OK)
        *type = (hal_lms_algorithm_t)n;

    return err;
}

static inline hal_error_t hal_asn1_encode_lmots_algorithm(const hal_lmots_algorithm_t type, uint8_t *der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_encode_uint32((const uint32_t)type, der, der_len, der_max);
}

static inline hal_error_t hal_asn1_decode_lmots_algorithm(hal_lmots_algorithm_t *type, const uint8_t * const der, size_t *der_len, const size_t der_max)
{
    uint32_t n;
    hal_error_t err;

    if ((err = hal_asn1_decode_uint32(&n, der, der_len, der_max)) == HAL_OK)
        *type = (hal_lmots_algorithm_t)n;

    return err;
}

#if 0 /* currently unused */
static inline hal_error_t hal_asn1_encode_uuid(const hal_uuid_t * const data, uint8_t *der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_encode_octet_string((const uint8_t * const)data, sizeof(hal_uuid_t), der, der_len, der_max);
}

static inline hal_error_t hal_asn1_decode_uuid(hal_uuid_t *data, const uint8_t * const der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_decode_octet_string((uint8_t *)data, sizeof(hal_uuid_t), der, der_len, der_max);
}
#endif

static inline hal_error_t hal_asn1_encode_bytestring16(const bytestring16 * const data, uint8_t *der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_encode_octet_string((const uint8_t * const)data, sizeof(bytestring16), der, der_len, der_max);
}

static inline hal_error_t hal_asn1_decode_bytestring16(bytestring16 *data, const uint8_t * const der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_decode_octet_string((uint8_t *)data, sizeof(bytestring16), der, der_len, der_max);
}

static inline hal_error_t hal_asn1_encode_bytestring32(const bytestring32 * const data, uint8_t *der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_encode_octet_string((const uint8_t * const)data, sizeof(bytestring32), der, der_len, der_max);
}

static inline hal_error_t hal_asn1_decode_bytestring32(bytestring32 *data, const uint8_t * const der, size_t *der_len, const size_t der_max)
{
    return hal_asn1_decode_octet_string((uint8_t *)data, sizeof(bytestring32), der, der_len, der_max);
}

/* ---------------------------------------------------------------- */

/*
 * LM-OTS
 */

typedef const struct lmots_parameter_set {
    hal_lmots_algorithm_t type;
    size_t                     n,  w, p,   ls;
} lmots_parameter_t;
static lmots_parameter_t lmots_parameters[] = {
    { hal_lmots_sha256_n32_w1, 32, 1, 265, 7 },
    { hal_lmots_sha256_n32_w2, 32, 2, 133, 6 },
    { hal_lmots_sha256_n32_w4, 32, 4, 67,  4 },
    { hal_lmots_sha256_n32_w8, 32, 8, 34,  0 },
};

typedef struct lmots_key {
    hal_key_type_t type;
    lmots_parameter_t *lmots;
    bytestring16 I;
    size_t q;
    bytestring32 * x;
    bytestring32 K;
} lmots_key_t;

static inline lmots_parameter_t *lmots_select_parameter_set(const hal_lmots_algorithm_t lmots_type)
{
    if (lmots_type < hal_lmots_sha256_n32_w1 || lmots_type > hal_lmots_sha256_n32_w8)
        return NULL;
    else
        return &lmots_parameters[lmots_type - hal_lmots_sha256_n32_w1];
}

static inline size_t lmots_private_key_len(lmots_parameter_t * const lmots)
{
    /* u32str(type) || I || u32str(q) || x[0] || x[1] || ... || x[p-1] */
    return 2 * sizeof(uint32_t) + sizeof(bytestring16) + (lmots->p * lmots->n);
}

#if 0 /* currently unused */
static inline size_t lmots_public_key_len(lmots_parameter_t * const lmots)
{
    /* u32str(type) || I || u32str(q) || K */
    return 2 * sizeof(uint32_t) + sizeof(bytestring16) + lmots->n;
}
#endif

static inline size_t lmots_signature_len(lmots_parameter_t * const lmots)
{
    /* u32str(type) || C || y[0] || ... || y[p-1] */
    return sizeof(uint32_t) + (lmots->p + 1) * lmots->n;
}

#if RPC_CLIENT == RPC_CLIENT_LOCAL
/* Given a key with most fields filled in, generate the lmots private and
 * public key components (x and K).
 * Let the caller worry about storage.
 */
static hal_error_t lmots_generate(lmots_key_t * const key, bytestring32 *seed)
{
    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_LMOTS || key->lmots == NULL || key->x == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

//   Algorithm 0: Generating a Private Key

//  3. set n and p according to the typecode and Table 1

    size_t n = key->lmots->n;
    size_t p = key->lmots->p;
    size_t w = key->lmots->w;

    if (seed == NULL) {
//  4. compute the array x as follows:
//     for ( i = 0; i < p; i = i + 1 ) {
//       set x[i] to a uniformly random n-byte string
//     }

        for (size_t i = 0; i < p; ++i)
            check(hal_rpc_get_random(&key->x[i], n));
    }

    else {
        for (size_t i = 0; i < p; ++i) {
// Appendix A.  Pseudorandom Key Generation
//  x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)

            uint8_t statebuf[512];
            hal_hash_state_t *state = NULL;
            uint32_t l;
            uint16_t s;
            uint8_t b;

            check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
            check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
            l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
            s = u16str(i); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
            b = u8str(0xff); check(hal_hash_update(state, (const uint8_t *)&b, sizeof(b)));
            check(hal_hash_update(state, (const uint8_t *)seed, sizeof(bytestring32)));
            check(hal_hash_finalize(state, (uint8_t *)&key->x[i], sizeof(bytestring32)));
        }
    }

//   Algorithm 1: Generating a One Time Signature Public Key From a
//   Private Key

//   4. compute the string K as follows:

    uint8_t statebuf[512];
    hal_hash_state_t *state = NULL;
    bytestring32 y[p];
    uint32_t l;
    uint16_t s;
    uint8_t b;

//      for ( i = 0; i < p; i = i + 1 ) {
    for (size_t i = 0; i < p; ++i) {

//        tmp = x[i]
        bytestring32 tmp;
        memcpy(&tmp, &key->x[i], sizeof(tmp));

//        for ( j = 0; j < 2^w - 1; j = j + 1 ) {
        for (size_t j = 0; j < (1U << w) - 1; ++j) {

//           tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
            check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
            check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
            l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
            s = u16str(i); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
            b = u8str(j); check(hal_hash_update(state, (const uint8_t *)&b, sizeof(b)));
            check(hal_hash_update(state, (const uint8_t *)&tmp, sizeof(tmp)));
            check(hal_hash_finalize(state, (uint8_t *)&tmp, sizeof(tmp)));
        }

//        y[i] = tmp
        memcpy(&y[i], &tmp, sizeof(tmp));
//      }
    }

//      K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1])
    check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
    check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
    l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
    s = u16str(D_PBLC); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
    for (size_t i = 0; i < p; ++i)
        check(hal_hash_update(state, (const uint8_t *)&y[i], sizeof(y[i])));
    check(hal_hash_finalize(state, (uint8_t *)&key->K, sizeof(key->K)));

    return HAL_OK;
}
#endif

/* strings of w-bit elements */
static uint8_t coef(const uint8_t * const S, const size_t i, size_t w)
{
    switch (w) {
    case 1:
        return (S[i/8] >> (7 - (i % 8))) & 0x01;
    case 2:
        return (S[i/4] >> (6 - (2 * (i % 4)))) & 0x03;
    case 4:
        return (S[i/2] >> (4 - (4 * (i % 2)))) & 0x0f;
    case 8:
        return S[i];
    default:
        return 0;
    }
}

/* checksum */
static uint16_t Cksm(const uint8_t * const S, lmots_parameter_t *lmots)
{
    uint16_t sum = 0;

    for (size_t i = 0; i < (lmots->n * 8 / lmots->w); ++i)
        sum += ((1 << lmots->w) - 1) - coef(S, i, lmots->w);

    return (sum << lmots->ls);
}

#if RPC_CLIENT == RPC_CLIENT_LOCAL
static hal_error_t lmots_sign(lmots_key_t *key,
                              const uint8_t * const msg, const size_t msg_len,
                              uint8_t * sig, size_t *sig_len, const size_t sig_max)
{
    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_LMOTS || msg == NULL || sig == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

//   Algorithm 3: Generating a One Time Signature From a Private Key and a
//   Message

//     1. set type to the typecode of the algorithm
//
//     2. set n, p, and w according to the typecode and Table 1

    size_t n = key->lmots->n;
    size_t p = key->lmots->p;
    size_t w = key->lmots->w;

    if (sig_max < lmots_signature_len(key->lmots))
        return HAL_ERROR_BAD_ARGUMENTS;

//     3. determine x, I and q from the private key
//
//     4. set C to a uniformly random n-byte string

    bytestring32 C;
    check(hal_rpc_get_random(&C, n));

//     5. compute the array y as follows:

    uint8_t statebuf[512];
    hal_hash_state_t *state = NULL;
    uint8_t Q[n + 2];           /* hash || 16-bit checksum */
    uint32_t l;
    uint16_t s;
    uint8_t b;

//        Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
    check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
    check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
    l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
    s = u16str(D_MESG); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
    check(hal_hash_update(state, (const uint8_t *)&C, sizeof(C)));
    check(hal_hash_update(state, msg, msg_len));
    check(hal_hash_finalize(state, Q, n));

    /* append checksum */
    *(uint16_t *)&Q[n] = u16str(Cksm((uint8_t *)Q, key->lmots));

    bytestring32 y[p];

//        for ( i = 0; i < p; i = i + 1 ) {
    for (size_t i = 0; i < p; ++i) {

//          a = coef(Q || Cksm(Q), i, w)
        uint8_t a = coef(Q, i, w);

//          tmp = x[i]
        bytestring32 tmp;
        memcpy(&tmp, &key->x[i], sizeof(tmp));

//          for ( j = 0; j < a; j = j + 1 ) {
        for (size_t j = 0; j < (size_t)a; ++j) {

//             tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
            check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
            check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
            l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
            s = u16str(i); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
            b = u8str(j); check(hal_hash_update(state, (const uint8_t *)&b, sizeof(b)));
            check(hal_hash_update(state, (const uint8_t *)&tmp, sizeof(tmp)));
            check(hal_hash_finalize(state, (uint8_t *)&tmp, sizeof(tmp)));
//          }
        }

//          y[i] = tmp
        memcpy(&y[i], &tmp, sizeof(tmp));
    }

//      6. return u32str(type) || C || y[0] || ... || y[p-1]
    uint8_t *sigptr = sig;
    const uint8_t * const siglim = sig + sig_max;
    check(hal_xdr_encode_int(&sigptr, siglim, key->lmots->type));
    check(hal_xdr_encode_bytestring32(&sigptr, siglim, &C));
    for (size_t i = 0; i < p; ++i)
        check(hal_xdr_encode_bytestring32(&sigptr, siglim, &y[i]));

    if (sig_len != NULL)
        *sig_len = sigptr - sig;

    return HAL_OK;
}
#endif

static hal_error_t lmots_public_key_candidate(const lmots_key_t * const key,
                                              const uint8_t * const msg, const size_t msg_len,
                                              const uint8_t * const sig, const size_t sig_len)
{
    if (key == NULL || msg == NULL || sig == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    /* Skip the length checks here, because we did a unitary length check
     * at the start of lms_verify.
     */

//  1. if the signature is not at least four bytes long, return INVALID
//
//  2. parse sigtype, C, and y from the signature as follows:
//     a. sigtype = strTou32(first 4 bytes of signature)

    const uint8_t *sigptr = sig;
    const uint8_t * const siglim = sig + sig_len;

    uint32_t sigtype;
    check(hal_xdr_decode_int(&sigptr, siglim, &sigtype));

//     b. if sigtype is not equal to pubtype, return INVALID

    if ((hal_lmots_algorithm_t)sigtype != key->lmots->type)
        return HAL_ERROR_INVALID_SIGNATURE;

//     c. set n and p according to the pubtype and Table 1;  if the
//     signature is not exactly 4 + n * (p+1) bytes long, return INVALID

    size_t n = key->lmots->n;
    size_t p = key->lmots->p;
    size_t w = key->lmots->w;

//     d. C = next n bytes of signature

    bytestring32 C;
    check(hal_xdr_decode_bytestring32(&sigptr, siglim, &C));

//     e.  y[0] = next n bytes of signature
//         y[1] = next n bytes of signature
//         ...
//       y[p-1] = next n bytes of signature

    bytestring32 y[p];
    for (size_t i = 0; i < p; ++i)
        check(hal_xdr_decode_bytestring32(&sigptr, siglim, &y[i]));

//  3. compute the string Kc as follows

    uint8_t statebuf[512];
    hal_hash_state_t *state = NULL;
    uint8_t Q[n + 2];           /* hash || 16-bit checksum */
    uint32_t l;
    uint16_t s;
    uint8_t b;

//     Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
    check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
    check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
    l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
    s = u16str(D_MESG); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
    check(hal_hash_update(state, (const uint8_t *)&C, sizeof(C)));
    check(hal_hash_update(state, msg, msg_len));
    check(hal_hash_finalize(state, Q, n));

    /* append checksum */
    *(uint16_t *)&Q[n] = u16str(Cksm((uint8_t *)Q, key->lmots));

    bytestring32 z[p];

//     for ( i = 0; i < p; i = i + 1 ) {
    for (size_t i = 0; i < p; ++i) {

//       a = coef(Q || Cksm(Q), i, w)
        uint8_t a = coef(Q, i, w);

//       tmp = y[i]
        bytestring32 tmp;
        memcpy(&tmp, &y[i], sizeof(tmp));

//       for ( j = a; j < 2^w - 1; j = j + 1 ) {
        for (size_t j = (size_t)a; j < (1U << w) - 1; ++j) {

//          tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
            check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
            check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
            l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
            s = u16str(i); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
            b = u8str(j); check(hal_hash_update(state, (const uint8_t *)&b, sizeof(b)));
            check(hal_hash_update(state, (const uint8_t *)&tmp, sizeof(tmp)));
            check(hal_hash_finalize(state, (uint8_t *)&tmp, sizeof(tmp)));
//       }
        }

//       z[i] = tmp
        memcpy(&z[i], &tmp, sizeof(tmp));
//     }
    }

//     Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || z[1] || ... || z[p-1])
    check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
    check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
    l = u32str(key->q); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
    s = u16str(D_PBLC); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
    for (size_t i = 0; i < p; ++i)
        check(hal_hash_update(state, (const uint8_t *)&z[i], sizeof(z[i])));
    check(hal_hash_finalize(state, (uint8_t *)&key->K, sizeof(key->K)));

//  4. return Kc
    return HAL_OK;
}

#if RPC_CLIENT == RPC_CLIENT_LOCAL
static hal_error_t lmots_private_key_to_der(const lmots_key_t * const key,
                                            uint8_t *der, size_t *der_len, const size_t der_max)
{
    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_LMOTS)
        return HAL_ERROR_BAD_ARGUMENTS;

    // u32str(lmots_type) || I || u32str(q) || K || x[0] || x[1] || ... || x[p-1]
    /* K is not an integral part of the private key, but we store it to speed up restart */

    /*
     * Calculate data length.
     */

    size_t len, vlen = 0, hlen;

    check(hal_asn1_encode_lmots_algorithm(key->lmots->type, NULL, &len, 0)); vlen += len;
    check(hal_asn1_encode_bytestring16(&key->I, NULL, &len, 0));             vlen += len;
    check(hal_asn1_encode_size_t(key->q, NULL, &len, 0));                    vlen += len;
    check(hal_asn1_encode_bytestring32(&key->K, NULL, &len, 0));             vlen += len;
    for (size_t i = 0; i < key->lmots->p; ++i) {
        check(hal_asn1_encode_bytestring32(&key->x[i], NULL, &len, 0));      vlen += len;
    }

    check(hal_asn1_encode_header(ASN1_SEQUENCE, vlen, NULL, &hlen, 0));

    check(hal_asn1_encode_pkcs8_privatekeyinfo(hal_asn1_oid_mts_hashsig, hal_asn1_oid_mts_hashsig_len,
                                               NULL, 0, NULL, hlen + vlen, NULL, der_len, der_max));

    if (der == NULL)
        return HAL_OK;

    /*
     * Encode data.
     */

    check(hal_asn1_encode_header(ASN1_SEQUENCE, vlen, der, &hlen, der_max));

    uint8_t *d = der + hlen;
    memset(d, 0, vlen);

    check(hal_asn1_encode_lmots_algorithm(key->lmots->type, d, &len, vlen)); d += len; vlen -= len;
    check(hal_asn1_encode_bytestring16(&key->I, d, &len, vlen));             d += len; vlen -= len;
    check(hal_asn1_encode_size_t(key->q, d, &len, vlen));                    d += len; vlen -= len;
    check(hal_asn1_encode_bytestring32(&key->K, d, &len, vlen));             d += len; vlen -= len;
    for (size_t i = 0; i < key->lmots->p; ++i) {
        check(hal_asn1_encode_bytestring32(&key->x[i], d, &len, vlen));      d += len; vlen -= len;
    }

    return hal_asn1_encode_pkcs8_privatekeyinfo(hal_asn1_oid_mts_hashsig, hal_asn1_oid_mts_hashsig_len,
                                                NULL, 0, der, d - der, der, der_len, der_max);
}

static size_t lmots_private_key_to_der_len(const lmots_key_t * const key)
{
    size_t len = 0;
    return (lmots_private_key_to_der(key, NULL, &len, 0) == HAL_OK) ? len : 0;
}

static hal_error_t lmots_private_key_from_der(lmots_key_t *key,
                                              const uint8_t *der, const size_t der_len)
{
    if (key == NULL || der == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    key->type = HAL_KEY_TYPE_HASHSIG_LMOTS;

    size_t hlen, vlen, alg_oid_len, curve_oid_len, privkey_len;
    const uint8_t     *alg_oid,    *curve_oid,    *privkey;

    check(hal_asn1_decode_pkcs8_privatekeyinfo(&alg_oid, &alg_oid_len,
                                               &curve_oid, &curve_oid_len,
                                               &privkey, &privkey_len,
                                               der, der_len));

    if (alg_oid_len != hal_asn1_oid_mts_hashsig_len ||
        memcmp(alg_oid, hal_asn1_oid_mts_hashsig, alg_oid_len) != 0 ||
        curve_oid_len != 0)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    check(hal_asn1_decode_header(ASN1_SEQUENCE, privkey, privkey_len, &hlen, &vlen));

    const uint8_t *d = privkey + hlen;
    size_t len;

    // u32str(lmots_type) || I || u32str(q) || K || x[0] || x[1] || ... || x[p-1]

    hal_lmots_algorithm_t lmots_type;
    check(hal_asn1_decode_lmots_algorithm(&lmots_type, d, &len, vlen));  d += len; vlen -= len;
    key->lmots = lmots_select_parameter_set(lmots_type);
    check(hal_asn1_decode_bytestring16(&key->I, d, &len, vlen));         d += len; vlen -= len;
    check(hal_asn1_decode_size_t(&key->q, d, &len, vlen));               d += len; vlen -= len;
    check(hal_asn1_decode_bytestring32(&key->K, d, &len, vlen));         d += len; vlen -= len;
    if (key->x != NULL) {
        for (size_t i = 0; i < key->lmots->p; ++i) {
            check(hal_asn1_decode_bytestring32(&key->x[i], d, &len, vlen));  d += len; vlen -= len;
        }

        if (d != privkey + privkey_len)
            return HAL_ERROR_ASN1_PARSE_FAILED;
    }

    return HAL_OK;
}
#endif

/* ---------------------------------------------------------------- */

/*
 * LMS
 */

typedef const struct lms_parameter_set {
    hal_lms_algorithm_t type;
    size_t                    m,  h;
} lms_parameter_t;
static lms_parameter_t lms_parameters[] = {
    { hal_lms_sha256_n32_h5,  32, 5  },
    { hal_lms_sha256_n32_h10, 32, 10 },
    { hal_lms_sha256_n32_h15, 32, 15 },
    { hal_lms_sha256_n32_h20, 32, 20 },
    { hal_lms_sha256_n32_h25, 32, 25 },
};

typedef struct lms_key {
    hal_key_type_t type;
    size_t level;
    lms_parameter_t *lms;
    lmots_parameter_t *lmots;
    bytestring16 I;
    size_t q;			/* index of next lmots signing key */
    size_t q_end;
    hal_uuid_t *lmots_keys;	/* private key components */
    bytestring32 *T;		/* public key components */
    bytestring32 T1;		/* copy of T[1] */
    uint8_t *pubkey;            /* in XDR format */
    size_t pubkey_len;
    uint8_t *signature;         /* of public key by parent lms key */
    size_t signature_len;
} lms_key_t;

static inline lms_parameter_t *lms_select_parameter_set(const hal_lms_algorithm_t lms_type)
{
    if (lms_type < hal_lms_sha256_n32_h5 || lms_type > hal_lms_sha256_n32_h25)
        return NULL;
    else
        return &lms_parameters[lms_type - hal_lms_sha256_n32_h5];
}

static inline size_t lms_public_key_len(lms_parameter_t * const lms)
{
    /* u32str(type) || u32str(otstype) || I || T[1] */
    return 2 * sizeof(uint32_t) + 16 + lms->m;
}

static inline size_t lms_signature_len(lms_parameter_t * const lms, lmots_parameter_t * const lmots)
{
    /* u32str(q) || ots_signature || u32str(type) || path[0] || path[1] || ... || path[h-1] */
    return 2 * sizeof(uint32_t) + lmots_signature_len(lmots) + lms->h * lms->m;
}

#if RPC_CLIENT == RPC_CLIENT_LOCAL
static hal_error_t lms_compute_T_leaf(lms_key_t *key, lmots_key_t *lmots_key)
{
    /* compute T[r] = H(I || u32str(r) || u16str(D_LEAF) || K) */
    size_t r = (1U << key->lms->h) + lmots_key->q;
    uint8_t statebuf[512];
    hal_hash_state_t *state = NULL;
    check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
    check(hal_hash_update(state, (const uint8_t *)&lmots_key->I, sizeof(lmots_key->I)));
    uint32_t l = u32str(r); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
    uint16_t s = u16str(D_LEAF); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
    check(hal_hash_update(state, (const uint8_t *)&lmots_key->K, sizeof(lmots_key->K)));
    check(hal_hash_finalize(state, (uint8_t *)&key->T[r], sizeof(key->T[r])));

    return HAL_OK;
}

static hal_error_t lms_compute_T_intr(lms_key_t *key)
{
    /* generate the rest of T[r] = H(I || u32str(r) || u16str(D_INTR) || T[2*r] || T[2*r+1]) */
    for (size_t r = (1U << key->lms->h) - 1; r > 0; --r) {
        uint8_t statebuf[512];
        hal_hash_state_t *state = NULL;
        check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
        check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
        uint32_t l = u32str(r); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
        uint16_t s = u16str(D_INTR); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
        check(hal_hash_update(state, (const uint8_t *)&key->T[2*r], sizeof(key->T[r])));
        check(hal_hash_update(state, (const uint8_t *)&key->T[2*r+1], sizeof(key->T[r])));
        check(hal_hash_finalize(state, (uint8_t *)&key->T[r], sizeof(key->T[r])));
        hal_task_yield_maybe();
    }

    return HAL_OK;
}

static hal_error_t lms_generate_lmots(lms_key_t *key, size_t q, bytestring32 *seed)
{
    bytestring32 x[key->lmots->p];
    lmots_key_t lmots_key = {
        .type = HAL_KEY_TYPE_HASHSIG_LMOTS,
        .lmots = key->lmots,
        .q = q,
        .x = x
    };
    memcpy(&lmots_key.I, &key->I, sizeof(key->I));

    /* generate the lmots private and public key components */
    check(lmots_generate(&lmots_key, seed));

    /* Note: we have to generate all the lmots keys, even if q > 0 or
     * q_end < 2^h, because we need them to calculate T[].
     * We just don't need to store the ones that are out of range.
     */

    if (q >= key->q && q < key->q_end) {
        /* store the lmots key */
        hal_ks_t *ks = (key->level == 0) ? hal_ks_token : hal_ks_volatile;
        hal_pkey_slot_t slot = {
            .type  = HAL_KEY_TYPE_HASHSIG_LMOTS,
            .curve = HAL_CURVE_NONE,
            .flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | ((key->level == 0) ? HAL_KEY_FLAG_TOKEN: 0)
        };                    
        uint8_t der[lmots_private_key_to_der_len(&lmots_key)];
        size_t der_len;
        check(lmots_private_key_to_der(&lmots_key, der, &der_len, sizeof(der)));
        check(hal_uuid_gen(&slot.name));
        hal_error_t err = hal_ks_store(ks, &slot, der, der_len);
        memset(&x, 0, sizeof(x));
        memset(der, 0, sizeof(der));
        if (err != HAL_OK) return err;

        /* record the lmots keystore name */
        memcpy(&key->lmots_keys[q], &slot.name, sizeof(slot.name));
    }
    else
        memset(&x, 0, sizeof(x));

    /* compute T[r] = H(I || u32str(r) || u16str(D_LEAF) || K) */
    check(lms_compute_T_leaf(key, &lmots_key));

    return HAL_OK;
}

/* Given a key with most fields filled in, generate the lms private and
 * public key components.
 * Let the caller worry about storage.
 */
static hal_error_t lms_generate(lms_key_t *key, bytestring32 *seed)
{
    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_LMS ||
        key->lms == NULL || key->lmots == NULL ||
        key->lmots_keys == NULL || key->T == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    hal_uuid_t I_0 = {{0}};
    if (hal_uuid_cmp((hal_uuid_t *)&key->I, &I_0) == 0)
        check(hal_uuid_gen((hal_uuid_t *)&key->I));

    /* private key - array of lmots key names */
    for (size_t q = 0; q < (1U << key->lms->h); ++q) {
        check(lms_generate_lmots(key, q, seed));
        hal_task_yield_maybe();
    }

    /* generate the rest of T[r] = H(I || u32str(r) || u16str(D_INTR) || T[2*r] || T[2*r+1]) */
    check(lms_compute_T_intr(key));

    memcpy(&key->T1, &key->T[1], sizeof(key->T1));

    /* generate the XDR encoding of the public key, which will be signed
     * by the previous lms key
     */
    uint8_t *pubkey = key->pubkey;
    const uint8_t * const publim = key->pubkey + key->pubkey_len;
    // u32str(lms_type) || u32str(lmots_type) || I || T[1]
    check(hal_xdr_encode_int(&pubkey, publim, key->lms->type));
    check(hal_xdr_encode_int(&pubkey, publim, key->lmots->type));
    check(hal_xdr_encode_bytestring16(&pubkey, publim, &key->I));
    check(hal_xdr_encode_bytestring32(&pubkey, publim, &key->T1));

    return HAL_OK;
}

static hal_error_t lms_delete(const lms_key_t * const key)
{
    hal_ks_t *ks = (key->level == 0) ? hal_ks_token : hal_ks_volatile;
    hal_pkey_slot_t slot = {{0}};
    hal_uuid_t uuid_0 = {{0}};

    /* delete the lmots keys */
    for (size_t i = 0; i < (1U << key->lms->h); ++i) {
        if (hal_uuid_cmp(&key->lmots_keys[i], &uuid_0) != 0) {
            memcpy(&slot.name, &key->lmots_keys[i], sizeof(slot.name));
            (void)hal_ks_delete(ks, &slot);
            hal_task_yield_maybe();
        }
    }

    /* delete the lms key */
    memcpy(&slot.name, &key->I, sizeof(slot.name));
    return hal_ks_delete(ks, &slot);
}

static hal_error_t lms_private_key_to_der(const lms_key_t * const key,
                                          uint8_t *der, size_t *der_len, const size_t der_max);

static hal_error_t lms_sign(lms_key_t * const key,
                            const uint8_t * const msg, const size_t msg_len,
                            uint8_t *sig, size_t *sig_len, const size_t sig_max)
{
    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_LMS || msg == NULL || sig == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    if (key->q >= key->q_end)
        return HAL_ERROR_HASHSIG_KEY_EXHAUSTED;

    if (sig_max < lms_signature_len(key->lms, key->lmots))
        return HAL_ERROR_RESULT_TOO_LONG;

    /* u32str(q) || ots_signature || u32str(lms_type) || path[0] || path[1] || ... || path[h-1] */

    uint8_t *sigptr = sig;
    const uint8_t * const siglim = sig + sig_max;
    check(hal_xdr_encode_int(&sigptr, siglim, key->q));

    /* fetch and decode the lmots signing key from the keystore */
    hal_pkey_slot_t slot = {0};
    memcpy(&slot.name, &key->lmots_keys[key->q], sizeof(slot.name));

    lmots_key_t lmots_key;
    memset(&lmots_key, 0, sizeof(lmots_key));
    bytestring32 x[key->lmots->p];
    memset(&x, 0, sizeof(x));
    lmots_key.x = x;

    uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
    size_t der_len;
    hal_ks_t *ks = (key->level == 0) ? hal_ks_token : hal_ks_volatile;
    check(hal_ks_fetch(ks, &slot, der, &der_len, sizeof(der)));
    check(lmots_private_key_from_der(&lmots_key, der, der_len));
    memset(&der, 0, sizeof(der));

    //? check lmots_type and I vs. lms key?

    /* generate the lmots signature */
    size_t lmots_sig_len;
    check(lmots_sign(&lmots_key, msg, msg_len, sigptr, &lmots_sig_len, sig_max - (sigptr - sig)));
    memset(&x, 0, sizeof(x));
    sigptr += lmots_sig_len;

    check(hal_xdr_encode_int(&sigptr, siglim, key->lms->type));

    /* generate the path array */
    for (size_t r = (1 << key->lms->h) + key->q; r > 1; r /= 2)
        check(hal_xdr_encode_bytestring32(&sigptr, siglim, ((r & 1) ? &key->T[r-1] : &key->T[r+1])));

    if (sig_len != NULL)
        *sig_len = sigptr - sig;

    /* update and store q before returning the signature */
    ++key->q;
    check(lms_private_key_to_der(key, der, &der_len, sizeof(der)));
    slot.type = HAL_KEY_TYPE_HASHSIG_LMS;
    slot.flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | ((key->level == 0) ? HAL_KEY_FLAG_TOKEN : 0);
    memcpy(&slot.name, &key->I, sizeof(slot.name));
    check(hal_ks_rewrite_der(ks, &slot, der, der_len));

    return HAL_OK;
}
#endif

static hal_error_t lms_public_key_candidate(const lms_key_t * const key,
                                            const uint8_t * const msg, const size_t msg_len,
                                            const uint8_t * const sig, const size_t sig_len,
                                            bytestring32 * Tc);

static hal_error_t lms_verify(const lms_key_t * const key,
                              const uint8_t * const msg, const size_t msg_len,
                              const uint8_t * const sig, const size_t sig_len)
{
    if (key == NULL || msg == NULL || sig == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    /* We can do one length check right now, rather than the 3 in
     * Algorithm 6b and 2 in Algorithm 4b, because the lms and lmots types
     * in the signature have to match the key.
     */
    if (sig_len != lms_signature_len(key->lms, key->lmots))
        return HAL_ERROR_INVALID_SIGNATURE;

//   Algorithm 6: LMS Signature Verification
//
//    1. if the public key is not at least eight bytes long, return
//       INVALID
//
//    2. parse pubtype, I, and T[1] from the public key as follows:
//
//       a. pubtype = strTou32(first 4 bytes of public key)
//
//       b. ots_typecode = strTou32(next 4 bytes of public key)
//
//       c. set m according to pubtype, based on Table 2
//
//       d. if the public key is not exactly 24 + m bytes
//          long, return INVALID
//
//       e. I = next 16 bytes of the public key
//
//       f. T[1] = next m bytes of the public key
//
//    3. compute the candidate LMS root value Tc from the signature,
//       message, identifier and pubtype using Algorithm 6b.

    bytestring32 Tc;
    check(lms_public_key_candidate(key, msg, msg_len, sig, sig_len, &Tc));

//    4. if Tc is equal to T[1], return VALID; otherwise, return INVALID

    return (memcmp(&Tc, &key->T1, sizeof(Tc)) ? HAL_ERROR_INVALID_SIGNATURE : HAL_OK);
}

static hal_error_t lms_public_key_candidate(const lms_key_t * const key,
                                            const uint8_t * const msg, const size_t msg_len,
                                            const uint8_t * const sig, const size_t sig_len,
                                            bytestring32 * Tc)
{
//   Algorithm 6b: Computing an LMS Public Key Candidate from a Signature,
//   Message, Identifier, and algorithm typecode
    /* XXX and pubotstype */

//  1. if the signature is not at least eight bytes long, return INVALID
//
//  2. parse sigtype, q, ots_signature, and path from the signature as
//     follows:
//
//    a. q = strTou32(first 4 bytes of signature)

    const uint8_t *sigptr = sig;
    const uint8_t * const siglim = sig + sig_len;

    uint32_t q;
    check(hal_xdr_decode_int(&sigptr, siglim, &q));

//    b. otssigtype = strTou32(next 4 bytes of signature)

    uint32_t otssigtype;
    check(hal_xdr_decode_int_peek(&sigptr, siglim, &otssigtype));

//    c. if otssigtype is not the OTS typecode from the public key, return INVALID

    if ((hal_lmots_algorithm_t)otssigtype != key->lmots->type)
        return HAL_ERROR_INVALID_SIGNATURE;

//    d. set n, p according to otssigtype and Table 1; if the
//    signature is not at least 12 + n * (p + 1) bytes long, return INVALID
//
//    e. ots_signature = bytes 8 through 8 + n * (p + 1) - 1 of signature

    /* XXX Technically, this is also wrong - this is the remainder of
     * ots_signature after otssigtype. The full ots_signature would be
     * bytes 4 through 8 + n * (p + 1) - 1.
     */

    const uint8_t * const ots_signature = sigptr;
    sigptr += lmots_signature_len(key->lmots);

//    f. sigtype = strTou32(4 bytes of signature at location 8 + n * (p + 1))

    uint32_t sigtype;
    check(hal_xdr_decode_int(&sigptr, siglim, &sigtype));

//    f. if sigtype is not the LM typecode from the public key, return INVALID

    if ((hal_lms_algorithm_t)sigtype != key->lms->type)
        return HAL_ERROR_INVALID_SIGNATURE;

//    g. set m, h according to sigtype and Table 2

    size_t m = key->lms->m;
    size_t h = key->lms->h;
    size_t h2 = (1 << key->lms->h);

//    h. if q >= 2^h or the signature is not exactly 12 + n * (p + 1) + m * h bytes long, return INVALID

    if (q >= h2)
        return HAL_ERROR_INVALID_SIGNATURE;

//    i. set path as follows:
//          path[0] = next m bytes of signature
//          path[1] = next m bytes of signature
//          ...
//          path[h-1] = next m bytes of signature

    bytestring32 path[h];
    for (size_t i = 0; i < h; ++i)
        check(hal_xdr_decode_bytestring32(&sigptr, siglim, &path[i]));

//  3. Kc = candidate public key computed by applying Algorithm 4b
//     to the signature ots_signature, the message, and the
//     identifiers I, q

    lmots_key_t lmots_key = {
        .type =  HAL_KEY_TYPE_HASHSIG_LMOTS,
        .lmots = key->lmots,
        .q = q
    };
    memcpy(&lmots_key.I, &key->I, sizeof(lmots_key.I));
    check(lmots_public_key_candidate(&lmots_key, msg, msg_len, ots_signature, lmots_signature_len(key->lmots)));

//  4. compute the candidate LMS root value Tc as follows:

    uint8_t statebuf[512];
    hal_hash_state_t *state = NULL;
    uint32_t l;
    uint16_t s;

//     node_num = 2^h + q
    size_t r = h2 + q;

//     tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
    bytestring32 tmp;
    check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
    check(hal_hash_update(state, (const uint8_t *)&lmots_key.I, sizeof(lmots_key.I)));
    l = u32str(r); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
    s = u16str(D_LEAF); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
    check(hal_hash_update(state, (const uint8_t *)&lmots_key.K, sizeof(lmots_key.K)));
    check(hal_hash_finalize(state, (uint8_t *)&tmp, sizeof(tmp)));

//     i = 0
//     while (node_num > 1) {
//       if (node_num is odd):
//         tmp = H(I || u32str(node_num/2) || u16str(D_INTR) || path[i] || tmp)
//       else:
//         tmp = H(I || u32str(node_num/2) || u16str(D_INTR) || tmp || path[i])
//       node_num = node_num/2
//       i = i + 1
//     }
    for (size_t i = 0; r > 1; r /= 2, ++i) {
        check(hal_hash_initialize(NULL, hal_hash_sha256, &state, statebuf, sizeof(statebuf)));
        check(hal_hash_update(state, (const uint8_t *)&key->I, sizeof(key->I)));
        l = u32str(r/2); check(hal_hash_update(state, (const uint8_t *)&l, sizeof(l)));
        s = u16str(D_INTR); check(hal_hash_update(state, (const uint8_t *)&s, sizeof(s)));
        if (r & 1) {
            check(hal_hash_update(state, (const uint8_t *)&path[i], m));
            check(hal_hash_update(state, (const uint8_t *)&tmp, sizeof(tmp)));
        }
        else {
            check(hal_hash_update(state, (const uint8_t *)&tmp, sizeof(tmp)));
            check(hal_hash_update(state, (const uint8_t *)&path[i], m));
        }
        check(hal_hash_finalize(state, (uint8_t *)&tmp, sizeof(tmp)));
    }

//     Tc = tmp
    memcpy(Tc, &tmp, sizeof(*Tc));

    return HAL_OK;
}

#if RPC_CLIENT == RPC_CLIENT_LOCAL
static hal_error_t lms_private_key_to_der(const lms_key_t * const key,
                                          uint8_t *der, size_t *der_len, const size_t der_max)
{
    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_LMS)
        return HAL_ERROR_BAD_ARGUMENTS;

    /*
     * Calculate data length.
     */

    // u32str(lms_type) || u32str(lmots_type) || I || q || q_end

    size_t len, vlen = 0, hlen;

    check(hal_asn1_encode_lms_algorithm(key->lms->type, NULL, &len, 0));     vlen += len;
    check(hal_asn1_encode_lmots_algorithm(key->lmots->type, NULL, &len, 0)); vlen += len;
    check(hal_asn1_encode_bytestring16(&key->I, NULL, &len, 0));             vlen += len;
    check(hal_asn1_encode_size_t(key->q, NULL, &len, 0));                    vlen += len;
    check(hal_asn1_encode_size_t(key->q_end, NULL, &len, 0));                vlen += len;

    check(hal_asn1_encode_header(ASN1_SEQUENCE, vlen, NULL, &hlen, 0));

    check(hal_asn1_encode_pkcs8_privatekeyinfo(hal_asn1_oid_mts_hashsig, hal_asn1_oid_mts_hashsig_len,
                                               NULL, 0, NULL, hlen + vlen, NULL, der_len, der_max));

    if (der == NULL)
        return HAL_OK;

    /*
     * Encode data.
     */

    check(hal_asn1_encode_header(ASN1_SEQUENCE, vlen, der, &hlen, der_max));

    uint8_t *d = der + hlen;
    memset(d, 0, vlen);

    check(hal_asn1_encode_lms_algorithm(key->lms->type, d, &len, vlen));     d += len; vlen -= len;
    check(hal_asn1_encode_lmots_algorithm(key->lmots->type, d, &len, vlen)); d += len; vlen -= len;
    check(hal_asn1_encode_bytestring16(&key->I, d, &len, vlen));             d += len; vlen -= len;
    check(hal_asn1_encode_size_t(key->q, d, &len, vlen));                    d += len; vlen -= len;
    check(hal_asn1_encode_size_t(key->q_end, d, &len, vlen));                d += len; vlen -= len;

    return hal_asn1_encode_pkcs8_privatekeyinfo(hal_asn1_oid_mts_hashsig, hal_asn1_oid_mts_hashsig_len,
                                                NULL, 0, der, d - der, der, der_len, der_max);
}

static size_t lms_private_key_to_der_len(const lms_key_t * const key)
{
    size_t len = 0;
    return lms_private_key_to_der(key, NULL, &len, 0) == HAL_OK ? len : 0;
}

static hal_error_t lms_private_key_from_der(lms_key_t *key,
                                            const uint8_t *der, const size_t der_len)
{
    if (key == NULL || der == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    memset(key, 0, sizeof(*key));

    key->type = HAL_KEY_TYPE_HASHSIG_LMS;

    size_t hlen, vlen, alg_oid_len, curve_oid_len, privkey_len;
    const uint8_t     *alg_oid,    *curve_oid,    *privkey;

    check(hal_asn1_decode_pkcs8_privatekeyinfo(&alg_oid, &alg_oid_len,
                                               &curve_oid, &curve_oid_len,
                                               &privkey, &privkey_len,
                                               der, der_len));

    if (alg_oid_len != hal_asn1_oid_mts_hashsig_len ||
        memcmp(alg_oid, hal_asn1_oid_mts_hashsig, alg_oid_len) != 0 ||
        curve_oid_len != 0)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    check(hal_asn1_decode_header(ASN1_SEQUENCE, privkey, privkey_len, &hlen, &vlen));

    const uint8_t *d = privkey + hlen;
    size_t n;

    // u32str(lms_type) || u32str(lmots_type) || I || q || q_end

    hal_lms_algorithm_t lms_type;
    check(hal_asn1_decode_lms_algorithm(&lms_type, d, &n, vlen));     d += n; vlen -= n;
    key->lms = lms_select_parameter_set(lms_type);
    hal_lmots_algorithm_t lmots_type;
    check(hal_asn1_decode_lmots_algorithm(&lmots_type, d, &n, vlen)); d += n; vlen -= n;
    key->lmots = lmots_select_parameter_set(lmots_type);
    check(hal_asn1_decode_bytestring16(&key->I, d, &n, vlen));        d += n; vlen -= n;
    check(hal_asn1_decode_size_t(&key->q, d, &n, vlen));              d += n; vlen -= n;
    check(hal_asn1_decode_size_t(&key->q_end, d, &n, vlen));          d += n; vlen -= n;

    if (d != privkey + privkey_len)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    return HAL_OK;
}
#endif

/* ---------------------------------------------------------------- */

/*
 * HSS
 */

/* For purposes of the external API, the key type is "hal_hashsig_key_t".
 * Internally, we refer to it as "hss_key_t".
 */

typedef struct hal_hashsig_key hss_key_t;

struct hal_hashsig_key {
    hal_key_type_t type;
    hss_key_t *next;
    hal_uuid_t name;
    size_t L;
    lms_parameter_t *lms;
    lmots_parameter_t *lmots;
    bytestring16 I;
    size_t q_start, q_end;
    bytestring32 T1;
    bytestring32 seed;
    lms_key_t *lms_keys;
};

const size_t hal_hashsig_key_t_size = sizeof(hss_key_t);

static hss_key_t *hss_keys = NULL;

static hss_key_t *hss_find(bytestring16 *I)
{
    for (hss_key_t *key = hss_keys; key != NULL; key = key->next) {
        if (memcmp(&key->I, I, sizeof(*I)) == 0)
            return key;
    }

    return NULL;
}

#if 0 /* currently unused */
static inline size_t hss_public_key_len(lms_parameter_t * const lms)
{
    /* L || pub[0] */
    return sizeof(uint32_t) + lms_public_key_len(lms);
}
#endif

static inline size_t hss_signature_len(const size_t L, lms_parameter_t * const lms, lmots_parameter_t * const lmots)
{
    /* u32str(Nspk) || sig[0] || pub[1] || ... || sig[Nspk-1] || pub[Nspk] || sig[Nspk] */
    return sizeof(uint32_t) + L * lms_signature_len(lms, lmots) + (L - 1) * lms_public_key_len(lms);
}

size_t hal_hashsig_signature_len(const size_t L,
                                 const hal_lms_algorithm_t lms_type,
                                 const hal_lmots_algorithm_t lmots_type)
{
    lms_parameter_t * const lms = lms_select_parameter_set(lms_type);
    if (lms == NULL)
        return 0;

    lmots_parameter_t * const lmots = lmots_select_parameter_set(lmots_type);
    if (lmots == NULL)
        return 0;

    return hss_signature_len(L, lms, lmots);
}

size_t hal_hashsig_lmots_private_key_len(const hal_lmots_algorithm_t lmots_type)
{
    lmots_parameter_t * const lmots = lmots_select_parameter_set(lmots_type);
    if (lmots == NULL)
        return 0;

    return lmots_private_key_len(lmots);
}

#if RPC_CLIENT == RPC_CLIENT_LOCAL
static int restart_in_progress = 0;

static inline void *gnaw(uint8_t **mem, size_t *len, const size_t size)
{
    if (mem == NULL || *mem == NULL || len == NULL || size > *len)
        return NULL;
    void *ret = *mem;
    *mem += size;
    *len -= size;
    return ret;
}

static hal_error_t hss_alloc(hal_hashsig_key_t **key_)
{
    if (key_ == NULL || *key_ == NULL ||
        (*key_)->type != HAL_KEY_TYPE_HASHSIG_PRIVATE ||
        (*key_)->L == 0 || (*key_)->L > 8 ||
        (*key_)->lms == NULL || (*key_)->lmots == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    size_t L = (*key_)->L;
    lms_parameter_t *lms = (*key_)->lms;
    lmots_parameter_t *lmots = (*key_)->lmots;
    size_t h2 = (1U << lms->h);

    /* w=1 fails on the Alpha, because the key exceeds the keystore block
     * size. The XDR encoding of the key is going to differ from the DER
     * encoding, but it's at least in the ballpark to tell us whether the key
     * will fit.
     */
    if (lmots_private_key_len(lmots) > HAL_KS_BLOCK_SIZE)
        return HAL_ERROR_UNSUPPORTED_KEY;

    if (hss_signature_len(L, lms, lmots) > HAL_RPC_MAX_PKT_SIZE)
        return HAL_ERROR_UNSUPPORTED_KEY;

    /* check volatile keystore for space to store the lower-level trees */
    size_t available;
    check(hal_ks_available(hal_ks_volatile, &available));
    if (available < (L - 1) * (h2 + 1))
        return HAL_ERROR_NO_KEY_INDEX_SLOTS;

    size_t lms_sig_len = lms_signature_len(lms, lmots);
    size_t lms_pub_len = lms_public_key_len(lms);

    /* allocate lms tree nodes and lmots key names, atomically */
    size_t len = (sizeof(hss_key_t) +
                  L * sizeof(lms_key_t) +
                  L * lms_sig_len +
                  L * lms_pub_len +
                  L * h2 * sizeof(hal_uuid_t) +
                  L * (2 * h2) * sizeof(bytestring32));
    uint8_t *mem = hal_allocate_static_memory(len);
    if (mem == NULL)
        return HAL_ERROR_ALLOCATION_FAILURE;
    memset(mem, 0, len);

    /* allocate the key that will stay in working memory */
    hss_key_t *key = gnaw(&mem, &len, sizeof(*key));

    /* initialize it from the transitory key */
    memcpy(key, *key_, sizeof(*key));
    *key_ = key;

    /* add the in-memory key to the list of active keys */
    key->next = hss_keys;
    hss_keys = key;

    /* allocate the list of lms trees */
    key->lms_keys = gnaw(&mem, &len, L * sizeof(lms_key_t));
    for (size_t i = 0; i < L; ++i) {
        lms_key_t * lms_key = &key->lms_keys[i];
        lms_key->type = HAL_KEY_TYPE_HASHSIG_LMS;
        lms_key->lms = lms;
        lms_key->lmots = lmots;
        lms_key->level = i;
        lms_key->lmots_keys = (hal_uuid_t *)gnaw(&mem, &len, h2 * sizeof(hal_uuid_t));
        lms_key->T = gnaw(&mem, &len, (2 * h2) * sizeof(bytestring32));
        lms_key->signature = gnaw(&mem, &len, lms_sig_len);
        lms_key->signature_len = lms_sig_len;
        lms_key->pubkey = gnaw(&mem, &len, lms_pub_len);
        lms_key->pubkey_len = lms_pub_len;
        lms_key->q_end = h2;
    }

    return HAL_OK;
}

static hal_error_t hss_generate(hss_key_t **key_, const hal_key_flags_t flags)
{
    /* Hashsig keys can only be used for signing, so it makes sense to check
     * that now, rather than waiting until the user tries to sign.
     *
     * Also, the top-level tree must be stored in the token (flash) keystore.
     * I experimented with allowing keys to be stored in the volatile
     * keystore, but that had some ugly consequences around the fact that
     * volatile keys are automatically deleted when the user logs out. I'm
     * also not sure there's a good use case for volatile hashsig keys.
     */
    if (!(flags & HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE) ||
        !(flags & HAL_KEY_FLAG_TOKEN))
        return HAL_ERROR_FORBIDDEN;

    if (key_ == NULL || *key_ == NULL || (*key_)->lms == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    /* hss_alloc does most of the sanity checks */

    /* check flash keystore for space to store the root tree:
     * 2^h lmots keys + 1 lms key + 1 hss key
     */
    size_t available;
    check(hal_ks_available(hal_ks_token, &available));
    if (available < (*key_)->q_end - (*key_)->q_start + 2)
        return HAL_ERROR_NO_KEY_INDEX_SLOTS;

    check(hss_alloc(key_));
    hss_key_t *key = *key_;
    hal_error_t err;

    /* generate the lms trees */
    for (size_t i = 0; i < key->L; ++i) {
        lms_key_t * lms_key = &key->lms_keys[i];
        bytestring32 *seed = NULL;

        if (i == 0) {
            memcpy(&lms_key->I, &key->I, sizeof(key->I));
            lms_key->q = key->q_start;
            lms_key->q_end = key->q_end;

            /* If we're called from import, seed will be filled in.
             * If called from key_gen, seed will be 0, and we may need to
             * generate it.
             */
            bytestring32 seed_0 = {{0}};
            if (memcmp(&key->seed, &seed_0, sizeof(seed_0)) != 0) {
                seed = &key->seed;
            }
            else if (flags & HAL_KEY_FLAG_EXPORTABLE) {
                seed = &key->seed;
                if ((err = hal_rpc_get_random(seed, sizeof(*seed))) != HAL_OK)
                    goto err_out;
            }
        }

        if ((err = lms_generate(lms_key, seed)) != HAL_OK)
            goto err_out;

        if (i > 0)
            /* sign this tree with the previous */
            if ((err = lms_sign(&key->lms_keys[i-1],
                                (const uint8_t * const)lms_key->pubkey,
                                lms_public_key_len(key->lms),
                                lms_key->signature, NULL,
                                lms_signature_len(key->lms, key->lmots))) != HAL_OK)
                goto err_out;

        /* store the lms key */
        hal_ks_t *ks = (i == 0) ? hal_ks_token : hal_ks_volatile;
        hal_pkey_slot_t slot = {
            .type  = HAL_KEY_TYPE_HASHSIG_LMS,
            .flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | ((i == 0) ? HAL_KEY_FLAG_TOKEN: 0)
        };
        uint8_t der[lms_private_key_to_der_len(lms_key)];
        size_t der_len;

        memcpy(&slot.name, &lms_key->I, sizeof(slot.name));
        if ((err = lms_private_key_to_der(lms_key, der, &der_len, sizeof(der))) != HAL_OK ||
            (err = hal_ks_store(ks, &slot, der, der_len)) != HAL_OK)
            goto err_out;
    }

    memcpy(&key->I, &key->lms_keys[0].I, sizeof(key->I));
    memcpy(&key->T1, &key->lms_keys[0].T1, sizeof(key->T1));

    /* pkey_local_generate_hashsig stores the key */

    return HAL_OK;

err_out:
    (void)hal_free_static_memory(key);
    return err;
}

/* called from pkey_local_generate_hashsig
 * caller will store the key
 */
hal_error_t hal_hashsig_key_gen(hal_core_t *core,
                                hal_hashsig_key_t **key_,
                                void *keybuf, const size_t keybuf_len,
                                const size_t L,
                                const hal_lms_algorithm_t lms_type,
                                const hal_lmots_algorithm_t lmots_type,
                                const hal_key_flags_t flags)
{ 
   if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(hss_key_t))
        return HAL_ERROR_BAD_ARGUMENTS;

    if (restart_in_progress)
        return HAL_ERROR_NOT_READY;

    hss_key_t *key = *key_ = keybuf;
    memset(key, 0, sizeof(*key));
    key->type = HAL_KEY_TYPE_HASHSIG_PRIVATE;
    key->L = L;
    key->lms = lms_select_parameter_set(lms_type);
    key->lmots = lmots_select_parameter_set(lmots_type);
    key->q_end = (1U << key->lms->h);

    return hss_generate(key_, flags);
}

static void hss_delete(hss_key_t *key)
{
    /* remove key from global hss_keys linked list */
    if (hss_keys == key) {
        hss_keys = key->next;
    }
    else {
        for (hss_key_t *prev = hss_keys; prev != NULL; prev = prev->next) {
            if (prev->next == key) {
                prev->next = key->next;
                break;
            }
        }
    }

    /* delete the lms trees and their lmots keys */
    for (size_t level = 0; level < key->L; ++level)
        (void)lms_delete(&key->lms_keys[level]);

    /* free memory, if possible */
    (void)hal_free_static_memory(key);
}

/* caller will delete the hss key from the keystore */
hal_error_t hal_hashsig_delete(const hal_uuid_t * const name)
{
    if (restart_in_progress)
        return HAL_ERROR_NOT_READY;

    hal_pkey_slot_t slot = { .name = *name };
    uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
    size_t der_len;
    check(hal_ks_fetch(hal_ks_token, &slot, der, &der_len, sizeof(der)));

    hal_hashsig_key_t keybuf, *key;
    check(hal_hashsig_private_key_from_der(&key, &keybuf, sizeof(keybuf), der, der_len));

    /* hal_hashsig_private_key_from_der returns the key in the list of
     * active hashsig keys, so we don't need this temporary key.
     */
    memset(der, 0, sizeof(der));
    memset(&keybuf, 0, sizeof(keybuf));

    /* OTOH, if we found the key in the keystore, but not in the list of
     * active hashsig keys, that's Bad.
     */
    if (key == &keybuf)
        return HAL_ERROR_KEY_NOT_FOUND;

    hss_delete(key);
    return HAL_OK;
}

hal_error_t hal_hashsig_sign(hal_core_t *core,
                             const hal_hashsig_key_t * const key,
                             const uint8_t * const msg, const size_t msg_len,
                             uint8_t *sig, size_t *sig_len, const size_t sig_max)
{
    if (restart_in_progress)
        return HAL_ERROR_NOT_READY;

    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_PRIVATE || msg == NULL || sig == NULL || sig_len == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    if (sig_max < hss_signature_len(key->L, key->lms, key->lmots))
        return HAL_ERROR_RESULT_TOO_LONG;

//   To sign a message using the private key prv, the following steps are
//   performed:
//
//      If prv[L-1] is exhausted, then determine the smallest integer d
//      such that all of the private keys prv[d], prv[d+1], ... , prv[L-1]
//      are exhausted.  If d is equal to zero, then the HSS key pair is
//      exhausted, and it MUST NOT generate any more signatures.
//      Otherwise, the key pairs for levels d through L-1 must be
//      regenerated during the signature generation process, as follows.
//      For i from d to L-1, a new LMS public and private key pair with a
//      new identifier is generated, pub[i] and prv[i] are set to those
//      values, then the public key pub[i] is signed with prv[i-1], and
//      sig[i-1] is set to the resulting value.

    if (key->lms_keys[key->L-1].q >= key->lms_keys[key->L-1].q_end) {
        size_t d;
        for (d = key->L-1; d > 0 && key->lms_keys[d-1].q >= key->lms_keys[d-1].q_end; --d) {
        }
        if (d == 0)
            return HAL_ERROR_HASHSIG_KEY_EXHAUSTED;
        for ( ; d < key->L; ++d) {
            lms_key_t *lms_key = &key->lms_keys[d];
            /* Delete then regenerate the LMS key. We don't worry about
             * power-cycling in the middle, because the lower-level trees are
             * all stored in the volatile keystore, so we'd have to regenerate
             * them anyway on restart; and this way we don't have to allocate
             * any additional memory.
             */
            check(lms_delete(lms_key));
            lms_key->q = 0;
            check(lms_generate(lms_key, NULL));
            check(lms_sign(&key->lms_keys[d-1],
                           (const uint8_t * const)lms_key->pubkey, lms_key->pubkey_len,
                           lms_key->signature, NULL, lms_key->signature_len));

            hal_pkey_slot_t slot = {
                .type  = HAL_KEY_TYPE_HASHSIG_LMS,
                .curve = HAL_CURVE_NONE,
                .flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | (lms_key->level == 0) ? HAL_KEY_FLAG_TOKEN: 0
            };
            hal_ks_t *ks = hal_ks_volatile;
            uint8_t der[lms_private_key_to_der_len(lms_key)];
            size_t der_len;

            memcpy(&slot.name, &lms_key->I, sizeof(slot.name));
            check(lms_private_key_to_der(lms_key, der, &der_len, sizeof(der)));
            check(hal_ks_store(ks, &slot, der, der_len));
        }
    }

//      The message is signed with prv[L-1], and the value sig[L-1] is set
//      to that result.
//
//      The value of the HSS signature is set as follows.  We let
//      signed_pub_key denote an array of octet strings, where
//      signed_pub_key[i] = sig[i] || pub[i+1], for i between 0 and Nspk-
//      1, inclusive, where Nspk = L-1 denotes the number of signed public
//      keys.  Then the HSS signature is u32str(Nspk) ||
//      signed_pub_key[0] || ... || signed_pub_key[Nspk-1] || sig[Nspk].

    uint8_t *sigptr = sig;
    const uint8_t * const siglim = sig + sig_max;
    check(hal_xdr_encode_int(&sigptr, siglim, key->L - 1));

    /* copy the lms signed public keys into the signature */
    for (size_t i = 1; i < key->L; ++i) {
        lms_key_t *lms_key = &key->lms_keys[i];
        check(hal_xdr_encode_fixed_opaque(&sigptr, siglim, lms_key->signature, lms_key->signature_len));
        check(hal_xdr_encode_fixed_opaque(&sigptr, siglim, lms_key->pubkey, lms_key->pubkey_len));
    }

    /* sign the message with the last lms private key */
    size_t len;
    check(lms_sign(&key->lms_keys[key->L-1], msg, msg_len, sigptr, &len, sig_max - (sigptr - sig)));
    sigptr += len;
    *sig_len = sigptr - sig;

    return HAL_OK;
}
#endif

hal_error_t hal_hashsig_verify(hal_core_t *core,
                               const hal_hashsig_key_t * const key,
                               const uint8_t * const msg, const size_t msg_len,
                               const uint8_t * const sig, const size_t sig_len)
{
    if (key == NULL || (key->type != HAL_KEY_TYPE_HASHSIG_PRIVATE && key->type != HAL_KEY_TYPE_HASHSIG_PUBLIC) || msg == NULL || sig == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

//   To verify a signature sig and message using the public key pub, the
//   following steps are performed:
//
//      The signature S is parsed into its components as follows:
//
//      Nspk = strTou32(first four bytes of S)
//      if Nspk+1 is not equal to the number of levels L in pub:
//         return INVALID

    const uint8_t *sigptr = sig;
    const uint8_t * const siglim = sig + sig_len;

    uint32_t Nspk;
    check(hal_xdr_decode_int(&sigptr, siglim, &Nspk));
    if (Nspk + 1 != key->L)
        return HAL_ERROR_INVALID_SIGNATURE;

//      key = pub
//      for (i = 0; i < Nspk; i = i + 1) {
//         sig = next LMS signature parsed from S
//         msg = next LMS public key parsed from S
//         if (lms_verify(msg, key, sig) != VALID):
//             return INVALID
//         key = msg
//      }

    lms_key_t pub = {
        .type = HAL_KEY_TYPE_HASHSIG_LMS,
        .lms = key->lms,
        .lmots = key->lmots
    };
    memcpy(&pub.I, &key->I, sizeof(pub.I));
    memcpy(&pub.T1, &key->T1, sizeof(pub.T1));

    for (size_t i = 0; i < Nspk; ++i) {
        const uint8_t * const lms_sig = sigptr;
        /* peek into the signature for the lmots and lms types */
        /* XXX The structure of the LMS signature makes this a bigger pain
         * in the ass than necessary.
         */
        /* skip over q */
        sigptr += 4;
        /* read lmots_type out of the ots_signature */
        uint32_t lmots_type;
        check(hal_xdr_decode_int_peek(&sigptr, siglim, &lmots_type));
        lmots_parameter_t *lmots = lmots_select_parameter_set((hal_lmots_algorithm_t)lmots_type);
        if (lmots == NULL)
            return HAL_ERROR_INVALID_SIGNATURE;
        /* skip over ots_signature */
        sigptr += lmots_signature_len(lmots);
        /* read lms_type after ots_signature */
        uint32_t lms_type;
        check(hal_xdr_decode_int(&sigptr, siglim, &lms_type));
        lms_parameter_t *lms = lms_select_parameter_set((hal_lms_algorithm_t)lms_type);
        if (lms == NULL)
            return HAL_ERROR_INVALID_SIGNATURE;
        /* skip over the path elements of the lms signature */
        sigptr += lms->h * lms->m;
        /*XXX sigptr = lms_sig + lms_signature_len(lms, lmots); */

        /* verify the signature over the bytestring version of the signed public key */
        check(lms_verify(&pub, sigptr, lms_public_key_len(lms), lms_sig, sigptr - lms_sig));

        /* parse the signed public key */
        check(hal_xdr_decode_int(&sigptr, siglim, &lms_type));
        pub.lms = lms_select_parameter_set((hal_lms_algorithm_t)lms_type);
        if (pub.lms == NULL)
            return HAL_ERROR_INVALID_SIGNATURE;
        check(hal_xdr_decode_int(&sigptr, siglim, &lmots_type));
        pub.lmots = lmots_select_parameter_set((hal_lmots_algorithm_t)lmots_type);
        if (pub.lmots == NULL)
            return HAL_ERROR_INVALID_SIGNATURE;
        check(hal_xdr_decode_bytestring16(&sigptr, siglim, &pub.I));
        check(hal_xdr_decode_bytestring32(&sigptr, siglim, &pub.T1));
    }

    /* verify the final signature over the message */
    return lms_verify(&pub, msg, msg_len, sigptr, sig_len - (sigptr - sig));
}

hal_error_t hal_hashsig_private_key_to_der(const hal_hashsig_key_t * const key,
                                           uint8_t *der, size_t *der_len, const size_t der_max)
{
    if (key == NULL || key->type != HAL_KEY_TYPE_HASHSIG_PRIVATE)
        return HAL_ERROR_BAD_ARGUMENTS;

    /*
     * Calculate data length.
     */

    size_t len, vlen = 0, hlen;

    check(hal_asn1_encode_size_t(key->L, NULL, &len, 0));                    vlen += len;
    check(hal_asn1_encode_lms_algorithm(key->lms->type, NULL, &len, 0));     vlen += len;
    check(hal_asn1_encode_lmots_algorithm(key->lmots->type, NULL, &len, 0)); vlen += len;
    check(hal_asn1_encode_bytestring16(&key->I, NULL, &len, 0));             vlen += len;
    check(hal_asn1_encode_bytestring32(&key->T1, NULL, &len, 0));            vlen += len;
    check(hal_asn1_encode_bytestring32(&key->seed, NULL, &len, 0));          vlen += len;
    check(hal_asn1_encode_size_t(key->q_start, NULL, &len, 0));              vlen += len;
    check(hal_asn1_encode_size_t(key->q_end, NULL, &len, 0));                vlen += len;

    check(hal_asn1_encode_header(ASN1_SEQUENCE, vlen, NULL, &hlen, 0));

    check(hal_asn1_encode_pkcs8_privatekeyinfo(hal_asn1_oid_mts_hashsig, hal_asn1_oid_mts_hashsig_len,
                                               NULL, 0, NULL, hlen + vlen, NULL, der_len, der_max));

    if (der == NULL)
        return HAL_OK;

    /*
     * Encode data.
     */

    check(hal_asn1_encode_header(ASN1_SEQUENCE, vlen, der, &hlen, der_max));

    uint8_t *d = der + hlen;
    memset(d, 0, vlen);

    check(hal_asn1_encode_size_t(key->L, d, &len, vlen));                    d += len; vlen -= len;
    check(hal_asn1_encode_lms_algorithm(key->lms->type, d, &len, vlen));     d += len; vlen -= len;
    check(hal_asn1_encode_lmots_algorithm(key->lmots->type, d, &len, vlen)); d += len; vlen -= len;
    check(hal_asn1_encode_bytestring16(&key->I, d, &len, vlen));             d += len; vlen -= len;
    check(hal_asn1_encode_bytestring32(&key->T1, d, &len, vlen));            d += len; vlen -= len;
    check(hal_asn1_encode_bytestring32(&key->seed, d, &len, vlen));          d += len; vlen -= len;
    check(hal_asn1_encode_size_t(key->q_start, d, &len, vlen));              d += len; vlen -= len;
    check(hal_asn1_encode_size_t(key->q_end, d, &len, vlen));                d += len; vlen -= len;

    return hal_asn1_encode_pkcs8_privatekeyinfo(hal_asn1_oid_mts_hashsig, hal_asn1_oid_mts_hashsig_len,
                                                NULL, 0, der, d - der, der, der_len, der_max);
}

size_t hal_hashsig_private_key_to_der_len(const hal_hashsig_key_t * const key)
{
    size_t len = 0;
    return hal_hashsig_private_key_to_der(key, NULL, &len, 0) == HAL_OK ? len : 0;
}

hal_error_t hal_hashsig_private_key_from_der(hal_hashsig_key_t **key_,
                                             void *keybuf, const size_t keybuf_len,
                                             const uint8_t *der, const size_t der_len)
{
    if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(hal_hashsig_key_t) || der == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    memset(keybuf, 0, keybuf_len);

    hss_key_t *key = *key_ = keybuf;

    key->type = HAL_KEY_TYPE_HASHSIG_PRIVATE;

    size_t hlen, vlen, alg_oid_len, curve_oid_len, privkey_len;
    const uint8_t     *alg_oid,    *curve_oid,    *privkey;
    hal_error_t err;

    if ((err = hal_asn1_decode_pkcs8_privatekeyinfo(&alg_oid, &alg_oid_len,
                                                    &curve_oid, &curve_oid_len,
                                                    &privkey, &privkey_len,
                                                    der, der_len)) != HAL_OK)
        return err;

    if (alg_oid_len != hal_asn1_oid_mts_hashsig_len ||
        memcmp(alg_oid, hal_asn1_oid_mts_hashsig, alg_oid_len) != 0 ||
        curve_oid_len != 0)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    if ((err = hal_asn1_decode_header(ASN1_SEQUENCE, privkey, privkey_len, &hlen, &vlen)) != HAL_OK)
        return err;

    const uint8_t *d = privkey + hlen;
    size_t n;

    check(hal_asn1_decode_size_t(&key->L, d, &n, vlen));              d += n; vlen -= n;
    hal_lms_algorithm_t lms_type;
    check(hal_asn1_decode_lms_algorithm(&lms_type, d, &n, vlen));     d += n; vlen -= n;
    key->lms = lms_select_parameter_set(lms_type);
    hal_lmots_algorithm_t lmots_type;
    check(hal_asn1_decode_lmots_algorithm(&lmots_type, d, &n, vlen)); d += n; vlen -= n;
    key->lmots = lmots_select_parameter_set(lmots_type);
    check(hal_asn1_decode_bytestring16(&key->I, d, &n, vlen));        d += n; vlen -= n;
    check(hal_asn1_decode_bytestring32(&key->T1, d, &n, vlen));       d += n; vlen -= n;
    check(hal_asn1_decode_bytestring32(&key->seed, d, &n, vlen));     d += n; vlen -= n;
    check(hal_asn1_decode_size_t(&key->q_start, d, &n, vlen));        d += n; vlen -= n;
    check(hal_asn1_decode_size_t(&key->q_end, d, &n, vlen));          d += n; vlen -= n;

    if (d != privkey + privkey_len)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    /* Find this key in the list of active hashsig keys, and return a
     * pointer to that key structure, rather than the caller-provided key
     * structure. (The caller will wipe his own key structure when done,
     * and not molest ours.)
     */
    hss_key_t *hss_key = hss_find(&key->I);
    if (hss_key != NULL)
        *key_ = hss_key;

    return HAL_OK;
}

hal_error_t hal_hashsig_public_key_to_der(const hal_hashsig_key_t * const key,
                                          uint8_t *der, size_t *der_len, const size_t der_max)
{
    if (key == NULL || (key->type != HAL_KEY_TYPE_HASHSIG_PRIVATE &&
                        key->type != HAL_KEY_TYPE_HASHSIG_PUBLIC))
        return HAL_ERROR_BAD_ARGUMENTS;

    // L || u32str(lms_type) || u32str(lmots_type) || I || T[1]

    size_t len, vlen = 0, hlen;

    check(hal_asn1_encode_size_t(key->L, NULL, &len, 0));                    vlen += len;
    check(hal_asn1_encode_lms_algorithm(key->lms->type, NULL, &len, 0));     vlen += len;
    check(hal_asn1_encode_lmots_algorithm(key->lmots->type, NULL, &len, 0)); vlen += len;
    check(hal_asn1_encode_bytestring16(&key->I, NULL, &len, 0));             vlen += len;
    check(hal_asn1_encode_bytestring32(&key->T1, NULL, &len, 0));            vlen += len;

    check(hal_asn1_encode_header(ASN1_SEQUENCE, vlen, der, &hlen, der_max));

    if (der != NULL) {
        uint8_t *d = der + hlen;
        size_t dlen = vlen;
        memset(d, 0, vlen);

        check(hal_asn1_encode_size_t(key->L, d, &len, dlen));                    d += len; dlen -= len;
        check(hal_asn1_encode_lms_algorithm(key->lms->type, d, &len, dlen));     d += len; dlen -= len;
        check(hal_asn1_encode_lmots_algorithm(key->lmots->type, d, &len, dlen)); d += len; dlen -= len;
        check(hal_asn1_encode_bytestring16(&key->I, d, &len, dlen));             d += len; dlen -= len;
        check(hal_asn1_encode_bytestring32(&key->T1, d, &len, dlen));            d += len; dlen -= len;
    }

    return hal_asn1_encode_spki(hal_asn1_oid_mts_hashsig, hal_asn1_oid_mts_hashsig_len,
                                NULL, 0, der, hlen + vlen,
                                der, der_len, der_max);

}

size_t hal_hashsig_public_key_to_der_len(const hal_hashsig_key_t * const key)
{
    size_t len = 0;
    return hal_hashsig_public_key_to_der(key, NULL, &len, 0) == HAL_OK ? len : 0;
}

hal_error_t hal_hashsig_public_key_from_der(hal_hashsig_key_t **key_,
                                            void *keybuf, const size_t keybuf_len,
                                            const uint8_t * const der, const size_t der_len)
{
    if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(hss_key_t) || der == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    hss_key_t *key = keybuf;

    memset(keybuf, 0, keybuf_len);
    *key_ = key;

    key->type = HAL_KEY_TYPE_HASHSIG_PUBLIC;

    const uint8_t *alg_oid = NULL, *null = NULL, *pubkey = NULL;
    size_t         alg_oid_len,     null_len,     pubkey_len;

    check(hal_asn1_decode_spki(&alg_oid, &alg_oid_len, &null, &null_len, &pubkey, &pubkey_len, der, der_len));

    if (null != NULL || null_len != 0 || alg_oid == NULL ||
        alg_oid_len != hal_asn1_oid_mts_hashsig_len || memcmp(alg_oid, hal_asn1_oid_mts_hashsig, alg_oid_len) != 0)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    size_t len, hlen, vlen;

    check(hal_asn1_decode_header(ASN1_SEQUENCE, pubkey, pubkey_len, &hlen, &vlen));

    const uint8_t * const pubkey_end = pubkey + hlen + vlen;
    const uint8_t *d = pubkey + hlen;

    // L || u32str(lms_type) || u32str(lmots_type) || I || T[1]

    hal_lms_algorithm_t lms_type;
    hal_lmots_algorithm_t lmots_type;

    check(hal_asn1_decode_size_t(&key->L, d, &len, pubkey_end - d));              d += len;
    check(hal_asn1_decode_lms_algorithm(&lms_type, d, &len, pubkey_end - d));     d += len;
    key->lms = lms_select_parameter_set(lms_type);
    check(hal_asn1_decode_lmots_algorithm(&lmots_type, d, &len, pubkey_end - d)); d += len;
    key->lmots = lmots_select_parameter_set(lmots_type);
    check(hal_asn1_decode_bytestring16(&key->I, d, &len, pubkey_end - d));        d += len;
    check(hal_asn1_decode_bytestring32(&key->T1, d, &len, pubkey_end - d));       d += len;

    if (d != pubkey_end)
        return HAL_ERROR_ASN1_PARSE_FAILED;


    return HAL_OK;
}

hal_error_t hal_hashsig_key_load_public(hal_hashsig_key_t **key_,
                                        void *keybuf, const size_t keybuf_len,
                                        const size_t L,
                                        const hal_lms_algorithm_t lms_type,
                                        const hal_lmots_algorithm_t lmots_type,
                                        const uint8_t * const I, const size_t I_len,
                                        const uint8_t * const T1, const size_t T1_len)
{
    if (key_ == NULL || keybuf == NULL || keybuf_len < sizeof(hal_hashsig_key_t) ||
        I == NULL || I_len != sizeof(bytestring16) ||
        T1 == NULL || T1_len != sizeof(bytestring32))
        return HAL_ERROR_BAD_ARGUMENTS;

    memset(keybuf, 0, keybuf_len);

    hal_hashsig_key_t *key = keybuf;

    key->type = HAL_KEY_TYPE_HASHSIG_PUBLIC;

    key->L = L;
    key->lms = lms_select_parameter_set(lms_type);
    key->lmots = lmots_select_parameter_set(lmots_type);
    if (key->lms == NULL || key->lmots == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    memcpy(&key->I, I, I_len);
    memcpy(&key->T1, T1, T1_len);

    *key_ = key;

    return HAL_OK;
}


hal_error_t hal_hashsig_key_load_public_xdr(hal_hashsig_key_t **key_,
                                            void *keybuf, const size_t keybuf_len,
                                            const uint8_t * const xdr, const size_t xdr_len)
{
    const uint8_t *xdrptr = xdr;
    const uint8_t * const xdrlim = xdr + xdr_len;

    /* L || u32str(lms_type) || u32str(lmots_type) || I || T[1] */

    uint32_t L, lms_type, lmots_type;
    bytestring16 *I;
    bytestring32 *T1;
    
    check(hal_xdr_decode_int(&xdrptr, xdrlim, &L));
    check(hal_xdr_decode_int(&xdrptr, xdrlim, &lms_type));
    check(hal_xdr_decode_int(&xdrptr, xdrlim, &lmots_type));
    check(hal_xdr_decode_bytestring16_ptr(&xdrptr, xdrlim, &I));
    check(hal_xdr_decode_bytestring32_ptr(&xdrptr, xdrlim, &T1));

    return hal_hashsig_key_load_public(key_, keybuf, keybuf_len, L, lms_type, lmots_type,
                                       (const uint8_t * const)I, sizeof(bytestring16),
                                       (const uint8_t * const)T1, sizeof(bytestring32));
}

hal_error_t hal_hashsig_public_key_der_to_xdr(const uint8_t * const der, const size_t der_len,
                                              uint8_t * const xdr, size_t * const xdr_len , const size_t xdr_max)
{
    if (der == NULL || xdr == NULL)
        return HAL_ERROR_BAD_ARGUMENTS;

    const uint8_t *alg_oid = NULL, *null = NULL, *pubkey = NULL;
    size_t         alg_oid_len,     null_len,     pubkey_len;

    check(hal_asn1_decode_spki(&alg_oid, &alg_oid_len, &null, &null_len, &pubkey, &pubkey_len, der, der_len));

    if (null != NULL || null_len != 0 || alg_oid == NULL ||
        alg_oid_len != hal_asn1_oid_mts_hashsig_len || memcmp(alg_oid, hal_asn1_oid_mts_hashsig, alg_oid_len) != 0)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    size_t len, hlen, vlen;

    check(hal_asn1_decode_header(ASN1_SEQUENCE, pubkey, pubkey_len, &hlen, &vlen));

    const uint8_t * const pubkey_end = pubkey + hlen + vlen;
    const uint8_t *d = pubkey + hlen;

    // L || u32str(lms_type) || u32str(lmots_type) || I || T[1]

    size_t L;
    hal_lms_algorithm_t lms_type;
    hal_lmots_algorithm_t lmots_type;
    bytestring16 I;
    bytestring32 T1;

    check(hal_asn1_decode_size_t(&L, d, &len, pubkey_end - d));                   d += len;
    check(hal_asn1_decode_lms_algorithm(&lms_type, d, &len, pubkey_end - d));     d += len;
    check(hal_asn1_decode_lmots_algorithm(&lmots_type, d, &len, pubkey_end - d)); d += len;
    check(hal_asn1_decode_bytestring16(&I, d, &len, pubkey_end - d));             d += len;
    check(hal_asn1_decode_bytestring32(&T1, d, &len, pubkey_end - d));            d += len;

    if (d != pubkey_end)
        return HAL_ERROR_ASN1_PARSE_FAILED;

    uint8_t * xdrptr = xdr;
    const uint8_t * const xdrlim = xdr + xdr_max;

    check(hal_xdr_encode_int(&xdrptr, xdrlim, L));
    check(hal_xdr_encode_int(&xdrptr, xdrlim, lms_type));
    check(hal_xdr_encode_int(&xdrptr, xdrlim, lmots_type));
    check(hal_xdr_encode_bytestring16(&xdrptr, xdrlim, &I));
    check(hal_xdr_encode_bytestring32(&xdrptr, xdrlim, &T1));

    if (xdr_len != NULL)
        *xdr_len = xdrptr - xdr;

    return HAL_OK;
}

#if RPC_CLIENT == RPC_CLIENT_LOCAL
/* Reinitialize the hashsig key structures after a device restart */
hal_error_t hal_hashsig_ks_init(void)
{
    const hal_client_handle_t  client  = { -1 };
    const hal_session_handle_t session = { HAL_HANDLE_NONE };
    hal_uuid_t prev_name = {{0}};
    unsigned len;
    hal_pkey_slot_t slot = {{0}};
    uint8_t der[HAL_KS_WRAPPED_KEYSIZE];
    size_t der_len;

    restart_in_progress = 1;

    /* Find all hss private keys */
    while ((hal_ks_match(hal_ks_token, client, session,
                         HAL_KEY_TYPE_HASHSIG_PRIVATE, HAL_CURVE_NONE, 0, 0, NULL, 0,
                         &slot.name, &len, 1, &prev_name) == HAL_OK) &&  (len > 0)) {
        hal_hashsig_key_t keybuf, *key;
        if (hal_ks_fetch(hal_ks_token, &slot, der, &der_len, sizeof(der)) != HAL_OK ||
            hal_hashsig_private_key_from_der(&key, (void *)&keybuf, sizeof(keybuf), der, der_len) != HAL_OK) {
            (void)hal_ks_delete(hal_ks_token, &slot);
            memset(der, 0, sizeof(der));
            memset(&keybuf, 0, sizeof(keybuf));
            key = NULL;
            continue;
        }

        /* Make sure we have the lms key */
        hal_pkey_slot_t lms_slot = {{0}};
        lms_key_t lms_key;
        memcpy(&lms_slot.name, &key->I, sizeof(lms_slot.name));
        if (hal_ks_fetch(hal_ks_token, &lms_slot, der, &der_len, sizeof(der)) != HAL_OK ||
            lms_private_key_from_der(&lms_key, der, der_len) != HAL_OK ||
            /* check keys for consistency */
            lms_key.lms != key->lms ||
            lms_key.lmots != key->lmots ||
            memcmp(&lms_key.I, &key->I, sizeof(lms_key.I)) != 0 ||
            /* check that key isn't exhausted */
            lms_key.q >= lms_key.q_end ||
            /* optimistically allocate the full hss key structure */
            hss_alloc(&key) != HAL_OK) {
            (void)hal_ks_delete(hal_ks_token, &slot);
            (void)hal_ks_delete(hal_ks_token, &lms_slot);
            memset(der, 0, sizeof(der));
            memset(&lms_key, 0, sizeof(lms_key));
            memset(&keybuf, 0, sizeof(keybuf));
            key = NULL;
            continue;
        }

        /* initialize top-level lms key (beyond what hss_alloc did) */
        memcpy(&key->lms_keys[0].I, &lms_key.I, sizeof(lms_key.I));
        key->lms_keys[0].q = lms_key.q;
        key->lms_keys[0].q_end = key->q_end;

        prev_name = key->name = slot.name;
        memset(der, 0, sizeof(der));
        memset(&lms_key, 0, sizeof(lms_key));
        memset(&keybuf, 0, sizeof(keybuf));
        key = NULL;
        hal_task_yield_maybe();
    }

    /* Delete orphaned lms keys */
    memset(&prev_name, 0, sizeof(prev_name));
    while ((hal_ks_match(hal_ks_token, client, session,
                         HAL_KEY_TYPE_HASHSIG_LMS, HAL_CURVE_NONE, 0, 0, NULL, 0,
                         &slot.name, &len, 1, &prev_name) == HAL_OK) && (len > 0)) {
        if (hss_find((bytestring16 *)&slot.name) == NULL) {
            (void)hal_ks_delete(hal_ks_token, &slot);
            continue;
        }

        prev_name = slot.name;
        hal_task_yield_maybe();
    }

    /* Find all lmots keys */
    memset(&prev_name, 0, sizeof(prev_name));
    while ((hal_ks_match(hal_ks_token, client, session,
                         HAL_KEY_TYPE_HASHSIG_LMOTS, HAL_CURVE_NONE, 0, 0, NULL, 0,
                         &slot.name, &len, 1, &prev_name) == HAL_OK) && (len > 0)) {
        if (hss_keys == NULL) {
            /* if no hss keys were recovered, all lmots keys are orphaned */
            (void)hal_ks_delete(hal_ks_token, &slot);
            continue;
        }

        lmots_key_t lmots_key = {0};
        if (hal_ks_fetch(hal_ks_token, &slot, der, &der_len, sizeof(der)) != HAL_OK ||
            lmots_private_key_from_der(&lmots_key, der, der_len) != HAL_OK) {
            (void)hal_ks_delete(hal_ks_token, &slot);
            memset(&lmots_key, 0, sizeof(lmots_key));
            continue;
        }

        hss_key_t *hss_key = hss_find(&lmots_key.I);
        if (hss_key == NULL) {
            /* delete orphaned key */
            (void)hal_ks_delete(hal_ks_token, &slot);
            memset(&lmots_key, 0, sizeof(lmots_key));
            continue;
        }

        /* record this lmots key in the top-level lms key */
        memcpy(&hss_key->lms_keys[0].lmots_keys[lmots_key.q], &slot.name, sizeof(slot.name));

        /* compute T[r] = H(I || u32str(r) || u16str(D_LEAF) || K) */
        if (lms_compute_T_leaf(&hss_key->lms_keys[0], &lmots_key) != HAL_OK) {
            (void)hal_ks_delete(hal_ks_token, &slot);
            memset(&lmots_key, 0, sizeof(lmots_key));
            continue;
        }

        prev_name = slot.name;
        memset(&lmots_key, 0, sizeof(lmots_key));
        hal_task_yield_maybe();
    }

    /* After all keys have been read, scan for completeness. */
    hal_uuid_t uuid_0 = {{0}};
    hss_key_t *hss_key, *hss_next = NULL;
    for (hss_key = hss_keys; hss_key != NULL; hss_key = hss_next) {
        hss_next = hss_key->next;
        int fail = 0;
        lms_key_t *lms_key = hss_key->lms_keys;
        for (size_t q = 0; q < (1U << hss_key->lms->h); ++q) {
            if (hal_uuid_cmp(&lms_key->lmots_keys[q], &uuid_0) == 0) {
                bytestring32 seed_0 = {{0}};
                if (memcmp(&hss_key->seed, &seed_0, sizeof(seed_0)) == 0) {
                    /* lms key is incomplete, give up on it */
                    fail = 1;
                    break;
                }
                else {
                    /* This key was generated with the pseudo-random method,
                     * and can be regenerated.
                     */
                    check(lms_generate_lmots(lms_key, q, &hss_key->seed));
                    hal_task_yield_maybe();
                }
            }
        }
        if (fail) {
        fail:
            /* delete hss key */
            hss_delete(hss_key);
            slot.name = hss_key->name;
            (void)hal_ks_delete(hal_ks_token, &slot);
            hal_task_yield_maybe();
            continue;
        }

        /* generate the rest of T[] */
        lms_compute_T_intr(lms_key);
        if (memcmp(&lms_key->T[1], &hss_key->T1, sizeof(lms_key->T[1])) != 0)
            goto fail;

        /* generate the lower-level lms keys */
        for (size_t i = 1; i < hss_key->L; ++i) {
            lms_key = &hss_key->lms_keys[i];
            if (lms_generate(lms_key, NULL) != HAL_OK)
                goto fail;

            /* store the lms key */
            slot.type  = HAL_KEY_TYPE_HASHSIG_LMS;
            slot.flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE;
            memcpy(&slot.name, &lms_key->I, sizeof(slot.name));
            if (lms_private_key_to_der(lms_key, der, &der_len, sizeof(der)) != HAL_OK ||
                hal_ks_store(hal_ks_volatile, &slot, der, der_len) != HAL_OK ||
                /* sign this lms key with the previous */
                lms_sign(&hss_key->lms_keys[i-1],
                         (const uint8_t * const)lms_key->pubkey, lms_key->pubkey_len,
                         lms_key->signature, NULL, lms_key->signature_len) != HAL_OK)
                goto fail;
            hal_task_yield_maybe();
        }
    }

    restart_in_progress = 0;
    return HAL_OK;
}

hal_error_t hal_hashsig_export(const hal_uuid_t * const name, uint8_t *der, size_t *der_len, const size_t der_max)
{
    hal_error_t err;
    hal_hashsig_key_t keybuf, *tmp_key = &keybuf, *hss_key;

    if ((err = hal_hashsig_private_key_from_der(&hss_key, &keybuf, sizeof(keybuf), der, *der_len)) != HAL_OK)
        goto err_out;
    if (hss_key == tmp_key) {
        err = HAL_ERROR_KEY_NOT_FOUND;         /* or IMPOSSIBLE? */
        goto err_out;
    }

    /* adjust hss_key->end and tmp_key->start */
    size_t new_end = (hss_key->lms_keys[0].q + hss_key->lms_keys[0].q_end) / 2;
    if (new_end == hss_key->lms_keys[0].q) {
        err = HAL_ERROR_HASHSIG_KEY_EXHAUSTED;
        goto err_out;
    }
    hss_key->q_end = hss_key->lms_keys[0].q_end = tmp_key->q_start = new_end;

    /* store updated hss_key */
    hal_pkey_slot_t slot = {
        .type = HAL_KEY_TYPE_HASHSIG_PRIVATE,
        .name = *name,
        .flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN | HAL_KEY_FLAG_EXPORTABLE
    };
    if ((err = hal_hashsig_private_key_to_der(hss_key, der, der_len, der_max)) != HAL_OK ||
        (err = hal_ks_rewrite_der(hal_ks_token, &slot, der, *der_len)) != HAL_OK)
        goto err_out;

    /* store updated lms_key */
    lms_key_t *lms_key = &hss_key->lms_keys[0];
    uint8_t lms_der[HAL_KS_WRAPPED_KEYSIZE];
    size_t lms_der_len;
    if ((err = lms_private_key_to_der(lms_key, lms_der, &lms_der_len, sizeof(lms_der))) != HAL_OK)
        goto err_out;

    hal_pkey_slot_t lms_slot = {
        .type = HAL_KEY_TYPE_HASHSIG_LMS,
        .flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN
    };
    memcpy(&lms_slot.name, &lms_key->I, sizeof(lms_slot.name));
    if ((err = hal_ks_rewrite_der(hal_ks_token, &lms_slot, lms_der, lms_der_len)) != HAL_OK)
        goto err_out;

    /* re-encode tmp_key to der */
    if ((err = hal_hashsig_private_key_to_der(tmp_key, der, der_len, der_max)) != HAL_OK)
        goto err_out;

    /* delete unused lmots keys? */

err_out:
    memset(&keybuf, 0, sizeof(keybuf));
    hss_key = NULL;
    return err;
}

hal_error_t hal_hashsig_import(const uint8_t *der, const size_t der_len,
                               const hal_key_flags_t flags)
{
    if (restart_in_progress)
        return HAL_ERROR_NOT_READY;

    hss_key_t keybuf, *key;
    hal_error_t err;

    if ((err = hal_hashsig_private_key_from_der(&key, &keybuf, sizeof(keybuf), der, der_len)) != HAL_OK)
        goto err_out;

    /* If the key already exists, it could be that the user is attempting to
     * return an exported key to its origin, and we could consolidate them,
     * but then we have to deal with the possibility of disjoint partitions of
     * the keyspace (or worse, overlapping or duplicate partitions, which is
     * always an error). In any case, it's easier just to disallow it.
     */
    if (hss_find(&key->I) != NULL) {
        err = HAL_ERROR_KEY_NAME_IN_USE;
        goto err_out;
    }

    err = hss_generate(&key, flags);

err_out:
    memset(&keybuf, 0, sizeof(keybuf));
    key = NULL;
    return err;
}
#endif
