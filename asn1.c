/*
 * asn1.c
 * ------
 * Minimal ASN.1 implementation in support of Cryptech libhal.
 *
 * The functions in this module are not intended to be part of the
 * public API.  Rather, these are utility functions used by more than
 * one module within the library, which would otherwise have to be
 * duplicated.  The main reason for keeping these private is to avoid
 * having the public API depend on any details of the underlying
 * bignum implementation (currently libtfm, but that might change).
 *
 * As of this writing, the ASN.1 support we need is quite minimal, so,
 * rather than attempting to clean all the unecessary cruft out of a
 * general purpose ASN.1 implementation, we hand code the very small
 * number of data types we need.  At some point this will probably
 * become impractical, at which point we might want to look into using
 * something like the asn1c compiler.
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

#include "hal.h"

#include "asn1_internal.h"

/*
 * Encode tag and length fields of an ASN.1 object.  If der is NULL,
 * just return the size that would be encoded.
 */

hal_error_t hal_asn1_encode_header(const uint8_t tag,
				   const size_t value_len,
				   uint8_t *der, size_t *der_len, const size_t der_max)
{
  size_t header_len = 2;	/* Shortest encoding is one octet each for tag and length */

  if (value_len >= 128)		/* Add octets for longer length encoding as needed */
    for (size_t n = value_len; n > 0; n >>= 8)
      ++header_len;

  if (der_len != NULL)
    *der_len = header_len;

  if (der == NULL)		/* If caller just wanted the length, we're done */
    return HAL_OK;

  /*
   * Make sure there's enough room for header + value, then encode.
   */

  if (value_len + header_len > der_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  if (value_len < 128) {
    *der = (uint8_t) value_len;
  }

  else {
    *der = 0x80 | (uint8_t) (header_len -= 2);
    for (size_t n = value_len; n > 0 && header_len > 0; n >>= 8)
      der[header_len--] = (uint8_t) (n & 0xFF);
  }

  return HAL_OK;
}

/*
 * Encode an unsigned ASN.1 INTEGER from a libtfm bignum.  If der is
 * NULL, just return the length of what we would have encoded.
 */

hal_error_t hal_asn1_encode_integer(fp_int *bn,
				    uint8_t *der, size_t *der_len, const size_t der_max)
{
  if (bn == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  /*
   * We only handle unsigned INTEGERs, so we need to pad data with a
   * leading zero if the most significant bit is set, to avoid
   * flipping the ASN.1 sign bit.  Conveniently, this also handles the
   * difference between libtfm's and ASN.1's encoding of zero.
   */

  if (fp_cmp_d(bn, 0) == FP_LT)
    return HAL_ERROR_BAD_ARGUMENTS;

  const int leading_zero = fp_iszero(bn) || (fp_count_bits(bn) & 7) == 0;
  const size_t vlen = fp_unsigned_bin_size(bn) + leading_zero;
  hal_error_t err;
  size_t hlen;

  if ((err = hal_asn1_encode_header(ASN1_INTEGER, vlen, der, &hlen, der_max)) != HAL_OK)
    return err;

  if (der_len != NULL)
    *der_len = hlen + vlen;

  if (der == NULL)
    return HAL_OK;

  if (hlen + vlen > der_max)
    return HAL_ERROR_RESULT_TOO_LONG;

  der += hlen;
  if (leading_zero)
    *der++ = 0x00;
  fp_to_unsigned_bin(bn, der);

  return HAL_OK;
}


hal_error_t hal_asn1_decode_header(const uint8_t tag,
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

hal_error_t hal_asn1_decode_integer(fp_int *bn,
				    const uint8_t * const der, size_t *der_len, const size_t der_max)
{
  if (bn == NULL || der == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err;
  size_t hlen, vlen;

  if ((err = hal_asn1_decode_header(ASN1_INTEGER, der, der_max, &hlen, &vlen)) != HAL_OK)
    return err;

  if (der_len != NULL)
    *der_len = hlen + vlen;

  if (vlen < 1 || (der[hlen] & 0x80) != 0x00)
    return HAL_ERROR_ASN1_PARSE_FAILED;

  fp_init(bn);
  fp_read_unsigned_bin(bn, (uint8_t *) der + hlen, vlen);
  return HAL_OK;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
