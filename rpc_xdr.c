/*
 * rpc_xdr.c
 * ---------
 * Serialization/deserialization routines, using XDR (RFC 4506) encoding.
 *
 * Copyright (c) 2016, NORDUnet A/S All rights reserved.
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
#include <string.h>		/* memcpy */
#include <strings.h>		/* bzero */
#include <arpa/inet.h>		/* htonl/ntohl */

#include "hal.h"

/* encode/decode_int. This covers int, unsigned int, enum, and bool types,
 * which are all encoded as 32-bit big-endian fields. Signed integers are
 * defined to use two's complement, but that's universal these days, yes?
 */

hal_error_t rpc_encode_int(uint8_t ** const outbuf, const uint8_t * const limit, const uint32_t value)
{
    /* arg checks */
    if (outbuf == NULL || *outbuf == NULL || limit == NULL)
	return HAL_ERROR_BAD_ARGUMENTS;

    /* buffer overflow check */
    if (limit - *outbuf < sizeof(value))
	return HAL_ERROR_IO_BAD_COUNT;

    **(uint32_t **)outbuf = htonl(value);
    *outbuf += sizeof(value);
    return HAL_OK;
}

hal_error_t rpc_decode_int(uint8_t **inbuf, const uint8_t * const limit, uint32_t *value)
{
    /* arg checks */
    if (inbuf == NULL || *inbuf == NULL || limit == NULL || value == NULL)
	return HAL_ERROR_BAD_ARGUMENTS;

    /* buffer overflow check */
    if (limit - *inbuf < sizeof(*value))
	return HAL_ERROR_IO_BAD_COUNT;

    *value = ntohl(**(uint32_t **)inbuf);
    *inbuf += sizeof(*value);
    return HAL_OK;
}

/* encode/decode_buffer. This covers variable-length string and opaque types.
 * The data is preceded by a 4-byte length word (encoded as above), and padded
 * to a multiple of 4 bytes as necessary.
 */

hal_error_t rpc_encode_buffer(uint8_t **outbuf, const uint8_t * const limit, const uint8_t *value, const uint32_t len)
{
    hal_error_t ret;

    /* arg checks */
    if (outbuf == NULL || *outbuf == NULL || limit == NULL || 
	(value == NULL && len != 0))
	return HAL_ERROR_BAD_ARGUMENTS;

    /* buffer overflow check */
    if ((limit - *outbuf) < (((len + 3) & ~3) + sizeof(len)))
	return HAL_ERROR_IO_BAD_COUNT;

    /* encode length */
    if ((ret = rpc_encode_int(outbuf, limit, len)) != HAL_OK)
	return ret;

    /* write the string or opaque data */
    memcpy(*outbuf, value, len);
    *outbuf += len;

    /* pad if necessary */
    if (len & 3) {
	size_t n = 4 - (len & 3);
	bzero(*outbuf, n);
	*outbuf += n;
    }

    return HAL_OK;
}

/* This version returns a pointer to the data in the input buffer.
 * It is used in the rpc server.
 */
hal_error_t rpc_decode_buffer_in_place(uint8_t **inbuf, const uint8_t * const limit, uint8_t ** const value, uint32_t * const len)
{
    hal_error_t ret;
    uint32_t xdr_len;
    uint8_t *orig_inbuf = *inbuf;

    /* arg checks */
    if (inbuf == NULL || *inbuf == NULL || limit == NULL || value == NULL || len == NULL)
	return HAL_ERROR_BAD_ARGUMENTS;

    /* decode the length */
    if ((ret = rpc_decode_int(inbuf, limit, &xdr_len)) != HAL_OK)
	return ret;

    /* input and output buffer overflow checks vs decoded length */

    /* decoded length is past the end of the input buffer;
     * we're probably out of sync, but nothing we can do now
     */
    if (limit - *inbuf < xdr_len) {
	/* undo read of length */
	*inbuf = orig_inbuf;
	return HAL_ERROR_IO_BAD_COUNT;
    }

    /* user buffer is too small, update *len
     */
    if (*len < xdr_len) {
	*len = xdr_len;
	/* undo read of length */
	*inbuf = orig_inbuf;
	return HAL_ERROR_IO_BAD_COUNT;
    }

    /* return a pointer to the string or opaque data */
    *value = *inbuf;
    *len = xdr_len;

    /* update the buffer pointer, skipping any padding bytes */
    *inbuf += (xdr_len + 3) & ~3;

    return HAL_OK;
}

/* This version copies the data to the user-supplied buffer.
 * It is used in the rpc client.
 */
hal_error_t rpc_decode_buffer(uint8_t **inbuf, const uint8_t * const limit, uint8_t * const value, uint32_t * const len)
{
    hal_error_t ret;
    uint8_t *vptr;

    if ((ret = rpc_decode_buffer_in_place(inbuf, limit, &vptr, len)) == HAL_OK)
	memcpy(value, vptr, *len);
    return ret;
}

#ifdef TEST
void hexdump(uint8_t *buf, uint32_t len)
{
    int i;

    for (i = 0; i < len; ++i) {
	uint8_t c = buf[i];
	printf("%02x ", c);
	if ((i & 0x07) == 0x07)
	    printf("\n");
    }
    if ((len & 0x07) != 0)
	printf("\n");
}

int main(int argc, char *argv[])
{
    uint32_t i;
    uint8_t buf[64] = {0};
    uint8_t *bufptr = buf, *readptr;
    uint8_t *limit = buf + sizeof(buf);
    hal_error_t ret;
    uint8_t alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    uint8_t readbuf[64] = {0};

    printf("rpc_encode_int: work to failure\n");
    for (i = 1; i < 100; ++i) {
	if ((ret = rpc_encode_int(&bufptr, limit, i)) != HAL_OK) {
	    printf("%d: %s\n", i, hal_error_string(ret));
	    break;
	}
    }
    hexdump(buf, ((uint8_t *)bufptr - buf));

    printf("\nrpc_decode_int:\n");
    readptr = buf;
    while (readptr < bufptr) {
	if ((ret = rpc_decode_int(&readptr, limit, &i)) != HAL_OK) {
	    printf("%s\n", hal_error_string(ret));
	    break;
	}
	printf("%u ", i);
    }
    printf("\n");

    printf("\nrpc_encode_buffer: work to failure\n");
    bzero(buf, sizeof(buf));
    bufptr = buf;
     for (i = 1; i < 10; ++i) {
	if ((ret = rpc_encode_buffer(&bufptr, limit, alphabet, i)) != HAL_OK) {
	    printf("%d: %s\n", i, hal_error_string(ret));
	    break;
	}
    }
    hexdump(buf, ((uint8_t *)bufptr - buf));

    printf("\nrpc_decode_buffer:\n");
    readptr = buf;
    i = sizeof(readbuf);
    while (readptr < bufptr) {
	if ((ret = rpc_decode_buffer(&readptr, limit, readbuf, &i)) != HAL_OK) {
	    printf("%s\n", hal_error_string(ret));
	    break;
	}
	printf("%u: ", i); for (int j = 0; j < i; ++j) putchar(readbuf[j]); putchar('\n');
	i = sizeof(readbuf);
	bzero(readbuf, sizeof(readbuf));
    }

    return 0;
}
#endif
