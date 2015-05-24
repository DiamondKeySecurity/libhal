/* 
 * hashes.c
 * --------
 *
 * HAL interface to Cryptech hash cores.
 * 
 * Authors: Joachim Strömbergson, Paul Selkirk, Rob Austein
 * Copyright (c) 2014-2015, SUNET
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

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "cryptech.h"

/* Longest digest block we support at the moment */
#define MAX_BLOCK_LEN           SHA512_BLOCK_LEN

/* Hash state */
typedef struct {
  uint64_t msg_length_high;             /* Total data hashed in this message */
  uint64_t msg_length_low;              /* (128 bits in SHA-512 cases) */
  size_t block_length;                  /* Block length for this algorithm */
  uint8_t block[MAX_BLOCK_LEN];         /* Block we're accumulating */
  size_t block_used;                    /* How much of the block we've used */
  unsigned block_count;                 /* Blocks sent */
} hash_state_t;

static int debug = 0;

/*
 * Debugging control.
 */

void hal_hash_set_debug(int onoff)
{
  debug = onoff;
}

/*
 * Tell caller how much space to allocate for a hash_state_t.  This
 * lets us hide details that are nobody else's business while letting
 * somebody else deal with memory allocation (and is the way
 * Cryptlib's HAL code works, not by coincidence).
 */

size_t hal_hash_state_size(void)
{
  return sizeof(hash_state_t);
}

void hal_hash_state_initialize(void *_state)
{
  hash_state_t *state = _state;
  assert(state != NULL);
  memset(state, 0, sizeof(*state));
}

/*
 * Report whether cores are present.
 */

hal_error_t hash_sha1_core_present(void)
{
  return hal_io_expected(SHA1_ADDR_NAME0, (const uint8_t *) (SHA1_NAME0 SHA1_NAME1), 8);
}

hal_error_t hash_sha256_core_present(void)
{
  return hal_io_expected(SHA256_ADDR_NAME0, (const uint8_t *) (SHA256_NAME0 SHA256_NAME1), 8);
}

hal_error_t hash_sha512_core_present(void)
{
  return hal_io_expected(SHA512_ADDR_NAME0, (const uint8_t *) (SHA512_NAME0 SHA512_NAME1), 8);
}

/*
 * Send one block to a core.
 */

static hal_error_t hash_write_block(const off_t block_addr,
                                    const off_t ctrl_addr,
                                    const off_t status_addr,
                                    const uint8_t ctrl_mode,
                                    const hash_state_t * const state)
{
  uint8_t ctrl_cmd[4];
  hal_error_t err;

  assert(state != NULL && state->block_length % 4 == 0);

  if (debug)
    fprintf(stderr, "[ %s ]\n", state->block_count == 0 ? "init" : "next");

  if ((err = hal_io_write(block_addr, state->block, state->block_length)) != HAL_OK)
    return err;

  ctrl_cmd[0] = ctrl_cmd[1] = ctrl_cmd[2] = 0;
  ctrl_cmd[3] = state->block_count == 0 ? CTRL_INIT : CTRL_NEXT;  
  ctrl_cmd[3] |= ctrl_mode;

  /*
   * Not sure why we're waiting for ready here, but it's what the old
   * (read: tested) code did, so keep that behavior for now.
   */

  if ((err = hal_io_write(ctrl_addr, ctrl_cmd, sizeof(ctrl_cmd))) != HAL_OK)
    return err;

  return hal_io_wait_valid(status_addr);
}

/*
 * Read hash result from core.
 */

static hal_error_t hash_read_digest(const off_t digest_addr,
                                    const off_t status_addr,
                                    uint8_t *digest,
                                    const size_t digest_length)
{
  hal_error_t err;

  assert(digest != NULL && digest_length % 4 == 0);

  if ((err = hal_io_wait_valid(status_addr)) != HAL_OK)
    return err;

  return hal_io_read(digest_addr, digest, digest_length);
}

/*
 * Hash data.  All supported hash algorithms use similar block
 * manipulations and padding algorithms, so all can use this method
 * with a few parameters which we handle via closures below.
 */

static hal_error_t hash_do_hash(hash_state_t *state,                    /* Opaque state block */
                                const uint8_t * const data_buffer,	/* Data to be hashed */
                                size_t data_buffer_length,              /* Length of data_buffer */
                                uint8_t *digest_buffer,                 /* Returned digest */
                                const size_t digest_buffer_length,      /* Length of digest_buffer */
                                const size_t block_length,              /* Length of a block */
                                const size_t digest_length,             /* Length of resulting digest */
                                const size_t length_length,             /* Length of the length field */
                                const off_t block_addr,                 /* Where to write hash blocks */
                                const off_t ctrl_addr,                  /* Control register */
                                const off_t status_addr,                /* Status register */
                                const off_t digest_addr,                /* Where to read digest */
                                const uint8_t ctrl_mode)                /* Digest mode, for cores that have modes */
{
  hal_error_t err;
  size_t n;
  int i;

  if (state == NULL ||
      (state->block_length != 0 && state->block_length != block_length) ||
      (data_buffer_length > 0 && data_buffer == NULL) ||
      (data_buffer_length == 0 && digest_buffer == NULL) ||
      (digest_buffer != NULL && digest_buffer_length < digest_length))
    return HAL_ERROR_BAD_ARGUMENTS;

  if (state->block_length == 0)
    state->block_length = block_length;

  assert(block_length <= sizeof(state->block));

  if (data_buffer_length > 0) {                            /* We have data to hash */

    const uint8_t *p = data_buffer;

    while ((n = state->block_length - state->block_used) <= data_buffer_length) {
      /*
       * We have enough data for another complete block.
       */
      if (debug)
        fprintf(stderr, "[ Full block, data_buffer_length %lu, used %lu, n %lu, msg_length %llu ]\n",
                (unsigned long) data_buffer_length, (unsigned long) state->block_used, (unsigned long) n, state->msg_length_low);
      memcpy(state->block + state->block_used, p, n);
      if ((state->msg_length_low += n) < n)
        state->msg_length_high++;
      state->block_used = 0;
      data_buffer_length -= n;
      p += n;
      if ((err = hash_write_block(block_addr, ctrl_addr, status_addr, ctrl_mode, state)) != HAL_OK)
        return err;
      state->block_count++;
    }

    if (data_buffer_length > 0) {
      /*
       * Data left over, but not enough for a full block, stash it.
       */
      if (debug)
        fprintf(stderr, "[ Partial block, data_buffer_length %lu, used %lu, n %lu, msg_length %llu ]\n",
                (unsigned long) data_buffer_length, (unsigned long) state->block_used, (unsigned long) n, state->msg_length_low);
      assert(data_buffer_length < n);
      memcpy(state->block + state->block_used, p, data_buffer_length);
      if ((state->msg_length_low += data_buffer_length) < data_buffer_length)
        state->msg_length_high++;
      state->block_used += data_buffer_length;
    }
  }

  else {           /* Done: add padding, then pull result from the core */

    uint64_t bit_length_low  = (state->msg_length_low  << 3);
    uint64_t bit_length_high = (state->msg_length_high << 3) | (state->msg_length_low >> 61);
    uint8_t *p;

    /* Initial pad byte */
    assert(state->block_used < state->block_length);
    state->block[state->block_used++] = 0x80;

    /* If not enough room for bit count, zero and push current block */
    if ((n = state->block_length - state->block_used) < length_length) {
      if (debug)
        fprintf(stderr, "[ Overflow block, data_buffer_length %lu, used %lu, n %lu, msg_length %llu ]\n",
                (unsigned long) data_buffer_length, (unsigned long) state->block_used, (unsigned long) n, state->msg_length_low);
      if (n > 0)
        memset(state->block + state->block_used, 0, n);
      if ((err = hash_write_block(block_addr, ctrl_addr, status_addr, ctrl_mode, state)) != HAL_OK)
        return err;
      state->block_count++;
      state->block_used = 0;
    }

    /* Pad final block */
    n = state->block_length - state->block_used;
    assert(n >= length_length);
    if (n > 0)
      memset(state->block + state->block_used, 0, n);
    if (debug)
      fprintf(stderr, "[ Final block, data_buffer_length %lu, used %lu, n %lu, msg_length %llu ]\n",
              (unsigned long) data_buffer_length, (unsigned long) state->block_used, (unsigned long) n, state->msg_length_low);
    p = state->block + state->block_length;
    for (i = 0; (bit_length_low || bit_length_high) && i < length_length; i++) {
      *--p = (uint8_t) (bit_length_low & 0xFF);
      bit_length_low >>= 8;
      if (bit_length_high) {
        bit_length_low |= ((bit_length_high & 0xFF) << 56);
        bit_length_high >>= 8;
      }
    }

    /* Push final block */
    if ((err = hash_write_block(block_addr, ctrl_addr, status_addr, ctrl_mode, state)) != HAL_OK)
      return err;
    state->block_count++;

    /* All data pushed to core, now we just need to read back the result */
    if ((err = hash_read_digest(digest_addr, status_addr, digest_buffer, digest_length)) != HAL_OK)
      return err;
  }

  return HAL_OK;
}

/*
 * Closures to provide the public API.
 */

hal_error_t hal_hash_sha1(void *state,
                          const uint8_t *data_buffer,
                          const size_t data_buffer_length,
                          uint8_t *digest_buffer,
                          const size_t digest_buffer_length)
{
  return hash_do_hash(state, data_buffer, data_buffer_length, digest_buffer, digest_buffer_length,
                      SHA1_BLOCK_LEN, SHA1_DIGEST_LEN, SHA1_LENGTH_LEN,
                      SHA1_ADDR_BLOCK, SHA1_ADDR_CTRL, SHA1_ADDR_STATUS, SHA1_ADDR_DIGEST, 0);
}

hal_error_t hal_hash_sha256(void *state,
                            const uint8_t *data_buffer,
                            const size_t data_buffer_length,
                            uint8_t *digest_buffer,
                            const size_t digest_buffer_length)
{
  return hash_do_hash(state, data_buffer, data_buffer_length, digest_buffer, digest_buffer_length,
                      SHA256_BLOCK_LEN, SHA256_DIGEST_LEN, SHA256_LENGTH_LEN,
                      SHA256_ADDR_BLOCK, SHA256_ADDR_CTRL, SHA256_ADDR_STATUS, SHA256_ADDR_DIGEST, 0);
}

hal_error_t hal_hash_sha512_224(void *state,
                                const uint8_t *data_buffer,
                                const size_t data_buffer_length,
                                uint8_t *digest_buffer,
                                const size_t digest_buffer_length)
{
  return hash_do_hash(state, data_buffer, data_buffer_length, digest_buffer, digest_buffer_length,
                      SHA512_BLOCK_LEN, SHA512_DIGEST_LEN, SHA512_LENGTH_LEN,
                      SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
                      MODE_SHA_512_224);
}

hal_error_t hal_hash_sha512_256(void *state,
                                const uint8_t *data_buffer,
                                const size_t data_buffer_length,
                                uint8_t *digest_buffer,
                                const size_t digest_buffer_length)
{
  return hash_do_hash(state, data_buffer, data_buffer_length, digest_buffer, digest_buffer_length,
                      SHA512_BLOCK_LEN, SHA512_DIGEST_LEN, SHA512_LENGTH_LEN,
                      SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
                      MODE_SHA_512_256);
}

hal_error_t hal_hash_sha384(void *state,
                            const uint8_t *data_buffer,
                            const size_t data_buffer_length,
                            uint8_t *digest_buffer,
                            const size_t digest_buffer_length)
{
  return hash_do_hash(state, data_buffer, data_buffer_length, digest_buffer, digest_buffer_length,
                      SHA512_BLOCK_LEN, SHA512_DIGEST_LEN, SHA512_LENGTH_LEN,
                      SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
                      MODE_SHA_384);
}

hal_error_t hal_hash_sha512(void *state,
                            const uint8_t *data_buffer,
                            const size_t data_buffer_length,
                            uint8_t *digest_buffer,
                            const size_t digest_buffer_length)
{
  return hash_do_hash(state, data_buffer, data_buffer_length, digest_buffer, digest_buffer_length,
                      SHA512_BLOCK_LEN, SHA512_DIGEST_LEN, SHA512_LENGTH_LEN,
                      SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
                      MODE_SHA_512);
}

/*
 * "Any programmer who fails to comply with the standard naming, formatting,
 *  or commenting conventions should be shot.  If it so happens that it is
 *  inconvenient to shoot him, then he is to be politely requested to recode
 *  his program in adherence to the above standard."
 *                      -- Michael Spier, Digital Equipment Corporation
 *
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
