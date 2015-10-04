/*
 * hashes.c
 * --------
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

#include "hal.h"

/*
 * HMAC magic numbers.
 */

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

/*
 * Driver.  This encapsulates whatever per-algorithm voodoo we need
 * this week.  At the moment, this is mostly Cryptech core addresses,
 * but this is subject to change without notice.
 *
 * Most of the addresses in the current version could be calculated
 * from a single address (the core base address), but this week's
 * theory prefers the precomputed composite addresses, and doing it
 * this way saves some microscopic bit of addition at runtime.
 * Whatever.  It'll probably all change again once we have a dynamic
 * memory map, so it's not really worth overthinking at the moment.
 */

struct hal_hash_driver {
  size_t length_length;                 /* Length of the length field */
  hal_addr_t block_addr;                     /* Where to write hash blocks */
  hal_addr_t ctrl_addr;                      /* Control register */
  hal_addr_t status_addr;                    /* Status register */
  hal_addr_t digest_addr;                    /* Where to read digest */
  hal_addr_t name_addr;                      /* Where to read core name */
  char core_name[8];                    /* Expected name of core */
  uint8_t ctrl_mode;                    /* Digest mode, for cores that have modes */
};

/*
 * Hash state.  For now we assume that the only core state we need to
 * save and restore is the current digest value.
 */

struct hal_hash_state {
  const hal_hash_descriptor_t *descriptor;
  const hal_hash_driver_t *driver;
  uint64_t msg_length_high;                     /* Total data hashed in this message */
  uint64_t msg_length_low;                      /* (128 bits in SHA-512 cases) */
  uint8_t block[HAL_MAX_HASH_BLOCK_LENGTH],     /* Block we're accumulating */
    core_state[HAL_MAX_HASH_DIGEST_LENGTH];     /* Saved core state */
  size_t block_used;                            /* How much of the block we've used */
  unsigned block_count;                         /* Blocks sent */
  unsigned flags;
};

#define STATE_FLAG_STATE_ALLOCATED 0x1          /* State buffer dynamically allocated */

/*
 * HMAC state.  Right now this just holds the key block and a hash
 * context; if and when we figure out how PCLSR the hash cores, we
 * might want to save a lot more than that, and may also want to
 * reorder certain operations during HMAC initialization to get a
 * performance boost for things like PBKDF2.
 */

struct hal_hmac_state {
  hal_hash_state_t hash_state;               /* Hash state */
  uint8_t keybuf[HAL_MAX_HASH_BLOCK_LENGTH]; /* HMAC key */
};

/*
 * Drivers for known digest algorithms.
 *
 * Initialization of the core_name field is not a typo, we're
 * concatenating two string constants and trusting the compiler to
 * whine if the resulting string doesn't fit into the field.
 */

static const hal_hash_driver_t sha1_driver = {
  SHA1_LENGTH_LEN,
  SHA1_ADDR_BLOCK, SHA1_ADDR_CTRL, SHA1_ADDR_STATUS, SHA1_ADDR_DIGEST,
  SHA1_ADDR_NAME0, (SHA1_NAME0 SHA1_NAME1),
  0
};

static const hal_hash_driver_t sha256_driver = {
  SHA256_LENGTH_LEN,
  SHA256_ADDR_BLOCK, SHA256_ADDR_CTRL, SHA256_ADDR_STATUS, SHA256_ADDR_DIGEST,
  SHA256_ADDR_NAME0, (SHA256_NAME0 SHA256_NAME1),
  0
};

static const hal_hash_driver_t sha512_224_driver = {
  SHA512_LENGTH_LEN,
  SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
  SHA512_ADDR_NAME0, (SHA512_NAME0 SHA512_NAME1),
  MODE_SHA_512_224
};

static const hal_hash_driver_t sha512_256_driver = {
  SHA512_LENGTH_LEN,
  SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
  SHA512_ADDR_NAME0, (SHA512_NAME0 SHA512_NAME1),
  MODE_SHA_512_256
};

static const hal_hash_driver_t sha384_driver = {
  SHA512_LENGTH_LEN,
  SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
  SHA512_ADDR_NAME0, (SHA512_NAME0 SHA512_NAME1),
  MODE_SHA_384
};

static const hal_hash_driver_t sha512_driver = {
  SHA512_LENGTH_LEN,
  SHA512_ADDR_BLOCK, SHA512_ADDR_CTRL, SHA512_ADDR_STATUS, SHA512_ADDR_DIGEST,
  SHA512_ADDR_NAME0, (SHA512_NAME0 SHA512_NAME1),
  MODE_SHA_512
};

/*
 * Digest algorithm identifiers: DER encoded full TLV of an
 * DigestAlgorithmIdentifier SEQUENCE including OID for the algorithm in
 * question and a NULL parameters value.
 *
 * See RFC 2313 and the NIST algorithm registry:
 * http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html
 *
 * The DER encoding is too complex to generate in the C preprocessor,
 * and we want these as compile-time constants, so we just supply the
 * raw hex encoding here.  If this gets seriously out of control we'll
 * write a script to generate a header file we can include.
 */

static const uint8_t
  dalgid_sha1[]       = { 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00 },
  dalgid_sha256[]     = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 },
  dalgid_sha384[]     = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00 },
  dalgid_sha512[]     = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00 },
  dalgid_sha512_224[] = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00 },
  dalgid_sha512_256[] = { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00 };

/*
 * Descriptors.  Yes, the {hash,hmac}_state_length fields are a bit
 * repetitive given that they (currently) have the same value
 * regardless of algorithm, but we don't want to wire in that
 * assumption, so it's simplest to be explicit.
 */

const hal_hash_descriptor_t hal_hash_sha1[1] = {{
  SHA1_BLOCK_LEN, SHA1_DIGEST_LEN,
  sizeof(hal_hash_state_t), sizeof(hal_hmac_state_t),
  dalgid_sha1, sizeof(dalgid_sha1),
  &sha1_driver, 0
}};

const hal_hash_descriptor_t hal_hash_sha256[1] = {{
  SHA256_BLOCK_LEN, SHA256_DIGEST_LEN,
  sizeof(hal_hash_state_t), sizeof(hal_hmac_state_t),
  dalgid_sha256, sizeof(dalgid_sha256),
  &sha256_driver, 1
}};

const hal_hash_descriptor_t hal_hash_sha512_224[1] = {{
  SHA512_BLOCK_LEN, SHA512_224_DIGEST_LEN,
  sizeof(hal_hash_state_t), sizeof(hal_hmac_state_t),
  dalgid_sha512_224, sizeof(dalgid_sha512_224),
  &sha512_224_driver, 0
}};

const hal_hash_descriptor_t hal_hash_sha512_256[1] = {{
  SHA512_BLOCK_LEN, SHA512_256_DIGEST_LEN,
  sizeof(hal_hash_state_t), sizeof(hal_hmac_state_t),
  dalgid_sha512_256, sizeof(dalgid_sha512_256),
  &sha512_256_driver, 0
}};

const hal_hash_descriptor_t hal_hash_sha384[1] = {{
  SHA512_BLOCK_LEN, SHA384_DIGEST_LEN,
  sizeof(hal_hash_state_t), sizeof(hal_hmac_state_t),
  dalgid_sha384, sizeof(dalgid_sha384),
  &sha384_driver, 0
}};

const hal_hash_descriptor_t hal_hash_sha512[1] = {{
  SHA512_BLOCK_LEN, SHA512_DIGEST_LEN,
  sizeof(hal_hash_state_t), sizeof(hal_hmac_state_t),
  dalgid_sha512, sizeof(dalgid_sha512),
  &sha512_driver, 0
}};

/*
 * Debugging control.
 */

static int debug = 0;

void hal_hash_set_debug(int onoff)
{
  debug = onoff;
}

/*
 * Internal utility to do whatever checking we need of a descriptor,
 * then extract the driver pointer in a way that works nicely with
 * initialization of an automatic const pointer.
 *
 * Returns the driver pointer on success, NULL on failure.
 */

static const hal_hash_driver_t *check_driver(const hal_hash_descriptor_t * const descriptor)
{
  return descriptor == NULL ? NULL : descriptor->driver;
}

/*
 * Report whether cores are present.
 */

hal_error_t hal_hash_core_present(const hal_hash_descriptor_t * const descriptor)
{
  const hal_hash_driver_t * const driver = check_driver(descriptor);

  if (driver == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  return hal_io_expected(driver->name_addr,
                         (const uint8_t *) driver->core_name,
                         sizeof(driver->core_name));
}

/*
 * Initialize hash state.
 */

hal_error_t hal_hash_initialize(const hal_hash_descriptor_t * const descriptor,
                                hal_hash_state_t **state_,
                                void *state_buffer, const size_t state_length)
{
  const hal_hash_driver_t * const driver = check_driver(descriptor);
  hal_hash_state_t *state = state_buffer;

  if (driver == NULL || state_ == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (state_buffer != NULL && state_length < descriptor->hash_state_length)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (state_buffer == NULL && (state = malloc(descriptor->hash_state_length)) == NULL)
      return HAL_ERROR_ALLOCATION_FAILURE;

  memset(state, 0, sizeof(*state));
  state->descriptor = descriptor;
  state->driver = driver;
    
  if (state_buffer == NULL)
    state->flags |= STATE_FLAG_STATE_ALLOCATED;

  *state_ = state;

  return HAL_OK;
}

/*
 * Clean up hash state.  No-op unless memory was dynamically allocated.
 */

void hal_hash_cleanup(hal_hash_state_t **state_)
{
  if (state_ == NULL)
    return;

  hal_hash_state_t *state = *state_;

  if (state == NULL || (state->flags & STATE_FLAG_STATE_ALLOCATED) == 0)
    return;

  memset(state, 0, state->descriptor->hash_state_length);
  free(state);
  *state_ = NULL;
}

/*
 * Read hash result from core.  At least for now, this also serves to
 * read current hash state from core.
 */

static hal_error_t hash_read_digest(const hal_hash_driver_t * const driver,
                                    uint8_t *digest,
                                    const size_t digest_length)
{
  hal_error_t err;

  assert(digest != NULL && digest_length % 4 == 0);

  if ((err = hal_io_wait_valid(driver->status_addr)) != HAL_OK)
    return err;

  return hal_io_read(driver->digest_addr, digest, digest_length);
}

/*
 * Write hash state back to core.
 */

static hal_error_t hash_write_digest(const hal_hash_driver_t * const driver,
                                     const uint8_t * const digest,
                                     const size_t digest_length)
{
  hal_error_t err;

  assert(digest != NULL && digest_length % 4 == 0);

  if ((err = hal_io_wait_ready(driver->status_addr)) != HAL_OK)
    return err;

  return hal_io_write(driver->digest_addr, digest, digest_length);
}

/*
 * Send one block to a core.
 */

static hal_error_t hash_write_block(hal_hash_state_t * const state)
{
  uint8_t ctrl_cmd[4];
  hal_error_t err;

  assert(state != NULL && state->descriptor != NULL && state->driver != NULL);
  assert(state->descriptor->block_length % 4 == 0);

  assert(state->descriptor->digest_length <= sizeof(state->core_state) ||
         !state->descriptor->can_restore_state);

  if (debug)
    fprintf(stderr, "[ %s ]\n", state->block_count == 0 ? "init" : "next");

  if ((err = hal_io_wait_ready(state->driver->status_addr)) != HAL_OK)
    return err;

  if (state->descriptor->can_restore_state &&
      state->block_count != 0 &&
      (err = hash_write_digest(state->driver, state->core_state,
                               state->descriptor->digest_length)) != HAL_OK)
    return err;

  if ((err = hal_io_write(state->driver->block_addr, state->block,
                          state->descriptor->block_length)) != HAL_OK)
    return err;

  ctrl_cmd[0] = ctrl_cmd[1] = ctrl_cmd[2] = 0;
  ctrl_cmd[3] = state->block_count == 0 ? CTRL_INIT : CTRL_NEXT;
  ctrl_cmd[3] |= state->driver->ctrl_mode;

  if ((err = hal_io_write(state->driver->ctrl_addr, ctrl_cmd, sizeof(ctrl_cmd))) != HAL_OK)
    return err;

  if (state->descriptor->can_restore_state &&
      (err = hash_read_digest(state->driver, state->core_state,
                              state->descriptor->digest_length)) != HAL_OK)
    return err;

  return hal_io_wait_valid(state->driver->status_addr);
}

/*
 * Add data to hash.
 */

hal_error_t hal_hash_update(hal_hash_state_t *state,            /* Opaque state block */
                            const uint8_t * const data_buffer,  /* Data to be hashed */
                            size_t data_buffer_length)          /* Length of data_buffer */
{
  const uint8_t *p = data_buffer;
  hal_error_t err;
  size_t n;

  if (state == NULL || data_buffer == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (data_buffer_length == 0)
    return HAL_OK;

  assert(state->descriptor != NULL && state->driver != NULL);
  assert(state->descriptor->block_length <= sizeof(state->block));

  while ((n = state->descriptor->block_length - state->block_used) <= data_buffer_length) {
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
    if ((err = hash_write_block(state)) != HAL_OK)
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

  return HAL_OK;
}

/*
 * Finish hash and return digest.
 */

hal_error_t hal_hash_finalize(hal_hash_state_t *state,            	/* Opaque state block */
                              uint8_t *digest_buffer,                   /* Returned digest */
                              const size_t digest_buffer_length)        /* Length of digest_buffer */
{
  uint64_t bit_length_high, bit_length_low;
  hal_error_t err;
  uint8_t *p;
  size_t n;
  int i;

  if (state == NULL || digest_buffer == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  assert(state->descriptor != NULL && state->driver != NULL);

  if (digest_buffer_length < state->descriptor->digest_length)
    return HAL_ERROR_BAD_ARGUMENTS;

  assert(state->descriptor->block_length <= sizeof(state->block));

  /*
   * Add padding, then pull result from the core
   */

  bit_length_low  = (state->msg_length_low  << 3);
  bit_length_high = (state->msg_length_high << 3) | (state->msg_length_low >> 61);

  /* Initial pad byte */
  assert(state->block_used < state->descriptor->block_length);
  state->block[state->block_used++] = 0x80;

  /* If not enough room for bit count, zero and push current block */
  if ((n = state->descriptor->block_length - state->block_used) < state->driver->length_length) {
    if (debug)
      fprintf(stderr, "[ Overflow block, used %lu, n %lu, msg_length %llu ]\n",
              (unsigned long) state->block_used, (unsigned long) n, state->msg_length_low);
    if (n > 0)
      memset(state->block + state->block_used, 0, n);
    if ((err = hash_write_block(state)) != HAL_OK)
      return err;
    state->block_count++;
    state->block_used = 0;
  }

  /* Pad final block */
  n = state->descriptor->block_length - state->block_used;
  assert(n >= state->driver->length_length);
  if (n > 0)
    memset(state->block + state->block_used, 0, n);
  if (debug)
    fprintf(stderr, "[ Final block, used %lu, n %lu, msg_length %llu ]\n",
            (unsigned long) state->block_used, (unsigned long) n, state->msg_length_low);
  p = state->block + state->descriptor->block_length;
  for (i = 0; (bit_length_low || bit_length_high) && i < state->driver->length_length; i++) {
    *--p = (uint8_t) (bit_length_low & 0xFF);
    bit_length_low >>= 8;
    if (bit_length_high) {
      bit_length_low |= ((bit_length_high & 0xFF) << 56);
      bit_length_high >>= 8;
    }
  }

  /* Push final block */
  if ((err = hash_write_block(state)) != HAL_OK)
    return err;
  state->block_count++;

  /* All data pushed to core, now we just need to read back the result */
  if ((err = hash_read_digest(state->driver, digest_buffer, state->descriptor->digest_length)) != HAL_OK)
    return err;

  return HAL_OK;
}

/*
 * Initialize HMAC state.
 */

hal_error_t hal_hmac_initialize(const hal_hash_descriptor_t * const descriptor,
                                hal_hmac_state_t **state_,
                                void *state_buffer, const size_t state_length,
                                const uint8_t * const key, const size_t key_length)
{
  const hal_hash_driver_t * const driver = check_driver(descriptor);
  hal_hmac_state_t *state = state_buffer;
  hal_error_t err;
  int i;

  if (descriptor == NULL || driver == NULL || state_ == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (state_buffer != NULL && state_length < descriptor->hmac_state_length)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (state_buffer == NULL && (state = malloc(descriptor->hmac_state_length)) == NULL)
    return HAL_ERROR_ALLOCATION_FAILURE;

  hal_hash_state_t *h = &state->hash_state;

  assert(descriptor->block_length <= sizeof(state->keybuf));

#if 0
  /*
   * RFC 2104 frowns upon keys shorter than the digest length.
   * ... but most of the test vectors fail this test!
   */

  if (key_length < descriptor->digest_length)
    return HAL_ERROR_UNSUPPORTED_KEY;
#endif

  if ((err = hal_hash_initialize(descriptor, &h, &state->hash_state,
                                 sizeof(state->hash_state))) != HAL_OK)
    goto fail;

  if (state_buffer == NULL)
    h->flags |= STATE_FLAG_STATE_ALLOCATED;

  /*
   * If the supplied HMAC key is longer than the hash block length, we
   * need to hash the supplied HMAC key to get the real HMAC key.
   * Otherwise, we just use the supplied HMAC key directly.
   */

  memset(state->keybuf, 0, sizeof(state->keybuf));

  if (key_length <= descriptor->block_length)
    memcpy(state->keybuf, key, key_length);

  else if ((err = hal_hash_update(h, key, key_length))                         != HAL_OK ||
           (err = hal_hash_finalize(h, state->keybuf, sizeof(state->keybuf)))  != HAL_OK ||
           (err = hal_hash_initialize(descriptor, &h, &state->hash_state,
                                      sizeof(state->hash_state)))              != HAL_OK)
    goto fail;

  /*
   * XOR the key with the IPAD value, then start the inner hash.
   */

  for (i = 0; i < descriptor->block_length; i++)
    state->keybuf[i] ^= HMAC_IPAD;

  if ((err = hal_hash_update(h, state->keybuf, descriptor->block_length)) != HAL_OK)
    goto fail;

  /*
   * Prepare the key for the final hash.  Since we just XORed key with
   * IPAD, we need to XOR with both IPAD and OPAD to get key XOR OPAD.
   */

  for (i = 0; i < descriptor->block_length; i++)
    state->keybuf[i] ^= HMAC_IPAD ^ HMAC_OPAD;

  /*
   * If we had some good way of saving all of our state (including
   * state internal to the hash core), this would be a good place to
   * do it, since it might speed up algorithms like PBKDF2 which do
   * repeated HMAC operations using the same key.  Revisit this if and
   * when the hash cores support such a thing.
   */

  *state_ = state;

  return HAL_OK;

 fail:
  if (state_buffer == NULL)
    free(state);
  return err;
}

/*
 * Clean up HMAC state.  No-op unless memory was dynamically allocated.
 */

void hal_hmac_cleanup(hal_hmac_state_t **state_)
{
  if (state_ == NULL)
    return;

  hal_hmac_state_t *state = *state_;

  if (state == NULL)
    return;

  hal_hash_state_t *h = &state->hash_state;

  if ((h->flags & STATE_FLAG_STATE_ALLOCATED) == 0)
    return;

  memset(state, 0, h->descriptor->hmac_state_length);
  free(state);
  *state_ = NULL;
}

/*
 * Add data to HMAC.
 */

hal_error_t hal_hmac_update(hal_hmac_state_t *state,
                            const uint8_t * data, const size_t length)
{
  if (state == NULL || data == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  return hal_hash_update(&state->hash_state, data, length);
}

/*
 * Finish and return HMAC.
 */

hal_error_t hal_hmac_finalize(hal_hmac_state_t *state,
                              uint8_t *hmac, const size_t length)
{
  if (state == NULL || hmac == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_hash_state_t *h = &state->hash_state;
  const hal_hash_descriptor_t *descriptor = h->descriptor;
  uint8_t d[HAL_MAX_HASH_DIGEST_LENGTH];
  hal_error_t err;

  assert(descriptor != NULL && descriptor->digest_length <= sizeof(d));

  /*
   * Finish up inner hash and extract digest, then perform outer hash
   * to get HMAC.  Key was prepared for this in hal_hmac_initialize().
   */

  if ((err = hal_hash_finalize(h, d, sizeof(d)))                           != HAL_OK ||
      (err = hal_hash_initialize(descriptor, &h, &state->hash_state,
                                 sizeof(state->hash_state)))               != HAL_OK ||
      (err = hal_hash_update(h, state->keybuf, descriptor->block_length))  != HAL_OK ||
      (err = hal_hash_update(h, d, descriptor->digest_length))             != HAL_OK ||
      (err = hal_hash_finalize(h, hmac, length))                           != HAL_OK)
    return err;

  return HAL_OK;
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
