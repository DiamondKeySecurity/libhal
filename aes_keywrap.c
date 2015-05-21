/*
 * Implementation of RFC 5649 variant of AES Key Wrap, using Cryptlib
 * to supply the AES ECB encryption and decryption functions.
 *
 * Note that there are two different block sizes involved here: the
 * key wrap algorithm deals entirely with 64-bit blocks, while AES
 * itself deals with 128-bit blocks.  In practice, this is not as
 * confusing as it sounds, because we combine two 64-bit blocks to
 * create one 128-bit block just prior to performing an AES operation,
 * then split the result back to 64-bit blocks immediately afterwards.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "cryptech.h"


/*
 * How long the ciphertext will be for a given plaintext length.
 */

size_t hal_aes_keywrap_ciphertext_length(const size_t plaintext_length)
{
  return (plaintext_length + 15) & ~7;
}


/*
 * Check the KEK, then load it into the AES core.
 * Note that our AES core only supports 128 and 256 bit keys.
 */

typedef enum { KEK_encrypting, KEK_decrypting } kek_action_t;

static hal_error_t load_kek(const uint8_t *K, const size_t K_len, const kek_action_t action)
{
  uint8_t config[4];
  hal_error_t err;

  if (K == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  memset(config, 0, sizeof(config));

  switch (K_len) {
  case bitsToBytes(128):
    config[3] &= ~AES_CONFIG_KEYLEN;
    break;
  case bitsToBytes(256):
    config[3] |=  AES_CONFIG_KEYLEN;
    break;
  case bitsToBytes(192):
    return HAL_ERROR_UNSUPPORTED_KEY;
  default:
    return HAL_ERROR_BAD_ARGUMENTS;
  }

  switch (action) {
  case KEK_encrypting:
    config[3] |=  AES_CONFIG_ENCDEC;
    break;
  case KEK_decrypting:
    config[3] &= !AES_CONFIG_ENCDEC;
    break;
  default:
    return HAL_ERROR_BAD_ARGUMENTS;
  }

  /*
   * Load the KEK and tell the core to expand it.
   */

  if ((err = hal_io_write(AES_ADDR_KEY0, K, K_len)) != HAL_OK ||
      (err = hal_io_init(AES_ADDR_CTRL))            != HAL_OK)
    return err;

  return HAL_OK;
}


/*
 * Process one block.  Since AES Key Wrap always deals with 64-bit
 * half blocks and since the bus is going to break this up into 32-bit
 * words no matter what we do, we can eliminate a few gratuitous
 * memcpy() operations by receiving our arguments as two half blocks.
 *
 * Since the length of these half blocks is constant, there's no real
 * point in passing the length as an argument, we'd just be checking a
 * constant against a constant and a smart compiler will optimize
 * the whole check out.
 *
 * Just be VERY careful if you change anything here.
 */

static hal_error_t do_block(uint8_t *b1, uint8_t *b2)
{
  hal_error_t err;

  assert(b1 != NULL && b2 != NULL);

  if ((err = hal_io_write(AES_ADDR_BLOCK0, b1, 8)) != HAL_OK ||
      (err = hal_io_write(AES_ADDR_BLOCK2, b2, 8)) != HAL_OK ||
      (err = hal_io_next(AES_ADDR_CTRL))           != HAL_OK ||
      (err = hal_io_wait_ready(AES_ADDR_STATUS))   != HAL_OK ||
      (err = hal_io_read(AES_ADDR_RESULT0, b1, 8)) != HAL_OK ||
      (err = hal_io_read(AES_ADDR_RESULT2, b2, 8)) != HAL_OK)
    return err;

  return HAL_OK;
}


/*
 * Wrap plaintext Q using KEK K, placing result in C.
 *
 * Q and C can overlap.  For encrypt-in-place, use Q = C + 8 (that is,
 * leave 8 empty bytes before the plaintext).
 *
 * Use hal_aes_keywrap_ciphertext_length() to calculate the correct
 * buffer size.
 */

hal_error_t hal_aes_keywrap(const uint8_t *K, const size_t K_len,
                            const uint8_t * const Q,
                            const size_t m,
                            uint8_t *C,
                            size_t *C_len)
{
  const size_t calculated_C_len = hal_aes_keywrap_ciphertext_length(m);
  hal_error_t err;
  uint32_t n;
  long i, j;

  assert(calculated_C_len % 8 == 0);

  if (Q == NULL || C == NULL || C_len == NULL || *C_len < calculated_C_len)
    return HAL_ERROR_BAD_ARGUMENTS;

  if ((err = load_kek(K, K_len, KEK_encrypting)) != HAL_OK)
    return err;

  *C_len = calculated_C_len;

  if (C + 8 != Q)
    memmove(C + 8, Q, m);
  if (m % 8 != 0)
    memset(C + 8 + m, 0, 8 -  (m % 8));
  C[0] = 0xA6;
  C[1] = 0x59;
  C[2] = 0x59;
  C[3] = 0xA6;
  C[4] = (m >> 24) & 0xFF;
  C[5] = (m >> 16) & 0xFF;
  C[6] = (m >>  8) & 0xFF;
  C[7] = (m >>  0) & 0xFF;

  n = calculated_C_len/8 - 1;

  if (n == 1) {
    if ((err = do_block(C, C + 8)) != HAL_OK)
      return err;
  }

  else {
    for (j = 0; j <= 5; j++) {
      for (i = 1; i <= n; i++) {
        uint32_t t = n * j + i;
        if ((err = do_block(C, C + i * 8)) != HAL_OK)
          return err;
        C[7] ^= t & 0xFF; t >>= 8;
        C[6] ^= t & 0xFF; t >>= 8;
        C[5] ^= t & 0xFF; t >>= 8;
        C[4] ^= t & 0xFF;
      }
    }
  }

  return HAL_OK;
}


/*
 * Unwrap ciphertext C using KEK K, placing result in Q.
 *
 * Q should be the same size as C.  Q and C can overlap.
 */

hal_error_t hal_aes_keyunwrap(const uint8_t *K, const size_t K_len,
                              const uint8_t * const C,
                              const size_t C_len,
                              uint8_t *Q,
                              size_t *Q_len)
{
  hal_error_t err;
  uint32_t n;
  long i, j;
  size_t m;

  if (C == NULL || Q == NULL || C_len % 8 != 0 || C_len < 16 || Q_len == NULL || *Q_len < C_len)
    return HAL_ERROR_BAD_ARGUMENTS;

  if ((err = load_kek(K, K_len, KEK_decrypting)) != HAL_OK)
    return err;

  n = (C_len / 8) - 1;

  if (Q != C)
    memmove(Q, C, C_len);

  if (n == 1) {
    if ((err = do_block(Q, Q + 8)) != HAL_OK)
      return err;
  }

  else {
    for (j = 5; j >= 0; j--) {
      for (i = n; i >= 1; i--) {
        uint32_t t = n * j + i;
        Q[7] ^= t & 0xFF; t >>= 8;
        Q[6] ^= t & 0xFF; t >>= 8;
        Q[5] ^= t & 0xFF; t >>= 8;
        Q[4] ^= t & 0xFF;
        if ((err = do_block(Q, Q + i * 8)) != HAL_OK)
          return err;
      }
    }
  }

  if (Q[0] != 0xA6 || Q[1] != 0x59 || Q[2] != 0x59 || Q[3] != 0xA6)
    return HAL_ERROR_KEYWRAP_BAD_MAGIC;

  m = (((((Q[4] << 8) + Q[5]) << 8) + Q[6]) << 8) + Q[7];

  if (m <= 8 * (n - 1) || m > 8 * n)
    return HAL_ERROR_KEYWRAP_BAD_LENGTH;

  if (m % 8 != 0)
    for (i = m + 8; i < 8 * (n + 1); i++)
      if (Q[i] != 0x00)
        return HAL_ERROR_KEYWRAP_BAD_PADDING;

  *Q_len = m;

  memmove(Q, Q + 8, m);

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
