/*
 * Test code for hash cores.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <cryptech.h>

/* Usual NIST sample messages. */

/* "abc" */
static const uint8_t nist_512_single[] = { /* 3 bytes */
  0x61, 0x62, 0x63
};

static const uint8_t sha1_single_digest[] = { /* 20 bytes */
  0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71,
  0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
};

static const uint8_t sha256_single_digest[] = { /* 32 bytes */
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
  0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

/* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
static const uint8_t nist_512_double[] = { /* 56 bytes */
  0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 0x65, 0x66,
  0x64, 0x65, 0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
  0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c,
  0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
  0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71
};

static const uint8_t sha1_double_digest[] = { /* 20 bytes */
  0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1,
  0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
};

static const uint8_t sha256_double_digest[] = { /* 32 bytes */
  0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93,
  0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
  0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};

/* "abc" */
static const uint8_t nist_1024_single[] = { /* 3 bytes */
  0x61, 0x62, 0x63
};

static const uint8_t sha384_single_digest[] = { /* 48 bytes */
  0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
  0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
  0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
  0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
};

static const uint8_t sha512_single_digest[] = { /* 64 bytes */
  0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49,
  0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
  0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a,
  0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
  0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
  0xa5, 0x4c, 0xa4, 0x9f
};

/* "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
   "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" */
static const uint8_t nist_1024_double[] = { /* 112 bytes */
  0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x62, 0x63, 0x64, 0x65,
  0x66, 0x67, 0x68, 0x69, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
  0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x65, 0x66, 0x67, 0x68,
  0x69, 0x6a, 0x6b, 0x6c, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
  0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x68, 0x69, 0x6a, 0x6b,
  0x6c, 0x6d, 0x6e, 0x6f, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
  0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x6b, 0x6c, 0x6d, 0x6e,
  0x6f, 0x70, 0x71, 0x72, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
  0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x6e, 0x6f, 0x70, 0x71,
  0x72, 0x73, 0x74, 0x75
};

static const uint8_t sha384_double_digest[] = { /* 48 bytes */
  0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7,
  0x82, 0xcd, 0x1b, 0x47, 0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2,
  0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12, 0xfc, 0xc7, 0xc7, 0x1a,
  0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39
};

static const uint8_t sha512_double_digest[] = { /* 64 bytes */
  0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28,
  0x14, 0xfc, 0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
  0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e,
  0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
  0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b,
  0x87, 0x4b, 0xe9, 0x09
};

static int _test_hash(hal_error_t (*hash)(void *, const uint8_t *, const size_t, uint8_t *, const size_t),
		      const uint8_t * const data, const size_t data_len,
		      const uint8_t * const result, const size_t result_len,
		      const char * const label)
{
  uint8_t state[512], digest[512];
  hal_error_t err;

  assert(hash != NULL && data != NULL && result != NULL && label != NULL);

  assert(result_len <= sizeof(digest) && hal_hash_state_size() <= sizeof(state));

  printf("Starting %s test\n", label);

  hal_hash_state_initialize(state);

  if ((err = hash(state, data, data_len, NULL, 0)) != HAL_OK) {
    printf("Failed: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hash(state, NULL, 0, digest, sizeof(digest))) != HAL_OK) {
    printf("Failed: %s\n", hal_error_string(err));
    return 0;
  }

  printf("Comparing result with known value\n");
  if (memcmp(result, digest, result_len)) {
    size_t i;
    printf("MISMATCH\nExpected:");
    for (i = 0; i < result_len; i++)
      printf(" %02x", result[i]);
    printf("\nGot:     ");
    for (i = 0; i < result_len; i++)
      printf(" %02x", digest[i]);
    printf("\n");
    return 0;
  }

  printf("OK\n");
    return 1;
}

#define test_hash(_hash_, _data_, _result_, _label_) \
  _test_hash(_hash_, _data_, sizeof(_data_), _result_, sizeof(_result_), _label_)

int main (int argc, char *argv[])
{
  int ok = 1;

  /*
   * Missing some tests here because I started from the Cryptlib test
   * script, which skips the 224 and 256 options of the SHA-512 core.
   */

  if (hash_sha1_core_present() == HAL_OK) {
    ok &= test_hash(hal_hash_sha1,   nist_512_single, sha1_single_digest, "SHA-1 single block");
    ok &= test_hash(hal_hash_sha1,   nist_512_double, sha1_double_digest, "SHA-1 double block");
  }
  else {
    printf("SHA-1 core not present, skipping tests which depend on it\n");
  }

  if (hash_sha256_core_present() == HAL_OK) {
    ok &= test_hash(hal_hash_sha256, nist_512_single, sha256_single_digest, "SHA-256 single block");
    ok &= test_hash(hal_hash_sha256, nist_512_double, sha256_double_digest, "SHA-256 double block");
  }
  else {
    printf("SHA-256 core not present, skipping tests which depend on it\n");
  }

  if (hash_sha512_core_present() == HAL_OK) {
    ok &= test_hash(hal_hash_sha384, nist_1024_single, sha384_single_digest, "SHA-384 single block");
    ok &= test_hash(hal_hash_sha384, nist_1024_double, sha384_double_digest, "SHA-384 double block");

    ok &= test_hash(hal_hash_sha512, nist_1024_single, sha512_single_digest, "SHA-512 single block");
    ok &= test_hash(hal_hash_sha512, nist_1024_double, sha512_double_digest, "SHA-512 double block");
  }
  else {
    printf("SHA-512 core not present, skipping tests which depend on it\n");
  }

  return !ok;
}
