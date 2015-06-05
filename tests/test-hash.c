/*
 * test-hash.c
 * -----------
 * Test code for HAL interface to Cryptech hash cores.
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

static const uint8_t sha512_224_single_digest[] = { /* 28 bytes */
  0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54, 0xda, 0xae, 0x75, 0x30,
  0x46, 0x08, 0x42, 0xe2, 0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4,
  0x3e, 0x89, 0x24, 0xaa
};

static const uint8_t sha512_256_single_digest[] = { /* 32 bytes */
  0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e, 0x29, 0xb7,
  0x6b, 0x4c, 0x7d, 0xab, 0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46,
  0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23
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

static const uint8_t sha512_224_double_digest[] = { /* 28 bytes */
  0x23, 0xfe, 0xc5, 0xbb, 0x94, 0xd6, 0x0b, 0x23, 0x30, 0x81, 0x92, 0x64,
  0x0b, 0x0c, 0x45, 0x33, 0x35, 0xd6, 0x64, 0x73, 0x4f, 0xe4, 0x0e, 0x72,
  0x68, 0x67, 0x4a, 0xf9
};

static const uint8_t sha512_256_double_digest[] = { /* 32 bytes */
  0x39, 0x28, 0xe1, 0x84, 0xfb, 0x86, 0x90, 0xf8, 0x40, 0xda, 0x39, 0x88,
  0x12, 0x1d, 0x31, 0xbe, 0x65, 0xcb, 0x9d, 0x3e, 0xf8, 0x3e, 0xe6, 0x14,
  0x6f, 0xea, 0xc8, 0x61, 0xe1, 0x9b, 0x56, 0x3a
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

/* HMAC-SHA-1 test cases from RFC 2202. */

static const uint8_t hmac_sha1_tc_1_key[] = { /* 20 bytes */
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

/* 'Hi There' */
static const uint8_t hmac_sha1_tc_1_data[] = { /* 8 bytes */
  0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
};

static const uint8_t hmac_sha1_tc_1_result_sha1[] = { /* 20 bytes */
  0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6,
  0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
};

/* 'Jefe' */
static const uint8_t hmac_sha1_tc_2_key[] = { /* 4 bytes */
  0x4a, 0x65, 0x66, 0x65
};

/* 'what do ya want for nothing?' */
static const uint8_t hmac_sha1_tc_2_data[] = { /* 28 bytes */
  0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77,
  0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
  0x69, 0x6e, 0x67, 0x3f
};

static const uint8_t hmac_sha1_tc_2_result_sha1[] = { /* 20 bytes */
  0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5,
  0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
};

static const uint8_t hmac_sha1_tc_3_key[] = { /* 20 bytes */
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};

static const uint8_t hmac_sha1_tc_3_data[] = { /* 50 bytes */
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd
};

static const uint8_t hmac_sha1_tc_3_result_sha1[] = { /* 20 bytes */
  0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4,
  0x8a, 0xa1, 0x7b, 0x4f, 0x63, 0xf1, 0x75, 0xd3
};

static const uint8_t hmac_sha1_tc_4_key[] = { /* 25 bytes */
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
};

static const uint8_t hmac_sha1_tc_4_data[] = { /* 50 bytes */
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd
};

static const uint8_t hmac_sha1_tc_4_result_sha1[] = { /* 20 bytes */
  0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6, 0xbc, 0x84, 0x14, 0xf9,
  0xbf, 0x50, 0xc8, 0x6c, 0x2d, 0x72, 0x35, 0xda
};

static const uint8_t hmac_sha1_tc_5_key[] = { /* 20 bytes */
  0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
  0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c
};

/* 'Test With Truncation' */
static const uint8_t hmac_sha1_tc_5_data[] = { /* 20 bytes */
  0x54, 0x65, 0x73, 0x74, 0x20, 0x57, 0x69, 0x74, 0x68, 0x20, 0x54, 0x72,
  0x75, 0x6e, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e
};

static const uint8_t hmac_sha1_tc_5_result_sha1[] = { /* 20 bytes */
  0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7, 0xf2, 0x7b, 0xe1,
  0xd5, 0x8b, 0xb9, 0x32, 0x4a, 0x9a, 0x5a, 0x04
};

static const uint8_t hmac_sha1_tc_6_key[] = { /* 80 bytes */
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};

/* 'Test Using Larger Than Block-Size Key - Hash Key First' */
static const uint8_t hmac_sha1_tc_6_data[] = { /* 54 bytes */
  0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c,
  0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
  0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65,
  0x79, 0x20, 0x2d, 0x20, 0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79,
  0x20, 0x46, 0x69, 0x72, 0x73, 0x74
};

static const uint8_t hmac_sha1_tc_6_result_sha1[] = { /* 20 bytes */
  0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70, 0x56, 0x37,
  0xce, 0x8a, 0x3b, 0x55, 0xed, 0x40, 0x21, 0x12
};

static const uint8_t hmac_sha1_tc_7_key[] = { /* 80 bytes */
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};

/* 'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data' */
static const uint8_t hmac_sha1_tc_7_data[] = { /* 73 bytes */
  0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c,
  0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
  0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65,
  0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65, 0x72,
  0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x4f, 0x6e, 0x65, 0x20, 0x42, 0x6c,
  0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x44, 0x61, 0x74, 0x61
};

static const uint8_t hmac_sha1_tc_7_result_sha1[] = { /* 20 bytes */
  0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78, 0x6d, 0x6b, 0xba, 0xa7,
  0x96, 0x5c, 0x78, 0x08, 0xbb, 0xff, 0x1a, 0x91
};

/* HMAC-SHA-2 test cases from RFC 4231. */

static const uint8_t hmac_sha2_tc_1_key[] = { /* 20 bytes */
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

/* 'Hi There' */
static const uint8_t hmac_sha2_tc_1_data[] = { /* 8 bytes */
  0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
};

static const uint8_t hmac_sha2_tc_1_result_sha256[] = { /* 32 bytes */
  0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce,
  0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
  0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

static const uint8_t hmac_sha2_tc_1_result_sha384[] = { /* 48 bytes */
  0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4,
  0xab, 0x46, 0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
  0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9,
  0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6
};

static const uint8_t hmac_sha2_tc_1_result_sha512[] = { /* 64 bytes */
  0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24,
  0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
  0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7,
  0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
  0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20,
  0x3a, 0x12, 0x68, 0x54
};

/* 'Jefe' */
static const uint8_t hmac_sha2_tc_2_key[] = { /* 4 bytes */
  0x4a, 0x65, 0x66, 0x65
};

/* 'what do ya want for nothing?' */
static const uint8_t hmac_sha2_tc_2_data[] = { /* 28 bytes */
  0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77,
  0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
  0x69, 0x6e, 0x67, 0x3f
};

static const uint8_t hmac_sha2_tc_2_result_sha256[] = { /* 32 bytes */
  0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26,
  0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
  0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
};

static const uint8_t hmac_sha2_tc_2_result_sha384[] = { /* 48 bytes */
  0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2,
  0xb5, 0x8a, 0x6b, 0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47,
  0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22, 0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca,
  0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32, 0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49
};

static const uint8_t hmac_sha2_tc_2_result_sha512[] = { /* 64 bytes */
  0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7,
  0x3b, 0x56, 0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6,
  0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75,
  0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd,
  0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a,
  0x38, 0xbc, 0xe7, 0x37
};

static const uint8_t hmac_sha2_tc_3_key[] = { /* 20 bytes */
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};

static const uint8_t hmac_sha2_tc_3_data[] = { /* 50 bytes */
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd
};

static const uint8_t hmac_sha2_tc_3_result_sha256[] = { /* 32 bytes */
  0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb,
  0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
  0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe
};

static const uint8_t hmac_sha2_tc_3_result_sha384[] = { /* 48 bytes */
  0x88, 0x06, 0x26, 0x08, 0xd3, 0xe6, 0xad, 0x8a, 0x0a, 0xa2, 0xac, 0xe0,
  0x14, 0xc8, 0xa8, 0x6f, 0x0a, 0xa6, 0x35, 0xd9, 0x47, 0xac, 0x9f, 0xeb,
  0xe8, 0x3e, 0xf4, 0xe5, 0x59, 0x66, 0x14, 0x4b, 0x2a, 0x5a, 0xb3, 0x9d,
  0xc1, 0x38, 0x14, 0xb9, 0x4e, 0x3a, 0xb6, 0xe1, 0x01, 0xa3, 0x4f, 0x27
};

static const uint8_t hmac_sha2_tc_3_result_sha512[] = { /* 64 bytes */
  0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75,
  0x6c, 0x89, 0x0b, 0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36,
  0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27, 0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82,
  0x79, 0xa7, 0x22, 0xc8, 0x06, 0xb4, 0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07,
  0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26, 0x74, 0x27, 0x88, 0x59,
  0xe1, 0x32, 0x92, 0xfb
};

static const uint8_t hmac_sha2_tc_4_key[] = { /* 25 bytes */
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
};

static const uint8_t hmac_sha2_tc_4_data[] = { /* 50 bytes */
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd
};

static const uint8_t hmac_sha2_tc_4_result_sha256[] = { /* 32 bytes */
  0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98,
  0x99, 0xf2, 0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
  0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b
};

static const uint8_t hmac_sha2_tc_4_result_sha384[] = { /* 48 bytes */
  0x3e, 0x8a, 0x69, 0xb7, 0x78, 0x3c, 0x25, 0x85, 0x19, 0x33, 0xab, 0x62,
  0x90, 0xaf, 0x6c, 0xa7, 0x7a, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9c,
  0xc5, 0x57, 0x7c, 0x6e, 0x1f, 0x57, 0x3b, 0x4e, 0x68, 0x01, 0xdd, 0x23,
  0xc4, 0xa7, 0xd6, 0x79, 0xcc, 0xf8, 0xa3, 0x86, 0xc6, 0x74, 0xcf, 0xfb
};

static const uint8_t hmac_sha2_tc_4_result_sha512[] = { /* 64 bytes */
  0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69, 0x90, 0xe5, 0xa8, 0xc5,
  0xf6, 0x1d, 0x4a, 0xf7, 0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d,
  0xe7, 0x6f, 0x80, 0x50, 0x36, 0x1e, 0xe3, 0xdb, 0xa9, 0x1c, 0xa5, 0xc1,
  0x1a, 0xa2, 0x5e, 0xb4, 0xd6, 0x79, 0x27, 0x5c, 0xc5, 0x78, 0x80, 0x63,
  0xa5, 0xf1, 0x97, 0x41, 0x12, 0x0c, 0x4f, 0x2d, 0xe2, 0xad, 0xeb, 0xeb,
  0x10, 0xa2, 0x98, 0xdd
};

/* Skipping HMAC-SHA-2 test case 5. */

static const uint8_t hmac_sha2_tc_6_key[] = { /* 131 bytes */
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};

/* 'Test Using Larger Than Block-Size Key - Hash Key First' */
static const uint8_t hmac_sha2_tc_6_data[] = { /* 54 bytes */
  0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c,
  0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
  0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65,
  0x79, 0x20, 0x2d, 0x20, 0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79,
  0x20, 0x46, 0x69, 0x72, 0x73, 0x74
};

static const uint8_t hmac_sha2_tc_6_result_sha256[] = { /* 32 bytes */
  0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa,
  0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
  0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54
};

static const uint8_t hmac_sha2_tc_6_result_sha384[] = { /* 48 bytes */
  0x4e, 0xce, 0x08, 0x44, 0x85, 0x81, 0x3e, 0x90, 0x88, 0xd2, 0xc6, 0x3a,
  0x04, 0x1b, 0xc5, 0xb4, 0x4f, 0x9e, 0xf1, 0x01, 0x2a, 0x2b, 0x58, 0x8f,
  0x3c, 0xd1, 0x1f, 0x05, 0x03, 0x3a, 0xc4, 0xc6, 0x0c, 0x2e, 0xf6, 0xab,
  0x40, 0x30, 0xfe, 0x82, 0x96, 0x24, 0x8d, 0xf1, 0x63, 0xf4, 0x49, 0x52
};

static const uint8_t hmac_sha2_tc_6_result_sha512[] = { /* 64 bytes */
  0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1,
  0xdd, 0x7b, 0xe8, 0xb4, 0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1,
  0x12, 0x1b, 0x01, 0x37, 0x83, 0xf8, 0xf3, 0x52, 0x6b, 0x56, 0xd0, 0x37,
  0xe0, 0x5f, 0x25, 0x98, 0xbd, 0x0f, 0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52,
  0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec, 0x8b, 0x91, 0x5a, 0x98,
  0x5d, 0x78, 0x65, 0x98
};

static const uint8_t hmac_sha2_tc_7_key[] = { /* 131 bytes */
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};

/* 'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.' */
static const uint8_t hmac_sha2_tc_7_data[] = { /* 152 bytes */
  0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65,
  0x73, 0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6c,
  0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x62,
  0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65,
  0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67,
  0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63,
  0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2e,
  0x20, 0x54, 0x68, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6e, 0x65, 0x65,
  0x64, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x68, 0x61, 0x73,
  0x68, 0x65, 0x64, 0x20, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62,
  0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x62, 0x79,
  0x20, 0x74, 0x68, 0x65, 0x20, 0x48, 0x4d, 0x41, 0x43, 0x20, 0x61, 0x6c,
  0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e
};

static const uint8_t hmac_sha2_tc_7_result_sha256[] = { /* 32 bytes */
  0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc,
  0xd5, 0xb0, 0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
  0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2
};

static const uint8_t hmac_sha2_tc_7_result_sha384[] = { /* 48 bytes */
  0x66, 0x17, 0x17, 0x8e, 0x94, 0x1f, 0x02, 0x0d, 0x35, 0x1e, 0x2f, 0x25,
  0x4e, 0x8f, 0xd3, 0x2c, 0x60, 0x24, 0x20, 0xfe, 0xb0, 0xb8, 0xfb, 0x9a,
  0xdc, 0xce, 0xbb, 0x82, 0x46, 0x1e, 0x99, 0xc5, 0xa6, 0x78, 0xcc, 0x31,
  0xe7, 0x99, 0x17, 0x6d, 0x38, 0x60, 0xe6, 0x11, 0x0c, 0x46, 0x52, 0x3e
};

static const uint8_t hmac_sha2_tc_7_result_sha512[] = { /* 64 bytes */
  0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba, 0xa4, 0xdf, 0xa9, 0xf9,
  0x6e, 0x5e, 0x3f, 0xfd, 0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86,
  0x5d, 0xf5, 0xa3, 0x2d, 0x20, 0xcd, 0xc9, 0x44, 0xb6, 0x02, 0x2c, 0xac,
  0x3c, 0x49, 0x82, 0xb1, 0x0d, 0x5e, 0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15,
  0x13, 0x46, 0x76, 0xfb, 0x6d, 0xe0, 0x44, 0x60, 0x65, 0xc9, 0x74, 0x40,
  0xfa, 0x8c, 0x6a, 0x58
};

static int _test_hash(const hal_hash_descriptor_t * const descriptor,
                      const uint8_t * const data, const size_t data_len,
                      const uint8_t * const result, const size_t result_len,
                      const char * const label)
{
  uint8_t statebuf[512], digest[512];
  hal_hash_state_t state;
  hal_error_t err;

  assert(descriptor != NULL && data != NULL && result != NULL && label != NULL);
  assert(result_len <= sizeof(digest));
  assert(descriptor->hash_state_length <= sizeof(statebuf));

  printf("Starting %s test\n", label);

  err = hal_hash_core_present(descriptor);

  switch (err) {

  case HAL_OK:
    break;

  case HAL_ERROR_IO_UNEXPECTED:
    printf("Core not present, skipping test\n");
    return 1;

  default:
    printf("Failed while checking for core: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hal_hash_initialize(descriptor, &state, statebuf, sizeof(statebuf))) != HAL_OK) {
    printf("Failed while initializing hash: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hal_hash_update(state, data, data_len)) != HAL_OK) {
    printf("Failed while updating hash: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hal_hash_finalize(state, digest, sizeof(digest))) != HAL_OK) {
    printf("Failed while finalizing hash: %s\n", hal_error_string(err));
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

static int _test_hmac(const hal_hash_descriptor_t * const descriptor,
                      const uint8_t * const key,  const size_t key_len,
                      const uint8_t * const data, const size_t data_len,
                      const uint8_t * const result, const size_t result_len,
                      const char * const label)
{
  uint8_t statebuf[1024], digest[512];
  hal_hmac_state_t state;
  hal_error_t err;

  assert(descriptor != NULL && data != NULL && result != NULL && label != NULL);
  assert(result_len <= sizeof(digest));
  assert(descriptor->hmac_state_length <= sizeof(statebuf));

  printf("Starting %s test\n", label);

  err = hal_hash_core_present(descriptor);

  switch (err) {

  case HAL_OK:
    break;

  case HAL_ERROR_IO_UNEXPECTED:
    printf("Core not present, skipping test\n");
    return 1;

  default:
    printf("Failed while checking for core: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hal_hmac_initialize(descriptor, &state, statebuf, sizeof(statebuf), key, key_len)) != HAL_OK) {
    printf("Failed while initializing HMAC: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hal_hmac_update(state, data, data_len)) != HAL_OK) {
    printf("Failed while updating HMAC: %s\n", hal_error_string(err));
    return 0;
  }

  if ((err = hal_hmac_finalize(state, digest, sizeof(digest))) != HAL_OK) {
    printf("Failed while finalizing HMAC: %s\n", hal_error_string(err));
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

#define test_hash(_desc_, _data_, _result_, _label_) \
  _test_hash(_desc_, _data_, sizeof(_data_), _result_, sizeof(_result_), _label_)

#define test_hmac(_desc_, _key_, _data_, _result_, _label_) \
  _test_hmac(_desc_, _key_, sizeof(_key_), _data_, sizeof(_data_), _result_, sizeof(_result_), _label_)

int main (int argc, char *argv[])
{
  int ok = 1;

  ok &= test_hash(hal_hash_sha1,   nist_512_single, sha1_single_digest, "SHA-1 single block");
  ok &= test_hash(hal_hash_sha1,   nist_512_double, sha1_double_digest, "SHA-1 double block");

  ok &= test_hash(hal_hash_sha256, nist_512_single, sha256_single_digest, "SHA-256 single block");
  ok &= test_hash(hal_hash_sha256, nist_512_double, sha256_double_digest, "SHA-256 double block");

  ok &= test_hash(hal_hash_sha512_224, nist_1024_single, sha512_224_single_digest, "SHA-512/224 single block");
  ok &= test_hash(hal_hash_sha512_224, nist_1024_double, sha512_224_double_digest, "SHA-512/224 double block");

  ok &= test_hash(hal_hash_sha512_256, nist_1024_single, sha512_256_single_digest, "SHA-512/256 single block");
  ok &= test_hash(hal_hash_sha512_256, nist_1024_double, sha512_256_double_digest, "SHA-512/256 double block");

  ok &= test_hash(hal_hash_sha384, nist_1024_single, sha384_single_digest, "SHA-384 single block");
  ok &= test_hash(hal_hash_sha384, nist_1024_double, sha384_double_digest, "SHA-384 double block");

  ok &= test_hash(hal_hash_sha512, nist_1024_single, sha512_single_digest, "SHA-512 single block");
  ok &= test_hash(hal_hash_sha512, nist_1024_double, sha512_double_digest, "SHA-512 double block");

  ok &= test_hmac(hal_hash_sha1, hmac_sha1_tc_1_key, hmac_sha1_tc_1_data, hmac_sha1_tc_1_result_sha1, "HMAC-SHA-1 test case 1");
  ok &= test_hmac(hal_hash_sha1, hmac_sha1_tc_2_key, hmac_sha1_tc_2_data, hmac_sha1_tc_2_result_sha1, "HMAC-SHA-1 test case 2");
  ok &= test_hmac(hal_hash_sha1, hmac_sha1_tc_3_key, hmac_sha1_tc_3_data, hmac_sha1_tc_3_result_sha1, "HMAC-SHA-1 test case 3");
  ok &= test_hmac(hal_hash_sha1, hmac_sha1_tc_4_key, hmac_sha1_tc_4_data, hmac_sha1_tc_4_result_sha1, "HMAC-SHA-1 test case 4");
  ok &= test_hmac(hal_hash_sha1, hmac_sha1_tc_5_key, hmac_sha1_tc_5_data, hmac_sha1_tc_5_result_sha1, "HMAC-SHA-1 test case 5");
  ok &= test_hmac(hal_hash_sha1, hmac_sha1_tc_6_key, hmac_sha1_tc_6_data, hmac_sha1_tc_6_result_sha1, "HMAC-SHA-1 test case 6");
  ok &= test_hmac(hal_hash_sha1, hmac_sha1_tc_7_key, hmac_sha1_tc_7_data, hmac_sha1_tc_7_result_sha1, "HMAC-SHA-1 test case 7");

  ok &= test_hmac(hal_hash_sha256, hmac_sha2_tc_1_key, hmac_sha2_tc_1_data, hmac_sha2_tc_1_result_sha256, "HMAC-SHA-256 test case 1");
  ok &= test_hmac(hal_hash_sha256, hmac_sha2_tc_2_key, hmac_sha2_tc_2_data, hmac_sha2_tc_2_result_sha256, "HMAC-SHA-256 test case 2");
  ok &= test_hmac(hal_hash_sha256, hmac_sha2_tc_3_key, hmac_sha2_tc_3_data, hmac_sha2_tc_3_result_sha256, "HMAC-SHA-256 test case 3");
  ok &= test_hmac(hal_hash_sha256, hmac_sha2_tc_4_key, hmac_sha2_tc_4_data, hmac_sha2_tc_4_result_sha256, "HMAC-SHA-256 test case 4");
  ok &= test_hmac(hal_hash_sha256, hmac_sha2_tc_6_key, hmac_sha2_tc_6_data, hmac_sha2_tc_6_result_sha256, "HMAC-SHA-256 test case 6");
  ok &= test_hmac(hal_hash_sha256, hmac_sha2_tc_7_key, hmac_sha2_tc_7_data, hmac_sha2_tc_7_result_sha256, "HMAC-SHA-256 test case 7");

  ok &= test_hmac(hal_hash_sha384, hmac_sha2_tc_1_key, hmac_sha2_tc_1_data, hmac_sha2_tc_1_result_sha384, "HMAC-SHA-384 test case 1");
  ok &= test_hmac(hal_hash_sha384, hmac_sha2_tc_2_key, hmac_sha2_tc_2_data, hmac_sha2_tc_2_result_sha384, "HMAC-SHA-384 test case 2");
  ok &= test_hmac(hal_hash_sha384, hmac_sha2_tc_3_key, hmac_sha2_tc_3_data, hmac_sha2_tc_3_result_sha384, "HMAC-SHA-384 test case 3");
  ok &= test_hmac(hal_hash_sha384, hmac_sha2_tc_4_key, hmac_sha2_tc_4_data, hmac_sha2_tc_4_result_sha384, "HMAC-SHA-384 test case 4");
  ok &= test_hmac(hal_hash_sha384, hmac_sha2_tc_6_key, hmac_sha2_tc_6_data, hmac_sha2_tc_6_result_sha384, "HMAC-SHA-384 test case 6");
  ok &= test_hmac(hal_hash_sha384, hmac_sha2_tc_7_key, hmac_sha2_tc_7_data, hmac_sha2_tc_7_result_sha384, "HMAC-SHA-384 test case 7");

  ok &= test_hmac(hal_hash_sha512, hmac_sha2_tc_1_key, hmac_sha2_tc_1_data, hmac_sha2_tc_1_result_sha512, "HMAC-SHA-512 test case 1");
  ok &= test_hmac(hal_hash_sha512, hmac_sha2_tc_2_key, hmac_sha2_tc_2_data, hmac_sha2_tc_2_result_sha512, "HMAC-SHA-512 test case 2");
  ok &= test_hmac(hal_hash_sha512, hmac_sha2_tc_3_key, hmac_sha2_tc_3_data, hmac_sha2_tc_3_result_sha512, "HMAC-SHA-512 test case 3");
  ok &= test_hmac(hal_hash_sha512, hmac_sha2_tc_4_key, hmac_sha2_tc_4_data, hmac_sha2_tc_4_result_sha512, "HMAC-SHA-512 test case 4");
  ok &= test_hmac(hal_hash_sha512, hmac_sha2_tc_6_key, hmac_sha2_tc_6_data, hmac_sha2_tc_6_result_sha512, "HMAC-SHA-512 test case 6");
  ok &= test_hmac(hal_hash_sha512, hmac_sha2_tc_7_key, hmac_sha2_tc_7_data, hmac_sha2_tc_7_result_sha512, "HMAC-SHA-512 test case 7");

  return !ok;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
