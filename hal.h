/*
 * hal.h
 * ----------
 * Memory map, access functions, and HAL for Cryptech cores.
 *
 * Authors: Joachim Strombergson, Paul Selkirk, Rob Austein
 * Copyright (c) 2015, NORDUnet A/S All rights reserved.
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

/*
 * Each Cryptech core has a set of 4-byte registers, which are accessed
 * through a 16-bit address. The address space is divided as follows:
 *   3 bits segment selector       | up to 8 segments
 *   5 bits core selector          | up to 32 cores/segment (see note below)
 *   8 bits register selector      | up to 256 registers/core (see modexp below)
 * 
 * i.e, the address is structured as:
 * sss ccccc rrrrrrrr
 * 
 * The I2C and UART communication channels use this 16-bit address format
 * directly in their read and write commands.
 * 
 * The EIM communications channel translates this 16-bit address into a
 * 32-bit memory-mapped address in the range 0x08000000..807FFFF:
 * 00001000000000 sss 0 ccccc rrrrrrrr 00
 * 
 * EIM, as implemented on the Novena, uses a 19-bit address space:
 *   Bits 18..16 are the semgent selector.
 *   Bits 15..10 are the core selector.
 *   Bits 9..2 are the register selector.
 *   Bits 1..0 are zero, because reads and writes are always word aligned.
 * 
 * Note that EIM can support 64 cores per segment, but we sacrifice one bit
 * in order to map it into a 16-bit address space.
 */

#ifndef _HAL_H_
#define _HAL_H_


/*
 * Default sizes.
 */
#define CORE_SIZE               (0x100)
#define SEGMENT_SIZE            (0x20 * CORE_SIZE)


/*
 * Segments.
 */
#define SEGMENT_OFFSET_GLOBALS  (0 * SEGMENT_SIZE)
#define SEGMENT_OFFSET_HASHES   (1 * SEGMENT_SIZE)
#define SEGMENT_OFFSET_RNGS     (2 * SEGMENT_SIZE)
#define SEGMENT_OFFSET_CIPHERS  (3 * SEGMENT_SIZE)
#define SEGMENT_OFFSET_MATH     (4 * SEGMENT_SIZE)


/*
 * Addresses and codes common to all cores.
 */
#define ADDR_NAME0              (0x00)
#define ADDR_NAME1              (0x01)
#define ADDR_VERSION            (0x02)
#define ADDR_CTRL               (0x08)
#define CTRL_INIT               (1)
#define CTRL_NEXT               (2)
#define ADDR_STATUS             (0x09)
#define STATUS_READY            (1)
#define STATUS_VALID            (2)


/* A handy macro from cryptlib */
#ifndef bitsToBytes
#define bitsToBytes(x)          (x / 8)
#endif


/*
 * Board segment.
 * Board-level registers and communication channel registers.
 */
#define BOARD_ADDR_BASE         (SEGMENT_OFFSET_GLOBALS + (0 * CORE_SIZE))
#define BOARD_ADDR_NAME0        (BOARD_ADDR_BASE + ADDR_NAME0)
#define BOARD_ADDR_NAME1        (BOARD_ADDR_BASE + ADDR_NAME1)
#define BOARD_ADDR_VERSION      (BOARD_ADDR_BASE + ADDR_VERSION)
#define BOARD_ADDR_DUMMY        (BOARD_ADDR_BASE + 0xFF)

#define COMM_ADDR_BASE          (SEGMENT_OFFSET_GLOBALS + (1 * CORE_SIZE))
#define COMM_ADDR_NAME0         (COMM_ADDR_BASE + ADDR_NAME0)
#define COMM_ADDR_NAME1         (COMM_ADDR_BASE + ADDR_NAME1)
#define COMM_ADDR_VERSION       (COMM_ADDR_BASE + ADDR_VERSION)

/* Current name and version values */
#define NOVENA_BOARD_NAME0      "PVT1"
#define NOVENA_BOARD_NAME1      "    "
#define NOVENA_BOARD_VERSION    "0.10"

#define EIM_INTERFACE_NAME0     "eim "
#define EIM_INTERFACE_NAME1     "    "
#define EIM_INTERFACE_VERSION   "0.10"

#define I2C_INTERFACE_NAME0     "i2c "
#define I2C_INTERFACE_NAME1     "    "
#define I2C_INTERFACE_VERSION   "0.10"


/*
 * Hashes segment.
 */

/* Addresses common to all hash cores */
#define ADDR_BLOCK              (0x10)
#define ADDR_DIGEST             (0x20)      /* except SHA512 */

/* Addresses and codes for the specific hash cores */
#define SHA1_ADDR_BASE          (SEGMENT_OFFSET_HASHES + (0 * CORE_SIZE))
#define SHA1_ADDR_NAME0         (SHA1_ADDR_BASE + ADDR_NAME0)
#define SHA1_ADDR_NAME1         (SHA1_ADDR_BASE + ADDR_NAME1)
#define SHA1_ADDR_VERSION       (SHA1_ADDR_BASE + ADDR_VERSION)
#define SHA1_ADDR_CTRL          (SHA1_ADDR_BASE + ADDR_CTRL)
#define SHA1_ADDR_STATUS        (SHA1_ADDR_BASE + ADDR_STATUS)
#define SHA1_ADDR_BLOCK         (SHA1_ADDR_BASE + ADDR_BLOCK)
#define SHA1_ADDR_DIGEST        (SHA1_ADDR_BASE + ADDR_DIGEST)
#define SHA1_BLOCK_LEN          bitsToBytes(512)
#define SHA1_LENGTH_LEN         bitsToBytes(64)
#define SHA1_DIGEST_LEN         bitsToBytes(160)

#define SHA256_ADDR_BASE        (SEGMENT_OFFSET_HASHES + (1 * CORE_SIZE))
#define SHA256_ADDR_NAME0       (SHA256_ADDR_BASE + ADDR_NAME0)
#define SHA256_ADDR_NAME1       (SHA256_ADDR_BASE + ADDR_NAME1)
#define SHA256_ADDR_VERSION     (SHA256_ADDR_BASE + ADDR_VERSION)
#define SHA256_ADDR_CTRL        (SHA256_ADDR_BASE + ADDR_CTRL)
#define SHA256_ADDR_STATUS      (SHA256_ADDR_BASE + ADDR_STATUS)
#define SHA256_ADDR_BLOCK       (SHA256_ADDR_BASE + ADDR_BLOCK)
#define SHA256_ADDR_DIGEST      (SHA256_ADDR_BASE + ADDR_DIGEST)
#define SHA256_BLOCK_LEN        bitsToBytes(512)
#define SHA256_LENGTH_LEN       bitsToBytes(64)
#define SHA256_DIGEST_LEN       bitsToBytes(256)

#define SHA512_ADDR_BASE        (SEGMENT_OFFSET_HASHES + (2 * CORE_SIZE))
#define SHA512_ADDR_NAME0       (SHA512_ADDR_BASE + ADDR_NAME0)
#define SHA512_ADDR_NAME1       (SHA512_ADDR_BASE + ADDR_NAME1)
#define SHA512_ADDR_VERSION     (SHA512_ADDR_BASE + ADDR_VERSION)
#define SHA512_ADDR_CTRL        (SHA512_ADDR_BASE + ADDR_CTRL)
#define SHA512_ADDR_STATUS      (SHA512_ADDR_BASE + ADDR_STATUS)
#define SHA512_ADDR_BLOCK       (SHA512_ADDR_BASE + ADDR_BLOCK)
#define SHA512_ADDR_DIGEST      (SHA512_ADDR_BASE + 0x40)
#define SHA512_BLOCK_LEN        bitsToBytes(1024)
#define SHA512_LENGTH_LEN       bitsToBytes(128)
#define SHA512_224_DIGEST_LEN   bitsToBytes(224)
#define SHA512_256_DIGEST_LEN   bitsToBytes(256)
#define SHA384_DIGEST_LEN       bitsToBytes(384)
#define SHA512_DIGEST_LEN       bitsToBytes(512)
#define MODE_SHA_512_224        (0 << 2)
#define MODE_SHA_512_256        (1 << 2)
#define MODE_SHA_384            (2 << 2)
#define MODE_SHA_512            (3 << 2)

/* Current name and version values */
#define SHA1_NAME0              "sha1"
#define SHA1_NAME1              "    "
#define SHA1_VERSION            "0.50"

#define SHA256_NAME0            "sha2"
#define SHA256_NAME1            "-256"
#define SHA256_VERSION          "0.80"

#define SHA512_NAME0            "sha2"
#define SHA512_NAME1            "-512"
#define SHA512_VERSION          "0.80"


/*
 * TRNG segment.
 */

/* addresses and codes for the TRNG cores */
#define TRNG_ADDR_BASE          (SEGMENT_OFFSET_RNGS + (0x00 * CORE_SIZE))
#define TRNG_ADDR_NAME0         (TRNG_ADDR_BASE + ADDR_NAME0)
#define TRNG_ADDR_NAME1         (TRNG_ADDR_BASE + ADDR_NAME1)
#define TRNG_ADDR_VERSION       (TRNG_ADDR_BASE + ADDR_VERSION)
#define TRNG_ADDR_CTRL          (TRNG_ADDR_BASE + 0x10)
#define TRNG_CTRL_DISCARD       (1)
#define TRNG_CTRL_TEST_MODE     (2)
#define TRNG_ADDR_STATUS        (TRNG_ADDR_BASE + 0x11)
/* No status bits defined (yet) */
#define TRNG_ADDR_DELAY         (TRNG_ADDR_BASE + 0x13)

#define ENTROPY1_ADDR_BASE      (SEGMENT_OFFSET_RNGS + (0x05 * CORE_SIZE))
#define ENTROPY1_ADDR_NAME0     (ENTROPY1_ADDR_BASE + ADDR_NAME0)
#define ENTROPY1_ADDR_NAME1     (ENTROPY1_ADDR_BASE + ADDR_NAME1)
#define ENTROPY1_ADDR_VERSION   (ENTROPY1_ADDR_BASE + ADDR_VERSION)
#define ENTROPY1_ADDR_CTRL      (ENTROPY1_ADDR_BASE + 0x10)
#define ENTROPY1_CTRL_ENABLE    (1)
#define ENTROPY1_ADDR_STATUS    (ENTROPY1_ADDR_BASE + 0x11)
#define ENTROPY1_STATUS_VALID   (1)
#define ENTROPY1_ADDR_ENTROPY   (ENTROPY1_ADDR_BASE + 0x20)
#define ENTROPY1_ADDR_DELTA     (ENTROPY1_ADDR_BASE + 0x30)

#define ENTROPY2_ADDR_BASE      (SEGMENT_OFFSET_RNGS + (0x06 * CORE_SIZE))
#define ENTROPY2_ADDR_NAME0     (ENTROPY2_ADDR_BASE + ADDR_NAME0)
#define ENTROPY2_ADDR_NAME1     (ENTROPY2_ADDR_BASE + ADDR_NAME1)
#define ENTROPY2_ADDR_VERSION   (ENTROPY2_ADDR_BASE + ADDR_VERSION)
#define ENTROPY2_ADDR_CTRL      (ENTROPY2_ADDR_BASE + 0x10)
#define ENTROPY2_CTRL_ENABLE    (1)
#define ENTROPY2_ADDR_STATUS    (ENTROPY2_ADDR_BASE + 0x11)
#define ENTROPY2_STATUS_VALID   (1)
#define ENTROPY2_ADDR_OPA       (ENTROPY2_ADDR_BASE + 0x18)
#define ENTROPY2_ADDR_OPB       (ENTROPY2_ADDR_BASE + 0x19)
#define ENTROPY2_ADDR_ENTROPY   (ENTROPY2_ADDR_BASE + 0x20)
#define ENTROPY2_ADDR_RAW       (ENTROPY2_ADDR_BASE + 0x21)
#define ENTROPY2_ADDR_ROSC      (ENTROPY2_ADDR_BASE + 0x22)

#define MIXER_ADDR_BASE         (SEGMENT_OFFSET_RNGS + (0x0a * CORE_SIZE))
#define MIXER_ADDR_NAME0        (MIXER_ADDR_BASE + ADDR_NAME0)
#define MIXER_ADDR_NAME1        (MIXER_ADDR_BASE + ADDR_NAME1)
#define MIXER_ADDR_VERSION      (MIXER_ADDR_BASE + ADDR_VERSION)
#define MIXER_ADDR_CTRL         (MIXER_ADDR_BASE + 0x10)
#define MIXER_CTRL_ENABLE       (1)
#define MIXER_CTRL_RESTART      (2)
#define MIXER_ADDR_STATUS       (MIXER_ADDR_BASE + 0x11)
/* No status bits defined (yet) */
#define MIXER_ADDR_TIMEOUT      (MIXER_ADDR_BASE + 0x20)

#define CSPRNG_ADDR_BASE        (SEGMENT_OFFSET_RNGS + (0x0b * CORE_SIZE))
#define CSPRNG_ADDR_NAME0       (CSPRNG_ADDR_BASE + ADDR_NAME0)
#define CSPRNG_ADDR_NAME1       (CSPRNG_ADDR_BASE + ADDR_NAME1)
#define CSPRNG_ADDR_VERSION     (CSPRNG_ADDR_BASE + ADDR_VERSION)
#define CSPRNG_ADDR_CTRL        (CSPRNG_ADDR_BASE + 0x10)
#define CSPRNG_CTRL_ENABLE      (1)
#define CSPRNG_CTRL_SEED        (2)
#define CSPRNG_ADDR_STATUS      (CSPRNG_ADDR_BASE + 0x11)
#define CSPRNG_STATUS_VALID     (1)
#define CSPRNG_ADDR_RANDOM      (CSPRNG_ADDR_BASE + 0x20)
#define CSPRNG_ADDR_NROUNDS     (CSPRNG_ADDR_BASE + 0x40)
#define CSPRNG_ADDR_NBLOCKS_LO  (CSPRNG_ADDR_BASE + 0x41)
#define CSPRNG_ADDR_NBLOCKS_HI  (CSPRNG_ADDR_BASE + 0x42)

/* Current name and version values */
#define TRNG_NAME0              "trng"
#define TRNG_NAME1              "    "
#define TRNG_VERSION            "0.50"

#define AVALANCHE_ENTROPY_NAME0   "extn"
#define AVALANCHE_ENTROPY_NAME1   "oise"
#define AVALANCHE_ENTROPY_VERSION "0.10"

#define ROSC_ENTROPY_NAME0      "rosc"
#define ROSC_ENTROPY_NAME1      " ent"
#define ROSC_ENTROPY_VERSION    "0.10"

#define CSPRNG_NAME0            "cspr"
#define CSPRNG_NAME1            "ng  "
#define CSPRNG_VERSION          "0.50"


/*
 * CIPHERS segment.
 */

/* AES core */
#define AES_ADDR_BASE           (SEGMENT_OFFSET_CIPHERS + (0 * CORE_SIZE))
#define AES_ADDR_NAME0          (AES_ADDR_BASE + ADDR_NAME0)
#define AES_ADDR_NAME1          (AES_ADDR_BASE + ADDR_NAME1)
#define AES_ADDR_VERSION        (AES_ADDR_BASE + ADDR_VERSION)
#define AES_ADDR_CTRL           (AES_ADDR_BASE + ADDR_CTRL)
#define AES_ADDR_STATUS         (AES_ADDR_BASE + ADDR_STATUS)

#define AES_ADDR_CONFIG         (AES_ADDR_BASE + 0x0a)
#define AES_CONFIG_ENCDEC       (1)
#define AES_CONFIG_KEYLEN       (2)

#define AES_ADDR_KEY0           (AES_ADDR_BASE + 0x10)
#define AES_ADDR_KEY1           (AES_ADDR_BASE + 0x11)
#define AES_ADDR_KEY2           (AES_ADDR_BASE + 0x12)
#define AES_ADDR_KEY3           (AES_ADDR_BASE + 0x13)
#define AES_ADDR_KEY4           (AES_ADDR_BASE + 0x14)
#define AES_ADDR_KEY5           (AES_ADDR_BASE + 0x15)
#define AES_ADDR_KEY6           (AES_ADDR_BASE + 0x16)
#define AES_ADDR_KEY7           (AES_ADDR_BASE + 0x17)

#define AES_ADDR_BLOCK0         (AES_ADDR_BASE + 0x20)
#define AES_ADDR_BLOCK1         (AES_ADDR_BASE + 0x21)
#define AES_ADDR_BLOCK2         (AES_ADDR_BASE + 0x22)
#define AES_ADDR_BLOCK3         (AES_ADDR_BASE + 0x23)

#define AES_ADDR_RESULT0        (AES_ADDR_BASE + 0x30)
#define AES_ADDR_RESULT1        (AES_ADDR_BASE + 0x31)
#define AES_ADDR_RESULT2        (AES_ADDR_BASE + 0x32)
#define AES_ADDR_RESULT3        (AES_ADDR_BASE + 0x33)

/* Current name and version values */
#define AES_CORE_NAME0          "aes "
#define AES_CORE_NAME1          "    "
#define AES_CORE_VERSION        "0.80"


/* Chacha core */
#define CHACHA_ADDR_BASE        (SEGMENT_OFFSET_CIPHERS + (1 * CORE_SIZE))
#define CHACHA_ADDR_NAME0       (CHACHA_ADDR_BASE + ADDR_NAME0)
#define CHACHA_ADDR_NAME1       (CHACHA_ADDR_BASE + ADDR_NAME1)
#define CHACHA_ADDR_VERSION     (CHACHA_ADDR_BASE + ADDR_VERSION)
#define CHACHA_ADDR_CTRL        (CHACHA_ADDR_BASE + ADDR_CTRL)
#define CHACHA_ADDR_STATUS      (CHACHA_ADDR_BASE + ADDR_STATUS)

#define CHACHA_ADDR_KEYLEN      (CHACHA_ADDR_BASE + 0x0a)
#define CHACHA_KEYLEN           (1)

#define CHACHA_ADDR_ROUNDS      (CHACHA_ADDR_BASE + 0x0b)

#define CHACHA_ADDR_KEY0        (CHACHA_ADDR_BASE + 0x10)
#define CHACHA_ADDR_KEY1        (CHACHA_ADDR_BASE + 0x11)
#define CHACHA_ADDR_KEY2        (CHACHA_ADDR_BASE + 0x12)
#define CHACHA_ADDR_KEY3        (CHACHA_ADDR_BASE + 0x13)
#define CHACHA_ADDR_KEY4        (CHACHA_ADDR_BASE + 0x14)
#define CHACHA_ADDR_KEY5        (CHACHA_ADDR_BASE + 0x15)
#define CHACHA_ADDR_KEY6        (CHACHA_ADDR_BASE + 0x16)
#define CHACHA_ADDR_KEY7        (CHACHA_ADDR_BASE + 0x17)

#define CHACHA_ADDR_IV0         (CHACHA_ADDR_BASE + 0x20)
#define CHACHA_ADDR_IV1         (CHACHA_ADDR_BASE + 0x21)

#define CHACHA_ADDR_DATA_IN0    (CHACHA_ADDR_BASE + 0x40)
#define CHACHA_ADDR_DATA_IN1    (CHACHA_ADDR_BASE + 0x41)
#define CHACHA_ADDR_DATA_IN2    (CHACHA_ADDR_BASE + 0x42)
#define CHACHA_ADDR_DATA_IN3    (CHACHA_ADDR_BASE + 0x43)
#define CHACHA_ADDR_DATA_IN4    (CHACHA_ADDR_BASE + 0x44)
#define CHACHA_ADDR_DATA_IN5    (CHACHA_ADDR_BASE + 0x45)
#define CHACHA_ADDR_DATA_IN6    (CHACHA_ADDR_BASE + 0x46)
#define CHACHA_ADDR_DATA_IN7    (CHACHA_ADDR_BASE + 0x47)
#define CHACHA_ADDR_DATA_IN8    (CHACHA_ADDR_BASE + 0x48)
#define CHACHA_ADDR_DATA_IN9    (CHACHA_ADDR_BASE + 0x49)
#define CHACHA_ADDR_DATA_IN10   (CHACHA_ADDR_BASE + 0x4a)
#define CHACHA_ADDR_DATA_IN11   (CHACHA_ADDR_BASE + 0x4b)
#define CHACHA_ADDR_DATA_IN12   (CHACHA_ADDR_BASE + 0x4c)
#define CHACHA_ADDR_DATA_IN13   (CHACHA_ADDR_BASE + 0x4d)
#define CHACHA_ADDR_DATA_IN14   (CHACHA_ADDR_BASE + 0x4e)
#define CHACHA_ADDR_DATA_IN15   (CHACHA_ADDR_BASE + 0x4f)

#define CHACHA_ADDR_DATA_OUT0   (CHACHA_ADDR_BASE + 0x80)
#define CHACHA_ADDR_DATA_OUT1   (CHACHA_ADDR_BASE + 0x81)
#define CHACHA_ADDR_DATA_OUT2   (CHACHA_ADDR_BASE + 0x82)
#define CHACHA_ADDR_DATA_OUT3   (CHACHA_ADDR_BASE + 0x83)
#define CHACHA_ADDR_DATA_OUT4   (CHACHA_ADDR_BASE + 0x84)
#define CHACHA_ADDR_DATA_OUT5   (CHACHA_ADDR_BASE + 0x85)
#define CHACHA_ADDR_DATA_OUT6   (CHACHA_ADDR_BASE + 0x86)
#define CHACHA_ADDR_DATA_OUT7   (CHACHA_ADDR_BASE + 0x87)
#define CHACHA_ADDR_DATA_OUT8   (CHACHA_ADDR_BASE + 0x88)
#define CHACHA_ADDR_DATA_OUT9   (CHACHA_ADDR_BASE + 0x89)
#define CHACHA_ADDR_DATA_OUT10  (CHACHA_ADDR_BASE + 0x8a)
#define CHACHA_ADDR_DATA_OUT11  (CHACHA_ADDR_BASE + 0x8b)
#define CHACHA_ADDR_DATA_OUT12  (CHACHA_ADDR_BASE + 0x8c)
#define CHACHA_ADDR_DATA_OUT13  (CHACHA_ADDR_BASE + 0x8d)
#define CHACHA_ADDR_DATA_OUT14  (CHACHA_ADDR_BASE + 0x8e)
#define CHACHA_ADDR_DATA_OUT15  (CHACHA_ADDR_BASE + 0x8f)

/* Current name and version values */
#define CHACHA_NAME0            "chac"
#define CHACHA_NAME1            "ha  "
#define CHACHA_VERSION          "0.80"


/*
 * MATH segment.
 */

/* Modexp core */
#define MODEXP_ADDR_BASE        (SEGMENT_OFFSET_MATH + (0x00 * CORE_SIZE))
#define MODEXP_ADDR_NAME0       (MODEXP_ADDR_BASE + ADDR_NAME0)
#define MODEXP_ADDR_NAME1       (MODEXP_ADDR_BASE + ADDR_NAME1)
#define MODEXP_ADDR_VERSION     (MODEXP_ADDR_BASE + ADDR_VERSION)
#define MODEXP_ADDR_CTRL        (MODEXP_ADDR_BASE + ADDR_CTRL)
#define MODEXP_CTRL_INIT_BIT    (1)
#define MODEXP_CTRL_NEXT_BIT    (2)
#define MODEXP_ADDR_STATUS      (MODEXP_ADDR_BASE + ADDR_STATUS)

#define MODEXP_ADDR_DELAY       (MODEXP_ADDR_BASE + 0x13)
#define MODEXP_STATUS_READY     (1)

#define MODEXP_MODULUS_LENGTH   (MODEXP_ADDR_BASE + 0x20)
#define MODEXP_EXPONENT_LENGTH  (MODEXP_ADDR_BASE + 0x21)
#define MODEXP_LENGTH           (MODEXP_ADDR_BASE + 0x22)

#define MODEXP_MODULUS_PTR_RST  (MODEXP_ADDR_BASE + 0x30)
#define MODEXP_MODULUS_DATA     (MODEXP_ADDR_BASE + 0x31)

#define MODEXP_EXPONENT_PTR_RST (MODEXP_ADDR_BASE + 0x40)
#define MODEXP_EXPONENT_DATA    (MODEXP_ADDR_BASE + 0x41)

#define MODEXP_MESSAGE_PTR_RST  (MODEXP_ADDR_BASE + 0x50)
#define MODEXP_MESSAGE_DATA     (MODEXP_ADDR_BASE + 0x51)

#define MODEXP_RESULT_PTR_RST   (MODEXP_ADDR_BASE + 0x60)
#define MODEXP_RESULT_DATA      (MODEXP_ADDR_BASE + 0x61)

#define MODEXP_NAME0            "mode"
#define MODEXP_NAME1            "xp  "
#define MODEXP_VERSION          "0.51"


/*
 * C API error codes.  Defined in this form so we can keep the tokens
 * and error strings together.  See errorstrings.c.
 */

#define HAL_ERROR_LIST \
  DEFINE_HAL_ERROR(HAL_OK,                              "No error")                                     \
  DEFINE_HAL_ERROR(HAL_ERROR_BAD_ARGUMENTS,             "Bad arguments given")                          \
  DEFINE_HAL_ERROR(HAL_ERROR_UNSUPPORTED_KEY,           "Unsupported key type or key length")           \
  DEFINE_HAL_ERROR(HAL_ERROR_IO_SETUP_FAILED,           "Could not set up I/O with FPGA")               \
  DEFINE_HAL_ERROR(HAL_ERROR_IO_TIMEOUT,                "I/O with FPGA timed out")                      \
  DEFINE_HAL_ERROR(HAL_ERROR_IO_UNEXPECTED,             "Unexpected response from FPGA")                \
  DEFINE_HAL_ERROR(HAL_ERROR_IO_OS_ERROR,               "Operating system error talking to FPGA")       \
  DEFINE_HAL_ERROR(HAL_ERROR_IO_BAD_COUNT,              "Bad byte count")                               \
  DEFINE_HAL_ERROR(HAL_ERROR_CSPRNG_BROKEN,             "CSPRNG is returning nonsense")                 \
  DEFINE_HAL_ERROR(HAL_ERROR_KEYWRAP_BAD_MAGIC,         "Bad magic number while unwrapping key")        \
  DEFINE_HAL_ERROR(HAL_ERROR_KEYWRAP_BAD_LENGTH,        "Length out of range while unwrapping key")     \
  DEFINE_HAL_ERROR(HAL_ERROR_KEYWRAP_BAD_PADDING,       "Non-zero padding detected unwrapping key")     \
  DEFINE_HAL_ERROR(HAL_ERROR_IMPOSSIBLE,                "\"Impossible\" error")                         \
  DEFINE_HAL_ERROR(HAL_ERROR_ALLOCATION_FAILURE,        "Memory allocation failed")                     \
  DEFINE_HAL_ERROR(HAL_ERROR_RESULT_TOO_LONG,           "Result too long for buffer")                   \
  DEFINE_HAL_ERROR(HAL_ERROR_ASN1_PARSE_FAILED,         "ASN.1 parse failed")                           \
  END_OF_HAL_ERROR_LIST

/* Marker to forestall silly line continuation errors */
#define END_OF_HAL_ERROR_LIST

/* Define the error code enum here.  See errorstrings.c for the text strings. */
#define DEFINE_HAL_ERROR(_code_,_text_)  _code_,
typedef enum { HAL_ERROR_LIST N_HAL_ERRORS } hal_error_t;
#undef  DEFINE_HAL_ERROR

/*
 * Public functions.
 */

#include <stdint.h>
#include <sys/types.h>

extern const char *hal_error_string(const hal_error_t err);

/*
 * Public I/O functions.
 */

extern void hal_io_set_debug(int onoff);
extern hal_error_t hal_io_write(off_t offset, const uint8_t *buf, size_t len);
extern hal_error_t hal_io_read(off_t offset, uint8_t *buf, size_t len);
extern hal_error_t hal_io_expected(off_t offset, const uint8_t *expected, size_t len);
extern hal_error_t hal_io_init(off_t offset);
extern hal_error_t hal_io_next(off_t offset);
extern hal_error_t hal_io_wait(off_t offset, uint8_t status, int *count);
extern hal_error_t hal_io_wait_ready(off_t offset);
extern hal_error_t hal_io_wait_valid(off_t offset);

/*
 * Higher level public API.
 */

/*
 * Get random bytes from the CSPRNG.
 */

extern hal_error_t hal_get_random(void *buffer, const size_t length);

/*
 * Hash and HMAC API.
 */

/*
 * Longest hash block and digest we support at the moment.
 */

#define HAL_MAX_HASH_BLOCK_LENGTH       SHA512_BLOCK_LEN
#define HAL_MAX_HASH_DIGEST_LENGTH      SHA512_DIGEST_LEN

/*
 * Public information about a digest algorithm.
 *
 * The _state_length values in the descriptor and the typed opaque
 * pointers in the API are all intended to hide internal details of
 * the implementation while making memory allocation the caller's
 * problem.
 */

typedef struct {
  size_t block_length;
  size_t digest_length;
  size_t hash_state_length;
  size_t hmac_state_length;
  const uint8_t * const digest_algorithm_id;
  size_t digest_algorithm_id_length;
  const void *driver;
} hal_hash_descriptor_t;

/*
 * Typed opaque pointers to internal state.
 */

typedef struct { void *state; } hal_hash_state_t;
typedef struct { void *state; } hal_hmac_state_t;

/*
 * Supported digest algorithms.  These are one-element arrays so that
 * they can be used as constant pointers.
 */

extern const hal_hash_descriptor_t hal_hash_sha1[1];
extern const hal_hash_descriptor_t hal_hash_sha256[1];
extern const hal_hash_descriptor_t hal_hash_sha512_224[1];
extern const hal_hash_descriptor_t hal_hash_sha512_256[1];
extern const hal_hash_descriptor_t hal_hash_sha384[1];
extern const hal_hash_descriptor_t hal_hash_sha512[1];

/*
 * Hash and HMAC functions.
 */

extern void hal_hash_set_debug(int onoff);

extern hal_error_t hal_hash_core_present(const hal_hash_descriptor_t * const descriptor);

extern hal_error_t hal_hash_initialize(const hal_hash_descriptor_t * const descriptor,
                                       hal_hash_state_t *state,
                                       void *state_buffer, const size_t state_length);

extern hal_error_t hal_hash_update(const hal_hash_state_t state,
                                   const uint8_t * data, const size_t length);

extern hal_error_t hal_hash_finalize(const hal_hash_state_t state,
                                     uint8_t *digest, const size_t length);

extern hal_error_t hal_hmac_initialize(const hal_hash_descriptor_t * const descriptor,
                                       hal_hmac_state_t *state,
                                       void *state_buffer, const size_t state_length,
                                       const uint8_t * const key, const size_t key_length);

extern hal_error_t hal_hmac_update(const hal_hmac_state_t state,
                                   const uint8_t * data, const size_t length);

extern hal_error_t hal_hmac_finalize(const hal_hmac_state_t state,
                                     uint8_t *hmac, const size_t length);

/*
 * AES key wrap functions.
 */

extern hal_error_t hal_aes_keywrap(const uint8_t *kek, const size_t kek_length,
                                   const uint8_t *plaintext, const size_t plaintext_length,
                                   uint8_t *cyphertext, size_t *ciphertext_length);

extern hal_error_t hal_aes_keyunwrap(const uint8_t *kek, const size_t kek_length,
                                     const uint8_t *ciphertext, const size_t ciphertext_length,
                                     unsigned char *plaintext, size_t *plaintext_length);

extern size_t hal_aes_keywrap_ciphertext_length(const size_t plaintext_length);

/*
 * PBKDF2 function.  Uses HMAC with the specified digest algorithm as
 * the pseudo-random function (PRF).
 */

extern hal_error_t hal_pbkdf2(const hal_hash_descriptor_t * const descriptor,
			      const uint8_t * const password, const size_t password_length,
			      const uint8_t * const salt,     const size_t salt_length,
			      uint8_t       * derived_key,    const size_t derived_key_length,
			      unsigned iterations_desired);

/*
 * Modular exponentiation.
 */

extern void hal_modexp_set_debug(const int onoff);

extern hal_error_t hal_modexp(const uint8_t * const msg, const size_t msg_len, /* Message */
                              const uint8_t * const exp, const size_t exp_len, /* Exponent */
                              const uint8_t * const mod, const size_t mod_len, /* Modulus */
                              uint8_t * result, const size_t result_len);


/*
 * RSA.
 */

typedef enum { HAL_RSA_PRIVATE, HAL_RSA_PUBLIC } hal_rsa_key_type_t;

typedef struct { void *key; } hal_rsa_key_t;

extern const size_t hal_rsa_key_t_size;

extern void hal_rsa_set_debug(const int onoff);

extern void hal_rsa_set_blinding(const int onoff);

extern hal_error_t hal_rsa_key_load_private(hal_rsa_key_t *key,
                                            void *keybuf, const size_t keybuf_len,
                                            const uint8_t * const n,  const size_t n_len,
                                            const uint8_t * const e,  const size_t e_len,
                                            const uint8_t * const d,  const size_t d_len,
                                            const uint8_t * const p,  const size_t p_len,
                                            const uint8_t * const q,  const size_t q_len,
                                            const uint8_t * const u,  const size_t u_len,
                                            const uint8_t * const dP, const size_t dP_len,
                                            const uint8_t * const dQ, const size_t dQ_len);

extern hal_error_t hal_rsa_key_load_public(hal_rsa_key_t *key,
                                           void *keybuf, const size_t keybuf_len,
                                           const uint8_t * const n,  const size_t n_len,
                                           const uint8_t * const e,  const size_t e_len);

extern hal_error_t hal_rsa_key_get_type(hal_rsa_key_t key,
                                        hal_rsa_key_type_t *key_type);

extern hal_error_t hal_rsa_key_get_modulus(hal_rsa_key_t key,
                                           uint8_t *modulus,
                                           size_t *modulus_len,
                                           const size_t modulus_max);

extern hal_error_t hal_rsa_key_get_public_exponent(hal_rsa_key_t key,
                                                   uint8_t *public_exponent,
                                                   size_t *public_exponent_len,
                                                   const size_t public_exponent_max);

extern void hal_rsa_key_clear(hal_rsa_key_t key);

extern hal_error_t hal_rsa_encrypt(hal_rsa_key_t key,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * output, const size_t output_len);

extern hal_error_t hal_rsa_decrypt(hal_rsa_key_t key,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * output, const size_t output_len);

extern hal_error_t hal_rsa_key_gen(hal_rsa_key_t *key,
                                   void *keybuf, const size_t keybuf_len,
                                   const unsigned key_length,
                                   const uint8_t * const public_exponent, const size_t public_exponent_len);

extern hal_error_t hal_rsa_key_to_der(hal_rsa_key_t key,
                                      uint8_t *der, size_t *der_len, const size_t der_max);

extern size_t hal_rsa_key_to_der_len(hal_rsa_key_t key);

extern hal_error_t hal_rsa_key_from_der(hal_rsa_key_t *key,
                                        void *keybuf, const size_t keybuf_len,
                                        const uint8_t * const der, const size_t der_len);

#endif /* _HAL_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */