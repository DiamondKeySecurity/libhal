/*
 * verilog_constants.h
 * -------------------
 * Magic constants which must match Verilog code, mostly bus addresses.
 *
 * In the long run, this should be generated by a script which pulls
 * these numbers out of the Verilog source code.  For the moment, it's
 * hand-edited.
 *
 * Authors: Joachim Strombergson, Paul Selkirk, Rob Austein
 * Copyright (c) 2015-2016, NORDUnet A/S All rights reserved.
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

#ifndef _VERILOG_CONSTANTS_H_
#define _VERILOG_CONSTANTS_H_

/*
 * Common to all cores.
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

/*
 * Hash cores.
 */

#define SHA1_ADDR_BLOCK         (0x10)
#define SHA1_ADDR_DIGEST        (0x20)
#define SHA1_BLOCK_LEN          bitsToBytes(512)
#define SHA1_LENGTH_LEN         bitsToBytes(64)
#define SHA1_DIGEST_LEN         bitsToBytes(160)

#define SHA256_ADDR_BLOCK       (0x10)
#define SHA256_ADDR_DIGEST      (0x20)
#define SHA256_BLOCK_LEN        bitsToBytes(512)
#define SHA256_LENGTH_LEN       bitsToBytes(64)
#define SHA224_DIGEST_LEN       bitsToBytes(224)
#define SHA256_DIGEST_LEN       bitsToBytes(256)
#define SHA256_MODE_SHA_224     (0 << 2)
#define SHA256_MODE_SHA_256     (1 << 2)
#define SHA256_MODE_MASK        (1 << 2)

#define SHA512_ADDR_BLOCK       (0x10)
#define SHA512_ADDR_DIGEST      (0x40)
#define SHA512_BLOCK_LEN        bitsToBytes(1024)
#define SHA512_LENGTH_LEN       bitsToBytes(128)
#define SHA512_224_DIGEST_LEN   bitsToBytes(224)
#define SHA512_256_DIGEST_LEN   bitsToBytes(256)
#define SHA384_DIGEST_LEN       bitsToBytes(384)
#define SHA512_DIGEST_LEN       bitsToBytes(512)
#define SHA512_MODE_SHA_512_224 (0 << 2)
#define SHA512_MODE_SHA_512_256 (1 << 2)
#define SHA512_MODE_SHA_384     (2 << 2)
#define SHA512_MODE_SHA_512     (3 << 2)
#define SHA512_MODE_MASK        (3 << 2)

/*
 * RNG cores.
 */

#define TRNG_CTRL_DISCARD       (1)
#define TRNG_CTRL_TEST_MODE     (2)
/* No status bits defined (yet) */
#define TRNG_ADDR_DELAY         (0x13)

#define ENTROPY1_CTRL_ENABLE    (1)
#define ENTROPY1_STATUS_VALID   (2)
#define ENTROPY1_ADDR_ENTROPY   (0x20)
#define ENTROPY1_ADDR_DELTA     (0x30)

#define ENTROPY2_CTRL_ENABLE    (1)
#define ENTROPY2_STATUS_VALID   (2)
#define ENTROPY2_ADDR_OPA       (0x18)
#define ENTROPY2_ADDR_OPB       (0x19)
#define ENTROPY2_ADDR_ENTROPY   (0x20)
#define ENTROPY2_ADDR_RAW       (0x21)
#define ENTROPY2_ADDR_ROSC      (0x22)

#define MIXER_CTRL_ENABLE       (1)
#define MIXER_CTRL_RESTART      (2)
/* No status bits defined (yet) */
#define MIXER_ADDR_TIMEOUT      (0x20)

#define CSPRNG_CTRL_ENABLE      (1)
#define CSPRNG_CTRL_SEED        (2)
#define CSPRNG_STATUS_VALID     (2)
#define CSPRNG_ADDR_RANDOM      (0x20)
#define CSPRNG_ADDR_NROUNDS     (0x40)
#define CSPRNG_ADDR_NBLOCKS_LO  (0x41)
#define CSPRNG_ADDR_NBLOCKS_HI  (0x42)

/*
 * Cipher cores.
 */

#define AES_ADDR_CONFIG         (0x0a)
#define AES_CONFIG_ENCDEC       (1)
#define AES_CONFIG_KEYLEN       (2)

#define AES_ADDR_KEY0           (0x10)
#define AES_ADDR_KEY1           (0x11)
#define AES_ADDR_KEY2           (0x12)
#define AES_ADDR_KEY3           (0x13)
#define AES_ADDR_KEY4           (0x14)
#define AES_ADDR_KEY5           (0x15)
#define AES_ADDR_KEY6           (0x16)
#define AES_ADDR_KEY7           (0x17)

#define AES_ADDR_BLOCK0         (0x20)
#define AES_ADDR_BLOCK1         (0x21)
#define AES_ADDR_BLOCK2         (0x22)
#define AES_ADDR_BLOCK3         (0x23)

#define AES_ADDR_RESULT0        (0x30)
#define AES_ADDR_RESULT1        (0x31)
#define AES_ADDR_RESULT2        (0x32)
#define AES_ADDR_RESULT3        (0x33)

/* Chacha core */

#define CHACHA_ADDR_KEYLEN      (0x0a)
#define CHACHA_KEYLEN           (1)

#define CHACHA_ADDR_ROUNDS      (0x0b)

#define CHACHA_ADDR_KEY0        (0x10)
#define CHACHA_ADDR_KEY1        (0x11)
#define CHACHA_ADDR_KEY2        (0x12)
#define CHACHA_ADDR_KEY3        (0x13)
#define CHACHA_ADDR_KEY4        (0x14)
#define CHACHA_ADDR_KEY5        (0x15)
#define CHACHA_ADDR_KEY6        (0x16)
#define CHACHA_ADDR_KEY7        (0x17)

#define CHACHA_ADDR_IV0         (0x20)
#define CHACHA_ADDR_IV1         (0x21)

#define CHACHA_ADDR_DATA_IN0    (0x40)
#define CHACHA_ADDR_DATA_IN1    (0x41)
#define CHACHA_ADDR_DATA_IN2    (0x42)
#define CHACHA_ADDR_DATA_IN3    (0x43)
#define CHACHA_ADDR_DATA_IN4    (0x44)
#define CHACHA_ADDR_DATA_IN5    (0x45)
#define CHACHA_ADDR_DATA_IN6    (0x46)
#define CHACHA_ADDR_DATA_IN7    (0x47)
#define CHACHA_ADDR_DATA_IN8    (0x48)
#define CHACHA_ADDR_DATA_IN9    (0x49)
#define CHACHA_ADDR_DATA_IN10   (0x4a)
#define CHACHA_ADDR_DATA_IN11   (0x4b)
#define CHACHA_ADDR_DATA_IN12   (0x4c)
#define CHACHA_ADDR_DATA_IN13   (0x4d)
#define CHACHA_ADDR_DATA_IN14   (0x4e)
#define CHACHA_ADDR_DATA_IN15   (0x4f)

#define CHACHA_ADDR_DATA_OUT0   (0x80)
#define CHACHA_ADDR_DATA_OUT1   (0x81)
#define CHACHA_ADDR_DATA_OUT2   (0x82)
#define CHACHA_ADDR_DATA_OUT3   (0x83)
#define CHACHA_ADDR_DATA_OUT4   (0x84)
#define CHACHA_ADDR_DATA_OUT5   (0x85)
#define CHACHA_ADDR_DATA_OUT6   (0x86)
#define CHACHA_ADDR_DATA_OUT7   (0x87)
#define CHACHA_ADDR_DATA_OUT8   (0x88)
#define CHACHA_ADDR_DATA_OUT9   (0x89)
#define CHACHA_ADDR_DATA_OUT10  (0x8a)
#define CHACHA_ADDR_DATA_OUT11  (0x8b)
#define CHACHA_ADDR_DATA_OUT12  (0x8c)
#define CHACHA_ADDR_DATA_OUT13  (0x8d)
#define CHACHA_ADDR_DATA_OUT14  (0x8e)
#define CHACHA_ADDR_DATA_OUT15  (0x8f)

/*
 * Math cores.
 */

/*
 * ModExpS6 core.  MODEXPS6_OPERAND_BITS is size in bits of largest
 * supported modulus.
 */

#define MODEXPS6_OPERAND_BITS           (4096)
#define MODEXPS6_OPERAND_WORDS          (MODEXPS6_OPERAND_BITS / 32)
#define MODEXPS6_ADDR_REGISTERS         (0 * MODEXPS6_OPERAND_WORDS)
#define MODEXPS6_ADDR_OPERANDS          (4 * MODEXPS6_OPERAND_WORDS)
#define MODEXPS6_ADDR_MODE              (MODEXPS6_ADDR_REGISTERS + 0x10)
#define MODEXPS6_ADDR_MODULUS_WIDTH     (MODEXPS6_ADDR_REGISTERS + 0x11)
#define MODEXPS6_ADDR_EXPONENT_WIDTH    (MODEXPS6_ADDR_REGISTERS + 0x12)
#define MODEXPS6_ADDR_MODULUS           (MODEXPS6_ADDR_OPERANDS + 0 * MODEXPS6_OPERAND_WORDS)
#define MODEXPS6_ADDR_MESSAGE           (MODEXPS6_ADDR_OPERANDS + 1 * MODEXPS6_OPERAND_WORDS)
#define MODEXPS6_ADDR_EXPONENT          (MODEXPS6_ADDR_OPERANDS + 2 * MODEXPS6_OPERAND_WORDS)
#define MODEXPS6_ADDR_RESULT            (MODEXPS6_ADDR_OPERANDS + 3 * MODEXPS6_OPERAND_WORDS)

/*
 * ModExpA7 core.  MODEXPA7_OPERAND_BITS is size in bits of largest
 * supported modulus.
 */

#define MODEXPA7_OPERAND_BITS           (4096)
#define MODEXPA7_OPERAND_WORDS          (MODEXPA7_OPERAND_BITS / 32)
#define MODEXPA7_ADDR_REGISTERS         (0 * MODEXPA7_OPERAND_WORDS)
#define MODEXPA7_ADDR_OPERANDS          (4 * MODEXPA7_OPERAND_WORDS)
#define MODEXPA7_ADDR_MODE              (MODEXPA7_ADDR_REGISTERS + 0x10)
#define MODEXPA7_ADDR_MODULUS_WIDTH     (MODEXPA7_ADDR_REGISTERS + 0x11)
#define MODEXPA7_ADDR_EXPONENT_WIDTH    (MODEXPA7_ADDR_REGISTERS + 0x12)
#define MODEXPA7_ADDR_MODULUS           (MODEXPA7_ADDR_OPERANDS + 0 * MODEXPA7_OPERAND_WORDS)
#define MODEXPA7_ADDR_MESSAGE           (MODEXPA7_ADDR_OPERANDS + 1 * MODEXPA7_OPERAND_WORDS)
#define MODEXPA7_ADDR_EXPONENT          (MODEXPA7_ADDR_OPERANDS + 2 * MODEXPA7_OPERAND_WORDS)
#define MODEXPA7_ADDR_RESULT            (MODEXPA7_ADDR_OPERANDS + 3 * MODEXPA7_OPERAND_WORDS)

/*
 * Utility cores.
 */

/*
 * Master Key Memory Interface core.
 */
#define MKMIF_ADDR_CTRL         ADDR_CTRL
#define MKMIF_CTRL_CMD_READ     (0x01)
#define MKMIF_CTRL_CMD_WRITE    (0x02)
#define MKMIF_CTRL_CMD_INIT     (0x04)
#define MKMIF_ADDR_SCLK_DIV     (0x0a)
#define MKMIF_ADDR_EMEM_ADDR    (0x10)
#define MKMIF_ADDR_EMEM_DATA    (0x20)

#endif /* _VERILOG_CONSTANTS_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
