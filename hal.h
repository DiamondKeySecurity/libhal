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

#ifndef _HAL_H_
#define _HAL_H_

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>

/*
 * A handy macro from cryptlib.
 */
#ifndef bitsToBytes
#define bitsToBytes(x)          ((x) / 8)
#endif

/*
 * Current name and version values for crypto cores.
 *
 * Should these even be here?  Dunno.
 * Should the versions be here even if the names should be?
 */

#define NOVENA_BOARD_NAME	"PVT1    "
#define NOVENA_BOARD_VERSION    "0.10"

#define EIM_INTERFACE_NAME      "eim     "
#define EIM_INTERFACE_VERSION   "0.10"

#define I2C_INTERFACE_NAME      "i2c     "
#define I2C_INTERFACE_VERSION   "0.10"

#define TRNG_NAME               "trng    "
#define TRNG_VERSION            "0.51"

#define AVALANCHE_ENTROPY_NAME	"extnoise"
#define AVALANCHE_ENTROPY_VERSION "0.10"

#define ROSC_ENTROPY_NAME       "rosc ent"
#define ROSC_ENTROPY_VERSION    "0.10"

#define CSPRNG_NAME             "csprng  "
#define CSPRNG_VERSION          "0.50"

#define SHA1_NAME               "sha1    "
#define SHA1_VERSION            "0.50"

#define SHA256_NAME             "sha2-256"
#define SHA256_VERSION          "0.81"

#define SHA512_NAME             "sha2-512"
#define SHA512_VERSION          "0.80"

#define AES_CORE_NAME           "aes     "
#define AES_CORE_VERSION        "0.80"

#define CHACHA_NAME             "chacha  "
#define CHACHA_VERSION          "0.80"

#define MODEXPS6_NAME		"modexps6"
#define MODEXPS6_VERSION	"0.10"

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
  DEFINE_HAL_ERROR(HAL_ERROR_KEY_NOT_ON_CURVE,          "EC key is not on its purported curve")         \
  DEFINE_HAL_ERROR(HAL_ERROR_INVALID_SIGNATURE,         "Invalid signature")                            \
  DEFINE_HAL_ERROR(HAL_ERROR_CORE_NOT_FOUND,            "Requested core not found")                     \
  DEFINE_HAL_ERROR(HAL_ERROR_KEYSTORE_ACCESS,           "Could not access keystore")                    \
  DEFINE_HAL_ERROR(HAL_ERROR_KEY_NOT_FOUND,             "Key not found")                                \
  DEFINE_HAL_ERROR(HAL_ERROR_KEY_NAME_IN_USE,           "Key name in use")                              \
  DEFINE_HAL_ERROR(HAL_ERROR_NO_KEY_SLOTS_AVAILABLE,    "No key slots available")                       \
  DEFINE_HAL_ERROR(HAL_ERROR_PIN_INCORRECT,             "PIN incorrect")                                \
  DEFINE_HAL_ERROR(HAL_ERROR_NO_CLIENT_SLOTS_AVAILABLE, "No client slots available")                    \
  DEFINE_HAL_ERROR(HAL_ERROR_FORBIDDEN,                 "Forbidden")                                    \
  DEFINE_HAL_ERROR(HAL_ERROR_RPC_TRANSPORT,             "RPC transport error")                          \
  END_OF_HAL_ERROR_LIST

/* Marker to forestall silly line continuation errors */
#define END_OF_HAL_ERROR_LIST

/* Define the error code enum here.  See errorstrings.c for the text strings. */
#define DEFINE_HAL_ERROR(_code_,_text_)  _code_,
typedef enum { HAL_ERROR_LIST N_HAL_ERRORS } hal_error_t;
#undef  DEFINE_HAL_ERROR

/*
 * Error translation.
 */

extern const char *hal_error_string(const hal_error_t err);

/*
 * Very low level public API for working directly with crypto cores.
 */

/*
 * Typedef to isolate code from our current choice of representation
 * for a Cryptech bus address.
 */

typedef off_t hal_addr_t;

/*
 * Opaque structure representing a core.
 */

typedef struct hal_core hal_core_t;

/*
 * Public I/O functions.
 */

extern void hal_io_set_debug(int onoff);
extern hal_error_t hal_io_write(const hal_core_t *core, hal_addr_t offset, const uint8_t *buf, size_t len);
extern hal_error_t hal_io_read(const hal_core_t *core, hal_addr_t offset, uint8_t *buf, size_t len);
extern hal_error_t hal_io_init(const hal_core_t *core);
extern hal_error_t hal_io_next(const hal_core_t *core);
extern hal_error_t hal_io_wait(const hal_core_t *core, uint8_t status, int *count);
extern hal_error_t hal_io_wait_ready(const hal_core_t *core);
extern hal_error_t hal_io_wait_valid(const hal_core_t *core);

/*
 * Core management functions.
 *
 * Given our druthers, we'd handle public information about a core
 * using the opaque type and individual access methods, but C's
 * insistence on discarding array bounds information makes
 * non-delimited character arrays problematic unless we wrap them in a
 * structure.
 */

typedef struct {
  char name[8];
  char version[4];
  hal_addr_t base;
} hal_core_info_t;

extern const hal_core_t *hal_core_find(const char *name, const hal_core_t *core);
extern const hal_core_info_t *hal_core_info(const hal_core_t *core);
extern hal_error_t hal_core_check_name(const hal_core_t **core, const char *name);
extern hal_addr_t hal_core_base(const hal_core_t *core);
extern const hal_core_t * hal_core_iterate(const hal_core_t *core);

/*
 * Slightly higher level public API, still working directly with cores.
 */

/*
 * Get random bytes from the CSPRNG.
 */

extern hal_error_t hal_get_random(const hal_core_t *core, void *buffer, const size_t length);

/*
 * Hash and HMAC API.
 */

/*
 * Opaque driver structure for digest algorithms.
 */

typedef struct hal_hash_driver hal_hash_driver_t;

/*
 * Public information about a digest algorithm.
 *
 * The _state_length values in the descriptor and the typed opaque
 * pointers in the API are all intended to hide internal details of
 * the implementation while making memory allocation the caller's
 * problem.
 */

typedef enum {
  hal_digest_algorithm_sha1,
  hal_digest_algorithm_sha256,
  hal_digest_algorithm_sha512_224,
  hal_digest_algorithm_sha512_256,
  hal_digest_algorithm_sha384,
  hal_digest_algorithm_sha512
} hal_digest_algorithm_t;

typedef struct {
  hal_digest_algorithm_t digest_algorithm;
  size_t block_length;
  size_t digest_length;
  size_t hash_state_length;
  size_t hmac_state_length;
  const uint8_t * const digest_algorithm_id;
  size_t digest_algorithm_id_length;
  const hal_hash_driver_t *driver;
  char core_name[8];
  unsigned can_restore_state : 1;
} hal_hash_descriptor_t;

/*
 * Opaque structures for internal state.
 */

typedef struct hal_hash_state hal_hash_state_t;
typedef struct hal_hmac_state hal_hmac_state_t;

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

extern hal_error_t hal_hash_initialize(const hal_core_t *core,
                                       const hal_hash_descriptor_t * const descriptor,
                                       hal_hash_state_t **state,
                                       void *state_buffer, const size_t state_length);

extern hal_error_t hal_hash_update(hal_hash_state_t *state,
                                   const uint8_t * data, const size_t length);

extern hal_error_t hal_hash_finalize(hal_hash_state_t *state,
                                     uint8_t *digest, const size_t length);

extern hal_error_t hal_hmac_initialize(const hal_core_t *core,
                                       const hal_hash_descriptor_t * const descriptor,
                                       hal_hmac_state_t **state,
                                       void *state_buffer, const size_t state_length,
                                       const uint8_t * const key, const size_t key_length);

extern hal_error_t hal_hmac_update(hal_hmac_state_t *state,
                                   const uint8_t * data, const size_t length);

extern hal_error_t hal_hmac_finalize(hal_hmac_state_t *state,
                                     uint8_t *hmac, const size_t length);
extern void hal_hash_cleanup(hal_hash_state_t **state);

extern void hal_hmac_cleanup(hal_hmac_state_t **state);

extern const hal_hash_descriptor_t *hal_hash_get_descriptor(const hal_hash_state_t * const state);

extern const hal_hash_descriptor_t *hal_hmac_get_descriptor(const hal_hmac_state_t * const state);

/*
 * AES key wrap functions.
 */

extern hal_error_t hal_aes_keywrap(const hal_core_t *core,
                                   const uint8_t *kek, const size_t kek_length,
                                   const uint8_t *plaintext, const size_t plaintext_length,
                                   uint8_t *cyphertext, size_t *ciphertext_length);

extern hal_error_t hal_aes_keyunwrap(const hal_core_t *core,
                                     const uint8_t *kek, const size_t kek_length,
                                     const uint8_t *ciphertext, const size_t ciphertext_length,
                                     unsigned char *plaintext, size_t *plaintext_length);

extern size_t hal_aes_keywrap_ciphertext_length(const size_t plaintext_length);

/*
 * PBKDF2 function.  Uses HMAC with the specified digest algorithm as
 * the pseudo-random function (PRF).
 */

extern hal_error_t hal_pbkdf2(const hal_core_t *core,
                              const hal_hash_descriptor_t * const descriptor,
			      const uint8_t * const password, const size_t password_length,
			      const uint8_t * const salt,     const size_t salt_length,
			      uint8_t       * derived_key,    const size_t derived_key_length,
			      unsigned iterations_desired);

/*
 * Modular exponentiation.
 */

extern void hal_modexp_set_debug(const int onoff);

extern hal_error_t hal_modexp(const hal_core_t *core,
                              const uint8_t * const msg, const size_t msg_len, /* Message */
                              const uint8_t * const exp, const size_t exp_len, /* Exponent */
                              const uint8_t * const mod, const size_t mod_len, /* Modulus */
                              uint8_t * result, const size_t result_len);


/*
 * Key types and curves, used in various places.
 */

typedef enum {
  HAL_KEY_TYPE_NONE,
  HAL_KEY_TYPE_RSA_PRIVATE,
  HAL_KEY_TYPE_RSA_PUBLIC,
  HAL_KEY_TYPE_EC_PRIVATE,
  HAL_KEY_TYPE_EC_PUBLIC
} hal_key_type_t;

typedef enum {
  HAL_CURVE_NONE,
  HAL_CURVE_P256,
  HAL_CURVE_P384,
  HAL_CURVE_P521
} hal_curve_name_t;

/*
 * RSA.
 */

typedef struct hal_rsa_key hal_rsa_key_t;

extern const size_t hal_rsa_key_t_size;

extern void hal_rsa_set_debug(const int onoff);

extern void hal_rsa_set_blinding(const int onoff);

extern hal_error_t hal_rsa_key_load_private(hal_rsa_key_t **key,
                                            void *keybuf, const size_t keybuf_len,
                                            const uint8_t * const n,  const size_t n_len,
                                            const uint8_t * const e,  const size_t e_len,
                                            const uint8_t * const d,  const size_t d_len,
                                            const uint8_t * const p,  const size_t p_len,
                                            const uint8_t * const q,  const size_t q_len,
                                            const uint8_t * const u,  const size_t u_len,
                                            const uint8_t * const dP, const size_t dP_len,
                                            const uint8_t * const dQ, const size_t dQ_len);

extern hal_error_t hal_rsa_key_load_public(hal_rsa_key_t **key,
                                           void *keybuf, const size_t keybuf_len,
                                           const uint8_t * const n,  const size_t n_len,
                                           const uint8_t * const e,  const size_t e_len);

extern hal_error_t hal_rsa_key_get_type(const hal_rsa_key_t * const key,
                                        hal_key_type_t *key_type);

extern hal_error_t hal_rsa_key_get_modulus(const hal_rsa_key_t * const key,
                                           uint8_t *modulus,
                                           size_t *modulus_len,
                                           const size_t modulus_max);

extern hal_error_t hal_rsa_key_get_public_exponent(const hal_rsa_key_t * const key,
                                                   uint8_t *public_exponent,
                                                   size_t *public_exponent_len,
                                                   const size_t public_exponent_max);

extern void hal_rsa_key_clear(hal_rsa_key_t *key);

extern hal_error_t hal_rsa_encrypt(const hal_core_t *core,
                                   const hal_rsa_key_t * const key,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * output, const size_t output_len);

extern hal_error_t hal_rsa_decrypt(const hal_core_t *core,
                                   const hal_rsa_key_t * const key,
                                   const uint8_t * const input,  const size_t input_len,
                                   uint8_t * output, const size_t output_len);

extern hal_error_t hal_rsa_key_gen(const hal_core_t *core,
                                   hal_rsa_key_t **key,
                                   void *keybuf, const size_t keybuf_len,
                                   const unsigned key_length,
                                   const uint8_t * const public_exponent, const size_t public_exponent_len);

extern hal_error_t hal_rsa_private_key_to_der(const hal_rsa_key_t * const key,
                                              uint8_t *der, size_t *der_len, const size_t der_max);

extern size_t hal_rsa_private_key_to_der_len(const hal_rsa_key_t * const key);

extern hal_error_t hal_rsa_private_key_from_der(hal_rsa_key_t **key,
                                                void *keybuf, const size_t keybuf_len,
                                                const uint8_t * const der, const size_t der_len);

extern hal_error_t hal_rsa_public_key_to_der(const hal_rsa_key_t * const key,
                                             uint8_t *der, size_t *der_len, const size_t der_max);

extern size_t hal_rsa_public_key_to_der_len(const hal_rsa_key_t * const key);

extern hal_error_t hal_rsa_public_key_from_der(hal_rsa_key_t **key,
                                               void *keybuf, const size_t keybuf_len,
                                               const uint8_t * const der, const size_t der_len);

/*
 * ECDSA.
 */

typedef struct hal_ecdsa_key hal_ecdsa_key_t;

extern const size_t hal_ecdsa_key_t_size;

extern void hal_ecdsa_set_debug(const int onoff);

extern hal_error_t hal_ecdsa_key_load_private(hal_ecdsa_key_t **key,
                                              void *keybuf, const size_t keybuf_len,
                                              const hal_curve_name_t curve,
                                              const uint8_t * const x, const size_t x_len,
                                              const uint8_t * const y, const size_t y_len,
                                              const uint8_t * const d, const size_t d_len);

extern hal_error_t hal_ecdsa_key_load_public(hal_ecdsa_key_t **key,
                                             void *keybuf, const size_t keybuf_len,
                                             const hal_curve_name_t curve,
                                             const uint8_t * const x, const size_t x_len,
                                             const uint8_t * const y, const size_t y_len);

extern hal_error_t hal_ecdsa_key_get_type(const hal_ecdsa_key_t * const key,
                                          hal_key_type_t *key_type);

extern hal_error_t hal_ecdsa_key_get_curve(const hal_ecdsa_key_t * const key,
                                           hal_curve_name_t *curve);

extern hal_error_t hal_ecdsa_key_get_public(const hal_ecdsa_key_t * const key,
                                            uint8_t *x, size_t *x_len, const size_t x_max,
                                            uint8_t *y, size_t *y_len, const size_t y_max);

extern void hal_ecdsa_key_clear(hal_ecdsa_key_t *key);

extern hal_error_t hal_ecdsa_key_gen(const hal_core_t *core,
                                     hal_ecdsa_key_t **key,
                                     void *keybuf, const size_t keybuf_len,
                                     const hal_curve_name_t curve);

extern hal_error_t hal_ecdsa_private_key_to_der(const hal_ecdsa_key_t * const key,
                                                uint8_t *der, size_t *der_len, const size_t der_max);

extern size_t hal_ecdsa_private_key_to_der_len(const hal_ecdsa_key_t * const key);

extern hal_error_t hal_ecdsa_private_key_from_der(hal_ecdsa_key_t **key,
                                                  void *keybuf, const size_t keybuf_len,
                                                  const uint8_t * const der, const size_t der_len);

extern hal_error_t hal_ecdsa_public_key_to_der(const hal_ecdsa_key_t * const key,
                                               uint8_t *der, size_t *der_len, const size_t der_max);

extern size_t hal_ecdsa_public_key_to_der_len(const hal_ecdsa_key_t * const key);

extern hal_error_t hal_ecdsa_public_key_from_der(hal_ecdsa_key_t **key,
                                                 void *keybuf, const size_t keybuf_len,
                                                 const uint8_t * const der, const size_t der_len);

extern hal_error_t hal_ecdsa_key_to_ecpoint(const hal_ecdsa_key_t * const key,
                                            uint8_t *der, size_t *der_len, const size_t der_max);

extern size_t hal_ecdsa_key_to_ecpoint_len(const hal_ecdsa_key_t * const key);

extern hal_error_t hal_ecdsa_key_from_ecpoint(hal_ecdsa_key_t **key,
                                              void *keybuf, const size_t keybuf_len,
                                              const uint8_t * const der, const size_t der_len,
                                              const hal_curve_name_t curve);

extern hal_error_t hal_ecdsa_sign(const hal_core_t *core,
                                  const hal_ecdsa_key_t * const key,
                                  const uint8_t * const hash, const size_t hash_len,
                                  uint8_t *signature, size_t *signature_len, const size_t signature_max);

extern hal_error_t hal_ecdsa_verify(const hal_core_t *core,
                                    const hal_ecdsa_key_t * const key,
                                    const uint8_t * const hash, const size_t hash_len,
                                    const uint8_t * const signature, const size_t signature_len);

/*
 * Higher level RPC-based mechanism for working with HSM at arm's
 * length, using handles instead of direct access to the cores.
 *
 * Session handles are pretty much as in PKCS #11: from our viewpoint,
 * a session is a lock-step stream of operations, so while operations
 * from different sessions can interleave, operations within a single
 * session cannot.
 *
 * Client handles are a small extension to the PKCS #11 model,
 * intended to support multiple PKCS #11 using applications sharing a
 * single HSM.  Technically, sessions are per-client, but in practice
 * there's no sane reason why we'd use the same session handle
 * concurrently in multiple clients.  Mostly, the client abstraction
 * is to handle login and logout against the HSM's PIN.  Clients add
 * nothing whatsoever to the security model (the HSM has no way of
 * knowing whether the host is lumping multiple applications into a
 * single "client"), the point of the exercise is just to make the
 * C_Login()/C_Logout() semantics work as expected in the presence of
 * multiple applications.
 *
 * NB: Unlike the other handles used in this protocol, session and
 * client handles are created by the client (host) side of the RPC
 * mechanism, not the server (HSM) side.
 */

typedef struct { uint32_t handle; } hal_client_handle_t;
typedef struct { uint32_t handle; } hal_session_handle_t;

typedef enum { HAL_USER_NONE, HAL_USER_NORMAL, HAL_USER_SO, HAL_USER_WHEEL } hal_user_t;

extern hal_error_t hal_rpc_set_pin(const hal_client_handle_t client,
                                   const hal_user_t user,
                                   const char * const newpin, const size_t newpin_len);

extern hal_error_t hal_rpc_login(const hal_client_handle_t client,
                                 const hal_user_t user,
                                 const char * const pin, const size_t pin_len);

extern hal_error_t hal_rpc_logout(const hal_client_handle_t client);

extern hal_error_t hal_rpc_logout_all(void);

extern hal_error_t hal_rpc_is_logged_in(const hal_client_handle_t client,
                                        const hal_user_t user);

/*
 * Get the version number of the remote RPC server.
 */

extern hal_error_t hal_rpc_get_version(uint32_t *version);

/*
 * Get random bytes.
 */

extern hal_error_t hal_rpc_get_random(void *buffer, const size_t length);

/*
 * Combined hash and HMAC functions: pass NULL key for plain hashing.
 */

typedef struct { uint32_t handle; } hal_hash_handle_t;

extern const hal_hash_handle_t hal_hash_handle_none;

extern hal_error_t hal_rpc_hash_get_digest_length(const hal_digest_algorithm_t alg, size_t *length);

extern hal_error_t hal_rpc_hash_get_digest_algorithm_id(const hal_digest_algorithm_t alg,
                                                        uint8_t *id, size_t *len, const size_t len_max);

extern hal_error_t hal_rpc_hash_get_algorithm(const hal_hash_handle_t hash, hal_digest_algorithm_t *alg);

/*
 * Once started, a hash or HMAC operation is bound to a particular
 * session, so we only need the client and session arguments to initialize.
 */

extern hal_error_t hal_rpc_hash_initialize(const hal_client_handle_t client,
                                           const hal_session_handle_t session,
                                           hal_hash_handle_t *hash,
                                           const hal_digest_algorithm_t alg,
                                           const uint8_t * const key, const size_t key_length);

extern hal_error_t hal_rpc_hash_update(const hal_hash_handle_t hash,
                                       const uint8_t * data, const size_t length);

extern hal_error_t hal_rpc_hash_finalize(const hal_hash_handle_t hash,
                                         uint8_t *digest, const size_t length);

extern hal_error_t hal_rpc_client_init(void);
extern hal_error_t hal_rpc_client_close(void);
extern hal_error_t hal_rpc_server_init(void);
extern hal_error_t hal_rpc_server_close(void);
extern void hal_rpc_server_main(void);

/*
 * Public key functions.
 *
 * The _sign() and _verify() methods accept a hash OR an input string;
 * either "hash" should be hal_hash_handle_none or input should be NULL,
 * but not both.
 *
 * Use of client and session handles here needs a bit more thought.
 *
 * Client handles are straightforward: basically, anything that
 * creates a new pkey handle should take a client handle, which should
 * suffice, as object handles never cross clients.
 *
 * Session handles are more interesting, as PKCS #11's versions of
 * session and object handles do in effect allow one session to hand
 * an object handle to another session.  So any action which can do
 * significant work (ie, which is complicated enough that we can't
 * guarantee an immediate response) needs to take a session handle.
 *
 * There will probably be a few cases where a session handle isn't
 * strictly required but we ask for one anyway because the API turns
 * out to be easier to understand that way (eg, we probably want to
 * ask for a session handle anywhere we ask for a client handle,
 * whether we need the session handle or not, so that users of this
 * API don't have to remember which pkey-handle-creating calls require
 * a session handle and which ones don't...).
 */

#define	HAL_RPC_PKEY_NAME_MAX 128

typedef struct { uint32_t handle; } hal_pkey_handle_t;

typedef uint32_t hal_key_flags_t;

#define	HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE	(1 << 0)
#define	HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT      (1 << 1)
#define	HAL_KEY_FLAG_USAGE_DATAENCIPHERMENT	(1 << 2)

extern hal_error_t hal_rpc_pkey_load(const hal_client_handle_t client,
                                     const hal_session_handle_t session,
                                     hal_pkey_handle_t *pkey,
                                     const hal_key_type_t type,
                                     const hal_curve_name_t curve,
                                     const uint8_t * const name, const size_t name_len,
                                     const uint8_t * const der, const size_t der_len,
                                     const hal_key_flags_t flags);

extern hal_error_t hal_rpc_pkey_find(const hal_client_handle_t client,
                                     const hal_session_handle_t session,
                                     hal_pkey_handle_t *pkey,
                                     const hal_key_type_t type,
                                     const uint8_t * const name, const size_t name_len);

extern hal_error_t hal_rpc_pkey_generate_rsa(const hal_client_handle_t client,
                                             const hal_session_handle_t session,
                                             hal_pkey_handle_t *pkey,
                                             const uint8_t * const name, const size_t name_len,
                                             const unsigned key_length,
                                             const uint8_t * const public_exponent, const size_t public_exponent_len,
                                             const hal_key_flags_t flags);

extern hal_error_t hal_rpc_pkey_generate_ec(const hal_client_handle_t client,
                                            const hal_session_handle_t session,
                                            hal_pkey_handle_t *pkey,
                                            const uint8_t * const name, const size_t name_len,
                                            const hal_curve_name_t curve,
                                            const hal_key_flags_t flags);

extern hal_error_t hal_rpc_pkey_close(const hal_pkey_handle_t pkey);

extern hal_error_t hal_rpc_pkey_delete(const hal_pkey_handle_t pkey);

extern hal_error_t hal_rpc_pkey_get_key_type(const hal_pkey_handle_t pkey,
                                             hal_key_type_t *type);

extern hal_error_t hal_rpc_pkey_get_key_flags(const hal_pkey_handle_t pkey,
                                              hal_key_flags_t *flags);

extern size_t hal_rpc_pkey_get_public_key_len(const hal_pkey_handle_t pkey);

extern hal_error_t hal_rpc_pkey_get_public_key(const hal_pkey_handle_t pkey,
                                               uint8_t *der, size_t *der_len, const size_t der_max);

extern hal_error_t hal_rpc_pkey_sign(const hal_session_handle_t session,
                                     const hal_pkey_handle_t pkey,
                                     const hal_hash_handle_t hash,
                                     const uint8_t * const input,  const size_t input_len,
                                     uint8_t * signature, size_t *signature_len, const size_t signature_max);

extern hal_error_t hal_rpc_pkey_verify(const hal_session_handle_t session,
                                       const hal_pkey_handle_t pkey,
                                       const hal_hash_handle_t hash,
                                       const uint8_t * const input, const size_t input_len,
                                       const uint8_t * const signature, const size_t signature_len);

typedef struct {
  hal_key_type_t type;
  hal_curve_name_t curve;
  hal_key_flags_t flags;
  char name[HAL_RPC_PKEY_NAME_MAX];
  size_t name_len;
  /* ... */
} hal_pkey_info_t;

extern hal_error_t hal_rpc_pkey_list(hal_pkey_info_t *result,
                                     unsigned *result_len,
                                     const unsigned result_max);

#endif /* _HAL_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
