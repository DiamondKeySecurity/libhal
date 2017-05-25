/*
 * ks.h
 * ----
 * Keystore, generic parts anyway.  This is internal within libhal.
 *
 * Copyright (c) 2015-2017, NORDUnet A/S All rights reserved.
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

#ifndef _KS_H_
#define _KS_H_

#include "hal.h"
#include "hal_internal.h"

/*
 * Size of a keystore "block".
 *
 * This must be an integer multiple of the flash subsector size, among
 * other reasons because that's the minimum erasable unit.
 */

#ifndef HAL_KS_BLOCK_SIZE
#define HAL_KS_BLOCK_SIZE       (KEYSTORE_SUBSECTOR_SIZE * 1)
#endif

/*
 * Known block states.
 *
 * C does not guarantee any particular representation for enums, so
 * including enums directly in the block header isn't safe.  Instead,
 * we use an access method which casts when reading from the header.
 * Writing to the header isn't a problem, because C does guarantee
 * that enum is compatible with *some* integer type, it just doesn't
 * specify which one.
 */

typedef enum {
  HAL_KS_BLOCK_TYPE_ERASED  = 0xFF, /* Pristine erased block (candidate for reuse) */
  HAL_KS_BLOCK_TYPE_ZEROED  = 0x00, /* Zeroed block (recently used) */
  HAL_KS_BLOCK_TYPE_KEY     = 0x55, /* Block contains key material */
  HAL_KS_BLOCK_TYPE_PIN     = 0xAA, /* Block contains PINs */
  HAL_KS_BLOCK_TYPE_UNKNOWN = -1,   /* Internal code for "I have no clue what this is" */
} hal_ks_block_type_t;

/*
 * Block status.
 */

typedef enum {
  HAL_KS_BLOCK_STATUS_LIVE      = 0x66, /* This is a live block */
  HAL_KS_BLOCK_STATUS_TOMBSTONE = 0x44, /* This is a tombstone left behind during an update  */
  HAL_KS_BLOCK_STATUS_UNKNOWN   = -1,   /* Internal code for "I have no clue what this is" */
} hal_ks_block_status_t;

/*
 * Common header for all keystore block types.
 * A few of these fields are deliberately omitted from the CRC.
 */

typedef struct {
  uint8_t               block_type;
  uint8_t               block_status;
  hal_crc32_t           crc;
} hal_ks_block_header_t;

/*
 * Key block.  Tail end of "der" field (after der_len) used for attributes.
 */

typedef struct {
  hal_ks_block_header_t	header;
  hal_uuid_t            name;
  hal_key_type_t        type;
  hal_curve_name_t      curve;
  hal_key_flags_t       flags;
  size_t                der_len;
  unsigned              attributes_len;
  uint8_t               der[];  /* Must be last field -- C99 "flexible array member" */
} hal_ks_blockkey_block_t;

#define SIZEOF_KS_BLOCKKEY_BLOCK_DER \
  (HAL_KS_BLOCK_SIZE - offsetof(hal_ks_blockkey_block_t, der))

/*
 * PIN block.  Also includes space for backing up the KEK when
 * HAL_MKM_FLASH_BACKUP_KLUDGE is enabled.
 */

typedef struct {
  hal_ks_block_header_t	header;
  hal_ks_pin_t          wheel_pin;
  hal_ks_pin_t          so_pin;
  hal_ks_pin_t          user_pin;
#if HAL_MKM_FLASH_BACKUP_KLUDGE
  uint32_t              kek_set;
  uint8_t               kek[KEK_LENGTH];
#endif
} hal_ks_blockpin_block_t;

#define FLASH_KEK_SET   0x33333333

/*
 * One keystore block.
 */

typedef union {
  uint8_t		    bytes[HAL_KS_BLOCK_SIZE];
  hal_ks_block_header_t     header;
  hal_ks_blockkey_block_t   key;
  hal_ks_blockpin_block_t   pin;
} hal_ks_block_t;

/*
 * In-memory cache.
 */

typedef struct {
  unsigned              blockno;
  unsigned              lru;
  hal_ks_block_t	block;
} hal_ks_cache_block_t;

/*
 * Medium-specific driver and in-memory database.
 *
 * The top-level structure is a static variable; the arrays are
 * allocated at runtime using hal_allocate_static_memory() because
 * they can get kind of large.
 *
 * Driver-specific stuff is handled by a form of subclassing: the
 * driver embeds the hal_ks_t structure at the head of whatever else
 * it needs, and performs (controlled, type-safe) casts as needed.
 */

typedef struct hal_ks_driver    hal_ks_driver_t;
typedef struct hal_ks           hal_ks_t;

struct hal_ks {
  const hal_ks_driver_t *driver;
  unsigned size;                /* Blocks in keystore */
  unsigned used;                /* How many blocks are in use */
  uint16_t *index;              /* Index/freelist array */
  hal_uuid_t *names;            /* Keyname array */
  unsigned cache_lru;           /* Cache LRU counter */
  unsigned cache_size;          /* Size (how many blocks) in cache */
  hal_ks_cache_block_t *cache;  /* Cache */
  int per_session;              /* Whether objects have per-session semantics (PKCS #11, sigh) */
};

#define KS_DRIVER_END_LIST
#define KS_DRIVER_METHODS                                                                               \
  KS_DRIVER_METHOD(read,        hal_ks_t *ks, const unsigned blockno, hal_ks_block_t *block)            \
  KS_DRIVER_METHOD(write,       hal_ks_t *ks, const unsigned blockno, hal_ks_block_t *block)            \
  KS_DRIVER_METHOD(deprecate,   hal_ks_t *ks, const unsigned blockno)                                   \
  KS_DRIVER_METHOD(zero,        hal_ks_t *ks, const unsigned blockno)                                   \
  KS_DRIVER_METHOD(erase,       hal_ks_t *ks, const unsigned blockno)                                   \
  KS_DRIVER_METHOD(erase_maybe, hal_ks_t *ks, const unsigned blockno)                                   \
  KS_DRIVER_METHOD(set_owner,   hal_ks_t *ks, const unsigned blockno,                                   \
                                const hal_client_handle_t client, const hal_session_handle_t session)   \
  KS_DRIVER_METHOD(test_owner,  hal_ks_t *ks, const unsigned blockno,                                   \
                                const hal_client_handle_t client, const hal_session_handle_t session)   \
  KS_DRIVER_END_LIST

#define KS_DRIVER_METHOD(_name_, ...) hal_error_t (*_name_)(__VA_ARGS__)
struct hal_ks_driver { KS_DRIVER_METHODS };
#undef  KS_DRIVER_METHOD

#define KS_DRIVER_METHOD(_name_, ...)                                   \
  static inline hal_error_t hal_ks_block_##_name_(__VA_ARGS__)		\
  {									\
    return                                                              \
      ks == NULL || ks->driver == NULL  ? HAL_ERROR_BAD_ARGUMENTS   :	\
      ks->driver->_name_ == NULL        ? HAL_ERROR_NOT_IMPLEMENTED :	\
      ks->driver->_name_(__VA_ARGS__);					\
  }
KS_DRIVER_METHODS
#undef  KS_DRIVER_METHOD

#undef  KS_DRIVER_METHODS
#undef  KS_DRIVER_END_LIST

#endif /* _KS_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
