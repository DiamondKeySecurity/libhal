// Notes towards unified keystore code (drivers become just low-level
// "disk" I/O and perhaps a bit of local init/shutdown).
//
// Most of the structure definitions in ks_flash.c and ks_volatile.c
// become common and go in ks.h (or wherever, but probably be enough
// stuff that separate .h file might be easier to read).
//
// We already have
//
//     typedef struct hal_ks hal_ks_t;
//
// which we "subclass" to get ks_t (ks_volatile) and db_t (ks_flash).
// We can move more common stuff there.
//
// flash_block_t (etc) becomes ks_block_t (etc) as these data
// structures will be used by all keystores, not just flash.
//
// We might want to fold hal_ks_index_t into hal_ks_t as everything
// will be using it.  Then again, it's relatively harmless as it is, a
// bit more verbose trading for a bit more isolation.  Probably go for
// less verbose, for readability.
//
// Each keystore will still have some weird private stuff, like the
// RAM for the keys themselves in the volatile case and the PIN stuff
// in the flash case.
//
// The ks_flash cache, however, probably wants to become common code.
// Yes we could get a bit more efficient if we skipped caching in the
// volatile case, but that's not our bottleneck and there are some
// cases where the code relies on knowing that mucking with the cache
// copy is harmless until we write the block to "disk", don't want to
// mess with that, so keep the flash model for volatile.  Cache size
// will need to become another hal_ks_t field.
//
// Don't remember exactly where we're doing the "subclassing" casts,
// should be easy enough to find...except that ks_flash is mostly
// ignoring that argument and using the static db variable directly.
// ks_volatile may be closer to write on this point, as it already had
// ks_to_ksv().  But most of the code will be in a driver-agnostic
// ks.c (or whatever) and will be calling functions that care through
// the driver, maybe this doesn't matter very much.
//
// Tedious though it sounds, might be simplest just to check each
// function in ks_*.c to see whether it moves to ks.[ch] or becomes
// something called by the new lower-level driver API.  Need a sketch
// of the lower-level driver API, chicken and egg there but probably
// is init(), shutdown(), block_read(), block_deprecate(),
// block_zero(), block_erase(), block_erase_maybe(), block-write().
// Possible that some of these don't really need to be driver, was
// mostly basing this on which things in ks_flash touch flash
// directly-ish via the keystore_*() functions.
//
// Would be nice if we can make the API regular enough (inline
// functions?) that user need not really care which functions are
// driver-specific and which are layered on top, but that may be
// impractical (or silly).
//
// Hmm, hal_ks_open() and hal_ks_close() don't quite fit new model,
// what was I thinking there?  Not much, existing implementations just
// use that to get back a (hal_ks_t*), so really just checking the
// binding between driver and keystore object.
//
// I think this boils down to another instance of the confusion
// between what in Python would be Keystore.__new__() and
// Keystore.__init__().  This even sort of fits with the weird `alloc`
// parameter in ks_init().
//
// Maybe we can trust C memory initialization enough to use a zeroed
// static variable as test for whether a keystore has been
// initialized, and just have the low-level (driver) methods check
// that and fail if trying to use an uninitialized keystore?
//
// Pythonesque view might be the right way to handle ks_init(0 and
// ks_shutdown() too: in most cases we have inline functions which
// call the driver function, but for these methods the subclass needs
// to extend the abstract method, which translates, in C, to the
// generic method calling the driver method of the same name at the
// right time.  Not quite what Python does but close enough.


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
  KS_BLOCK_TYPE_ERASED  = 0xFF, /* Pristine erased block (candidate for reuse) */
  KS_BLOCK_TYPE_ZEROED  = 0x00, /* Zeroed block (recently used) */
  KS_BLOCK_TYPE_KEY     = 0x55, /* Block contains key material */
  KS_BLOCK_TYPE_PIN     = 0xAA, /* Block contains PINs */
  KS_BLOCK_TYPE_UNKNOWN = -1,   /* Internal code for "I have no clue what this is" */
} ks_block_type_t;

/*
 * Block status.
 */

typedef enum {
  KS_BLOCK_STATUS_LIVE      = 0x66, /* This is a live block */
  KS_BLOCK_STATUS_TOMBSTONE = 0x44, /* This is a tombstone left behind during an update  */
  KS_BLOCK_STATUS_UNKNOWN   = -1,   /* Internal code for "I have no clue what this is" */
} ks_block_status_t;

/*
 * Common header for all keystore block types.
 * A few of these fields are deliberately omitted from the CRC.
 */

typedef struct {
  uint8_t               block_type;
  uint8_t               block_status;
  hal_crc32_t           crc;
} ks_block_header_t;

/*
 * Key block.  Tail end of "der" field (after der_len) used for attributes.
 */

typedef struct {
  ks_block_header_t     header;
  hal_uuid_t            name;
  hal_key_type_t        type;
  hal_curve_name_t      curve;
  hal_key_flags_t       flags;
  size_t                der_len;
  unsigned              attributes_len;
  uint8_t               der[];  /* Must be last field -- C99 "flexible array member" */
} ks_blockkey_block_t;

#define SIZEOF_KS_BLOCKKEY_BLOCK_DER \
  (HAL_KS_BLOCK_SIZE - offsetof(ks_blockkey_block_t, der))

/*
 * PIN block.  Also includes space for backing up the KEK when
 * HAL_MKM_FLASH_BACKUP_KLUDGE is enabled.
 */

typedef struct {
  ks_block_header_t     header;
  hal_ks_pin_t          wheel_pin;
  hal_ks_pin_t          so_pin;
  hal_ks_pin_t          user_pin;
#if HAL_MKM_FLASH_BACKUP_KLUDGE
  uint32_t              kek_set;
  uint8_t               kek[KEK_LENGTH];
#endif
} ks_blockpin_block_t;

#define FLASH_KEK_SET   0x33333333

/*
 * One keystore block.
 */

typedef union {
  uint8_t               bytes[HAL_KS_BLOCK_SIZE];
  ks_block_header_t     header;
  ks_blockkey_block_t   key;
  ks_blockpin_block_t   pin;
} ks_block_t;

/*
 * In-memory cache.
 */

typedef struct {
  unsigned              blockno;
  unsigned              lru;
  ks_block_t            block;
} ks_cache_block_t;

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
  ks_cache_block_t *cache;      /* Cache */
  int per_session;              /* Whether objects have per-session semantics (PKCS #11, sigh) */
};

struct hal_ks_driver {
  hal_error_t (*init)           (hal_ks_t *, const int alloc);
  hal_error_t (*shutdown)       (hal_ks_t *);
  hal_error_t (*read)           (hal_ks_t *, const unsigned blockno, ks_block_t *);
  hal_error_t (*write)          (hal_ks_t *, const unsigned blockno, ks_block_t *)
  hal_error_t (*deprecate)      (hal_ks_t *, const unsigned blockno);
  hal_error_t (*zero)           (hal_ks_t *, const unsigned blockno);
  hal_error_t (*erase)          (hal_ks_t *, const unsigned blockno);
  hal_error_t (*erase_maybe)    (hal_ks_t *, const unsigned blockno);
  hal_error_t (*get_owner)      (hal_ks_t *, const unsigned blockno,       hal_client_handle_t *,       hal_session_handle_t *);
  hal_error_t (*set_owner)      (hal_ks_t *, const unsigned blockno, const hal_client_handle_t,   const hal_session_handle_t);
};

#endif /* _KS_H_ */

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
