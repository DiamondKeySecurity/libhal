/*
 * First stumblings towards a test harness for RSA using Cryptech
 * ModExp core.
 *
 * For the moment this just does modular exponentiation tests using
 * RSA keys and pre-formatted data-to-be-signed, without attempting
 * CRT or any of the other clever stuff we should be doing.  This is
 * not usable for any sane purpose other than testing.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cryptech.h"
#include "test-rsa.h"

/*
 * Constant value to use with hal_io_write() when we don't want
 * a read-back check thus aren't using set_register().
 */

static const uint8_t one[] = { 0, 0, 0, 1 };

/*
 * Debugging aid: check a result, report on failure.
 */

#define check(_expr_)				\
  do {						\
    if ((_expr_) != 0)				\
      return printf("%s failed\n", #_expr_), 1;	\
  } while (0)

/*
 * Set an ordinary register, with read-back check.
 */

static int _set_register(const off_t addr,
			 const char * const name,
			 uint32_t value)
{
  uint8_t w1[4], w2[4];
  int i;
  assert(name != NULL);
  for (i = 3; i >= 0; i--) {
    w1[i] = value & 0xFF;
    value >>= 8;
  }
  printf("Setting register %#lx %s\n", (unsigned long) addr, name);
  check(hal_io_write(addr, w1, sizeof(w1)));
  check(hal_io_read(addr,  w2, sizeof(w2)));
  if (memcmp(w1, w2, sizeof(w1)) != 0)
    printf("MISMATCH\n");
  printf("\n");
  return 0;
}

/*
 * Get value of a block memory.
 */

static int _get_blockmem(const off_t reset_addr,
			 const char * const reset_name,
			 const off_t data_addr,
			 const char * const data_name,
			 uint8_t *value,
			 const size_t length)
{
  size_t i;
  assert(reset_name != NULL && data_name != NULL && value != NULL && length % 4 == 0 && length <= sizeof(value));
  printf("Setting register %#lx %s\n", (unsigned long) reset_addr, reset_name);
  check(hal_io_write(reset_addr, one, sizeof(one)));
  printf("\n");
  printf("Getting blockmem %#lx %s\n", (unsigned long) data_addr, data_name);
  for (i = 0; i < length; i += 4)
    check(hal_io_read(data_addr, &value[i], 4));
  return 0;
}

/*
 * Set value of a block memory, with read-back check.
 */

static int _set_blockmem(const off_t reset_addr,
			 const char * const reset_name,
			 const off_t data_addr,
			 const char * const data_name,
			 const uint8_t * const value,
			 const size_t value_length,
			 uint8_t *buffer,
			 const size_t buffer_length)
{
  size_t i;
  assert(reset_name != NULL && data_name != NULL && value != NULL && buffer_length >= value_length && value_length % 4 == 0);
  printf("Setting register %#lx %s\n", (unsigned long) reset_addr, reset_name);
  check(hal_io_write(reset_addr, one, sizeof(one)));
  printf("\n");
  printf("Setting blockmem %#lx %s\n", (unsigned long) data_addr, data_name);
  for (i = 0; i < value_length; i += 4)
    check(hal_io_write(data_addr, &value[i], 4));
  printf("\n");
  check(_get_blockmem(reset_addr, reset_name, data_addr, data_name, buffer, value_length));
  if (memcmp(value, buffer, value_length))
    printf("MISMATCH\n");
  printf("\n");
  return 0;
}

/*
 * Syntactic sugar.
 */

#define set_register(_field_, _value_) \
  _set_register(_field_, #_field_, _value_)

#define get_blockmem(_field_, _value_) \
  _get_blockmem(_field_##_PTR_RST, #_field_ "_PTR_RST", _field_##_DATA, #_field_ "_DATA", _value_, sizeof(_value_))

#define set_blockmem(_field_, _value_, _buffer_) \
  _set_blockmem(_field_##_PTR_RST, #_field_ "_PTR_RST", _field_##_DATA, #_field_ "_DATA", (_value_).val, (_value_).len, _buffer_, sizeof(_buffer_))

/*
 * Test driver.
 */

static int test(const rsa_tc_t * const tc)
{
  uint8_t b[4096];

  printf("Signature test for %lu-bit RSA key\n", (unsigned long) tc->size);

  check(set_blockmem(MODEXP_MODULUS, tc->n, b));
  check(set_blockmem(MODEXP_MESSAGE, tc->m, b));
  check(set_register(MODEXP_MODULUS_LENGTH, tc->n.len / 4));

  check(set_blockmem(MODEXP_EXPONENT, tc->d, b));
  check(set_register(MODEXP_EXPONENT_LENGTH, tc->d.len / 4));

  printf("Checking ready status\n");
  check(hal_io_wait_ready(MODEXP_ADDR_STATUS));
  printf("\n");

  check(set_register(MODEXP_ADDR_CTRL, 1));

  printf("Waiting for ready\n");
  check(hal_io_wait(MODEXP_ADDR_STATUS, STATUS_READY, NULL));
  printf("\n");

  check(get_blockmem(MODEXP_RESULT, b));

  printf("Comparing results with known value...");
  if (memcmp(b, tc->s.val, tc->s.len))
    printf("MISMATCH\n");
  else
    printf("OK\n");

  printf("Verification test for %lu-bit RSA key\n", (unsigned long) tc->size);

  check(set_blockmem(MODEXP_MODULUS, tc->n, b));
  check(set_blockmem(MODEXP_MESSAGE, tc->m, b));
  check(set_register(MODEXP_MODULUS_LENGTH, tc->n.len / 4));

  check(set_blockmem(MODEXP_EXPONENT, tc->e, b));
  check(set_register(MODEXP_EXPONENT_LENGTH, tc->e.len / 4));

  printf("Checking ready status\n");
  check(hal_io_wait_ready(MODEXP_ADDR_STATUS));
  printf("\n");

  check(set_register(MODEXP_ADDR_CTRL, 1));

  printf("Waiting for ready\n");
  check(hal_io_wait(MODEXP_ADDR_STATUS, STATUS_READY, NULL));
  printf("\n");

  check(get_blockmem(MODEXP_RESULT, b));

  printf("Comparing results with known value...");
  if (memcmp(b, tc->m.val, tc->m.len))
    printf("MISMATCH\n");
  else
    printf("OK\n");

  return 0;
}


int main(int argc, char *argv[])
{
  uint8_t name[8], version[4];
  int i;

  /*
   * Initialize EIM and report what core we're running.
   */

  check(hal_io_read(MODEXP_ADDR_NAME0,   name,    sizeof(name)));
  check(hal_io_read(MODEXP_ADDR_VERSION, version, sizeof(version)));
  printf("\"%8.8s\"  \"%4.4s\"\n\n", name, version);

  hal_io_set_debug(1);

  /*
   * Run all the test cases.
   */

  for (i = 0; i < sizeof(rsa_tc)/sizeof(*rsa_tc); i++)
    if (test(&rsa_tc[i]))
      return 1;

  return 0;
}
