/*
 * Test code for AES Key Wrap.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <cryptech.h>

#ifndef TC_BUFSIZE
#define TC_BUFSIZE      4096
#endif

/*
 * Test cases from RFC 5649...which all use a 192-bit key, which our
 * AES implementation doesn't support, to these will never pass.  Feh.
 *
 * Have to write our own, I guess, using our Python implementation or
 * something.
 */

typedef struct {
  const char *K;                /* Key-encryption-key */
  const char *Q;                /* Plaintext */
  const char *C;                /* Ciphertext */
} test_case_t;

static const test_case_t test_case[] = {

  { "5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8",                       /* K */
    "c37b7e6492584340 bed1220780894115 5068f738",                               /* Q */
    "138bdeaa9b8fa7fc 61f97742e72248ee 5ae6ae5360d1ae6a 5f54f373fa543b6a"},     /* C */

  { "5840df6e29b02af1 ab493b705bf16ea1 ae8338f4dcc176a8",                       /* K */
    "466f7250617369",                                                           /* Q */
    "afbeb0f07dfbf541 9200f2ccb50bb24f" }                                       /* C */

};

static int parse_hex(const char *hex, uint8_t *bin, size_t *len, const size_t max)
{
  static const char whitespace[] = " \t\r\n";
  size_t i;

  assert(hex != NULL && bin != NULL && len != NULL);

  hex += strspn(hex, whitespace);

  for (i = 0; *hex != '\0' && i < max; i++, hex += 2 + strspn(hex + 2, whitespace))
    if (sscanf(hex, "%2hhx", &bin[i]) != 1)
      return 0;

  *len = i;

  return *hex == '\0';
}

static const char *format_hex(const uint8_t *bin, const size_t len, char *hex, const size_t max)
{
  size_t i;

  assert(bin != NULL && hex != NULL && len * 3 < max);

  if (len == 0)
    return "";

  for (i = 0; i < len; i++)
    sprintf(hex + 3 * i, "%02x:", bin[i]);

  hex[len * 3 - 1] = '\0';
  return hex;
}

static int run_test(const test_case_t * const tc)
{
  uint8_t K[TC_BUFSIZE], Q[TC_BUFSIZE], C[TC_BUFSIZE], q[TC_BUFSIZE], c[TC_BUFSIZE];
  size_t K_len, Q_len, C_len, q_len = sizeof(q), c_len = sizeof(c);
  char h1[TC_BUFSIZE * 3],  h2[TC_BUFSIZE * 3];
  hal_error_t err;
  int ok = 1;

  assert(tc != NULL);

  if (!parse_hex(tc->K, K, &K_len, sizeof(K)))
    return printf("couldn't parse KEK %s\n", tc->K), 0;

  if (!parse_hex(tc->Q, Q, &Q_len, sizeof(Q)))
    return printf("couldn't parse plaintext %s\n", tc->Q), 0;

  if (!parse_hex(tc->C, C, &C_len, sizeof(C)))
    return printf("couldn't parse ciphertext %s\n", tc->C), 0;

  if ((err = hal_aes_keywrap(K, K_len, Q, Q_len, c, &c_len)) != HAL_OK)
    ok = printf("couldn't wrap %s: %s\n", tc->Q, hal_error_string(err)), 0;

  if ((err = hal_aes_keyunwrap(K, K_len, C, C_len, q, &q_len)) != HAL_OK)
    ok = printf("couldn't unwrap %s: %s\n", tc->C, hal_error_string(err)), 0;

  if (C_len != c_len || memcmp(C, c, C_len) != 0)
    ok = printf("ciphertext mismatch:\n  Want: %s\n  Got:  %s\n",
		format_hex(C, C_len, h1, sizeof(h1)),
		format_hex(c, c_len, h2, sizeof(h2))), 0;

  if (Q_len != q_len || memcmp(Q, q, Q_len) != 0)
    ok = printf("plaintext mismatch:\n  Want: %s\n  Got:  %s\n",
		format_hex(Q, Q_len, h1, sizeof(h1)),
		format_hex(q, q_len, h2, sizeof(h2))), 0;

  return ok;
}

int main (int argc, char *argv[])
{
  int i, ok = 1;

  for (i = 0; i < sizeof(test_case)/sizeof(*test_case); i++) {
    printf("Running test case #%d...", i);
    if (run_test(&test_case[i]))
      printf("OK\n");
    else
      ok = 0;
  }

  return !ok;
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
