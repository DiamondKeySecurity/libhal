/*
 * test-rpc_hashsig.c
 * ------------------
 * Test code for RPC interface to Cryptech public key operations.
 *
 * Authors: Rob Austein, Paul Selkirk
 * Copyright (c) 2015-2018, NORDUnet A/S
 * All rights reserved.
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

/* Parts of this may eventually get folded into test-rpc_pkey.c,
 * but for now I'd rather do it stand-alone.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>

#include <hal.h>
#include <hashsig.h>
#include "test-hashsig.h"

#include <sys/time.h>
/* not included in my glibc, sigh... */
void timersub(struct timeval *a, struct timeval *b, struct timeval *res)
{
    res->tv_sec = a->tv_sec - b->tv_sec;
    res->tv_usec = a->tv_usec - b->tv_usec;
    if (res->tv_usec < 0) {
        res->tv_usec += 1000000;
        --res->tv_sec;
    }
    if (res->tv_usec > 1000000) {
        res->tv_usec -= 1000000;
        ++res->tv_sec;
    }
}

static int debug = 0;
static int info = 0;

#define lose(...) do { printf(__VA_ARGS__); goto fail; } while (0)

static int test_hashsig_testvec_local(const hashsig_tc_t * const tc, hal_key_flags_t flags)
{
    hal_error_t err;

    assert(tc != NULL);

    printf("Starting local hashsig test vector test\n");

    uint8_t tc_keybuf[hal_hashsig_key_t_size];
    hal_hashsig_key_t *tc_key = NULL;

    if ((err = hal_hashsig_key_load_public_xdr(&tc_key,
                                               tc_keybuf, sizeof(tc_keybuf),
                                               tc->key.val, tc->key.len)) != HAL_OK)
        lose("Could not load public key from test vector: %s\n", hal_error_string(err));

    if ((err = hal_hashsig_verify(NULL, tc_key, tc->msg.val, tc->msg.len, tc->sig.val, tc->sig.len)) != HAL_OK)
        lose("Verify failed: %s\n", hal_error_string(err));

    printf("OK\n");
    return 1;

fail:
    return 0;
}

static int test_hashsig_testvec_remote(const hashsig_tc_t * const tc, hal_key_flags_t flags)
{
    const hal_client_handle_t client = {HAL_HANDLE_NONE};
    const hal_session_handle_t session = {HAL_HANDLE_NONE};
    hal_pkey_handle_t public_key = {HAL_HANDLE_NONE};
    hal_error_t err;
    size_t len;

    assert(tc != NULL);

    {
        flags |= HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE;

        printf("Starting remote hashsig test vector test, flags 0x%lx\n", (unsigned long) flags);

        uint8_t tc_keybuf[hal_hashsig_key_t_size];
        hal_hashsig_key_t *tc_key = NULL;

        if ((err = hal_hashsig_key_load_public_xdr(&tc_key,
                                                   tc_keybuf, sizeof(tc_keybuf),
                                                   tc->key.val, tc->key.len)) != HAL_OK)
            lose("Could not load public key from test vector: %s\n", hal_error_string(err));

        hal_uuid_t public_name;

        uint8_t public_der[hal_hashsig_public_key_to_der_len(tc_key)];

        if ((err = hal_hashsig_public_key_to_der(tc_key, public_der, &len, sizeof(public_der))) != HAL_OK)
            lose("Could not DER encode public key from test vector: %s\n", hal_error_string(err));

        assert(len == sizeof(public_der));

        if ((err = hal_rpc_pkey_load(client, session, &public_key, &public_name,
                                     public_der, sizeof(public_der), flags)) != HAL_OK)
            lose("Could not load public key into RPC: %s\n", hal_error_string(err));

        if ((err = hal_rpc_pkey_verify(public_key, hal_hash_handle_none,
                                       tc->msg.val, tc->msg.len, tc->sig.val, tc->sig.len)) != HAL_OK)
            lose("Could not verify: %s\n", hal_error_string(err));

        if ((err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
            lose("Could not delete public key: %s\n", hal_error_string(err));

        printf("OK\n");
        return 1;
    }

fail:
    if (public_key.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
        printf("Warning: could not delete public key: %s\n", hal_error_string(err));

    return 0;
}

static void hexdump(const char * const label, const uint8_t * const buf, const size_t len)
{
    printf("%-15s ", label);

    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
        if ((i & 0x0f) == 0x0f) {
            printf("\n");
            if (i < len - 1)
                printf("                ");
        }
    }
    if ((len & 0x0f) != 0)
        printf("\n");
}

static inline size_t lms_type_to_h(const lms_algorithm_t lms_type)
{
    switch (lms_type) {
    case lms_sha256_n32_h5:  return  5;
    case lms_sha256_n32_h10: return 10;
    case lms_sha256_n32_h15: return 15;
    case lms_sha256_n32_h20: return 20;
    case lms_sha256_n32_h25: return 25;
    default: return 0;
    }
}

static inline size_t two_to_the(const size_t n)
{
    if (n % 5 != 0)
        return 0;

    size_t result, i;
    for (result = 1, i = 0; i < n; i += 5)
        result *= 32;

    return result;
}

static inline size_t lms_type_to_h2(const lms_algorithm_t lms_type)
{
    switch (lms_type) {
    case lms_sha256_n32_h5:  return two_to_the(5);
    case lms_sha256_n32_h10: return two_to_the(10);
    case lms_sha256_n32_h15: return two_to_the(15);
    case lms_sha256_n32_h20: return two_to_the(20);
    case lms_sha256_n32_h25: return two_to_the(25);
    default:                 return 0;
    }
}

static inline size_t lmots_type_to_w(const lmots_algorithm_t lmots_type)
{
    switch (lmots_type) {
    case lmots_sha256_n32_w1: return 1;
    case lmots_sha256_n32_w2: return 2;
    case lmots_sha256_n32_w4: return 4;
    case lmots_sha256_n32_w8: return 8;
    default: return 0;
    }
}

static inline size_t lmots_type_to_p(const lmots_algorithm_t lmots_type)
{
    switch (lmots_type) {
    case lmots_sha256_n32_w1: return 265;
    case lmots_sha256_n32_w2: return 133;
    case lmots_sha256_n32_w4: return  67;
    case lmots_sha256_n32_w8: return  34;
    default: return 0;
    }
}

#include <xdr_internal.h>

static hal_error_t dump_hss_signature(const uint8_t * const sig, const size_t len)
{
    const uint8_t *sigptr = sig;
    const uint8_t * const siglim = sig + len;
    hal_error_t err;

    hexdump("Nspk", sigptr, 4);
    uint32_t Nspk;
    if ((err = hal_xdr_decode_int(&sigptr, siglim, &Nspk)) != HAL_OK) return err;

    for (size_t i = 0; i < Nspk + 1; ++i) {
        printf("--------------------------------------------\nsig[%lu]\n", i);
        hexdump("q", sigptr, 4); sigptr += 4;

        {
            hexdump("lmots type", sigptr, 4);
            uint32_t lmots_type;
            if ((err = hal_xdr_decode_int(&sigptr, siglim, &lmots_type)) != HAL_OK) return err;
            hexdump("C", sigptr, 32); sigptr += 32;
            size_t p = lmots_type_to_p((const lmots_algorithm_t)lmots_type);
            for (size_t j = 0; j < p; ++j) {
                char label[16];
                sprintf(label, "y[%lu]", j);
                hexdump(label, sigptr, 32); sigptr += 32;
            }
        }

        hexdump("lms type", sigptr, 4);
        uint32_t lms_type;
        if ((err = hal_xdr_decode_int(&sigptr, siglim, &lms_type)) != HAL_OK) return err;
        size_t h = lms_type_to_h((const lms_algorithm_t)lms_type);
        for (size_t j = 0; j < h; ++j) {
            char label[16];
            sprintf(label, "path[%lu]", j);
            hexdump(label, sigptr, 32); sigptr += 32;
        }

        if (i == Nspk)
            break;

        printf("--------------------------------------------\npubkey[%lu]\n", i + 1);
        hexdump("lms type", sigptr, 4); sigptr += 4;
        hexdump("lmots type", sigptr, 4); sigptr += 4;
        hexdump("I", sigptr, 16); sigptr += 16;
        hexdump("T[1]", sigptr, 32); sigptr += 32;
    }

    if (sigptr < siglim) {
        printf("--------------------------------------------\nextra\n");
        hexdump("", sigptr, siglim - sigptr);
    }

    return HAL_OK;
}

static int test_hashsig_sign(const size_t L,
                             const lms_algorithm_t lms_type,
                             const lmots_algorithm_t lmots_type,
                             size_t iterations)
{
    const hal_client_handle_t client = {HAL_HANDLE_NONE};
    const hal_session_handle_t session = {HAL_HANDLE_NONE};
    hal_pkey_handle_t private_key = {HAL_HANDLE_NONE};
    hal_pkey_handle_t public_key = {HAL_HANDLE_NONE};
    hal_error_t err;
    size_t len;

    {
        hal_key_flags_t flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE;

        printf("Starting hashsig key test: L %lu, lms type %u (h=%lu), lmots type %u (w=%lu)\n",
               L, lms_type, lms_type_to_h(lms_type), lmots_type, lmots_type_to_w(lmots_type));

        if (info)
            printf("Info: signature length %lu, lmots private key length %lu\n",
                   hal_hashsig_signature_len(L, lms_type, lmots_type),
                   hal_hashsig_lmots_private_key_len(lmots_type));

        hal_uuid_t private_name, public_name;
        struct timeval tv_start, tv_end, tv_diff;

        size_t Lh2 = two_to_the(L * lms_type_to_h(lms_type));
        size_t h2 = lms_type_to_h2(lms_type);

        if (info)
            gettimeofday(&tv_start, NULL);
        if ((err = hal_rpc_pkey_generate_hashsig(client, session, &private_key, &private_name,
                                                 L, lms_type, lmots_type, flags)) != HAL_OK)
            lose("Could not generate hashsig private key: %s\n", hal_error_string(err));
        if (info) {
            gettimeofday(&tv_end, NULL);
            timersub(&tv_end, &tv_start, &tv_diff);
            long per_key = (tv_diff.tv_sec * 1000000 + tv_diff.tv_usec) / (L * h2);
            printf("Info: %ldm%ld.%03lds to generate key (%ld.%03lds per lmots key)\n",
                   tv_diff.tv_sec / 60, tv_diff.tv_sec % 60, tv_diff.tv_usec / 1000,
                   per_key / 1000000, (per_key % 1000000) / 1000);
        }

        uint8_t public_der[hal_rpc_pkey_get_public_key_len(private_key)];

        if ((err = hal_rpc_pkey_get_public_key(private_key, public_der, &len, sizeof(public_der))) != HAL_OK)
            lose("Could not DER encode RPC hashsig public key from RPC hashsig private key: %s\n", hal_error_string(err));

        assert(len == sizeof(public_der));

        if ((err = hal_rpc_pkey_load(client, session, &public_key, &public_name,
                                     public_der, sizeof(public_der), flags)) != HAL_OK)
            lose("Could not load public key into RPC: %s\n", hal_error_string(err));

        if (iterations > 0) {
            uint8_t sig[hal_hashsig_signature_len(L, lms_type, lmots_type)];

            if (info)
                gettimeofday(&tv_start, NULL);
            int i;
            for (i = 0; i < iterations; ++i) {
                if ((err = hal_rpc_pkey_sign(private_key, hal_hash_handle_none,
                                             tc1_msg, sizeof(tc1_msg), sig, &len, sizeof(sig))) == HAL_OK) {
                    assert(len == sizeof(sig));
                    if (debug) {
                        printf("Debug: received signature:\n");
                        dump_hss_signature(sig, len);
                    }
                }
                else {
                    if (i == Lh2 && err == HAL_ERROR_HASHSIG_KEY_EXHAUSTED)
                        break;
                    else
                        lose("Could not sign (%d): %s\n", i, hal_error_string(err));
                }
            }
            if (info) {
                gettimeofday(&tv_end, NULL);
                timersub(&tv_end, &tv_start, &tv_diff);
                long per_sig = (tv_diff.tv_sec * 1000000 + tv_diff.tv_usec) / i;
                printf("Info: %ldm%ld.%03lds to generate %d signatures (%ld.%03lds per signature)\n",
                       tv_diff.tv_sec / 60, tv_diff.tv_sec % 60, tv_diff.tv_usec / 1000, i,
                       per_sig / 1000000, (per_sig % 1000000) / 1000);
            }

            if (info)
                gettimeofday(&tv_start, NULL);
            if ((err = hal_rpc_pkey_verify(public_key, hal_hash_handle_none,
                                           tc1_msg, sizeof(tc1_msg), sig, len)) != HAL_OK)
                lose("Could not verify: %s\n", hal_error_string(err));
            if (info) {
                gettimeofday(&tv_end, NULL);
                timersub(&tv_end, &tv_start, &tv_diff);
                printf("Info: %ldm%ld.%03lds to verify 1 signature\n",
                       tv_diff.tv_sec / 60, tv_diff.tv_sec % 60, tv_diff.tv_usec / 1000);
            }
        }

        if ((err = hal_rpc_pkey_delete(private_key)) != HAL_OK)
            lose("Could not delete private key: %s\n", hal_error_string(err));

        if ((err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
            lose("Could not delete public key: %s\n", hal_error_string(err));

        printf("OK\n");
        return 1;
    }

fail:
    if (private_key.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(private_key)) != HAL_OK)
        printf("Warning: could not delete private key: %s\n", hal_error_string(err));

    if (public_key.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
        printf("Warning: could not delete public key: %s\n", hal_error_string(err));

    return 0;
}

int main(int argc, char *argv[])
{
    const hal_client_handle_t client = {HAL_HANDLE_NONE};
    char *pin = "fnord";
    int do_default = 1;
    int do_testvec = 0;
    size_t iterations = 1;
    size_t L_lo = 0, L_hi = 0;
    size_t lms_lo = 5, lms_hi = 0;
    size_t lmots_lo = 3, lmots_hi = 0;
    char *p;
    hal_error_t err;
    int ok = 1;

char usage[] = "\
Usage: %s [-d] [-i] [-p pin] [-t] [-L n] [-l n] [-o n] [-n n]\n\
       -d: enable debugging - hexdump signatures\n\
       -i: enable informational messages - runtimes and signature lengths\n\
       -p: user PIN\n\
       -t: verify test vectors\n\
       -L: number of levels in the HSS scheme (1..8)\n\
       -l: LMS type (5..9)\n\
       -o: LM-OTS type (1..4)\n\
       -n: number of signatures to generate (0..'max')\n\
Numeric arguments can be a single number or a range, e.g. '1..4'\n";

    int opt;
    while ((opt = getopt(argc, argv, "ditp:L:l:o:n:h?")) != -1) {
        switch (opt) {
        case 'd':
            debug = 1;
            break;
        case 'i':
            info = 1;
            break;
        case 't':
            do_testvec = 1;
            do_default = 0;
            break;
        case 'p':
            pin = optarg;
            break;
        case 'n':
            if (strcmp(optarg, "max") == 0)
                iterations = (size_t)-1;
            else
                iterations = (size_t)atoi(optarg);
            do_default = 0;
            break;
        case 'L':
            if ((p = strtok(optarg, ".")) != NULL)
                L_lo = (size_t)atoi(p);
            if ((p = strtok(NULL, ".")) != NULL)
                L_hi = (size_t)atoi(p);
            do_default = 0;
            break;
        case 'l':
            if ((p = strtok(optarg, ".")) != NULL)
                lms_lo = (size_t)atoi(p);
            if ((p = strtok(NULL, ".")) != NULL)
                lms_hi = (size_t)atoi(p);
            do_default = 0;
            break;
        case 'o':
            if ((p = strtok(optarg, ".")) != NULL)
                lmots_lo = (size_t)atoi(p);
            if ((p = strtok(NULL, ".")) != NULL)
                lmots_hi = (size_t)atoi(p);
            do_default = 0;
            break;
        case 'h':
        case '?':
            fprintf(stdout, usage, argv[0]);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, usage, argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (do_default) {
        do_testvec = 1;
        L_lo = 1;
    }

    if (L_hi < L_lo) L_hi = L_lo;
    if (lms_hi < lms_lo) lms_hi = lms_lo;
    if (lmots_hi < lmots_lo) lmots_hi = lmots_lo;

    if ((err = hal_rpc_client_init()) != HAL_OK)
        printf("Warning: Trouble initializing RPC client: %s\n", hal_error_string(err));

    if ((err = hal_rpc_login(client, HAL_USER_NORMAL, pin, strlen(pin))) != HAL_OK)
        printf("Warning: Trouble logging into HSM: %s\n", hal_error_string(err));

    if (do_testvec) {
        for (int i = 0; i < (sizeof(hashsig_tc)/sizeof(*hashsig_tc)); i++)
            ok &= test_hashsig_testvec_local(&hashsig_tc[i], 0);

        for (int i = 0; i < (sizeof(hashsig_tc)/sizeof(*hashsig_tc)); i++)
            for (int j = 0; j < 2; j++)
                ok &= test_hashsig_testvec_remote(&hashsig_tc[i], j * HAL_KEY_FLAG_TOKEN);
    }

    /* signing/performance tests: run with -i */
    /* A single test would be of the form '-L 2 -l 5 -o 3 -n 1' */
    /* A range test of just keygen would be of the form '-o 1..4 -n 0' */
    /* A test to key exhaustion would be of the form '-n max' */
    if (L_lo > 0) {
        for (size_t L = L_lo; L <= L_hi; ++L) {
            for (lms_algorithm_t lms_type = lms_lo; lms_type <= lms_hi; ++lms_type) {
                for (lmots_algorithm_t lmots_type = lmots_lo; lmots_type <= lmots_hi; ++lmots_type) {
                    ok &= test_hashsig_sign(L, lms_type, lmots_type, iterations);
                }
            }
        }
    }

    if ((err = hal_rpc_logout(client)) != HAL_OK)
        printf("Warning: Trouble logging out of HSM: %s\n", hal_error_string(err));

    if ((err = hal_rpc_client_close()) != HAL_OK)
        printf("Warning: Trouble shutting down RPC client: %s\n", hal_error_string(err));

    return !ok;
}
