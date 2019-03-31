/*
 * test-rpc_hashsig.c
 * ------------------
 * Test code for RPC interface to Cryptech public key operations.
 *
 * Copyright (c) 2018, NORDUnet A/S
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
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <hal.h>
#include "test-hashsig.h"

#include <sys/time.h>

#ifndef timersub
#define timersub(a, b, res)                             \
    do {                                                \
        (res)->tv_sec = (a)->tv_sec - (b)->tv_sec;      \
        (res)->tv_usec = (a)->tv_usec - (b)->tv_usec;   \
        if ((res)->tv_usec < 0) {                       \
            (res)->tv_usec += 1000000;                  \
            --(res)->tv_sec;                            \
        }                                               \
    } while (0)
#endif

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
        lose("Error loading public key from test vector: %s\n", hal_error_string(err));

    if ((err = hal_hashsig_verify(NULL, tc_key, tc->msg.val, tc->msg.len, tc->sig.val, tc->sig.len)) != HAL_OK)
        lose("Error verifying: %s\n", hal_error_string(err));

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
            lose("Error loading public key from test vector: %s\n", hal_error_string(err));

        hal_uuid_t public_name;

        uint8_t public_der[hal_hashsig_public_key_to_der_len(tc_key)];

        if ((err = hal_hashsig_public_key_to_der(tc_key, public_der, &len, sizeof(public_der))) != HAL_OK)
            lose("Error DER encoding public key from test vector: %s\n", hal_error_string(err));

        assert(len == sizeof(public_der));

        if ((err = hal_rpc_pkey_load(client, session, &public_key, &public_name,
                                     public_der, sizeof(public_der), flags)) != HAL_OK)
            lose("Error loading public key: %s\n", hal_error_string(err));

        if ((err = hal_rpc_pkey_verify(public_key, hal_hash_handle_none,
                                       tc->msg.val, tc->msg.len, tc->sig.val, tc->sig.len)) != HAL_OK)
            lose("Error verifying: %s\n", hal_error_string(err));

        if ((err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
            goto fail_out;

        printf("OK\n");
        return 1;
    }

fail:
    if (public_key.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
    fail_out:
        printf("Error deleting public key: %s\n", hal_error_string(err));

    return 0;
}

static void hexdump(const char * const label, const uint8_t * const buf, const size_t len)
{
    printf("%-11s ", label);

    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
        if ((i & 0x0f) == 0x0f) {
            printf("\n");
            if (i < len - 1)
                printf("            ");
        }
    }
    if ((len & 0x0f) != 0)
        printf("\n");
}

static inline size_t lms_type_to_h(const hal_lms_algorithm_t lms_type)
{
    switch (lms_type) {
    case HAL_LMS_SHA256_N32_H5:  return  5;
    case HAL_LMS_SHA256_N32_H10: return 10;
    case HAL_LMS_SHA256_N32_H15: return 15;
    case HAL_LMS_SHA256_N32_H20: return 20;
    case HAL_LMS_SHA256_N32_H25: return 25;
    default: return 0;
    }
}

static inline size_t lmots_type_to_w(const hal_lmots_algorithm_t lmots_type)
{
    switch (lmots_type) {
    case HAL_LMOTS_SHA256_N32_W1: return 1;
    case HAL_LMOTS_SHA256_N32_W2: return 2;
    case HAL_LMOTS_SHA256_N32_W4: return 4;
    case HAL_LMOTS_SHA256_N32_W8: return 8;
    default: return 0;
    }
}

static inline size_t lmots_type_to_p(const hal_lmots_algorithm_t lmots_type)
{
    switch (lmots_type) {
    case HAL_LMOTS_SHA256_N32_W1: return 265;
    case HAL_LMOTS_SHA256_N32_W2: return 133;
    case HAL_LMOTS_SHA256_N32_W4: return  67;
    case HAL_LMOTS_SHA256_N32_W8: return  34;
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
            size_t p = lmots_type_to_p((const hal_lmots_algorithm_t)lmots_type);
            for (size_t j = 0; j < p; ++j) {
                char label[16];
                sprintf(label, "y[%lu]", j);
                hexdump(label, sigptr, 32); sigptr += 32;
            }
        }

        hexdump("lms type", sigptr, 4);
        uint32_t lms_type;
        if ((err = hal_xdr_decode_int(&sigptr, siglim, &lms_type)) != HAL_OK) return err;
        size_t h = lms_type_to_h((const hal_lms_algorithm_t)lms_type);
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

static int test_hashsig_generate(const size_t L,
                                 const hal_lms_algorithm_t lms_type,
                                 const hal_lmots_algorithm_t lmots_type,
                                 hal_key_flags_t flags,
                                 const int keep,
                                 hal_pkey_handle_t *handle)
{
    const hal_client_handle_t client = {HAL_HANDLE_NONE};
    const hal_session_handle_t session = {HAL_HANDLE_NONE};
    hal_pkey_handle_t private_key = {HAL_HANDLE_NONE};
    hal_error_t err;
    hal_uuid_t private_name;
    struct timeval tv_start, tv_end, tv_diff;

    if (info) {
        printf("Info: signature length %lu, lmots private key length %lu\n",
               hal_hashsig_signature_len(L, lms_type, lmots_type),
               hal_hashsig_lmots_private_key_len(lmots_type));
        gettimeofday(&tv_start, NULL);
    }

    if ((err = hal_rpc_pkey_generate_hashsig(client, session, &private_key, &private_name,
                                             L, lms_type, lmots_type, flags)) != HAL_OK)
        lose("Error generating private key: %s\n", hal_error_string(err));

    if (info) {
        gettimeofday(&tv_end, NULL);
        timersub(&tv_end, &tv_start, &tv_diff);
        long per_key = (tv_diff.tv_sec * 1000000 + tv_diff.tv_usec) / (L * (1 << lms_type_to_h(lms_type)));
        printf("Info: %ldm%ld.%03lds to generate key (%ld.%03lds per lmots key)\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000,
               (long)per_key / 1000000, ((long)per_key % 1000000) / 1000);
    }

    if (keep) {
        char name_str[HAL_UUID_TEXT_SIZE];
        if ((err = hal_uuid_format(&private_name, name_str, sizeof(name_str))) != HAL_OK)
            lose("Error formatting private key name: %s\n", hal_error_string(err));
        printf("Private key name: %s\n", name_str);
    }

    *handle = private_key;
    printf("OK\n");
    return 1;

fail:
    if (private_key.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(private_key)) != HAL_OK)
        printf("Error deleting private key: %s\n", hal_error_string(err));

    handle->handle = HAL_HANDLE_NONE;
    return 0;
}

static int test_hashsig_sign(const hal_pkey_handle_t private_key,
                             const uint8_t * const msg, const size_t msg_len,
                             const size_t iterations,
                             const char * const save_name,
                             uint8_t *sig, size_t *sig_len, const size_t sig_max)
{
    hal_error_t err;
    struct timeval tv_start, tv_end, tv_diff;
    int i;

    if (info)
        gettimeofday(&tv_start, NULL);

    for (i = 0; i < iterations; ++i) {
        if ((err = hal_rpc_pkey_sign(private_key, hal_hash_handle_none,
                                     msg, msg_len,
                                     sig, sig_len, sig_max)) != HAL_OK) {
            if (i > 0 && err == HAL_ERROR_HASHSIG_KEY_EXHAUSTED)
                break;
            else
                lose("Error signing (%d): %s\n", i, hal_error_string(err));
        }
    }

    if (info) {
        gettimeofday(&tv_end, NULL);
        timersub(&tv_end, &tv_start, &tv_diff);
        long per_sig = (tv_diff.tv_sec * 1000000 + tv_diff.tv_usec) / i;
        printf("Info: %ldm%ld.%03lds to generate %d signatures (%ld.%03lds per signature)\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000, i,
               (long)per_sig / 1000000, ((long)per_sig % 1000000) / 1000);
    }

    if (*save_name) {
        /* save the signature for interop verification */
        char fn[strlen(save_name) + 5];
        sprintf(fn, "%s.sig", save_name);
        FILE *fp;
        if ((fp = fopen(fn, "wb")) == NULL)
            lose("Error opening %s: %s\n", fn, strerror(errno));
        size_t len;
        if ((len = fwrite(sig, 1, *sig_len, fp)) != *sig_len)
            lose("Error: wrote %lu bytes to %s, expected %lu\n", len, fn, *sig_len);
        if (fclose(fp) != 0)
            lose("Error closing %s: %s\n", fn, strerror(errno));
    }

    printf("OK\n");
    return 1;

fail:
    return 0;
}

static int test_hashsig_verify(const hal_pkey_handle_t private_key, 
                               const uint8_t * const msg, const size_t msg_len,
                               const char * const save_name,
                               uint8_t *sig, size_t sig_len)
{
    const hal_client_handle_t client = {HAL_HANDLE_NONE};
    const hal_session_handle_t session = {HAL_HANDLE_NONE};
    hal_error_t err;

    hal_pkey_handle_t public_key = {HAL_HANDLE_NONE};
    hal_uuid_t public_name;
    uint8_t public_der[hal_rpc_pkey_get_public_key_len(private_key)];
    size_t der_len;

    if ((err = hal_rpc_pkey_get_public_key(private_key, public_der, &der_len, sizeof(public_der))) != HAL_OK)
        lose("Error DER encoding public key from private key: %s\n", hal_error_string(err));
    assert(der_len == sizeof(public_der));

    if ((err = hal_rpc_pkey_load(client, session, &public_key, &public_name,
                                 public_der, sizeof(public_der), HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)) != HAL_OK)
        lose("Error loading public key: %s\n", hal_error_string(err));

    if (*save_name) {
        /* save the public key for interop verification */
        char fn[strlen(save_name) + 5];
        sprintf(fn, "%s.pub", save_name);
        FILE *fp;
        if ((fp = fopen(fn, "wb")) == NULL)
            lose("Error opening %s: %s\n", fn, strerror(errno));
        uint8_t pub[60];
        size_t xdr_len;
        if ((err = hal_hashsig_public_key_der_to_xdr(public_der, sizeof(public_der), pub, &xdr_len, sizeof(pub))) != HAL_OK)
            lose("Error XDR encoding public key: %s\n", hal_error_string(err));
        size_t write_len;
        if ((write_len = fwrite(pub, 1, xdr_len, fp)) != xdr_len)
            lose("Wrote %lu bytes to %s, expected %lu\n", write_len, fn, xdr_len);
        if (fclose(fp) != 0)
            lose("Error closing %s: %s\n", fn, strerror(errno));
    }

    struct timeval tv_start, tv_end, tv_diff;
    if (info)
        gettimeofday(&tv_start, NULL);

    if ((err = hal_rpc_pkey_verify(public_key, hal_hash_handle_none,
                                   msg, msg_len, sig, sig_len)) != HAL_OK)
        lose("Error verifying: %s\n", hal_error_string(err));

    if (info) {
        gettimeofday(&tv_end, NULL);
        timersub(&tv_end, &tv_start, &tv_diff);
        printf("Info: %ldm%ld.%03lds to verify 1 signature\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000);
    }

    if ((err = hal_rpc_pkey_delete(public_key)) != HAL_OK)
        lose("Error deleting public key: %s\n", hal_error_string(err));

    printf("OK\n");
    return 1;

fail:
    return 0;
}

static int read_sig(char *fn)
{
    {
        FILE *fp;
        if ((fp = fopen(fn, "rb")) == NULL)
            lose("Error opening %s: %s\n", fn, strerror(errno));

        struct stat statbuf;
        if (stat(fn, &statbuf) != 0)
            lose("Error statting %s: %s\n", fn, strerror(errno));

        uint8_t sig[statbuf.st_size];
        size_t len;
        if ((len = fread(sig, 1, sizeof(sig), fp)) != sizeof(sig))
            lose("Error: read %lu bytes from %s, expected %lu\n", len, fn, sizeof(sig));

        if (fclose(fp) != 0)
            lose("Error closing %s: %s\n", fn, strerror(errno));

        hal_error_t err;
        if ((err = dump_hss_signature(sig, len)) != HAL_OK)
            lose("Error parsing signature: %s\n", hal_error_string(err));
    }

    return 1;
fail:
    return 0;        
}

int main(int argc, char *argv[])
{
    const hal_client_handle_t client = {HAL_HANDLE_NONE};
    const hal_session_handle_t session = {HAL_HANDLE_NONE};
    char *pin = "fnord";
    int do_testvec = 0;
    size_t iterations = 0;
    size_t L_lo = 0, L_hi = 0;
    size_t lms_lo = 5, lms_hi = 0;
    size_t lmots_lo = 3, lmots_hi = 0;
    int save = 0, keep = 0, verify = 0;
    char *name = NULL;
    hal_key_flags_t flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN;
    char *p;
    hal_error_t err;
    int ok = 1;
    uint8_t *msg = tc1_msg;
    size_t msg_len = sizeof(tc1_msg);

char usage[] = "\
Usage: %s [-i] [-p pin] [-t] [-L #] [-l #] [-o #] [-n #] [-s] [-r file] [-m file] [-x] [-v]\n\
       -i: enable informational messages - runtimes and signature lengths\n\
       -p: user PIN\n\
       -t: verify test vectors\n\
       -L: number of levels in the HSS scheme (1..8)\n\
       -l: LMS type (5..9)\n\
       -o: LM-OTS type (1..4)\n\
       -n: number of signatures to generate (0..'max')\n\
       -k: keep (don't delete) the generated keys on the hsm\n\
       -K: use named key for signing (don't generate)\n\
       -s: save generated public key and signatures for interop verification\n\
       -r: read and pretty-print a saved signature file\n\
       -m: use file as message to be signed\n\
       -x: mark key as exportable\n\
       -v: verify generated signature\n\
Numeric arguments can be a single number or a range, e.g. '1..4'\n";

    int opt;
    while ((opt = getopt(argc, argv, "itp:L:l:o:n:skK:r:xvm:h?")) != -1) {
        switch (opt) {
        case 'i':
            info = 1;
            break;
        case 't':
            do_testvec = 1;
            break;
        case 'p':
            pin = optarg;
            break;
        case 'n':
            if (strcmp(optarg, "max") == 0)
                iterations = (size_t)-1;
            else
                iterations = (size_t)atoi(optarg);
            break;
        case 'L':
            if ((p = strtok(optarg, ".")) != NULL)
                L_lo = (size_t)atoi(p);
            if ((p = strtok(NULL, ".")) != NULL)
                L_hi = (size_t)atoi(p);
            break;
        case 'l':
            if ((p = strtok(optarg, ".")) != NULL)
                lms_lo = (size_t)atoi(p);
            if ((p = strtok(NULL, ".")) != NULL)
                lms_hi = (size_t)atoi(p);
            break;
        case 'o':
            if ((p = strtok(optarg, ".")) != NULL)
                lmots_lo = (size_t)atoi(p);
            if ((p = strtok(NULL, ".")) != NULL)
                lmots_hi = (size_t)atoi(p);
            break;
        case's':
            save = 1;
            break;
        case 'k':
            keep = 1;
            break;
        case 'K':
            name = optarg;
            break;
        case 'r':
            ok &= read_sig(optarg);
            break;
        case 'x':
            flags |= HAL_KEY_FLAG_EXPORTABLE;
            break;
        case 'v':
            verify = 1;
            if (iterations == 0)
                iterations = 1;
            break;
        case 'm':
        {
            FILE *fp;
            struct stat statbuf;
            if (stat(optarg, &statbuf) != 0)
                lose("Error statting %s: %s\n", optarg, strerror(errno));
            msg_len = statbuf.st_size;
            if ((msg = malloc(msg_len)) == NULL)
                lose("Error allocating message buffer: %s\n", strerror(errno));
            if ((fp = fopen(optarg, "rb")) == NULL)
                lose("Error opening %s: %s\n", optarg, strerror(errno));
            size_t len;
            if ((len = fread(msg, 1, msg_len, fp)) != msg_len)
                lose("Error: read %lu bytes from %s, expected %lu\n", len, optarg, msg_len);
            if (fclose(fp) != 0)
                lose("Error closing %s: %s\n", optarg, strerror(errno));
            break;
        }
        case 'h':
        case '?':
            fprintf(stdout, usage, argv[0]);
            return EXIT_SUCCESS;
        default:
            fprintf(stderr, usage, argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (L_hi < L_lo) L_hi = L_lo;
    if (lms_hi < lms_lo) lms_hi = lms_lo;
    if (lmots_hi < lmots_lo) lmots_hi = lmots_lo;

    if ((err = hal_rpc_client_init()) != HAL_OK)
        lose("Error initializing RPC client: %s\n", hal_error_string(err));

    if ((err = hal_rpc_login(client, HAL_USER_NORMAL, pin, strlen(pin))) != HAL_OK)
        lose("Error logging into HSM: %s\n", hal_error_string(err));

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

    if (name != NULL) {
        hal_uuid_t uuid;
        hal_pkey_handle_t private_key = {HAL_HANDLE_NONE};

        if ((err = hal_uuid_parse(&uuid, name)) != HAL_OK)
            lose("Error parsing private key name: %s\n", hal_error_string(err));

        else if ((err = hal_rpc_pkey_open(client, session, &private_key, &uuid)) != HAL_OK)
            lose("Error opening private key: %s\n", hal_error_string(err));

        if (save) {
            /* save the message for interop verification */
            FILE *fp;
            if ((fp = fopen(name, "wb")) == NULL)
                lose("Error opening %s: %s\n", name, strerror(errno));
            size_t write_len;
            if ((write_len = fwrite(msg, 1, msg_len, fp)) != msg_len)
                lose("Error: wrote %lu bytes to %s, expected %lu\n", write_len, name, msg_len);
            if (fclose(fp) != 0)
                lose("Error closing %s: %s\n", name, strerror(errno));
        }

        uint8_t sig[16000];
        size_t sig_len;
        if (iterations > 0)
            ok &= test_hashsig_sign(private_key, msg, msg_len, iterations,
                                    save ? name : "", sig, &sig_len, sizeof(sig));

        if (ok && verify)
            ok &= test_hashsig_verify(private_key, msg, msg_len, save ? name : "", sig, sig_len);

        /* implicitly keep the key */
    }

    else {
        if (L_lo) {
            for (size_t L = L_lo; L <= L_hi; ++L) {
                for (hal_lms_algorithm_t lms_type = lms_lo; lms_type <= lms_hi; ++lms_type) {
                    for (hal_lmots_algorithm_t lmots_type = lmots_lo; lmots_type <= lmots_hi; ++lmots_type) {
                        printf("Starting hashsig key test: L %lu, lms type %u (h=%lu), lmots type %u (w=%lu)\n",
                               L, lms_type, lms_type_to_h(lms_type), lmots_type, lmots_type_to_w(lmots_type));

                        char save_name[16] = "";
                        if (save) {
                            /* save the message for interop verification */
                            sprintf(save_name, "L%d.lms%d.ots%d", (int)L, (int)lms_type, (int)lmots_type);
                            FILE *fp;
                            if ((fp = fopen(save_name, "wb")) == NULL)
                                lose("Error opening %s: %s\n", save_name, strerror(errno));
                            size_t write_len;
                            if ((write_len = fwrite(msg, 1, msg_len, fp)) != msg_len)
                                lose("Error: wrote %lu bytes to %s, expected %lu\n", write_len, save_name, msg_len);
                            if (fclose(fp) != 0)
                                lose("Error closing %s: %s\n", save_name, strerror(errno));
                        }

                        hal_pkey_handle_t private_key = {HAL_HANDLE_NONE};
                        ok &= test_hashsig_generate(L, lms_type, lmots_type, flags, keep, &private_key);

                        uint8_t sig[hal_hashsig_signature_len(L, lms_type, lmots_type)];
                        size_t sig_len;
                        if (ok && iterations > 0)
                            ok &= test_hashsig_sign(private_key, msg, msg_len, iterations, save_name, sig, &sig_len, sizeof(sig));

                        if (ok && verify)
                            ok &= test_hashsig_verify(private_key, msg, msg_len, save_name, sig, sig_len);

                        if (!keep && ((err = hal_rpc_pkey_delete(private_key)) != HAL_OK))
                            lose("Error deleting private key: %s\n", hal_error_string(err));
                    }
                }
            }
        }
    }

    if ((err = hal_rpc_logout(client)) != HAL_OK)
        lose("Error logging out of HSM: %s\n", hal_error_string(err));

    if ((err = hal_rpc_client_close()) != HAL_OK)
        lose("Error shutting down RPC client: %s\n", hal_error_string(err));

fail:
    return !ok;
}
