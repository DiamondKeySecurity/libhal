/*
 * pkey.c
 * ------
 * Fully-featured key management app
 *
 * Copyright (c) 2018, NORDUnet A/S All rights reserved.
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <hal.h>

/*
 * The all-singing, all-dancing key management app.
 * This is designed so that commands can be concatenated, e.g.
 *
 *   pkey generate rsa sign -h -n 100 verify -h delete
 *
 * i.e. Generate an RSA key with default parameters, hash the default message
 * and sign it 100 times, verify the signature, and delete the key.
 *
 * generate rsa [-l keylen-in-bits] [-e exponent]
 * generate ec [-c curve]
 * generate hashsig [-L levels] [-h height] [-w Winternitz factor]
 * list [-t type] [-c curve] [-y keystore]
 * sign [-h (hash)] [-k keyname] [-m msgfile] [-s sigfile] [-n iterations]
 * verify [-h (hash)] [-k keyname] [-m msgfile] [-s sigfile]
 * export [-k keyname] [-K kekekfile] [-o outfile]
 * import [-K kekekfile] [-i infile] [-x (exportable)] [-v (volatile keystore)]
 * delete [-k keyname]
 */

/*
 * By default, GNU getopt() permutes the arguments to put all options first,
 * followed by non-options. Adding a dash at the start of the option string
 * preserves argument ordering by treating any non-option as an option with
 * character code 1.
 *
 * In contrast, BSD getopt() does not permute the arguments, but returns -1 on
 * the first non-option it sees (and ignores a leading dash in the option
 * string, thank god).
 *
 * We can't predict or detect which version of getopt() we get linked with, so
 * we do this weird hybrid, where option value 1 causes the parser to back up
 * one and drop out.
 */

#define HAL_KS_WRAPPED_KEYSIZE  ((2373 + 6 * 4096 / 8 + 6 * 4 + 15) & ~7)

#define lose(...) do { printf(__VA_ARGS__); goto fail; } while (0)

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
static char *pin = "fnord";

static hal_pkey_handle_t key_handle = {HAL_HANDLE_NONE};
static hal_uuid_t key_uuid = {{0}};

#define DFLT_MSG "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
static uint8_t msg[16000] = DFLT_MSG;
static size_t msg_len = sizeof(DFLT_MSG);

static uint8_t sig[16000] = "";
static size_t sig_len = 0;

static hal_key_flags_t flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN;

static const hal_client_handle_t client = {HAL_HANDLE_NONE};
static const hal_session_handle_t session = {HAL_HANDLE_NONE};

static size_t file_size(const char * const fn)
{
    struct stat statbuf;
    if (stat(fn, &statbuf) != 0) {
        printf("%s: %s\n", fn, strerror(errno));
        return SIZE_MAX;
    }

    return statbuf.st_size;
}

static int file_read(const char * const fn, void *buf, size_t *buf_len, const size_t buf_max)
{
    size_t fsize = file_size(fn);
    if (fsize == SIZE_MAX)
        return -1;
    if (fsize > buf_max)
        lose("Error: %s (%lu bytes) is too big for buffer (%lu bytes)\n", fn, fsize, buf_max);

    FILE *fp;
    if ((fp = fopen(fn, "rb")) == NULL)
        lose("Error opening %s: %s\n", fn, strerror(errno));

    size_t len;
    if ((len = fread(buf, 1, fsize, fp)) != fsize)
        lose("Error: read %lu bytes from %s, expected %lu\n", len, fn, fsize);

    if (fclose(fp) != 0)
        lose("Error closing %s: %s\n", fn, strerror(errno));

    *buf_len = len;
    return 0;

fail:
    return -1;
}

static int file_write(const char * const fn, const void * const buf, const size_t buf_len, int secret)
{
    FILE *fp;
    if ((fp = fopen(fn, "wb")) == NULL)
        lose("Error opening %s: %s\n", fn, strerror(errno));

    size_t nwrite;
    if ((nwrite = fwrite(buf, 1, buf_len, fp)) != buf_len)
        lose("Error writing %s: wrote %lu, expected %lu\n", fn, nwrite, buf_len);

    if (fclose(fp) != 0)
        lose("Error closing %s: %s\n", fn, strerror(errno));

    if (secret && chmod(fn, S_IRUSR) != 0)
        lose("Error chmod'ing %s: %s\n", fn, strerror(errno));

    return 0;

fail:
    (void)unlink(fn);
    return -1;
}

static int logged_in = 0;
static int pkey_login(void)
{
    if (!logged_in) {
        hal_error_t err = HAL_OK;

        if ((err = hal_rpc_client_init()) != HAL_OK)
            lose("Error initializing RPC client: %s\n", hal_error_string(err));

        if ((err = hal_rpc_login(client, HAL_USER_NORMAL, pin, strlen(pin))) != HAL_OK)
            lose("Error logging into HSM: %s\n", hal_error_string(err));

        logged_in = 1;
    }
    return 0;

fail:
    return -1;
}

static int pkey_logout(void)
{
    if (logged_in) {
        hal_error_t err = HAL_OK;

        if ((err = hal_rpc_logout(client)) != HAL_OK)
            lose("Error logging out of HSM: %s\n", hal_error_string(err));

        if ((err = hal_rpc_client_close()) != HAL_OK)
            lose("Error shutting down RPC client: %s\n", hal_error_string(err));

        logged_in = 0;
    }
    return 0;

fail:
    return -1;
}

static int pkey_open(const char * const key_name)
{
    hal_error_t err;
    if (key_handle.handle == HAL_HANDLE_NONE) {
        if ((err = hal_uuid_parse(&key_uuid, key_name)) != HAL_OK)
            lose("Error parsing key name: %s\n", hal_error_string(err));
        if ((err = hal_rpc_pkey_open(client, session, &key_handle, &key_uuid)) != HAL_OK)
            lose("Error opening key: %s\n", hal_error_string(err));
    }
    return 0;

fail:
    key_handle.handle = HAL_HANDLE_NONE;
    return -1;
}

static int pkey_load(const char * const fn, hal_pkey_handle_t *key_handle)
{
    size_t der_len = file_size(fn);
    if (der_len == SIZE_MAX)
        return -1;
    uint8_t der[der_len];
    if (file_read(fn, der, &der_len, sizeof(der)) == -1)
        return -1;

    hal_pkey_handle_t handle = {HAL_HANDLE_NONE};
    hal_uuid_t uuid;
    hal_error_t err;
    if ((err = hal_rpc_pkey_load(client, session, &handle, &uuid,
                                 der, der_len,
                                 HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT)) != HAL_OK)
        lose("Error loading key: %s\n", hal_error_string(err));

    *key_handle = handle;

    return 0;

fail:
    return -1;
}

static int pkey_gen_rsa(int argc, char *argv[])
{
    char usage[] = "Usage: generate rsa [-l keylen-in-bits] [-e exponent]";

    unsigned keylen = 1024;
    unsigned long exponent = 0x010001; /* default exponent, and the only one accepted by hal_rsa_key_gen */
    uint8_t exp[sizeof(exponent)];

    int opt;
    while ((opt = getopt(argc, argv, "-l:e:xv")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
        case 'l':
            keylen = atoi(optarg);
            break;
        case 'e':
        {
            char *endptr;
            exponent = (uint32_t)strtoul(optarg, &endptr, 0);
            if (endptr == optarg || errno == ERANGE) {
                printf("invalid exponent %s\n", optarg);
                puts(usage);
                return -1;
            }
            break;
        }
        case 'x':
            flags |= HAL_KEY_FLAG_EXPORTABLE;
            break;
        case 'v':
            flags &= ~HAL_KEY_FLAG_TOKEN;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    for (int i = sizeof(exp) - 1; i >= 0; --i) {
        exp[i] = exponent & 0xff;
        exponent >>= 8;
    }

    struct timeval tv_start, tv_end, tv_diff;
    if (info)
        gettimeofday(&tv_start, NULL);

    hal_error_t err;
    if ((err = hal_rpc_pkey_generate_rsa(client, session, &key_handle, &key_uuid,
                                         keylen, exp, sizeof(exp), flags)) != HAL_OK)
        lose("Could not generate RSA private key: %s\n", hal_error_string(err));

    if (info) {
        gettimeofday(&tv_end, NULL);
        timersub(&tv_end, &tv_start, &tv_diff);
        printf("Info: %ldm%ld.%03lds to generate key\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000);
    }

    char key_name[HAL_UUID_TEXT_SIZE];
    if ((err = hal_uuid_format(&key_uuid, key_name, sizeof(key_name))) != HAL_OK)
        lose("Error formatting private key name: %s\n", hal_error_string(err));
    if (info)
        printf("Private key name: %s\n", key_name);

    return 0;

fail:
    if (key_handle.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(key_handle)) != HAL_OK)
        printf("Error deleting private key: %s\n", hal_error_string(err));

    key_handle.handle = HAL_HANDLE_NONE;

    return -1;
}

static int pkey_gen_ec(int argc, char *argv[])
{
    char usage[] = "Usage: generate ec [-c curve]";

    hal_curve_name_t curve = HAL_CURVE_P256;
    hal_error_t err;
    struct timeval tv_start, tv_end, tv_diff;

    int opt;
    while ((opt = getopt(argc, argv, "-c:xv")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
        case 'c':
            if (strcasecmp(optarg, "P256") == 0)
                curve = HAL_CURVE_P256;
            else if (strcasecmp(optarg, "P384") == 0)
                curve = HAL_CURVE_P384;
            else if (strcasecmp(optarg, "P521") == 0)
                curve = HAL_CURVE_P521;
            else {
                printf("generate ec: invalid curve %s - must be one of P256, P384, P521\n", optarg);
                return -1;
            }
            break;
        case 'x':
            flags |= HAL_KEY_FLAG_EXPORTABLE;
            break;
        case 'v':
            flags &= ~HAL_KEY_FLAG_TOKEN;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (info)
        gettimeofday(&tv_start, NULL);

    if ((err = hal_rpc_pkey_generate_ec(client, session, &key_handle, &key_uuid,
                                        curve, flags)) != HAL_OK)
        lose("Could not generate EC private key: %s\n", hal_error_string(err));

    if (info) {
        gettimeofday(&tv_end, NULL);
        timersub(&tv_end, &tv_start, &tv_diff);
        printf("Info: %ldm%ld.%03lds to generate key\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000);
    }

    char key_name[HAL_UUID_TEXT_SIZE];
    if ((err = hal_uuid_format(&key_uuid, key_name, sizeof(key_name))) != HAL_OK)
        lose("Error formatting private key name: %s\n", hal_error_string(err));
    if (info)
        printf("Private key name: %s\n", key_name);

    return 0;

fail:
    if (key_handle.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(key_handle)) != HAL_OK)
        printf("Error deleting private key: %s\n", hal_error_string(err));

    key_handle.handle = HAL_HANDLE_NONE;

    return -1;
}

static int pkey_gen_hashsig(int argc, char *argv[])
{
    char usage[] = "Usage: generate hashsig [-L levels] [-h height] [-w Winternitz factor]";

    unsigned L = 1, h = 5, w = 2;
    hal_lms_algorithm_t lms_type;
    hal_lmots_algorithm_t lmots_type;

    int opt;
    while ((opt = getopt(argc, argv, "-L:h:w:xv")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
        case 'L':
            L = atoi(optarg);
            break;
        case 'h':
            h = atoi(optarg);
            break;
        case 'w':
            w = atoi(optarg);
            break;
        case 'x':
            flags |= HAL_KEY_FLAG_EXPORTABLE;
            break;
        case 'v':
            flags &= ~HAL_KEY_FLAG_TOKEN;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    switch (h) {
    case 5:
        lms_type = HAL_LMS_SHA256_N32_H5;
        break;
    case 10:
        lms_type = HAL_LMS_SHA256_N32_H10;
        break;
    default:
        printf("generate hashsig: invalid/unsupported h value %u\n", h);
        return -1;
    }
        
    switch (w) {
    case 1:
        lmots_type = HAL_LMOTS_SHA256_N32_W1;
        break;
    case 2:
        lmots_type = HAL_LMOTS_SHA256_N32_W2;
        break;
    case 4:
        lmots_type = HAL_LMOTS_SHA256_N32_W4;
        break;
    case 8:
        lmots_type = HAL_LMOTS_SHA256_N32_W8;
        break;
    default:
        printf("generate hashsig: invalid w value %u\n", w);
        return -1;
    }
        
    hal_error_t err;
    struct timeval tv_start, tv_end, tv_diff;

    if (info) {
        printf("Info: signature length %lu, lmots private key length %lu\n",
               hal_hashsig_signature_len(L, lms_type, lmots_type),
               hal_hashsig_lmots_private_key_len(lmots_type));
        gettimeofday(&tv_start, NULL);
    }

    if ((err = hal_rpc_pkey_generate_hashsig(client, session, &key_handle, &key_uuid,
                                             L, lms_type, lmots_type, flags)) != HAL_OK)
        lose("Error generating private key: %s\n", hal_error_string(err));

    if (info) {
        gettimeofday(&tv_end, NULL);
        timersub(&tv_end, &tv_start, &tv_diff);
        long per_key = (tv_diff.tv_sec * 1000000 + tv_diff.tv_usec) / (L * (1 << h));
        printf("Info: %ldm%ld.%03lds to generate key (%ld.%03lds per lmots key)\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000,
               (long)per_key / 1000000, ((long)per_key % 1000000) / 1000);
    }

    char key_name[HAL_UUID_TEXT_SIZE];
    if ((err = hal_uuid_format(&key_uuid, key_name, sizeof(key_name))) != HAL_OK)
        lose("Error formatting private key name: %s\n", hal_error_string(err));
    if (info)
        printf("Private key name: %s\n", key_name);

    return 0;

fail:
    if (key_handle.handle != HAL_HANDLE_NONE &&
        (err = hal_rpc_pkey_delete(key_handle)) != HAL_OK)
        printf("Error deleting private key: %s\n", hal_error_string(err));

    key_handle.handle = HAL_HANDLE_NONE;

    return -1;
}

static int pkey_generate(int argc, char *argv[])
{
    char usage[] = "Usage: generate [-x (exportable)] [-v (volatile keystore)] rsa|ec|hashsig";

    int opt;
    while ((opt = getopt(argc, argv, "-xv")) != -1) {
        switch (opt) {
        case 1:
            /* found the keytype argument */
            --optind;
            goto done;
        case 'x':
            flags |= HAL_KEY_FLAG_EXPORTABLE;
            break;
        case 'v':
            flags &= ~HAL_KEY_FLAG_TOKEN;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (optind < argc) {
        optarg = argv[optind++];
        if (strcmp(optarg, "rsa") == 0)
            return pkey_gen_rsa(argc, argv);
        else if (strcmp(optarg, "ec") == 0)
            return pkey_gen_ec(argc, argv);
        else if (strcmp(optarg, "hashsig") == 0)
            return pkey_gen_hashsig(argc, argv);
        else {
            printf("generate: unknown key type %s\n", optarg);
            puts(usage);
            return -1;
        }
    }
    else {
        printf("generate: missing key type\n");
        puts(usage);
        return -1;
    }
}

static int pkey_list(int argc, char *argv[])
{
    char usage[] = "Usage: list [-t type] [-c curve] [-y keystore]";

#if 0
    char *type = NULL;
    char *curve = NULL;
    char *keystore = NULL;
#endif

    int type_rsa = 0, type_ec = 0, type_hashsig = 0;

    int opt;
    while ((opt = getopt(argc, argv, "-t:c:y:")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
        case 't':
            if (strcasecmp(optarg, "rsa") == 0)
                type_rsa = 1;
            else if (strcasecmp(optarg, "ec") == 0)
                type_ec = 1;
            else if (strcasecmp(optarg, "hashsig") == 0)
                type_hashsig = 1;
            else
                lose("unsupported key type %s, expected 'rsa', 'ec', or 'hashsig'\n", optarg);
            break;
#if 0
        case 'c':
            curve = optarg;
            break;
        case 'y':
            keystore = optarg;
            break;
#endif
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (type_rsa == 0 && type_ec == 0 && type_hashsig == 0)
        type_rsa = type_ec = type_hashsig = 1;

    char key_name[HAL_UUID_TEXT_SIZE];
    hal_uuid_t previous_uuid = {{0}};
    hal_pkey_handle_t pkey;
    hal_curve_name_t curve;
    hal_key_flags_t flags;
    unsigned n, state = 0;
    hal_uuid_t uuids[50];
    hal_key_type_t type;
    hal_error_t err;
    int done = 0;

    while (!done) {

	if ((err = hal_rpc_pkey_match(client, session, HAL_KEY_TYPE_NONE, HAL_CURVE_NONE,
					 0, 0, NULL, 0, &state, uuids, &n,
					 sizeof(uuids)/sizeof(*uuids),
					 &previous_uuid)) != HAL_OK) {
	    printf("Could not fetch UUID list: %s\n", hal_error_string(err));
	    return -1;
	}

	done = n < sizeof(uuids)/sizeof(*uuids);

	if (!done)
	    previous_uuid = uuids[sizeof(uuids)/sizeof(*uuids) - 1];

	for (unsigned i = 0; i < n; i++) {

	    if ((err = hal_uuid_format(&uuids[i], key_name, sizeof(key_name))) != HAL_OK) {
		printf("Could not convert key name, skipping: %s\n",
			  hal_error_string(err));
		continue;
	    }

	    if ((err = hal_rpc_pkey_open(client, session, &pkey, &uuids[i])) != HAL_OK) {
	        printf("Could not open key %s, skipping: %s\n",
			  key_name, hal_error_string(err));
		continue;
	    }

	    if ((err = hal_rpc_pkey_get_key_type(pkey, &type))   != HAL_OK ||
		(err = hal_rpc_pkey_get_key_curve(pkey, &curve)) != HAL_OK ||
		(err = hal_rpc_pkey_get_key_flags(pkey, &flags)) != HAL_OK)
	        printf("Could not fetch metadata for key %s, skipping: %s\n",
			  key_name, hal_error_string(err));

	    if (err == HAL_OK)
	        err = hal_rpc_pkey_close(pkey);
	    else
	        (void) hal_rpc_pkey_close(pkey);

	    if (err != HAL_OK)
	        continue;

	    const char *type_name = "unknown";
	    switch (type) {
	    case HAL_KEY_TYPE_RSA_PRIVATE:
                if (!type_rsa) continue;
                type_name = "RSA private";
                break;
	    case HAL_KEY_TYPE_RSA_PUBLIC:
                if (!type_rsa) continue;
                type_name = "RSA public";
                break;
	    case HAL_KEY_TYPE_EC_PRIVATE:
                if (!type_ec) continue;
                type_name = "EC private";
                break;
	    case HAL_KEY_TYPE_EC_PUBLIC:
                if (!type_hashsig) continue;
                type_name = "EC public";
                break;
            case HAL_KEY_TYPE_HASHSIG_PRIVATE:
                if (!type_hashsig) continue;
                type_name = "hashsig private";
                break;
            case HAL_KEY_TYPE_HASHSIG_PUBLIC:
                if (!type_hashsig) continue;
                type_name = "hashsig public";
                break;
            default:
                continue;
	    }

	    const char *curve_name = "unknown";
	    switch (curve) {
	    case HAL_CURVE_NONE:		curve_name = "none";		break;
	    case HAL_CURVE_P256:		curve_name = "P-256";		break;
	    case HAL_CURVE_P384:		curve_name = "P-384";		break;
	    case HAL_CURVE_P521:		curve_name = "P-521";		break;
	    }

	    printf("name %s, type %s, ", key_name, type_name);
            if (curve != HAL_CURVE_NONE)
                printf("curve %s, ", curve_name);
            printf("flags 0x%lx\n", (unsigned long) flags);
	}
    }

    return 0;

fail:
    return -1;
}

/* Hash and PKCS #1 encode a message, because that's what RSA and ECDSA(?)
 * expect to sign, rather than plaintext.
 *
 * Also, do the full hashing here, rather than passing a hash handle to
 * sign/verify, because we may want to sign/verify repeatedly to get
 * performance numbers.
 */
static int hash_message(uint8_t *digest, size_t *digest_len, const size_t digest_max)
{
    hal_error_t err;
    hal_hash_handle_t hash;

    if ((err = hal_rpc_hash_initialize(client, session, &hash, HAL_DIGEST_ALGORITHM_SHA256, NULL, 0)) != HAL_OK)
        lose("sign: Error initializing hash: %s\n", hal_error_string(err));

    if ((err = hal_rpc_hash_update(hash, msg, msg_len)) != HAL_OK)
        lose("sign: Error updating hash: %s\n", hal_error_string(err));

    extern hal_error_t hal_rpc_pkcs1_construct_digestinfo(const hal_hash_handle_t handle,
                                                          uint8_t *digest_info,
                                                          size_t *digest_info_len,
                                                          const size_t digest_info_max);
    if ((err = hal_rpc_pkcs1_construct_digestinfo(hash, digest, digest_len, digest_max)) != HAL_OK)
        lose("sign: Error constructing PKCS #1 DigestInfo: %s\n", hal_error_string(err));

    return 0;

fail:
    return -1;
}

static int pkey_sign(int argc, char *argv[])
{
    char usage[] = "Usage: sign [-h (hash)] [-k keyname] [-m msgfile] [-s sigfile] [-n iterations]";

    char *sig_fn = NULL;
    unsigned n = 1;
    int hash_msg = 0;

    int opt;
    while ((opt = getopt(argc, argv, "-hk:m:s:n:")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
        case 'h':
            hash_msg = 1;
            break;
        case 'k':
            if (pkey_open(optarg) != 0)
                return -1;
            break;
        case 'm':
            if (file_read(optarg, msg, &msg_len, sizeof(msg)) != 0)
                return -1;
            break;
        case 's':
            sig_fn = optarg;
            break;
        case 'n':
            n = atoi(optarg);
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (key_handle.handle == HAL_HANDLE_NONE) {
        printf("sign: missing key\n");
        puts(usage);
        return -1;
    }

    if (msg_len == 0) {
        printf("sign: missing message\n");
        puts(usage);
        return -1;
    }

    uint8_t *m = msg;
    size_t mlen = msg_len;
    uint8_t digest[128];
    if (hash_msg && hash_message(m = digest, &mlen, sizeof(digest)) != 0)
        goto fail;

    struct timeval tv_start, tv_end, tv_diff;
    if (info)
        gettimeofday(&tv_start, NULL);

    unsigned i;
    for (i = 0; i < n; ++i) {
        hal_error_t err;
        if ((err = hal_rpc_pkey_sign(key_handle, hal_hash_handle_none,
                                     m, mlen, sig, &sig_len, sizeof(sig))) != HAL_OK) {
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
        printf("Info: %ldm%ld.%03lds to generate %d signatures of length %lu (%ld.%03lds per signature)\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000, i, sig_len,
               (long)per_sig / 1000000, ((long)per_sig % 1000000) / 1000);
    }

    if (sig_fn != NULL && file_write(sig_fn, sig, sig_len, 0) != 0)
        return -1;

    return 0;

fail:
    return -1;
}

static int pkey_verify(int argc, char *argv[])
{
    char usage[] = "Usage: verify [-h (hash)] [-k keyname] [-m msgfile] [-s sigfile]";

    int hash_msg = 0;

    int opt;
    while ((opt = getopt(argc, argv, "-hk:m:s:")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
            break;
        case 'h':
            hash_msg = 1;
            break;
        case 'k':
            if (pkey_open(optarg) != 0)
                return -1;
            break;
        case 'm':
            if (file_read(optarg, msg, &msg_len, sizeof(msg)) != 0)
                return -1;
            break;
        case 's':
            if (file_read(optarg, sig, &sig_len, sizeof(sig)) != 0)
                return -1;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (key_handle.handle == HAL_HANDLE_NONE) {
        printf("verify: missing key\n");
        puts(usage);
        return -1;
    }

    if (msg_len == 0) {
        printf("verify: missing message\n");
        puts(usage);
        return -1;
    }

    if (sig_len == 0) {
        printf("verify: missing signature\n");
        puts(usage);
        return -1;
    }

    uint8_t *m = msg;
    size_t mlen = msg_len;
    uint8_t digest[128];
    if (hash_msg && hash_message(m = digest, &mlen, sizeof(digest)) != 0)
        goto fail;

    hal_error_t err;
    struct timeval tv_start, tv_end, tv_diff;
    if (info)
        gettimeofday(&tv_start, NULL);

    if ((err = hal_rpc_pkey_verify(key_handle, hal_hash_handle_none,
                                   m, mlen, sig, sig_len)) != HAL_OK)
        lose("Error verifying: %s\n", hal_error_string(err));

    if (info) {
        gettimeofday(&tv_end, NULL);
        timersub(&tv_end, &tv_start, &tv_diff);
        printf("Info: %ldm%ld.%03lds to verify 1 signature\n",
               (long)tv_diff.tv_sec / 60, (long)tv_diff.tv_sec % 60, (long)tv_diff.tv_usec / 1000);
    }

    return 0;

fail:
    return -1;
}

static int pkey_export(int argc, char *argv[])
{
    char usage[] = "Usage: export [-k keyname] [-K kekekfile] [-o outfile]";

    hal_pkey_handle_t kekek_handle = {HAL_HANDLE_NONE};
    char *kekek_fn = NULL;
    char *out_fn = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "-k:K:o:")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
            break;
        case 'k':
            if (pkey_open(optarg) != 0)
                return -1;
            break;
        case 'K':
            kekek_fn = optarg;
            break;
        case 'o':
            out_fn = optarg;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (key_handle.handle == HAL_HANDLE_NONE) {
        printf("export: missing key\n");
        puts(usage);
        return -1;
    }

    if (kekek_fn == NULL) {
        printf("export: missing kekek\n");
        puts(usage);
        return -1;
    }

    {
        hal_error_t err;
        char key_name[HAL_UUID_TEXT_SIZE];
        if (out_fn == NULL) {
            if ((err = hal_uuid_format(&key_uuid, key_name, sizeof(key_name))) != HAL_OK)
                lose("Error formatting private key name: %s\n", hal_error_string(err));
            out_fn = key_name;
        }

        if (pkey_load(kekek_fn, &kekek_handle) != 0)
            goto fail;

        uint8_t der[HAL_KS_WRAPPED_KEYSIZE]; size_t der_len;
        uint8_t kek[HAL_KS_WRAPPED_KEYSIZE]; size_t kek_len;

        if ((err = hal_rpc_pkey_export(key_handle, kekek_handle,
                                       der, &der_len, sizeof(der),
                                       kek, &kek_len, sizeof(kek))) != HAL_OK)
            lose("Error exporting private key: %s\n", hal_error_string(err));

        char fn[strlen(out_fn) + 5];
        strcpy(fn, out_fn); strcat(fn, ".der");
        if (file_write(fn, der, der_len, 1) != 0)
            goto fail;

        strcpy(fn, out_fn); strcat(fn, ".kek");
        if (file_write(fn, kek, kek_len, 1) != 0)
            goto fail;

        if ((err = hal_rpc_pkey_delete(kekek_handle)) != HAL_OK)
            lose("Could not delete key: %s\n", hal_error_string(err));
    }

    return 0;

fail:
    if (kekek_handle.handle != HAL_HANDLE_NONE)
        (void)hal_rpc_pkey_delete(kekek_handle);

    return -1;
}

static int pkey_import(int argc, char *argv[])
{
    char usage[] = "Usage: import [-K kekekfile] [-i infile] [-x (exportable)] [-v (volatile keystore)]";

    hal_pkey_handle_t kekek_handle = {HAL_HANDLE_NONE};
    char *kekek_fn = NULL;
    char *in_fn = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "-K:i:xv")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
            break;
        case 'K':
            kekek_fn = optarg;
            break;
        case 'i':
            in_fn = optarg;
            break;
        case 'x':
            flags |= HAL_KEY_FLAG_EXPORTABLE;
            break;
        case 'v':
            flags &= ~HAL_KEY_FLAG_TOKEN;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (kekek_fn == NULL) {
        printf("export: missing kekek\n");
        puts(usage);
        return -1;
    }

    if (in_fn == NULL) {
        printf("export: missing infile\n");
        puts(usage);
        return -1;
    }

    if (pkey_load(kekek_fn, &kekek_handle) != 0)
        goto fail;

    {
        char fn[strlen(in_fn) + 5];
        strcpy(fn, in_fn); strcat(fn, ".der");
        size_t der_len = file_size(fn);
        if (der_len == SIZE_MAX)
            goto fail;
        uint8_t der[der_len];
        if (file_read(fn, der, &der_len, sizeof(der)) != 0)
            goto fail;

        strcpy(fn, in_fn); strcat(fn, ".kek");
        size_t kek_len = file_size(fn);
        if (kek_len == SIZE_MAX)
            goto fail;
        uint8_t kek[kek_len]; 
        if (file_read(fn, kek, &kek_len, sizeof(kek)) != 0)
            goto fail;

        hal_error_t err;
        if ((err = hal_rpc_pkey_import(client, session,
                                       &key_handle, &key_uuid,
                                       kekek_handle,
                                       der, der_len,
                                       kek, kek_len,
                                       flags)) != HAL_OK)
            lose("Error importing private key: %s\n", hal_error_string(err));

        char name_str[HAL_UUID_TEXT_SIZE];
        if ((err = hal_uuid_format(&key_uuid, name_str, sizeof(name_str))) != HAL_OK)
            lose("Error formatting private key name: %s\n", hal_error_string(err));
        printf("New private key name: %s\n", name_str);

        if ((err = hal_rpc_pkey_delete(kekek_handle)) != HAL_OK)
            lose("Could not delete key: %s\n", hal_error_string(err));
    }

    return 0;

fail:
    if (kekek_handle.handle != HAL_HANDLE_NONE)
        (void)hal_rpc_pkey_delete(kekek_handle);

    return -1;
}

static int pkey_delete(int argc, char *argv[])
{
    char usage[] = "Usage: delete [-k keyname]";

    int opt;
    hal_error_t err;
    while ((opt = getopt(argc, argv, "-k:")) != -1) {
        switch (opt) {
        case 1:
            /* found the next command */
            --optind;
            goto done;
        case 'k':
            if (pkey_open(optarg) != 0)
                return -1;
            if ((err = hal_rpc_pkey_delete(key_handle)) != HAL_OK)
                lose("Could not delete key: %s\n", hal_error_string(err));
            key_handle.handle = HAL_HANDLE_NONE;
            break;
        default:
            puts(usage);
            return -1;
        }
    }
done:

    if (key_handle.handle != HAL_HANDLE_NONE) {
        if ((err = hal_rpc_pkey_delete(key_handle)) != HAL_OK)
            lose("Could not delete key: %s\n", hal_error_string(err));
        key_handle.handle = HAL_HANDLE_NONE;
    }

    return 0;

fail:
    return -1;    
}

int main(int argc, char *argv[])
{
    char usage[] = "Usage: %s [-i] [-p pin] generate|list|sign|verify|export|import|delete\n";

    if (argc == 1) {
        printf(usage, argv[0]);
        return -1;
    }

    do {
        int opt;
        while ((opt = getopt(argc, argv, "-ip:")) != -1) {
            switch (opt) {
            case 1:
                /* found the next command */
                --optind;
                goto done;
            case 'i':
                info = 1;
                break;
            case 'p':
                pin = optarg;
                break;
            default:
                printf(usage, argv[0]);
                goto fail;
            }
        }
    done:

        if (pkey_login() != 0)
            goto fail;

        if (optind < argc) {
            optarg = argv[optind++];
            if (strcmp(optarg, "generate") == 0) {
                if (pkey_generate(argc, argv) != 0)
                    goto fail;
            }
            else if (strcmp(optarg, "list") == 0) {
                if (pkey_list(argc, argv) != 0)
                    goto fail;
            }
            else if (strcmp(optarg, "sign") == 0) {
                if (pkey_sign(argc, argv) != 0)
                    goto fail;
            }
            else if (strcmp(optarg, "verify") == 0) {
                if (pkey_verify(argc, argv) != 0)
                    goto fail;
            }
            else if (strcmp(optarg, "export") == 0) {
                if (pkey_export(argc, argv) != 0)
                    goto fail;
            }
            else if (strcmp(optarg, "import") == 0) {
                if (pkey_import(argc, argv) != 0)
                    goto fail;
            }
            else if (strcmp(optarg, "delete") == 0) {
                if (pkey_delete(argc, argv) != 0)
                    goto fail;
            }
            else {
                printf("unknown command '%s'\n", optarg);
                printf(usage, argv[0]);
                goto fail;
            }
        }
    } while (optind < argc);

    return pkey_logout();

fail:
    (void)pkey_logout();
    return -1;
}
