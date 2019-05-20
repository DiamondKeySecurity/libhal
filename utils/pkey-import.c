/*
 * pkey-import.c
 * -------------
 * Import a key.
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

#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <hal.h>

#define HAL_KS_WRAPPED_KEYSIZE  ((2373 + 6 * 4096 / 8 + 6 * 4 + 15) & ~7)

#define lose(...) do { printf(__VA_ARGS__); goto fail; } while (0)

static int read_file(const char * const fn, uint8_t * const buf, size_t *buf_len, const size_t buf_max)
{
    int fd;
    if ((fd = open(fn, O_RDONLY)) == -1)
        lose("Error opening %s: %s\n", fn, strerror(errno));

    size_t nread;
    if ((nread = read(fd, buf, buf_max)) == -1)
        lose("Error reading %s: %s\n", fn, strerror(errno));

    *buf_len = nread;

    if (close(fd) != 0)
        lose("Error closing %s: %s\n", fn, strerror(errno));

    return 0;

fail:
    return -1;
}

static int read_buf(const char * const name, const char * const ext, uint8_t * const buf, size_t *buf_len, const size_t buf_max)
{
    char fn[strlen(name) + strlen(ext) + 1];
    strcpy(fn, name);
    strcat(fn, ext);

    return read_file(fn, buf, buf_len, buf_max);
}

#define lose_usage(...) do { printf(__VA_ARGS__); printf(usage, argv[0]); goto fail; } while (0)

int main(int argc, char *argv[])
{
    hal_error_t err;
    const hal_client_handle_t client = {HAL_HANDLE_NONE};
    const hal_session_handle_t session = {HAL_HANDLE_NONE};
    char *pin = "fnord";
    char *kekek_fn = NULL;
    char *key_fn = NULL;

char usage[] = "\
Usage: %s [-p pin] <-k kekek> keyfile\n\
";

    int opt;
    while ((opt = getopt(argc, argv, "p:k:")) != -1) {
        switch (opt) {
        case 'p':
            pin = optarg;
            break;
        case 'k':
            kekek_fn = optarg;
            break;
        case 'h':
        case '?':
            printf(usage, argv[0]);
            return 0;
        }
    }
    key_fn = argv[optind];

    if (kekek_fn == NULL)
        lose_usage("Error: missing option -k\n");
    if (key_fn == NULL)
        lose_usage("Error: missing keyfile\n");

    uint8_t kekek_der[HAL_KS_WRAPPED_KEYSIZE]; size_t kekek_der_len;

    if (read_file(kekek_fn, kekek_der, &kekek_der_len, sizeof(kekek_der)) != 0)
        goto fail;

    uint8_t der[HAL_KS_WRAPPED_KEYSIZE]; size_t der_len;
    uint8_t kek[HAL_KS_WRAPPED_KEYSIZE]; size_t kek_len;

    if (read_buf(key_fn, ".der", der, &der_len, sizeof(der)) != 0 ||
        read_buf(key_fn, ".kek", kek, &kek_len, sizeof(kek)) != 0)
        goto fail;

    if ((err = hal_rpc_client_init()) != HAL_OK)
        lose("Error initializing RPC client: %s\n", hal_error_string(err));

    if ((err = hal_rpc_login(client, HAL_USER_NORMAL, pin, strlen(pin))) != HAL_OK)
        lose("Error logging into HSM: %s\n", hal_error_string(err));

    hal_pkey_handle_t kekek = {HAL_HANDLE_NONE};
    hal_uuid_t kekek_name;

    if ((err = hal_rpc_pkey_load(client, session, &kekek, &kekek_name,
                                 kekek_der, kekek_der_len,
                                 HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT)) != HAL_OK)
        lose("Error loading import key: %s\n", hal_error_string(err));

    hal_pkey_handle_t private_key = {HAL_HANDLE_NONE};
    hal_uuid_t private_name;

    if ((err = hal_rpc_pkey_import(client, session,
                                   &private_key, &private_name,
                                   kekek,
                                   der, der_len,
                                   kek, kek_len,
                                   HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN | HAL_KEY_FLAG_EXPORTABLE)) != HAL_OK)
        lose("Error importing private key: %s\n", hal_error_string(err));

    char name_str[HAL_UUID_TEXT_SIZE];

    if ((err = hal_uuid_format(&private_name, name_str, sizeof(name_str))) != HAL_OK)
        lose("Error formatting private key name: %s\n", hal_error_string(err));
    printf("New private key name: %s\n", name_str);

    if ((err = hal_rpc_logout(client)) != HAL_OK)
        lose("Error logging out of HSM: %s\n", hal_error_string(err));

    if ((err = hal_rpc_client_close()) != HAL_OK)
        lose("Error shutting down RPC client: %s\n", hal_error_string(err));

    return 0;

fail:
    return -1;
}
