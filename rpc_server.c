/*
 * rpc_server.c
 * ------------
 * Remote procedure call server-side private API implementation.
 *
 * Copyright (c) 2016, NORDUnet A/S All rights reserved.
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

#include "hal.h"
#include "hal_internal.h"

/*
 * RPC calls.
 */

#define check(op) if ((ret = (op)) != HAL_OK) return ret;

#define pad(n) (((n) + 3) & ~3)

static hal_error_t get_random(uint8_t **iptr, const uint8_t * const ilimit,
                              uint8_t **optr, const uint8_t * const olimit)
{
    uint32_t length;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &length));
    /* sanity check length */
    if (length == 0 || length > olimit - *optr - 4)
        return HAL_ERROR_IO_BAD_COUNT;  /* need a better error */

    /* call the local function */
    /* get the data directly into the output buffer */
    check(rpc_encode_int(optr, olimit, length));
    ret = hal_rpc_local_misc_dispatch.get_random(*optr, (size_t)length);
    if (ret == HAL_OK)
        *optr += pad(length);
    else
        /* don't return data if error */
        *optr -= 4;

    return ret;
}

static hal_error_t set_pin(uint8_t **iptr, const uint8_t * const ilimit,
                           uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_user_t user;
    uint8_t *pin;
    uint32_t pin_len;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &user));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &pin, &pin_len));

    /* call the local function */
    ret = hal_rpc_local_misc_dispatch.set_pin(client, user, (const char * const)pin, pin_len);
    return ret;
}

static hal_error_t login(uint8_t **iptr, const uint8_t * const ilimit,
                         uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_user_t user;
    uint8_t *pin;
    uint32_t pin_len;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &user));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &pin, &pin_len));

    /* call the local function */
    ret = hal_rpc_local_misc_dispatch.login(client, user, (const char * const)pin, pin_len);
    return ret;
}

static hal_error_t logout(uint8_t **iptr, const uint8_t * const ilimit,
                          uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));

    /* call the local function */
    ret = hal_rpc_local_misc_dispatch.logout(client);
    return ret;
}

static hal_error_t logout_all(uint8_t **iptr, const uint8_t * const ilimit,
                              uint8_t **optr, const uint8_t * const olimit)
{
    hal_error_t ret;

    /* call the local function */
    ret = hal_rpc_local_misc_dispatch.logout_all();
    return ret;
}

static hal_error_t is_logged_in(uint8_t **iptr, const uint8_t * const ilimit,
                                uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_user_t user;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &user));

    /* call the local function */
    ret = hal_rpc_local_misc_dispatch.is_logged_in(client, user);
    return ret;
}

static hal_error_t hash_get_digest_len(uint8_t **iptr, const uint8_t * const ilimit,
                                       uint8_t **optr, const uint8_t * const olimit)
{
    hal_digest_algorithm_t alg;
    size_t length;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &alg));

    /* call the local function */
    ret = hal_rpc_local_hash_dispatch.get_digest_length(alg, &length);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, length));
    return ret;
}

static hal_error_t hash_get_digest_algorithm_id(uint8_t **iptr, const uint8_t * const ilimit,
                                                uint8_t **optr, const uint8_t * const olimit)
{
    hal_digest_algorithm_t alg;
    size_t len;
    uint32_t len_max;
    uint8_t *optr_orig = *optr;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &alg));
    check(rpc_decode_int(iptr, ilimit, &len_max));
    /* sanity check len_max */
    if (len_max > olimit - *optr - 4)
        return HAL_ERROR_IO_BAD_COUNT;  /* need a better error */

    /* call the local function */
    /* get the data directly into the output buffer */
    *optr += 4;         /* reserve 4 bytes for length */
    ret = hal_rpc_local_hash_dispatch.get_digest_algorithm_id(alg, *optr, &len, (size_t)len_max);
    if (ret == HAL_OK) {
        *optr = optr_orig;
        check(rpc_encode_int(optr, olimit, len));
        *optr += pad(len);
    }
    else {
        /* don't return data if error */
        *optr = optr_orig;
    }
    return ret;
}

static hal_error_t hash_get_algorithm(uint8_t **iptr, const uint8_t * const ilimit,
                                      uint8_t **optr, const uint8_t * const olimit)
{
    hal_hash_handle_t hash;
    hal_digest_algorithm_t alg;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &hash.handle));

    /* call the local function */
    ret = hal_rpc_local_hash_dispatch.get_algorithm(hash, &alg);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, alg));
    return ret;
}

static hal_error_t hash_initialize(uint8_t **iptr, const uint8_t * const ilimit,
                                   uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_session_handle_t session;
    hal_hash_handle_t hash;
    uint32_t alg;
    uint8_t *key;
    uint32_t key_len;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &session.handle));
    check(rpc_decode_int(iptr, ilimit, &alg));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &key, &key_len));

    /* call the local function */
    ret = hal_rpc_local_hash_dispatch.initialize(client, session, &hash, (hal_digest_algorithm_t)alg, key, (size_t)key_len);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, hash.handle));
    return ret;
}

static hal_error_t hash_update(uint8_t **iptr, const uint8_t * const ilimit,
                               uint8_t **optr, const uint8_t * const olimit)
{
    hal_hash_handle_t hash;
    uint8_t *data;
    uint32_t length;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &hash.handle));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &data, &length));

    /* call the local function */
    ret = hal_rpc_local_hash_dispatch.update(hash, data, (size_t)length);
    return ret;
}

static hal_error_t hash_finalize(uint8_t **iptr, const uint8_t * const ilimit,
                                 uint8_t **optr, const uint8_t * const olimit)
{
    hal_hash_handle_t hash;
    uint32_t length;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &hash.handle));
    check(rpc_decode_int(iptr, ilimit, &length));
    /* sanity check length */
    if (length == 0 || length > olimit - *optr - 4)
        return HAL_ERROR_IO_BAD_COUNT;  /* need a better error */

    /* call the local function */
    /* get the data directly into the output buffer */
    check(rpc_encode_int(optr, olimit, length));
    ret = hal_rpc_local_hash_dispatch.finalize(hash, *optr, (size_t)length);
    if (ret == HAL_OK)
        *optr += pad(length);
    else
        /* don't return data if error */
        *optr -= 4;
    return ret;
}

static hal_error_t pkey_load(uint8_t **iptr, const uint8_t * const ilimit,
                             uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_session_handle_t session;
    hal_pkey_handle_t pkey;
    hal_key_type_t type;
    hal_curve_name_t curve;
    uint8_t *name, *der;
    uint32_t name_len, der_len;
    hal_key_flags_t flags;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &session.handle));
    check(rpc_decode_int(iptr, ilimit, &type));
    check(rpc_decode_int(iptr, ilimit, &curve));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &name, &name_len));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &der, &der_len));
    check(rpc_decode_int(iptr, ilimit, &flags));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.load(client, session, &pkey, type, curve, name, name_len, der, der_len, flags);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, pkey.handle));
    return ret;
}

static hal_error_t pkey_find(uint8_t **iptr, const uint8_t * const ilimit,
                             uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_session_handle_t session;
    hal_pkey_handle_t pkey;
    hal_key_type_t type;
    uint8_t *name;
    uint32_t name_len;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &session.handle));
    check(rpc_decode_int(iptr, ilimit, &type));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &name, &name_len));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.find(client, session, &pkey, type, name, name_len);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, pkey.handle));
    return ret;
}

static hal_error_t pkey_generate_rsa(uint8_t **iptr, const uint8_t * const ilimit,
                                     uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_session_handle_t session;
    hal_pkey_handle_t pkey;
    uint8_t *name;
    uint32_t name_len;
    unsigned key_len;
    uint8_t *exp;
    uint32_t exp_len;
    hal_key_flags_t flags;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &session.handle));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &name, &name_len));
    check(rpc_decode_int(iptr, ilimit, &key_len));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &exp, &exp_len));
    check(rpc_decode_int(iptr, ilimit, &flags));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.generate_rsa(client, session, &pkey, name, name_len, key_len, exp, exp_len, flags);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, pkey.handle));
    return ret;
}

static hal_error_t pkey_generate_ec(uint8_t **iptr, const uint8_t * const ilimit,
                                    uint8_t **optr, const uint8_t * const olimit)
{
    hal_client_handle_t client;
    hal_session_handle_t session;
    hal_pkey_handle_t pkey;
    uint8_t *name;
    uint32_t name_len;
    hal_curve_name_t curve;
    hal_key_flags_t flags;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &client.handle));
    check(rpc_decode_int(iptr, ilimit, &session.handle));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &name, &name_len));
    check(rpc_decode_int(iptr, ilimit, &curve));
    check(rpc_decode_int(iptr, ilimit, &flags));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.generate_ec(client, session, &pkey, name, name_len, curve, flags);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, pkey.handle));
    return ret;
}

static hal_error_t pkey_close(uint8_t **iptr, const uint8_t * const ilimit,
                              uint8_t **optr, const uint8_t * const olimit)
{
    hal_pkey_handle_t pkey;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &pkey.handle));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.close(pkey);
    return ret;
}

static hal_error_t pkey_delete(uint8_t **iptr, const uint8_t * const ilimit,
                               uint8_t **optr, const uint8_t * const olimit)
{
    hal_pkey_handle_t pkey;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &pkey.handle));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.delete(pkey);
    return ret;
}

static hal_error_t pkey_get_key_type(uint8_t **iptr, const uint8_t * const ilimit,
                                     uint8_t **optr, const uint8_t * const olimit)
{
    hal_pkey_handle_t pkey;
    hal_key_type_t type;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &pkey.handle));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.get_key_type(pkey, &type);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, type));
    return ret;
}

static hal_error_t pkey_get_key_flags(uint8_t **iptr, const uint8_t * const ilimit,
                                      uint8_t **optr, const uint8_t * const olimit)
{
    hal_pkey_handle_t pkey;
    hal_key_flags_t flags;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &pkey.handle));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.get_key_flags(pkey, &flags);
    if (ret == HAL_OK)
        check(rpc_encode_int(optr, olimit, flags));
    return ret;
}

static hal_error_t pkey_get_public_key_len(uint8_t **iptr, const uint8_t * const ilimit,
                                           uint8_t **optr, const uint8_t * const olimit)
{
    hal_pkey_handle_t pkey;
    size_t len;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &pkey.handle));

    /* call the local function */
    len = hal_rpc_local_pkey_dispatch.get_public_key_len(pkey);
    check(rpc_encode_int(optr, olimit, len));
    return HAL_OK;
}

static hal_error_t pkey_get_public_key(uint8_t **iptr, const uint8_t * const ilimit,
                                       uint8_t **optr, const uint8_t * const olimit)
{
    hal_pkey_handle_t pkey;
    size_t len;
    uint32_t len_max;
    uint8_t *optr_orig = *optr;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &pkey.handle));
    check(rpc_decode_int(iptr, ilimit, &len_max));
    /* sanity check len_max */
    if (len_max > olimit - *optr - 4)
        return HAL_ERROR_IO_BAD_COUNT;  /* need a better error */

    /* call the local function */
    /* get the data directly into the output buffer */
    *optr += 4;         /* reserve 4 bytes for length */
    ret = hal_rpc_local_pkey_dispatch.get_public_key(pkey, *optr, &len, len_max);
    if (ret == HAL_OK) {
        *optr = optr_orig;
        check(rpc_encode_int(optr, olimit, len));
        *optr += pad(len);
    }
    else {
        /* don't return data if error */
        *optr = optr_orig;
    }
    return ret;
}

static hal_error_t pkey_remote_sign(uint8_t **iptr, const uint8_t * const ilimit,
                                    uint8_t **optr, const uint8_t * const olimit)
{
    hal_session_handle_t session;
    hal_pkey_handle_t pkey;
    hal_hash_handle_t hash;
    uint8_t *input;
    uint32_t input_len;
    uint32_t sig_max;
    size_t sig_len;
    uint8_t *optr_orig = *optr;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &session.handle));
    check(rpc_decode_int(iptr, ilimit, &pkey.handle));
    check(rpc_decode_int(iptr, ilimit, &hash.handle));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &input, &input_len));
    check(rpc_decode_int(iptr, ilimit, &sig_max));
    /* sanity check sig_max */
    if (sig_max > olimit - *optr - 4)
        return HAL_ERROR_IO_BAD_COUNT;  /* need a better error */

    /* call the local function */
    /* get the data directly into the output buffer */
    *optr += 4;         /* reserve 4 bytes for length */
    ret = hal_rpc_local_pkey_dispatch.sign(session, pkey, hash, input, input_len, *optr, &sig_len, sig_max);
    *optr = optr_orig;
    if (ret == HAL_OK) {
        check(rpc_encode_int(optr, olimit, sig_len));
        *optr += pad(sig_len);
    }
    return ret;
}

static hal_error_t pkey_remote_verify(uint8_t **iptr, const uint8_t * const ilimit,
                                      uint8_t **optr, const uint8_t * const olimit)
{
    hal_session_handle_t session;
    hal_pkey_handle_t pkey;
    hal_hash_handle_t hash;
    uint8_t *input;
    uint32_t input_len;
    uint8_t *sig;
    uint32_t sig_len;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &session.handle));
    check(rpc_decode_int(iptr, ilimit, &pkey.handle));
    check(rpc_decode_int(iptr, ilimit, &hash.handle));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &input, &input_len));
    check(rpc_decode_buffer_in_place(iptr, ilimit, &sig, &sig_len));

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.verify(session, pkey, hash, input, input_len, sig, sig_len);
    return ret;
}

static hal_error_t rpc_encode_pkey_info(uint8_t **optr, const uint8_t * const olimit, const hal_pkey_info_t *info)
{
    uint8_t *optr_orig = *optr;
    hal_error_t ret;
    
    if ((ret = rpc_encode_int(optr, olimit, info->type)) != HAL_OK ||
        (ret = rpc_encode_int(optr, olimit, info->curve)) != HAL_OK ||
        (ret = rpc_encode_int(optr, olimit, info->flags)) != HAL_OK ||
        (ret = rpc_encode_buffer(optr, olimit, (uint8_t *)&info->name[0], info->name_len)) != HAL_OK)
        *optr = optr_orig;
    return ret;
}


static hal_error_t pkey_list(uint8_t **iptr, const uint8_t * const ilimit,
                             uint8_t **optr, const uint8_t * const olimit)
{
    uint8_t *optr_orig = *optr;
    uint32_t result_max;
    hal_error_t ret;

    check(rpc_decode_int(iptr, ilimit, &result_max));

    hal_pkey_info_t result[result_max];
    unsigned result_len;

    /* call the local function */
    ret = hal_rpc_local_pkey_dispatch.list(result, &result_len, result_max);
    if (ret == HAL_OK) {
        int i;
        check(rpc_encode_int(optr, olimit, result_len));
        for (i = 0; i < result_len; ++i) {
            if ((ret = rpc_encode_pkey_info(optr, olimit, &result[i])) != HAL_OK) {
                *optr = optr_orig;
                break;
            }
        }
    }
    return ret;
}

#define MAX_PKT_SIZE 1024
#define interrupt 0

void rpc_server_main(void)
{
    uint8_t inbuf[MAX_PKT_SIZE], outbuf[MAX_PKT_SIZE];
    uint8_t *iptr, *ilimit, *optr, *olimit;
    size_t ilen, olen;
    rpc_func_num_t rpc_func_num;
    void *opaque;
    hal_error_t ret;
    
    while (!interrupt) {
        ilen = sizeof(inbuf);
        if (rpc_recvfrom(inbuf, &ilen, &opaque) == HAL_OK) {
            iptr = inbuf;
            ilimit = inbuf + ilen;
            optr = outbuf + 4;  /* reserve 4 bytes for return code */
            olimit = outbuf + sizeof(outbuf);
            rpc_decode_int(&iptr, ilimit, &rpc_func_num);
            switch (rpc_func_num) {
            case RPC_FUNC_GET_RANDOM:
                ret = get_random(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_SET_PIN:
                ret = set_pin(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_LOGIN:
                ret = login(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_LOGOUT:
                ret = logout(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_LOGOUT_ALL:
                ret = logout_all(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_IS_LOGGED_IN:
                ret = is_logged_in(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_HASH_GET_DIGEST_LEN:
                ret = hash_get_digest_len(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID:
                ret = hash_get_digest_algorithm_id(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_HASH_GET_ALGORITHM:
                ret = hash_get_algorithm(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_HASH_INITIALIZE:
                ret = hash_initialize(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_HASH_UPDATE:
                ret = hash_update(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_HASH_FINALIZE:
                ret = hash_finalize(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_LOAD:
                ret = pkey_load(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_FIND:
                ret = pkey_find(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_GENERATE_RSA:
                ret = pkey_generate_rsa(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_GENERATE_EC:
                ret = pkey_generate_ec(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_CLOSE:
                ret = pkey_close(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_DELETE:
                ret = pkey_delete(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_GET_KEY_TYPE:
                ret = pkey_get_key_type(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_GET_KEY_FLAGS:
                ret = pkey_get_key_flags(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN:
                ret = pkey_get_public_key_len(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_GET_PUBLIC_KEY:
                ret = pkey_get_public_key(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_REMOTE_SIGN:
                ret = pkey_remote_sign(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_REMOTE_VERIFY:
                ret = pkey_remote_verify(&iptr, ilimit, &optr, olimit);
                break;
            case RPC_FUNC_PKEY_LIST:
                ret = pkey_list(&iptr, ilimit, &optr, olimit);
                break;
            default:
                ret = HAL_ERROR_BAD_ARGUMENTS;  /* need a better error */
                break;
            }
            /* encode the return code at the beginning of the payload */
            olen = optr - outbuf;
            optr = outbuf;
            rpc_encode_int(&optr, olimit, ret);
            rpc_sendto(outbuf, olen, opaque);
        }
    }
}

/*
 * Dispatch vectors.
 */

const hal_rpc_misc_dispatch_t *hal_rpc_misc_dispatch = &hal_rpc_local_misc_dispatch;
const hal_rpc_hash_dispatch_t *hal_rpc_hash_dispatch = &hal_rpc_local_hash_dispatch;
const hal_rpc_pkey_dispatch_t *hal_rpc_pkey_dispatch = &hal_rpc_local_pkey_dispatch;

hal_error_t rpc_server_init(void)
{
    return rpc_server_transport_init();
}

hal_error_t rpc_server_close(void)
{
    return rpc_server_transport_close();
}


/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
