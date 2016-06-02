/*
 * rpc_client_daemon.c
 * -------------------
 * Remote procedure call transport over a socket to a daemon.
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

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/un.h>

#include "hal.h"
#include "hal_internal.h"

#ifndef SOCKET_NAME
#define SOCKET_NAME "/tmp/cryptechd.socket"
#endif

static int sock = -1;

hal_error_t hal_rpc_client_transport_init(void)
{
    struct sockaddr_un name;
    int ret;

    sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock == -1)
        return perror("socket"), HAL_ERROR_RPC_TRANSPORT;
    memset(&name, 0, sizeof(struct sockaddr_un));
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, SOCKET_NAME, sizeof(name.sun_path) - 1);
    ret = connect(sock, (const struct sockaddr *) &name, sizeof(struct sockaddr_un));
    if (ret == -1)
        return perror("connect"), HAL_ERROR_RPC_TRANSPORT;
    return HAL_OK;
}

hal_error_t hal_rpc_client_transport_close(void)
{
    int ret = close(sock);
    sock = -1;
    if (ret != 0)
        return perror("close"), HAL_ERROR_RPC_TRANSPORT;
    return HAL_OK;
}

hal_error_t hal_rpc_send(const uint8_t * const buf, const size_t len)
{
    ssize_t ret = send(sock, (const void *)buf, len, 0);
    return (ret == -1) ? HAL_ERROR_RPC_TRANSPORT : HAL_OK;
}

hal_error_t hal_rpc_recv(uint8_t * const buf, size_t * const len)
{
    ssize_t ret = recv(sock, (void *)buf, *len, 0);
    if (ret == -1)
	return HAL_ERROR_RPC_TRANSPORT;
    *len = (size_t)ret;
    return HAL_OK;
}
