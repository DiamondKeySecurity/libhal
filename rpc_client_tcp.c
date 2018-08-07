/*
 * rpc_client_tcp.c
 * -------------------
 * Remote procedure call transport over a TCP socket using LibreSSL TLS.
 *
 * BSD 3-Clause License
 * 
 * Copyright (c) 2018, Diamond Key Security, NFP
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * ----------------------------------------------------------------------------
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <stdbool.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <tls.h>

#include "hal.h"
#include "hal_internal.h"
#include "slip_internal.h"

static struct tls *tls = NULL;
static struct tls_config *config = NULL;

hal_error_t hal_rpc_client_transport_init(void)
{
    struct sockaddr_in server;
    int sock;

    // get the IP address from the DKS_HSM_HOST_IP environment variable
    const char *hostip = getenv("DKS_HSM_HOST_IP");
    const char *hostname = getenv("DKS_HSM_HOST_NAME");

    if(hostip == NULL) {
        return HAL_ERROR_BAD_ARGUMENTS;
    }

    if(hostname == NULL) {
        return HAL_ERROR_BAD_ARGUMENTS;
    }

    // make sure any previous attemps to open a connection have closed
    hal_rpc_client_transport_close();

    // start the tls connection
    tls_init();

    tls = tls_client();

    config = tls_config_new();

    tls_config_insecure_noverifycert(config);
    tls_config_insecure_noverifyname(config);

    tls_configure(tls, config);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_port = htons(8081);
    server.sin_addr.s_addr = inet_addr(hostip);
    server.sin_family = AF_INET;

    if(connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        return HAL_ERROR_RPC_TRANSPORT;
    }

    if(tls_connect_socket(tls, sock, hostname) < 0) {
        return HAL_ERROR_RPC_TRANSPORT;
    }
}

hal_error_t hal_rpc_client_transport_close(void)
{
    if(tls != NULL)
    {
        tls_close(tls);
        tls_free(tls);

        tls = NULL;
    }

    if(config != NULL)
    {
        tls_config_free(config);
        config = NULL;
    }

    return HAL_OK;
}


hal_error_t hal_rpc_send(const uint8_t * const buf, const size_t len)
{
    return hal_slip_send(buf, len);
}

hal_error_t hal_rpc_recv(uint8_t * const buf, size_t * const len)
{
    size_t maxlen = *len;
    *len = 0;
    hal_error_t err = hal_slip_recv(buf, len, maxlen);
    return err;
}

/*
 * These two are sort of mis-named, fix eventually, but this is what
 * the code in slip.c expects.
 */

hal_error_t hal_serial_send_char(const uint8_t c)
{
    if (tls_write(tls, &c, 1) == 1)
        return HAL_OK;
    else
        return HAL_ERROR_RPC_TRANSPORT;
}

hal_error_t hal_serial_recv_char(uint8_t * const c)
{
    if (tls_read(tls, c, 1) == 1)
        return HAL_OK;
    else
        return HAL_ERROR_RPC_TRANSPORT;
}
