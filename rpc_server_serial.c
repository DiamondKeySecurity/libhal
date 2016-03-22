/*
 * rpc_server_serial.c
 * -------------------
 * Remote procedure call transport over serial line with SLIP framing.
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
#include "slip_internal.h"

/* Don't include stm-uart.h to avoid conflicting definitions of HAL_OK.
 */
extern int uart_send_char(uint8_t ch);
extern int uart_recv_char(uint8_t *cp);

hal_error_t hal_rpc_server_transport_init(void)
{
    return HAL_OK;
}

hal_error_t hal_rpc_server_transport_close(void)
{
    return HAL_OK;
}

hal_error_t hal_rpc_sendto(const uint8_t * const buf, const size_t len, void *opaque)
{
    if (hal_slip_send(buf, len) == -1)
        return HAL_ERROR_RPC_TRANSPORT;
    return HAL_OK; 
}

hal_error_t hal_rpc_recvfrom(uint8_t * const buf, size_t * const len, void **opaque)
{
    int ret;
    
    if ((ret = hal_slip_recv(buf, *len)) == -1)
        return HAL_ERROR_RPC_TRANSPORT;
    *len = ret;
    return HAL_OK;
}

int hal_slip_send_char(uint8_t c)
{
    return (uart_send_char(c) == 0) ? 0 : -1;
}

int hal_slip_recv_char(uint8_t *c)
{
    return (uart_recv_char(c) == 0) ? 0 : -1;
}