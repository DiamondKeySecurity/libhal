/*
 * slip.c
 * ------
 * SLIP send/recv code, based on RFC 1055
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


#include <stdio.h>      /* perror */

#include "slip_internal.h"

/* SLIP special character codes
 */
#define END             0300    /* indicates end of packet */
#define ESC             0333    /* indicates byte stuffing */
#define ESC_END         0334    /* ESC ESC_END means END data byte */
#define ESC_ESC         0335    /* ESC ESC_ESC means ESC data byte */

#define check_send_char(c) \
    if (hal_serial_send_char(c) != HAL_OK) \
        return perror("hal_serial_send_char"), HAL_ERROR_RPC_TRANSPORT;

/* Send a single character with SLIP escaping.
 */
hal_error_t hal_slip_send_char(const uint8_t c)
{
    switch (c) {
    case END:
        check_send_char(ESC);
        check_send_char(ESC_END);
        break;
    case ESC:
        check_send_char(ESC);
        check_send_char(ESC_ESC);
        break;
    default:
        check_send_char(c);
    }

    return HAL_OK;
}

/* Send a message with SLIP framing.
 */
hal_error_t hal_slip_send(const uint8_t * const buf, const size_t len)
{
    /* send an initial END character to flush out any data that may
     * have accumulated in the receiver due to line noise
     */
    check_send_char(END);

    /* for each byte in the packet, send the appropriate character
     * sequence
     */
    for (int i = 0; i < len; ++i) {
        hal_error_t ret;
        if ((ret = hal_slip_send_char(buf[i])) != HAL_OK)
            return ret;
    }

    /* tell the receiver that we're done sending the packet
     */
    check_send_char(END);

    return HAL_OK;
}

#define check_recv_char(c) \
    if (hal_serial_recv_char(c) != HAL_OK) \
        return perror("hal_serial_recv_char"), HAL_ERROR_RPC_TRANSPORT;

/* Receive a single character into a buffer, with SLIP un-escaping
 */
hal_error_t hal_slip_recv_char(uint8_t * const buf, size_t * const len, const size_t maxlen, int * const complete)
{
#define buf_push(c) do { if (*len < maxlen) buf[(*len)++] = c; } while (0)
    static int esc_flag = 0;
    uint8_t c;
    hal_error_t ret = hal_serial_recv_char(&c);
    if (ret != HAL_OK)
        return perror("hal_slip_recv_char"), ret;
    *complete = 0;
    switch (c) {
    case END:
        if (*len)
            *complete = 1;
        break;
    case ESC:
        esc_flag = 1;
        break;
    default:
        if (esc_flag) {
            esc_flag = 0;
            switch (c) {
            case ESC_END:
                buf_push(END);
                break;
            case ESC_ESC:
                buf_push(ESC);
                break;
            default:
                buf_push(c);
            }
        }
        else {
            buf_push(c);
        }
        break;
    }
    return HAL_OK;
}

/* Receive a message with SLIP framing, blocking mode.
 */
hal_error_t hal_slip_recv(uint8_t * const buf, size_t * const len, const size_t maxlen)
{
    int complete;
    hal_error_t ret;

    while (1) {
	ret = hal_slip_recv_char(buf, len, maxlen, &complete);
	if ((ret != HAL_OK) || complete)
	    return ret;
    }
}
