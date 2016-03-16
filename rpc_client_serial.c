/*
 * rpc_client_serial.c
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#include "hal.h"
#include "hal_internal.h"
#include "slip_internal.h"

#define DEVICE "/dev/ttyUSB0"
#define SPEED B115200

static int fd = -1;

hal_error_t hal_rpc_client_transport_init(void)
{
    struct termios tty;
    
    fd = open(DEVICE, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd == -1)
	return perror("open"), HAL_ERROR_RPC_TRANSPORT;

    if (tcgetattr (fd, &tty) != 0)
	return perror("tcgetattr"), HAL_ERROR_RPC_TRANSPORT;

    cfsetospeed (&tty, SPEED);
    cfsetispeed (&tty, SPEED);

    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= (CS8 | CLOCAL | CREAD);

    tty.c_iflag = 0;
    tty.c_oflag = 0;
    tty.c_lflag = 0;

    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr (fd, TCSANOW, &tty) != 0)
	return perror("tcsetattr"), HAL_ERROR_RPC_TRANSPORT;

    return HAL_OK;
}

hal_error_t hal_rpc_client_transport_close(void)
{
    int ret = close(fd);
    fd = -1;
    if (ret != 0)
        return perror("close"), HAL_ERROR_RPC_TRANSPORT;
    return HAL_OK;
}

hal_error_t hal_rpc_send(const uint8_t * const buf, const size_t len)
{
    if (hal_slip_send(buf, len) == -1)
        return HAL_ERROR_RPC_TRANSPORT;
    return HAL_OK;
}

hal_error_t hal_rpc_recv(uint8_t * const buf, size_t * const len)
{
    int ret;
    
    if ((ret = hal_slip_recv(buf, *len)) == -1)
        return HAL_ERROR_RPC_TRANSPORT;
    *len = ret;
    return HAL_OK;
}

int hal_slip_send_char(const uint8_t c)
{
    return write(fd, &c, 1);
}

int hal_slip_recv_char(uint8_t * const c)
{
    return read(fd, c, 1);
}
