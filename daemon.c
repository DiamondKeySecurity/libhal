#define DEBUG
/*
 * daemon.c
 * --------
 * A daemon to arbitrate shared access to a serial connection to the HSM.
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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <getopt.h>             /* required with -std=c99 */
#include <termios.h>            /* for default speed */

#include "slip_internal.h"
#include "xdr_internal.h"

static char usage[] =
    "usage: %s [-n socketname] [-d ttydevice] [-s ttyspeed]\n";

/* select() is hopelessly broken, and epoll() is Linux-specific, so we'll use
 * poll() until such a time as libevent or libev seems more appropriate.
 * Unfortunately, poll() doesn't come with any macros or functions to manage
 * the pollfd array, so we have to invent them.
 */

static struct pollfd *pollfds = NULL;
static nfds_t nfds = 0;
static nfds_t npollfds = 0;

static void poll_add(int fd)
{
    /* add 4 entries at a time to avoid having to realloc too often */
#define NNEW 4
    
    /* expand the array if necessary */
    if (nfds == npollfds) {
        npollfds = nfds + NNEW;
        pollfds = realloc(pollfds, npollfds * sizeof(struct pollfd));
        if (pollfds == NULL) {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        /* zero the new entries for hygiene */
        memset(&pollfds[nfds], 0, NNEW * sizeof(struct pollfd));
    }

    /* populate the new entry */
    pollfds[nfds].fd = fd;
    pollfds[nfds].events = POLLIN;
    ++nfds;
}

static void poll_remove(int fd)
{
    nfds_t i;

    /* search the pollfd array */
    for (i = 0; i < nfds; ++i) {
        if (pollfds[i].fd == fd) {
            /* shift remainder of the array left by one */
            memmove(&pollfds[i], &pollfds[i + 1], (nfds - i - 1) * sizeof(struct pollfd));
            /* zero the last entry for hygiene */
            memset(&pollfds[nfds - 1], 0, sizeof(struct pollfd));
            --nfds;
            return;
        }
    }
    /* if it's not found, return without an error */
}

#ifndef MAX_PKT_SIZE    /* move this to hal_internal.h */
#define MAX_PKT_SIZE 4096
#endif

typedef struct {
    size_t len;
    uint8_t buf[MAX_PKT_SIZE];
} rpc_buffer_t;
static rpc_buffer_t ibuf, obuf;

#ifndef DEVICE
#define DEVICE "/dev/ttyUSB0"
#endif
#ifndef SPEED
#define SPEED B921600
#endif

#ifndef SOCKET_NAME
#define SOCKET_NAME "/tmp/cryptechd.socket"
#endif
char *socket_name = SOCKET_NAME;

/* Set up an atexit handler to remove the filesystem entry for the unix domain
 * socket. This will trigger on error exits, but not on the "normal" SIGKILL.
 */
void atexit_cleanup(void)
{
    unlink(socket_name);
}

#ifdef DEBUG
static void hexdump(uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i)
        printf("%02x%c", buf[i], ((i & 0x07) == 0x07) ? '\n' : ' ');
    if ((len & 0x07) != 0)
        printf("\n");
}
#endif

int main(int argc, char *argv[])
{
    struct sockaddr_un name;
    int ret;
    int lsock;
    int dsock;
    int opt;
    char *device = DEVICE;
    speed_t speed = SPEED;

    while ((opt = getopt(argc, argv, "hn:d:s:")) != -1) {
        switch (opt) {
        case 'h':
            printf(usage, argv[0]);
            exit(EXIT_SUCCESS);
        case 'n':
            socket_name = optarg;
            break;
        case 'd':
            device = optarg;
            break;
        case 's':
            switch (atoi(optarg)) {
            case 115200:
                speed = B115200;
                break;
            case 921600:
                speed = B921600;
                break;
            default:
                printf("invalid speed value %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        default:
            printf(usage, argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (atexit(atexit_cleanup) != 0) {
        perror("atexit");
        exit(EXIT_FAILURE);
    }

    if (hal_serial_init(device, speed) != HAL_OK)
        exit(EXIT_FAILURE);

    int serial_fd = hal_serial_get_fd();
    poll_add(serial_fd);

    /* Remove the filesystem entry for the unix domain socket. The usual way
     * to stop a daemon is SIGKILL, which we can't catch, so the file remains,
     * and will prevent us from binding the socket.
     *
     * XXX We should also scan the process table, to make sure the daemon
     * isn't already running.
     */
    unlink(socket_name);

    /* Create the listening socket.
     */
    lsock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (lsock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    poll_add(lsock);

    /* For portability, clear the whole address structure, since some
     * implementations have additional (nonstandard) fields in the structure.
     */
    memset(&name, 0, sizeof(struct sockaddr_un));

    /* Bind the listening socket.
     */
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, socket_name, sizeof(name.sun_path) - 1);
    ret = bind(lsock, (const struct sockaddr *) &name, sizeof(struct sockaddr_un));
    if (ret == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    /* Prepare to accept connections.
     */
    ret = listen(lsock, 20);
    if (ret == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    /* The main loop.
     */
    for (;;) {

        /* Blocking poll on all descriptors of interest.
         */
        ret = poll(pollfds, nfds, -1);
        if (ret == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }
        
        for (nfds_t i = 0; i < nfds; ++i) {
            if (pollfds[i].revents != 0) {
                /* XXX POLLERR|POLLHUP|POLLNVAL */

                /* serial port */
                if (pollfds[i].fd == serial_fd) {
		    int complete;
                    hal_slip_recv_char(ibuf.buf, &ibuf.len, sizeof(ibuf.buf), &complete);
                    if (complete) {
#ifdef DEBUG
                        printf("serial port received response:\n");
                        hexdump(ibuf.buf, ibuf.len);
#endif
                        /* We've got a complete rpc response packet. */
                        const uint8_t *bufptr = ibuf.buf;
                        const uint8_t * const limit = ibuf.buf + ibuf.len;
                        uint32_t sock;
                        /* First word of the response is the client ID. */
                        hal_xdr_decode_int(&bufptr, limit, &sock);
                        /* Pass response on to the client that requested it. */
                        send(sock, bufptr, ibuf.len - 4, 0);
                        /* Reinitialize the receive buffer. */
                        memset(&ibuf, 0, sizeof(ibuf));
                    }
                }

                /* listening socket */
                else if (pollfds[i].fd == lsock) {
                    /* Accept incoming connection. */
                    dsock = accept(lsock, NULL, NULL);
                    if (ret == -1) {
                        perror("accept");
                        exit(EXIT_FAILURE);
                    }
                    poll_add(dsock);
#ifdef DEBUG
                    printf("listening socket accept data socket %d\n", dsock);
#endif
                }

                /* client data socket */
                else {
                    uint8_t *bufptr = obuf.buf;
                    const uint8_t * const limit = obuf.buf + MAX_PKT_SIZE;
                    /* First word of the request is the client ID. */
                    hal_xdr_encode_int(&bufptr, limit, pollfds[i].fd);
                    /* Get the client's rpc request packet. */
                    obuf.len = recv(pollfds[i].fd, bufptr, MAX_PKT_SIZE - 4, 0);
#ifdef DEBUG
                    printf("data socket %d received request:\n", pollfds[i].fd);
                    hexdump(obuf.buf, obuf.len + 4);
#endif

		    /* Fill in the client handle arg as needed. */
		    uint32_t opcode;
		    hal_xdr_decode_int((const uint8_t ** const)&bufptr, limit, &opcode);
		    switch (opcode) {
		    case RPC_FUNC_SET_PIN:
		    case RPC_FUNC_LOGIN:
		    case RPC_FUNC_LOGOUT:
		    case RPC_FUNC_IS_LOGGED_IN:
		    case RPC_FUNC_HASH_INITIALIZE:
		    case RPC_FUNC_PKEY_LOAD:
		    case RPC_FUNC_PKEY_FIND:
		    case RPC_FUNC_PKEY_GENERATE_RSA:
		    case RPC_FUNC_PKEY_GENERATE_EC:
			/* first argument is client handle */
			hal_xdr_encode_int(&bufptr, limit, pollfds[i].fd);
			break;
		    default:
			break;
		    }

                    if (obuf.len > 0) {
#ifdef DEBUG
                        printf("passing to serial port\n");
#endif
                        /* Pass it on to the serial port. */
                        hal_slip_send(obuf.buf, obuf.len + 4);
                    }
                    else {
#ifdef DEBUG
                        printf("closing data socket\n");
#endif
                        /* Client has closed the socket. */
                        close(pollfds[i].fd);
                        poll_remove(pollfds[i].fd);
                    }
                    /* Reinitialize the transmit buffer. */
                    memset(&obuf, 0, sizeof(obuf));
                }
            }
        }
    }

    /*NOTREACHED*/
    exit(EXIT_SUCCESS);
}
