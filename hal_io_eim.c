/* 
 * hal_io_eim.c
 * ------------
 * This module contains common code to talk to the FPGA over the EIM bus.
 * 
 * Author: Paul Selkirk
 * Copyright (c) 2014-2015, NORDUnet A/S All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "novena-eim.h"
#include "cryptech.h"

static int debug = 0;
static int inited = 0;

/* ---------------- EIM low-level code ---------------- */

static int init(void)
{
    if (inited)
        return 0;

    if (eim_setup() != 0) {
        fprintf(stderr, "EIM setup failed\n");
        return -1;
    }

    inited = 1;
    return 0;
}

/* translate cryptech register number to EIM address
 *
 * register number format:
 * 3 bits segment selector
 * 5 bits core selector (6 bits in native eim)
 * 8 bits register selector
 *
 * sss ccccc rrrrrrrr => 00001000000000 sss 0 ccccc rrrrrrrr 00
 */
static off_t eim_offset(off_t offset)
{
    return EIM_BASE_ADDR + ((offset & ~0x1fff) << 3) + ((offset & 0x1fff) << 2);
}

/* ---------------- test-case low-level code ---------------- */

void hal_io_set_debug(int onoff)
{
    debug = onoff;
}

static void dump(char *label, const uint8_t *buf, size_t len)
{
    if (debug) {
        int i;
        printf("%s [", label);
        for (i = 0; i < len; ++i)
            printf(" %02x", buf[i]);
        printf(" ]\n");
    }
}

int hal_io_write(off_t offset, const uint8_t *buf, size_t len)
{
    if (init() != 0)
        return -1;

    dump("write ", buf, len);

    offset = eim_offset(offset);
    for (; len > 0; offset += 4, buf += 4, len -= 4) {
        uint32_t val;
        val = htonl(*(uint32_t *)buf);
        eim_write_32(offset, &val);
    }

    return 0;
}

int hal_io_read(off_t offset, uint8_t *buf, size_t len)
{
    uint8_t *rbuf = buf;
    int rlen = len;

    if (init() != 0)
        return -1;

    offset = eim_offset(offset);
    for (; rlen > 0; offset += 4, rbuf += 4, rlen -= 4) {
        uint32_t val;
        eim_read_32(offset, &val);
        *(uint32_t *)rbuf = ntohl(val);
    }

    dump("read  ", buf, len);

    return 0;
}

int hal_io_expected(off_t offset, const uint8_t *expected, size_t len)
{
    uint8_t *buf;
    int i;

    buf = malloc(len);
    if (buf == NULL) {
        perror("malloc");
        return 1;
    }
    dump("expect", expected, len);

    if (hal_io_read(offset, buf, len) != 0)
        goto errout;

    for (i = 0; i < len; ++i)
        if (buf[i] != expected[i]) {
            fprintf(stderr, "response byte %d: expected 0x%02x, got 0x%02x\n",
                    i, expected[i], buf[i]);
            goto errout;
        }

    free(buf);
    return 0;
errout:
    free(buf);
    return 1;
}

int hal_io_init(off_t offset)
{
    uint8_t buf[4] = { 0, 0, 0, CTRL_INIT };

    return hal_io_write(offset, buf, 4);
}

int hal_io_next(off_t offset)
{
    uint8_t buf[4] = { 0, 0, 0, CTRL_NEXT };

    return hal_io_write(offset, buf, 4);
}

int hal_io_wait(off_t offset, uint8_t status, int *count)
{
    uint8_t buf[4];
    int i;

    for (i = 1; ; ++i) {
        if (count && (*count > 0) && (i >= *count)) {
            fprintf(stderr, "hal_io_wait timed out\n");
            return 1;
        }
        if (hal_io_read(offset, buf, 4) != 0)
            return -1;
        if (buf[3] & status) {
            if (count)
                *count = i;
            return 0;
        }
    }
}

int hal_io_wait_ready(off_t offset)
{
    int limit = 256;
    return hal_io_wait(offset, STATUS_READY, &limit);
}

int hal_io_wait_valid(off_t offset)
{
    int limit = 256;
    return hal_io_wait(offset, STATUS_VALID, &limit);
}
