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
#include "hal.h"

static int debug = 0;
static int inited = 0;

#ifndef EIM_IO_TIMEOUT
#define EIM_IO_TIMEOUT  100000000
#endif

static hal_error_t init(void)
{
  if (inited)
    return HAL_OK;

  if (eim_setup() != 0)
    return HAL_ERROR_IO_SETUP_FAILED;

  inited = 1;
  return HAL_OK;
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

void hal_io_set_debug(int onoff)
{
  debug = onoff;
}

static void dump(char *label, const uint8_t *buf, size_t len)
{
  if (debug) {
    size_t i;
    printf("%s [", label);
    for (i = 0; i < len; ++i)
      printf(" %02x", buf[i]);
    printf(" ]\n");
  }
}

hal_error_t hal_io_write(off_t offset, const uint8_t *buf, size_t len)
{
  hal_error_t err;

  if (len % 4 != 0)
    return HAL_ERROR_IO_BAD_COUNT;

  if ((err = init()) != HAL_OK)
    return err;

  dump("write ", buf, len);

  offset = eim_offset(offset);
  for (; len > 0; offset += 4, buf += 4, len -= 4) {
    uint32_t val;
    val = htonl(*(uint32_t *)buf);
    eim_write_32(offset, &val);
  }

  return HAL_OK;
}

hal_error_t hal_io_read(off_t offset, uint8_t *buf, size_t len)
{
  uint8_t *rbuf = buf;
  int rlen = len;
  hal_error_t err;

  if (len % 4 != 0)
    return HAL_ERROR_IO_BAD_COUNT;

  if ((err = init()) != HAL_OK)
    return err;

  offset = eim_offset(offset);
  for (; rlen > 0; offset += 4, rbuf += 4, rlen -= 4) {
    uint32_t val;
    eim_read_32(offset, &val);
    *(uint32_t *)rbuf = ntohl(val);
  }

  dump("read  ", buf, len);

  return HAL_OK;
}

hal_error_t hal_io_expected(off_t offset, const uint8_t *expected, size_t len)
{
  hal_error_t err;
  uint8_t buf[4];
  size_t i;

  if (len % 4 != 0)
    return HAL_ERROR_IO_BAD_COUNT;

  dump("expect", expected, len);

  for (i = 0; i < len; i++) {
    if ((i & 3) == 0 && (err = hal_io_read(offset + i/4, buf, sizeof(buf))) != HAL_OK)
      return err;
    if (buf[i & 3] != expected[i])
      return HAL_ERROR_IO_UNEXPECTED;
  }

  return HAL_OK;
}

hal_error_t hal_io_init(off_t offset)
{
  uint8_t buf[4] = { 0, 0, 0, CTRL_INIT };
  return hal_io_write(offset, buf, sizeof(buf));
}

hal_error_t hal_io_next(off_t offset)
{
  uint8_t buf[4] = { 0, 0, 0, CTRL_NEXT };
  return hal_io_write(offset, buf, sizeof(buf));
}

hal_error_t hal_io_wait(off_t offset, uint8_t status, int *count)
{
  hal_error_t err;
  uint8_t buf[4];
  int i;

  for (i = 1; ; ++i) {

    if (count && (*count > 0) && (i >= *count))
      return HAL_ERROR_IO_TIMEOUT;

    if ((err = hal_io_read(offset, buf, sizeof(buf))) != HAL_OK)
      return err;

    if ((buf[3] & status) != 0) {
      if (count)
        *count = i;
      return HAL_OK;
    }
  }
}

hal_error_t hal_io_wait_ready(off_t offset)
{
  int limit = EIM_IO_TIMEOUT;
  return hal_io_wait(offset, STATUS_READY, &limit);
}

hal_error_t hal_io_wait_valid(off_t offset)
{
  int limit = EIM_IO_TIMEOUT;
  return hal_io_wait(offset, STATUS_VALID, &limit);
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
