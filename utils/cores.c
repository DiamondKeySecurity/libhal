/*
 * cores.c
 * -------
 * Report which cores are present on the FPGA.
 *
 * Copyright (c) 2015, NORDUnet A/S All rights reserved.
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
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>

#include <hal.h>

off_t cores[] = {
    BOARD_ADDR_BASE,
    COMM_ADDR_BASE,
    SHA1_ADDR_BASE,
    SHA256_ADDR_BASE,
    SHA512_ADDR_BASE,
    TRNG_ADDR_BASE,
    ENTROPY1_ADDR_BASE,
    ENTROPY2_ADDR_BASE,
    MIXER_ADDR_BASE,
    CSPRNG_ADDR_BASE,
    AES_ADDR_BASE,
    CHACHA_ADDR_BASE,
    MODEXPS6_ADDR_BASE
};

int main(int argc, char *argv[])
{
    uint8_t name[9] = {0}, version[5] = {0};
    hal_error_t err;
    int i;

    /*
     * Initialize EIM and report what cores we've got.
     */
    for (i = 0; i < sizeof(cores)/sizeof(cores[0]); ++i) {
	if ((err = hal_io_read(cores[i], name, 8)) != HAL_OK ||
	    (err = hal_io_read(cores[i] + 2, version, 4)) != HAL_OK) {
	    printf("hal_io_read failed: %s\n", hal_error_string(err));
	    return 1;
	}

	if (name[0] != 0)
	    printf("%08lx: %8s %4s\n", cores[i], name, version);
    }

    return 0;
}
