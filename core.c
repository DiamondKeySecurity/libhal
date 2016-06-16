/*
 * core.c
 * ------
 * This module contains code to probe the FPGA for its installed cores.
 *
 * Author: Paul Selkirk, Rob Austein
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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hal.h"
#include "hal_internal.h"

/*
 * Each Cryptech core has a set of 4-byte registers, which are accessed
 * through a 16-bit address. The address space is divided as follows:
 *   3 bits segment selector       | up to 8 segments
 *   5 bits core selector          | up to 32 cores/segment (see note below)
 *   8 bits register selector      | up to 256 registers/core (see modexp below)
 *
 * i.e, the address is structured as:
 * sss ccccc rrrrrrrr
 *
 * The I2C and UART communication channels use this 16-bit address format
 * directly in their read and write commands.
 *
 * The EIM communications channel translates this 16-bit address into a
 * 32-bit memory-mapped address in the range 0x08000000..807FFFF:
 * 00001000000000 sss 0 ccccc rrrrrrrr 00
 *
 * EIM, as implemented on the Novena, uses a 19-bit address space:
 *   Bits 18..16 are the semgent selector.
 *   Bits 15..10 are the core selector.
 *   Bits 9..2 are the register selector.
 *   Bits 1..0 are zero, because reads and writes are always word aligned.
 *
 * Note that EIM can support 64 cores per segment, but we sacrifice one bit
 * in order to map it into a 16-bit address space.
 */

/*
 * Structure of our internal database is private, in case we want to
 * be change representation (array, tree, list of lists, whatever) at
 * some later date without having to change the public API.
 */

struct hal_core {
  hal_core_info_t info;
  struct hal_core *next;
};

/*
 * Check whether a core's name matches a particular string.  This is a
 * bit nasty due to non-null-terminated fixed-length names.
 */

static int name_matches(const hal_core_t *const core, const char * const name)
{
  return (core != NULL && name != NULL && *name != '\0' &&
          strncmp(name, core->info.name, strnlen(name, sizeof(core->info.name))) == 0);
}

/*
 * Probe the FPGA and build our internal database.
 *
 * At the moment this knows far more than it should about pecularities
 * of certain cores.  In theory at least some of this will be fixed
 * soon on the Verilog side.  Adding a core-length word to the core
 * header sure would make this simpler.
 */

#define CORE_MIN                0
#define	CORE_MAX                0x10000
#define	CORE_SIZE               0x100

/* Extra space to leave after particular cores.  Yummy. */

static const struct { const char *name; hal_addr_t extra; } gaps[] = {
  { "csprng",  11 * CORE_SIZE }, /* empty slots after csprng */
  { "modexps6", 3 * CORE_SIZE }, /* ModexpS6 uses four slots */
  { "modexpa7", 3 * CORE_SIZE }, /* ModexpA7 uses four slots */
};

static hal_core_t *probe_cores(void)
{
  static hal_core_t *head = NULL;

  if (head != NULL)
    return head;

  hal_core_t **tail = &head;
  hal_core_t *core = NULL;
  hal_error_t err = HAL_OK;

  for (hal_addr_t addr = CORE_MIN; addr < CORE_MAX; addr += CORE_SIZE) {

    if (core == NULL && (core = malloc(sizeof(hal_core_t))) == NULL) {
      err = HAL_ERROR_ALLOCATION_FAILURE;
      goto fail;
    }

    memset(core, 0, sizeof(*core));
    core->info.base = addr;

    if ((err = hal_io_read(core, ADDR_NAME0,   (uint8_t *) core->info.name,    8)) != HAL_OK ||
        (err = hal_io_read(core, ADDR_VERSION, (uint8_t *) core->info.version, 4)) != HAL_OK)
      goto fail;

    if (core->info.name[0] == '\0')
      continue;

    for (int i = 0; i < sizeof(gaps)/sizeof(*gaps); i++) {
      if (name_matches(core, gaps[i].name)) {
        addr += gaps[i].extra;
        break;
      }
    }

    *tail = core;
    tail = &core->next;
    core = NULL;
  }

  if (core != NULL)
    free(core);

  return head;

 fail:
  if (core != NULL)
    free(core);
  while ((core = head) != NULL) {
    head = core->next;
    free(core);
  }
  return NULL;
}

const hal_core_t * hal_core_iterate(const hal_core_t *core)
{
  return core == NULL ? probe_cores() : core->next;
}

const hal_core_t *hal_core_find(const char *name, const hal_core_t *core)
{
  for (core = hal_core_iterate(core); core != NULL; core = core->next)
    if (name_matches(core, name))
      return core;
  return NULL;
}

hal_error_t hal_core_check_name(const hal_core_t **core, const char *name)
{
  if (core == NULL || name == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  if (*core == NULL && (*core = hal_core_find(name, NULL)) != NULL)
    return HAL_OK;

  if (*core == NULL || !name_matches(*core, name))
    return HAL_ERROR_CORE_NOT_FOUND;

  return HAL_OK;
}

hal_addr_t hal_core_base(const hal_core_t *core)
{
  return core == NULL ? 0 : core->info.base;
}

const hal_core_info_t *hal_core_info(const hal_core_t *core)
{
  return core == NULL ? NULL : &core->info;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
