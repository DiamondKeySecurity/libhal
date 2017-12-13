/*
 * core.c
 * ------
 * This module contains code to probe the FPGA for its installed cores.
 *
 * Author: Paul Selkirk, Rob Austein
 * Copyright (c) 2015-2016, NORDUnet A/S All rights reserved.
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
 * POSIX function whose declaration gets lost somewhere in the twisty
 * corridors of glibc's "Feature Test Macro" system.
 */

extern size_t strnlen(const char *, size_t);

/*
 * Structure of our internal database is private, in case we want to
 * change representation (array, tree, list of lists, whatever) at
 * some later date without having to change the public API.
 */

struct hal_core {
  hal_core_info_t info;
  uint32_t busy;
  struct hal_core *next;
};

#ifndef	HAL_STATIC_CORE_STATE_BLOCKS
#define	HAL_STATIC_CORE_STATE_BLOCKS 0
#endif

#if HAL_STATIC_CORE_STATE_BLOCKS > 0
static hal_core_t core_table[HAL_STATIC_CORE_STATE_BLOCKS];
#endif

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
  { "modexpa7", 7 * CORE_SIZE }, /* ModexpA7 uses eight slots */
};

static hal_core_t *head = NULL;

static hal_core_t *probe_cores(void)
{
  if (head != NULL)
    return head;

  hal_core_t *core = NULL;
  hal_core_t **tail = &head;
  hal_error_t err = HAL_OK;
#if HAL_STATIC_CORE_STATE_BLOCKS > 0
  int n = 0;
#endif

  for (hal_addr_t addr = CORE_MIN; addr < CORE_MAX; addr += CORE_SIZE) {

#if HAL_STATIC_CORE_STATE_BLOCKS > 0
    core = &core_table[n];
#else
    if (core == NULL && (core = malloc(sizeof(hal_core_t))) == NULL) {
      err = HAL_ERROR_ALLOCATION_FAILURE;
      goto fail;
    }
#endif

    memset(core, 0, sizeof(*core));
    core->info.base = addr;

    if ((err = hal_io_read(core, ADDR_NAME0,   (uint8_t *) core->info.name,    8)) != HAL_OK ||
        (err = hal_io_read(core, ADDR_VERSION, (uint8_t *) core->info.version, 4)) != HAL_OK)
      goto fail;

    if (core->info.name[0] == 0x00 || core->info.name[0] == 0xff)
      continue;

    for (size_t i = 0; i < sizeof(gaps)/sizeof(*gaps); i++) {
      if (name_matches(core, gaps[i].name)) {
        addr += gaps[i].extra;
        break;
      }
    }

    *tail = core;
    tail = &core->next;
    core = NULL;

#if HAL_STATIC_CORE_STATE_BLOCKS > 0
    if (++n >= HAL_STATIC_CORE_STATE_BLOCKS)
      break;
#endif
  }

#if HAL_STATIC_CORE_STATE_BLOCKS > 0
#else
  if (core != NULL)
    free(core);
#endif

  return head;

 fail:
#if HAL_STATIC_CORE_STATE_BLOCKS > 0
  memset(core_table, 0, sizeof(core_table));
#else
  if (core != NULL)
    free(core);
  while ((core = head) != NULL) {
    head = core->next;
    free(core);
  }
#endif
  return NULL;
}

void hal_core_reset_table(void)
{
#if HAL_STATIC_CORE_STATE_BLOCKS > 0
    head = NULL;
    memset(core_table, 0, sizeof(core_table));
#else
    while (head != NULL) {
        hal_core_t *next = head->next;
        free(head);
        head = next;
    }
#endif
}

hal_core_t * hal_core_iterate(hal_core_t *core)
{
  return core == NULL ? probe_cores() : core->next;
}

hal_core_t *hal_core_find(const char *name, hal_core_t *core)
{
  for (core = hal_core_iterate(core); core != NULL; core = core->next)
    if (name_matches(core, name))
      return core;
  return NULL;
}

hal_error_t hal_core_alloc(const char *name, hal_core_t **pcore)
{
  /*
   * This used to allow name == NULL iff *core != NULL, but the
   * semantics were fragile and in practice we always pass a name
   * anyway, so simplify by requiring name != NULL, always.
   */

  if (name == NULL || pcore == NULL)
    return HAL_ERROR_BAD_ARGUMENTS;

  hal_error_t err = HAL_ERROR_CORE_NOT_FOUND;
  hal_core_t *core = *pcore;

  if (core != NULL) {
    /* if we can reallocate the same core, do it now */
    if (!core->busy) {
      hal_critical_section_start();
      core->busy = 1;
      hal_critical_section_end();
      return HAL_OK;
    }
    /* else forget that core and fall through to search */
    *pcore = NULL;
  }

  while (1) {
    hal_critical_section_start();
    for (core = hal_core_iterate(NULL); core != NULL; core = core->next) {
      if (!name_matches(core, name))
        continue;
      if (core->busy) {
        err = HAL_ERROR_CORE_BUSY;
        continue;
      }
      err = HAL_OK;
      *pcore = core;
      core->busy = 1;
      break;
    }
    hal_critical_section_end();
    if (err == HAL_ERROR_CORE_BUSY)
      hal_task_yield();
    else
      break;
  }

  return err;
}

void hal_core_free(hal_core_t *core)
{
  if (core != NULL) {
    hal_critical_section_start();
    core->busy = 0;
    hal_critical_section_end();
    hal_task_yield();
  }
}

hal_addr_t hal_core_base(const hal_core_t *core)
{
  return core == NULL ? 0 : core->info.base;
}

const hal_core_info_t *hal_core_info(const hal_core_t *core)
{
  return core == NULL ? NULL : &core->info;
}

int hal_core_busy(const hal_core_t *core)
{
  return (int)core->busy;
}

/*
 * Local variables:
 * indent-tabs-mode: nil
 * End:
 */
