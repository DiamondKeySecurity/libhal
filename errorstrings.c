/*
 * Translate HAL error codes to strings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "cryptech.h"

#define DEFINE_HAL_ERROR(_code_,_text_)	\
  case _code_: return _text_;

const char *hal_error_string(const hal_error_t code)
{
  switch (code) {
    HAL_ERROR_LIST;
  default:
    return "Unknown HAL error code";
  }
}

#undef DEFINE_HAL_ERROR
