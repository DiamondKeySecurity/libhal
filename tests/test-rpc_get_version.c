#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <hal.h>
#include <hal_internal.h>

int main (int argc, char *argv[])
{
    uint32_t version;

#define check(op) { hal_error_t err; if ((err = (op)) != HAL_OK) { printf("%s: %s\n", #op, hal_error_string(err)); return 1; } }
    
    check(hal_rpc_client_init());
    check(hal_rpc_get_version(&version));
    printf("%08x\n", version);

    return 0;
}
