#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <hal.h>
#include <hal_internal.h>

int main (int argc, char *argv[])
{
    if (rpc_server_init() != HAL_OK)
	return 1;

    rpc_server_main();
    return 0;
}
