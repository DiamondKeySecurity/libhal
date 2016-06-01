#include <hal.h>

int main (int argc, char *argv[])
{
    if (hal_rpc_server_init() != HAL_OK)
	return 1;

    hal_rpc_server_main();
    hal_rpc_server_close();
    return 0;
}
