#include "server.h"

int main(int argc, char *argv[]) {
    server_config_t config = {};
    auto const      status = server_config_parse(&config, argc, argv);
    if (status == SERVER_CONFIG_EXIT_SUCCESS) {
        return 0;
    }
    if (status != SERVER_CONFIG_OK) {
        return 1;
    }
    return server_run(&config);
}
