/*
 * main.c - Реализация SOCKS5 сервера
 * 
 Cтандарт SOCKS5:
 * 
 * RFC1928: https://datatracker.ietf.org/doc/html/rfc1928
 * RFC1929: https://datatracker.ietf.org/doc/html/rfc1929
 * RFC1961: https://datatracker.ietf.org/doc/html/rfc1961
 * RFC3089: https://datatracker.ietf.org/doc/html/rfc3089
*/

#include "include/socks5.h"
#include "include/config.h"

#include <stdio.h>

int main(int argc, char *argv[])
{
    if (init_config(DEFAULT_CONFIG_PATH) < 0) {
        fprintf(stderr, "Error reading config at \"%s\"\n", DEFAULT_CONFIG_PATH);
        return -1;
    }

    struct config_t config;
    fill_config(&config);

    SOCKET server_socket = server_init(&config);
    if (server_socket == INVALID_SOCKET) return -1;
    server_run(server_socket);
}