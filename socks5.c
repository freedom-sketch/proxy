#include "socks5.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>

int handle_socks5_greeting(int client_fd)
{
    uint8_t header[2];
    ssize_t n;

    n = recv(client_fd, header, 2, 0);
    if (n < 2) return -1;

    uint8_t ver = header[0];
    uint8_t n_methods = header[1];

    if (ver != 0x05) return -1;
    if (n_methods < 1 || n_methods > 255) return -1;

    uint8_t methods[255];

    n = recv(client_fd, methods, 255, 0);
    if (n < n_methods) return -1;

    int auth_ok = 0;
    for (int i = 0; i < n_methods; i++) {
        if (methods[i] == 0x00) {
            auth_ok = 1;
            break;
        }
    }

    if (!auth_ok) {
        uint8_t resp[2] = {0x05, 0xFF};
        send(client_fd, resp, 2, 0);
        return -1;
    }

    uint8_t resp[2] = {0x05, 0x00};
    if (send(client_fd, resp, 2, 0) < 2) return -1;

    return 0;
}