#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>

struct __attribute__((packed)) socks5_header {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
};

int handle_socks5_greeting(int client_fd);

#endif /* SOCKS5_H */