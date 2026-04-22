/*
 * socks5.c - Реализация протокола SOCKS5 (RFC 1928)
 *
 * Cтандарт SOCKS5:
 * 
 * RFC1928: https://datatracker.ietf.org/doc/html/rfc1928
 * RFC1929: https://datatracker.ietf.org/doc/html/rfc1929
 * RFC1961: https://datatracker.ietf.org/doc/html/rfc1961
 * RFC3089: https://datatracker.ietf.org/doc/html/rfc3089
*/

#include "socks5.h"
#include "fmt.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>

#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* Обрабатывает SOCKS5 авторизацию */
int handle_socks5_greeting(int client_fd);
/* Обрабатывает запросы авторизованных клиентов */
int handle_socks5_request(int client_fd);

/* Формирует пакет ответа на 10 байт: VER=0x05; REP=0x00; ATYPE=0x01; BND.ADDR и BND.PORT обнуляет */
static void form_default_reply(uint8_t *rpl);
/* Обрабатывает запрос с ATYPE = IPv4 */
static int process_ipv4_request(int client_fd);
/* Запускает двустороннюю ретрансляцию данных между клиентом и целевым хостом*/
static void start_relay(int client_fd, int remote_fd);

int handle_socks5_greeting(int client_fd)
{
    uint8_t header[2];
    ssize_t n;

    n = recv(client_fd, header, 2, 0);
    if (n < 2)
        return -1;

    uint8_t ver = header[0];
    uint8_t n_methods = header[1];

    if (ver != 0x05) return -1;
    if (n_methods < 1 || n_methods > 255)
        return -1;

    uint8_t methods[255];

    n = recv(client_fd, methods, 255, 0);
    if (n < n_methods) return -1;

    int auth_ok = 0;
    for (int i = 0; i < n_methods; i++) {
        if (methods[i] == METHOD_NO_AUTH_REQ) {
            auth_ok = 1;
            break;
        }
    }

    if (!auth_ok) {
        uint8_t resp[2] = {0x05, NO_ACCEPTABLE_METHODS};

        LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);

        send(client_fd, resp, 2, 0);
        return -1;
    }

    uint8_t resp[2] = {0x05, METHOD_NO_AUTH_REQ};
    if (send(client_fd, resp, 2, 0) < 2) {
        LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);
        return -1;
    }

    return 0;
}

int handle_socks5_request(int client_fd)
{
    struct socks5_header hdr;

    if (recv(client_fd, &hdr, sizeof(hdr), 0) < (ssize_t)(sizeof(hdr)))
        return -1;
    
    LOG("REQUEST:\n\t" "VER: %#x\n\tCMD: %#x\n\tRSV: %#x\n\tATYP: %#x\n", 
    hdr.ver, hdr.cmd, hdr.rsv, hdr.atyp);

    if (hdr.ver != 0x05 || hdr.cmd != CMD_CONNECT)
        return -1;
    
    if (hdr.atyp == ATYPE_IPv4) {
        if (process_ipv4_request(client_fd) < 0)
            return -1;

    } else if (hdr.atyp == ATYPE_DOMAINNAME) {
        /*
        TODO: ВЫНЕСТИ В ОТДУЛЬНУЮ ФУНКЦИЮ, ДОПИСАТЬ
        uint8_t len;
        recv(client_fd, &len, sizeof(len), 0);
        if (len == 0) return -1;

        char domain[257];  0-255 под размер домена и 1 байте под \0
        recv(client_fd, domain, (size_t)len, 0);
        domain[len] = '\0';

        uint16_t port;
        recv(client_fd, &port, sizeof(port), 0);

        LOG("\tDST.ADDR: %s\n\tDST.PORT: %d\n", domain, ntohs(port));

        struct in_addr **in_addr_list = domain_to_ipv4_list(domain);
        if (in_addr_list == NULL) return -1;
        if (in_addr_list[0] == NULL) return -1;

        int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (remote_fd < 0) return -1;

        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));

        target_addr.sin_family = AF_INET;
        target_addr.sin_port = port;
        target_addr.sin_addr = *in_addr_list[0];

        uint8_t reply[7+len];
        memset(reply, 0, sizeof(reply));

        reply[0] = 0x05;
        reply[1] = REP_SUCCEEDED;
        reply[2] = RSV;
        reply[3] = ATYPE_DOMAINNAME;
        reply[4] = len;

        if (connect(remote_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            reply[1] = REP_HOST_UNREACHABLE;
            send(client_fd, reply, sizeof(reply), 0);
            close(remote_fd);

            LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

            return -1;
        } else {
            send(client_fd, reply, sizeof(reply), 0);

            LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

            start_relay(client_fd, remote_fd);
            close(remote_fd);
        }
        */
    } else
        return -1;
    
    return 0;
}

/* TODO: ПЕРЕПИСАТЬ!!!!!!!! Память под массив указателей не выделяется в куче!!!!!!!!
struct in_addr **domain_to_ipv4_list(const char *hostname)
{
    struct hostent *he;

    if ((he = gethostbyname(hostname)) == NULL) {
        perror("gethostbyname");
        return NULL;
    }

    return (struct in_addr **)he->h_addr_list;
}
*/

static int process_ipv4_request(int client_fd)
{
    uint8_t ip[4]; /* создаем буфер на 4 байта под IP адрес */
    uint16_t port; /* буфер на 2 байта под порт */

    /* читаем из клиентского сокета первые 6 байт. 4 под IP и 2 под порт */
    recv(client_fd, ip, sizeof(ip), 0);
    recv(client_fd, &port, sizeof(port), 0);

    LOG("\tDST.ADDR: %d.%d.%d.%d\n\tDST.PORT: %d\n", ip[0], ip[1], ip[2], ip[3], ntohs(port));

    /* создаем сокет с полножуплексной передачей семейства IPv4 для целевого хоста */
    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_fd < 0) return -1;

    /* создаем и заполняем структуру информации об IPv4 сокете */
    struct sockaddr_in target_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(*(in_addr_t *)ip),
        .sin_port = port
    };

    /* VER, REP, RSV, ATYP = 1 байт, BND.PORT = 2 байта, BND.ADDR = 4 байта (IPv4)
    1 * 4 + 2 + 4 = 10 байт */
    uint8_t reply[10] = {0};
    form_default_reply(reply);

    /* пытаемся установить соединение */
    if (connect(remote_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        /* в случае неудачи, меняем REP */
        reply[1] = REP_HOST_UNREACHABLE;
        /* отправляем ответ и закрываем сокет целевого хоста */
        send(client_fd, reply, sizeof(reply), 0);
        LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

        close(remote_fd);
        return -1;            
    }

    /* в случае удачи отправляем ответ и начинаем проксировать трафик */
    send(client_fd, reply, sizeof(reply), 0);

    LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

    start_relay(client_fd, remote_fd);
    close(remote_fd);
}

static void start_relay(int client_fd, int remote_fd)
{
    LOG(GRN_TXT "\nRELAY STARTED\n" RESET);
    
    struct pollfd fds[2];

    fds[0].fd = client_fd;
    fds[0].events = POLLIN;

    fds[1].fd = remote_fd;
    fds[1].events = POLLIN;

    uint8_t buffer[10240];

    while (1) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            perror("poll error");
            break;
        }

        for (int i=0; i < 2; i++) {
            if (fds[i].revents & POLLIN) {
                int source_fd = fds[i].fd;
                int dest_fd = (i == 0) ? fds[1].fd : fds[0].fd;

                ssize_t n = recv(source_fd, buffer, sizeof(buffer), 0);
                if (n <= 0) return;

                if (debug_info) {
                    char printf_buffer[10241];
                    memcpy(printf_buffer, buffer, n);
                    printf_buffer[n+1] = '\0';
                    printf(BOLD_TXT "\nCHANGES IN SOCKETS:\n" RESET);
                    printf("source fd: %d | dest fd: %d\nbuffer:\n" BLUE_TXT "%s" RESET, source_fd, dest_fd, printf_buffer);
                }

                if (send(dest_fd, buffer, n, 0) <= 0) return;
            }
        }
    }
}

static void form_default_reply(uint8_t *rpl)
{
    memset(rpl, 0, 10);
    rpl[0] = 0x05;
    rpl[1] = REP_SUCCEEDED;
    rpl[2] = RSV;
    rpl[3] = ATYPE_IPv4;
}