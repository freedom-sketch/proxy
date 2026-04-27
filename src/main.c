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

#include "socks5.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>

int debug_info = 0;
uint16_t server_port = 1080;

int main(int argc, char *argv[])
{
    /* устанавливаем игнорировать сигнал завершения дочерних процессов. Они будут автоматически
    удаляться после отработки, не попадая в состояние defunct */
    signal(SIGCHLD, SIG_IGN);

    int opt;
    while ((opt = getopt(argc, argv, "p:d")) != -1) {
        switch (opt) {
            case 'p':
                server_port = atoi(optarg);
                if (server_port <= 0 || server_port > 65535) {
                    fprintf(stderr, "Invalid port number: %s\n", optarg);
                    return -1;
                }
                printf("Port %d selected\n", server_port);
                break;
            case 'd':
                debug_info = 1;
                printf("Debug info is enabled\n");
                break;
            case '?':
                fprintf(stderr, "Usage: %s [-p port] [-d]\n", argv[0]);
                return -1;
        }
    }

    /* создаем сокет сервера и записываем его дескриптор */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Failed to create socket");
        return -1;
    }

    int socket_opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &socket_opt, sizeof(socket_opt)) < 0) {
        perror("setsockopt failed");
    }

    /* создаем структуру для хранения локального IPv4 адреса */
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET, /* семейство адресов IPv4 */
        .sin_addr.s_addr = INADDR_ANY, /* любой сетевой интерфейс */
        .sin_port = htons(server_port) /* перевод номера порта из формата хоста в формат сети */
    };

    /* связываем дескриптор сокета с локальным адресом */
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        return -1;
    };

    /* переводим сокет в состояние прослушки адреса */
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        return -1;
    }
    printf("Server listening on port %d...\n", server_port);

    /* создаем дескриптор для клиента */
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (1) {
        /* принимаем входящий запрос на соединение */
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        char *client_ip = inet_ntoa(client_addr.sin_addr);
        uint16_t client_port = ntohs(client_addr.sin_port);
        printf("Connected: %s:%d\n", client_ip, client_port);

        /* создаем дочерний процесс. fork() вернет PID созданного процесса в родительский процесс и 0 в дочерний */
        if (fork() == 0) {
            /* закрываем для дочернего процесса сокет SOCKS сервера */
            close(server_fd);

            if (handle_socks5_greeting(client_fd) == 0)
                handle_socks5_request(client_fd);
            
            /* закрываем для дочернего процесса сокет клиента после окончания ретрансляции и выходим из процесса */
            close(client_fd);
            exit(0);
        }

        /* закрываем сокет клиента для родительского процесса. */
        close(client_fd);
    }
}