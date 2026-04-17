#include "socks5.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

int handle_socks5_greeting(int client_fd);

int main(int argc, char *argv[])
{
    /* проверяем, что программа вызвана с указанием порта */
    if (argc < 2) {
        fprintf(stderr, "Error. Usage: %s <port>\n", argv[0]);
        return -1;
    }

    /* создаем сокет сервера и записываем его дескриптор */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Failed to create socket\n");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed\n");
    }

    /* создаем структуру для хранения локального IPv4 адреса */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET; /* семейство адресов IPv4 */
    server_addr.sin_addr.s_addr = INADDR_ANY; /* любой сетевой интерфейс */
    server_addr.sin_port = htons(atoi(argv[1])); /* перевод номера порта из формата хоста в формат сети (LE->BE) */

    /* связываем дескриптор сокета с локальным адресом */
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed\n");
        return -1;
    };

    /* переводим сокет в состояние прослушки адреса */
    if (listen(server_fd, 10) < 0) {
        perror("listen failed\n");
        return -1;
    }
    printf("Server listening on port %s...\n", argv[1]);

    /* создаем дескриптор для клиента */
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    /* принимаем входящий запрос на соединение */
    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        perror("accept failed\n");
        return -1;
    }

    /* получаем ip и порт клиента, выводим их */
    char *client_ip = inet_ntoa(client_addr.sin_addr);
    uint16_t client_port = ntohs(client_addr.sin_port);
    printf("Connected: %s:%d\n", client_ip, client_port);

    /* закрываем дескрипторы */
    close(client_fd);
    close(server_fd);
}