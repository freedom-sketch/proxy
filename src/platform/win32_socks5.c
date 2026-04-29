/*
 * socks5.c - Реализация протокола SOCKS5 (RFC 1928) для Windows систем
 *
 * Cтандарт SOCKS5:
 *
 * RFC1928: https://datatracker.ietf.org/doc/html/rfc1928
 * RFC1929: https://datatracker.ietf.org/doc/html/rfc1929
 * RFC1961: https://datatracker.ietf.org/doc/html/rfc1961
 * RFC3089: https://datatracker.ietf.org/doc/html/rfc3089
*/

#include "include/socks5.h"
#include "include/config.h"
#include "include/fmt.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <sys/types.h>

#include <stdio.h>

/* Создает сокет, биндит его к local_addr и возвращает дескриптор */
static SOCKET init_socket(int af, int type, int protocol, int reuse_addr, struct sockaddr_in* local_addr);
/* Инициализирует серверный сокет в соответствии с конфигом и начинает прослушку */
int proxy_init(struct config_t* cfg);

int proxy_init(struct config_t *cfg)
{
	WSADATA ws_data = {0};
	int err_stat = WSAStartup(MAKEWORD(2, 2), &ws_data);
	if (err_stat != 0) {
		fprintf(stderr, "Error WinSock version initializaion #%d\n", WSAGetLastError());
		return -1;
	}
	LOG("WinSock initialization is OK\n");

	struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
		.sin_addr = cfg->listen_addr,
		.sin_port = cfg->port
	};

	SOCKET server_socket = init_socket(AF_INET, SOCK_STREAM, 0, 1, &server_addr);
	if (server_socket == NULL) {
		fprintf(stderr, "Error initialization server socket #%d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}
	LOG("Server socket initialization is OK\n");

	err_stat = listen(server_socket, SOMAXCONN);
	if (err_stat != 0) {
		fprintf(stderr, "Can't start to listen to. #%d\n", WSAGetLastError());
		closesocket(server_socket);
		WSACleanup();
		return -1;
	}
	printf("Listening...\n");

	struct sockaddr_in client_addr = {0};
	socklen_t client_addr_len = sizeof(client_addr);

	while (1) {
		SOCKET client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_socket == INVALID_SOCKET) {
			fprintf(stderr, "Client detected, but can't connect to a client. #%d\n", WSAGetLastError());
			closesocket(server_socket);
			closesocket(client_socket);
			WSACleanup();
			return -1;
		}
		LOG("Connection to a client established successfully\n");
	}
}

static SOCKET init_socket(int af, int type, int protocol, int reuse_addr, struct sockaddr_in *local_addr)
{
	SOCKET new_socket = socket(af, type, protocol);
	if (new_socket == INVALID_SOCKET) {
		closesocket(new_socket);
		return NULL;
	}

	if (reuse_addr) {
		int socket_opt = 1;
		if (setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, &socket_opt, sizeof(socket_opt)) != 0)
			return NULL;
	}

	if (bind(new_socket, (struct sockaddr*)local_addr, sizeof(new_socket)) != 0) {
		closesocket(new_socket);
		return NULL;
	};

	return new_socket;
}