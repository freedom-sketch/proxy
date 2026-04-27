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

#include "../../include/socks5.h"
#include "../../include/fmt.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <sys/types.h>

#include <stdio.h>

int proxy_init()
{
	WSADATA ws_data = {0};

	int err_stat = WSAStartup(MAKEWORD(2, 2), &ws_data);
	if (err_stat != 0) {
		fprintf(stderr, "Error WinSock version initializaion #%d\n", WSAGetLastError());
		return -1;
	}
	LOG("WinSock initialization is OK\n");

	SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket == INVALID_SOCKET) {
		fprintf(stderr, "Error initialization socket #%d\n", WSAGetLastError());
		closesocket(server_socket);
		WSACleanup();
		return -1;
	}
	LOG("Server socket initialization is OK\n");
}