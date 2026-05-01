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

/* Инициализирует серверный сокет в соответствии с конфигом и начинает прослушку */
int server_init(struct config_t* cfg);
/* Обрабатывает SOCKS5 авторизацию */
int handle_socks5_greeting(SOCKET client_socket);
/* Обрабатывает запросы авторизованных клиентов */
int handle_socks5_request(SOCKET client_fd);
/* Формирует пакет ответа на 10 байт: VER=0x05; REP=0x00; ATYPE=0x01; BND.ADDR и BND.PORT обнуляет */
static void form_default_reply(uint8_t* rpl);
/* Обрабатывает запрос с ATYPE = 0x01 */
static int process_ipv4_request(SOCKET client_fd);
/* Обрабатывает запрос с ATYPE = 0x03 */
static int process_domainname_request(SOCKET client_fd);
/* Запускает двустороннюю ретрансляцию данных между клиентом и целевым хостом*/
static void start_relay(SOCKET client_fd, SOCKET remote_fd);
/* Создает сокет, биндит его к local_addr и возвращает дескриптор */
static SOCKET init_socket(int af, int type, int protocol, int reuse_addr, struct sockaddr_in* local_addr);

int server_init(struct config_t *cfg)
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
	if (server_socket == INVALID_SOCKET) {
		fprintf(stderr, "Error initialization server socket #%d\n", WSAGetLastError());
		return -1;
	}
	LOG("Server socket initialization is OK\n");

	err_stat = listen(server_socket, SOMAXCONN);
	if (err_stat != 0) {
		fprintf(stderr, "Can't start to listen to. #%d\n", WSAGetLastError());
		closesocket(server_socket);
		return -1;
	}
	char str_local_ip[47] = {0};
	inet_ntop(AF_INET, &cfg->listen_addr, str_local_ip, sizeof(str_local_ip));
	printf("Listening to %s:%d...\n", str_local_ip, ntohs(cfg->port));

	struct sockaddr_in client_addr = {0};
	socklen_t client_addr_len = sizeof(client_addr);

	while (1) {
		SOCKET client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_socket == INVALID_SOCKET) {
			fprintf(stderr, "Client detected, but can't connect to a client. #%d\n", WSAGetLastError());
			closesocket(server_socket);
			closesocket(client_socket);
			return -1;
		}
		char str_client_ip[47] = {0};
		inet_ntop(AF_INET, &client_addr.sin_addr, str_client_ip, sizeof(str_client_ip));
		LOG("Connection to client %s:%d successfully established\n", str_client_ip, ntohs(client_addr.sin_port));
	}
}

int handle_socks5_greeting(SOCKET client_socket)
{
	uint8_t header[2];
	int n;
	n = recv(client_socket, header, sizeof(header), 0);
	if (n < 2) return -1;

	uint8_t ver = header[0];
	uint8_t n_methods = header[1];

	if (ver != 0x05) return -1;
	if (n_methods < 1) return -1;

	uint8_t methods[255];
	n = recv(client_socket, methods, 255, 0);
	if (n < n_methods) return -1;

	int auth_ok = 0;
	for (int i = 0; i < n_methods; i++) {
		if (methods[i] == METHOD_NO_AUTH_REQ) {
			auth_ok = 1;
			break;
		}
	}

	if (auth_ok) {
		uint8_t resp[2] = { 0x05, NO_ACCEPTABLE_METHODS };
		LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);
		send(client_socket, resp, sizeof(resp), 0);
		return -1;
	}

	uint8_t resp[2] = { 0x05, METHOD_NO_AUTH_REQ };
	if (send(client_socket, resp, sizeof(resp), 0) < 2) {
		LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);
		return -1;
	}

	return 0;
}

int handle_socks5_request(SOCKET client_fd)
{
	struct socks5_header hdr = {0};

	if (recv(client_fd, &hdr, sizeof(hdr), 0) < sizeof(hdr)) return -1;
	LOG("REQUEST:\n\t" "VER: %#x\n\tCMD: %#x\n\tRSV: %#x\n\tATYP: %#x\n",
	hdr.ver, hdr.cmd, hdr.rsv, hdr.atyp);

	if (hdr.ver != 0x05 || hdr.cmd != CMD_CONNECT) return -1;

	if (hdr.atyp == ATYPE_IPv4) {
		if (process_ipv4_request(client_fd) < 0) return -1;
	}
	else if (hdr.atyp == ATYPE_DOMAINNAME) {
		if (process_domainname_request(client_fd) < 0) return -1;
	}
	else return -1;
	
	return 0;
}

static int process_ipv4_request(SOCKET client_socket)
{
	uint8_t ip[4];
	uint16_t port;

	int n = recv(client_socket, ip, sizeof(ip), 0);
	if (n != sizeof(ip)) return -1;
	n = recv(client_socket, &port, sizeof(port), 0);
	if (n != sizeof(port)) return -1;

	LOG("\tDST.ADDR: %d.%d.%d.%d\n\tDST.PORT: %d\n", ip[0], ip[1], ip[2], ip[3], ntohs(port));

	SOCKET remote_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (remote_socket == INVALID_SOCKET) {
		fprintf(stderr, "Error initialization remote socket #%d\n", WSAGetLastError());
		return -1;
	}
	LOG("Remote socket (#%llx) initialization is OK\n", (unsigned long long)remote_socket);

	struct sockaddr_in target_addr = {
		.sin_family = AF_INET,
		.sin_addr = htonl(*(uint32_t*)ip),
		.sin_port = port
	};

	uint8_t reply[10];
	form_default_reply(reply);

	if (connect(remote_socket, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
		reply[1] = REP_HOST_UNREACHABLE;
		send(client_socket, reply, sizeof(reply), 0);
		LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);
		closesocket(remote_socket);
		return -1;
	}

	send(client_socket, reply, sizeof(reply), 0);
	LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

	start_relay(client_socket, remote_socket);
	closesocket(remote_socket);
	return 0;
}

static SOCKET init_socket(int af, int type, int protocol, int reuse_addr, struct sockaddr_in *local_addr)
{
	SOCKET new_socket = socket(af, type, protocol);
	if (new_socket == INVALID_SOCKET) {
		closesocket(new_socket);
		return INVALID_SOCKET;
	}

	if (reuse_addr) {
		int socket_opt = 1;
		if (setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&socket_opt, sizeof(socket_opt)) != 0) {
			closesocket(new_socket);
			return INVALID_SOCKET;
		}
	}

	if (bind(new_socket, (struct sockaddr*)local_addr, sizeof(new_socket)) != 0) {
		closesocket(new_socket);
		return INVALID_SOCKET;
	};

	return new_socket;
}

static void form_default_reply(uint8_t* rpl)
{
	memset(rpl, 0, 10);
	rpl[0] = 0x05;
	rpl[1] = REP_SUCCEEDED;
	rpl[2] = RSV;
	rpl[3] = ATYPE_IPv4;
}