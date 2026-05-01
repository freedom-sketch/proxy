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
#include <process.h>

#include <stdio.h>

/* Обрабатывает запрос с ATYPE = 0x01 */
static int process_ipv4_request(SOCKET client_socket);
/* Обрабатывает запрос с ATYPE = 0x03 */
static int process_domainname_request(SOCKET client_socket);
/* Запускает двустороннюю ретрансляцию данных между клиентом и целевым хостом*/
static void start_relay(SOCKET client_socket, SOCKET remote_socket);

/* Создает сокет, биндит его к local_addr и возвращает дескриптор */
static SOCKET init_socket(int af, int type, int protocol, int reuse_addr, struct sockaddr_in* local_addr);

/* Формирует пакет ответа на 10 байт: VER=0x05; REP=0x00; ATYPE=0x01; BND.ADDR и BND.PORT обнуляет */
static void form_default_reply(uint8_t *rpl);
/* Дожидается len байтов из сети и записывает их в buffer */
static int recv_all(SOCKET socket, char *buffer, int len);

unsigned WINAPI client_handler(void *arg);

SOCKET server_init(struct config_t *cfg)
{
	WSADATA ws_data = {0};
	int err_stat = WSAStartup(MAKEWORD(2, 2), &ws_data);
	if (err_stat != 0) {
		fprintf(stderr, "Error WinSock version initializaion #%d\n", WSAGetLastError());
		return INVALID_SOCKET;
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
		WSACleanup();
		return INVALID_SOCKET;
	}
	LOG("Server socket initialization is OK\n");

	return server_socket;
}

int server_run(SOCKET srv_sock)
{
	int err_stat = listen(srv_sock, SOMAXCONN);
	if (err_stat != 0) {
		fprintf(stderr, "Can't start to listen to. #%d\n", WSAGetLastError());
		closesocket(srv_sock);
		WSACleanup();
		return -1;
	}
	printf("The server has started...");

	struct sockaddr_in client_addr = { 0 };
	socklen_t client_addr_len = sizeof(client_addr);

	while (1) {
		SOCKET client_socket = accept(srv_sock, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_socket == INVALID_SOCKET) {
			fprintf(stderr, "Accept failed. #%d\n", WSAGetLastError());
			continue;
		}

		char str_client_ip[47] = { 0 };
		inet_ntop(AF_INET, &client_addr.sin_addr, str_client_ip, sizeof(str_client_ip));
		LOG("Connection from %s:%d\n", str_client_ip, ntohs(client_addr.sin_port));

		HANDLE thread = (HANDLE)_beginthreadex(NULL, 0, client_handler, (void *)client_socket, 0, NULL);

		if (thread == NULL) {
			fprintf(stderr, "Failed to create thread\n");
			closesocket(client_socket);
		}
		else {
			CloseHandle(thread);
		}
	}

	closesocket(srv_sock);
	WSACleanup();
	return 0;
}

int handle_socks5_greeting(SOCKET client_socket)
{
	uint8_t header[2];
	int n;
	n = recv(client_socket, (char *)header, sizeof(header), 0);
	if (n < 2) return -1;

	uint8_t ver = header[0];
	uint8_t n_methods = header[1];

	if (ver != 0x05) return -1;
	if (n_methods < 1) return -1;

	uint8_t methods[255];
	n = recv(client_socket, (char *)methods, 255, 0);
	if (n < n_methods) return -1;

	int auth_ok = 0;
	for (int i = 0; i < n_methods; i++) {
		if (methods[i] == METHOD_NO_AUTH_REQ) {
			auth_ok = 1;
			break;
		}
	}

	if (!auth_ok) {
		uint8_t resp[2] = { 0x05, NO_ACCEPTABLE_METHODS };
		LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);
		send(client_socket, (char *)resp, sizeof(resp), 0);
		return -1;
	}

	uint8_t resp[2] = { 0x05, METHOD_NO_AUTH_REQ };
	if (send(client_socket, (char *)resp, sizeof(resp), 0) < 2) {
		LOG("AUTH:\n\tVER: %#x\n\tMETHOD: %#x\n", resp[0], resp[1]);
		return -1;
	}

	return 0;
}

int handle_socks5_request(SOCKET client_socket)
{
	struct socks5_header hdr = {0};

	if (recv_all(client_socket, (char*)&hdr, sizeof(hdr)) < (int)sizeof(hdr))
		return -1;
	LOG("REQUEST:\n\t" "VER: %#x\n\tCMD: %#x\n\tRSV: %#x\n\tATYP: %#x\n",
	hdr.ver, hdr.cmd, hdr.rsv, hdr.atyp);

	if (hdr.ver != 0x05 || hdr.cmd != CMD_CONNECT) return -1;

	if (hdr.atyp == ATYPE_IPv4) {
		if (process_ipv4_request(client_socket) < 0) return -1;
	}
	else if (hdr.atyp == ATYPE_DOMAINNAME) {
		if (process_domainname_request(client_socket) < 0) return -1;
	}
	else return -1;
	
	return 0;
}

static int process_ipv4_request(SOCKET client_socket)
{
	uint8_t ip[4];
	uint16_t port_net;

	if (recv_all(client_socket, (char *)ip, sizeof(ip)) == -1) return -1;
	if (recv_all(client_socket, (char *)&port_net, sizeof(port_net)) == -1) return -1;

	LOG("\tDST.ADDR: %d.%d.%d.%d\n\tDST.PORT: %d\n", ip[0], ip[1], ip[2], ip[3], ntohs(port_net));

	SOCKET remote_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (remote_socket == INVALID_SOCKET) {
		fprintf(stderr, "Error initialization remote socket #%d\n", WSAGetLastError());
		return -1;
	}
	LOG("Remote socket %llu initialization is OK\n", (unsigned long long)remote_socket);

	struct sockaddr_in target_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = *(uint32_t*)ip,
		.sin_port = port_net
	};

	uint8_t reply[10];
	form_default_reply(reply);

	if (connect(remote_socket, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
		reply[1] = REP_HOST_UNREACHABLE;
		send(client_socket, (char *)reply, sizeof(reply), 0);
		LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);
		closesocket(remote_socket);
		return -1;
	}

	send(client_socket, (char *)reply, sizeof(reply), 0);
	LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);

	start_relay(client_socket, remote_socket);
	closesocket(remote_socket);
	return 0;
}

static int process_domainname_request(SOCKET client_socket)
{
	uint8_t len = 0;
	if (recv_all(client_socket, (char*)&len, sizeof(len)) == -1 || len == 0)
		return -1;

	char domain[256];
	if (recv_all(client_socket, domain, len) == -1) return -1;
	domain[len] = '\0';

	uint16_t port_net;
	if (recv_all(client_socket, (char *)&port_net, sizeof(port_net)) == -1) return -1;

	LOG("\tDST.ADDR: %s\n\tDST.PORT: %d\n", domain, ntohs(port_net));

	SOCKET remote_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (remote_socket == INVALID_SOCKET) {
		fprintf(stderr, "Error initialization remote socket #%d\n", WSAGetLastError());
	}
	LOG("Remote socket %llu initialization is OK\n", (unsigned long long)remote_socket);

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	}, *res;

	uint8_t reply[10] = { 0 };
	form_default_reply(reply);

	char s_port[7] = { 0 };
	snprintf(s_port, sizeof(s_port), "%hu", ntohs(port_net));

	int status = getaddrinfo(domain, s_port, &hints, &res);
	if (status != 0) {
		reply[1] = REP_HOST_UNREACHABLE;
		send(client_socket, (char *)reply, sizeof(reply), 0);
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		closesocket(remote_socket);
		return -1;
	}

	struct sockaddr_in target_addr = *(struct sockaddr_in*)res->ai_addr;
	freeaddrinfo(res);

	if (connect(remote_socket, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
		reply[1] = REP_HOST_UNREACHABLE;
		send(client_socket, (char *)reply, sizeof(reply), 0);
		LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);
		closesocket(remote_socket);
		return -1;
	}

	send(client_socket, (char *)reply, sizeof(reply), 0);
	LOG("REPLY: \n\tREP: %#x\n\tRSV: %#x\n\tATYPE: %#x\n", reply[1], reply[2], reply[3]);
	start_relay(client_socket, remote_socket);
	closesocket(remote_socket);
	return 0;
}

static void start_relay(SOCKET client_socket, SOCKET remote_socket)
{
	WSAPOLLFD fds[2];

	fds[0].fd = client_socket;
	fds[0].events = POLLIN;
	fds[1].fd = remote_socket;
	fds[1].events = POLLIN;

	uint8_t buffer[5120];

	while (1) {
		int ret = WSAPoll(fds, 2, -1);
		if (ret == SOCKET_ERROR) {
			fprintf(stderr, "WSAPoll error #%d\n", WSAGetLastError());
			break;
		}

		for (int i = 0; i < 2; i++) {
			if (fds[i].revents & POLLIN) {
				SOCKET source = fds[i].fd;
				SOCKET dest = (i == 0) ? fds[1].fd : fds[0].fd;

				int n = recv(source, (char *)buffer, sizeof(buffer), 0);
				if (n <= 0) return;
				if (send(dest, (char *)buffer, n, 0) <= 0) return;
			}

			if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				return;
			}
		}
	}
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

	if (bind(new_socket, (struct sockaddr *)local_addr, sizeof(struct sockaddr)) != 0) {
		closesocket(new_socket);
		return INVALID_SOCKET;
	};

	return new_socket;
}

static void form_default_reply(uint8_t *rpl)
{
	memset(rpl, 0, 10);
	rpl[0] = 0x05;
	rpl[1] = REP_SUCCEEDED;
	rpl[2] = RSV;
	rpl[3] = ATYPE_IPv4;
}

static int recv_all(SOCKET socket, char *buffer, int len) {
	int total_received = 0;
	while (total_received < len) {
		int n = recv(socket, buffer + total_received, len - total_received, 0);
		if (n <= 0) {
			return -1;
		}
		total_received += n;
	}
	return total_received;
}

unsigned WINAPI client_handler(void *arg)
{
	SOCKET client_socket = (SOCKET)arg;

	LOG("Thread started for socket %llu\n", (unsigned long long)client_socket);

	if (handle_socks5_greeting(client_socket) == 0) {
		handle_socks5_request(client_socket);
	}

	closesocket(client_socket);
	LOG("Thread finished, socket %llu closed.\n", (unsigned long long)client_socket);

	return 0;
}