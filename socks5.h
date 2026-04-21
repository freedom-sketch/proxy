#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>

/* Методы аутенфикации */
#define METHOD_NO_AUTH_REQ 0x00 /* NO AUTHENTICATION REQUIRED */
#define METHOD_GSSAPI 0x01
#define METHOD_USR_PASSWD 0x02
#define NO_ACCEPTABLE_METHODS 0xFF /* собый случай ответа сервера, когда ни один из предложенных методов не подошел */

/* Команды (Commands) */
#define CMD_CONNECT 0x01 /* Команда подключения */
#define CMD_BIND 0x02
#define CMD_UDP_ASSOCIATE 0x03

/* Типы адресов */
#define ATYPE_IPv4 0x01 /* IPv4 */
#define ATYPE_DOMAINNAME 0x03 /* Домен */
#define ATYPE_IPv6 0x04 /* IPv6 */

/* Ответы (Replies) */
#define REP_SUCCEEDED 0x00 /* Успех */
#define REP_GEN_SRV_FAILURE 0x01 /* general SOCKS server failure */
#define REP_CON_NOT_ALLOWED_BY_RULESET 0x02 /* connection not allowed by ruleset */
#define REP_NETWORK_UNREACHABLE 0x03
#define REP_HOST_UNREACHABLE 0x04
#define REP_CONNECTION_REFUSED 0x05
#define REP_TTL_EXPIRED 0x06
#define REP_CMD_NOT_SUPPORTED 0x07 /* Command not supported */
#define REP_ATYPE_NOT_SUPPORTED 0x08 /* Address type not supported */

#define RSV 0x00 /* Зарезервированный байт */

/* Цвета */
#define RESET "\033[0m" /* Сброс цвета */
#define BLUE_TXT "\033[34m" /* Синий цвет текста */
#define GRN_TXT "\033[32m" /* Зеленый увет текста */
#define BOLD_TXT "\033[1m" /* Жирный текст */

struct __attribute__((packed)) socks5_header {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
};

extern int debug_info;
extern uint16_t server_port;

int handle_socks5_greeting(int client_fd);
int handle_socks5_request(int client_fd);

struct in_addr **domain_to_ipv4_list(const char *hostname);

/* Формирует дефолтный байтовый массив ответа. Переданный массив должен быть 10 байт.
VER = 0x05
REP = 0x00 (succeeded)
RSV = 0x00
ATYPE = 0x01 (IPv4)
BND.ADDR и BND.PORT заполняет нулями */
void form_default_reply(uint8_t rpl[10]);

void start_relay(int client_fd, int remote_fd);

#endif /* SOCKS5_H */