/*
 * socks5.h - Определение интерфейса реализации протокола SOCKS5
 * 
 * Cтандарт SOCKS5:
 * 
 * RFC1928: https://datatracker.ietf.org/doc/html/rfc1928
 * RFC1929: https://datatracker.ietf.org/doc/html/rfc1929
 * RFC1961: https://datatracker.ietf.org/doc/html/rfc1961
 * RFC3089: https://datatracker.ietf.org/doc/html/rfc3089
*/

#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>

extern int debug_info;
extern uint16_t server_port;

/* Макрос для логирования в stdout */
#define LOG(fmt, ...) \
    do { if (debug_info) printf(fmt, ##__VA_ARGS__); } while (0)

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

#ifdef _MSC_VER
    #pragma pack(push, 1)
    struct socks5_header {
        uint8_t ver;
        uint8_t cmd;
        uint8_t rsv;
        uint8_t atyp;
    };
    #pragma pack(pop)
#else
    struct __attribute__((packed)) socks5_header {
        uint8_t ver;
        uint8_t cmd;
        uint8_t rsv;
        uint8_t atyp;
    };
#endif /* _MSC_VER */

int handle_socks5_greeting(int client_fd);
int handle_socks5_request(int client_fd);

#endif /* !SOCKS5_H */