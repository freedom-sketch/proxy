/* Описание стандарта:
    https://datatracker.ietf.org/doc/html/rfc1928
    https://datatracker.ietf.org/doc/html/rfc1929
    https://datatracker.ietf.org/doc/html/rfc1961
    https://datatracker.ietf.org/doc/html/rfc3089
*/
/* Greeting:
The client connects to the server, and sends a version
identifier/method selection message:
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
The VER field is set to X'05' for this version of the protocol.  The
NMETHODS field contains the number of method identifier octets that
appear in the METHODS field.

The server selects from one of the methods given in METHODS, and
sends a METHOD selection message:
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+

The values currently defined for METHOD are:
    X'00' NO AUTHENTICATION REQUIRED
    X'01' GSSAPI
    X'02' USERNAME/PASSWORD
    X'03' to X'7F' IANA ASSIGNED
    X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    X'FF' NO ACCEPTABLE METHODS
*/
/* Requests:
Once the method-dependent subnegotiation has completed, the client
sends the request details.  If the negotiated method includes
encapsulation for purposes of integrity checking and/or
confidentiality, these requests MUST be encapsulated in the method-dependent encapsulation.

The SOCKS request is formed as follows:
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
Where:
   VER: protocol version: X'05'
   CMD:
    -CONNECT X'01'
    -BIND X'02'
    -UDP ASSOCIATE X'03'
   RSV: RESERVED
   ATYP (address type of following address):
    -IP V4 address: X'01'
    -DOMAINNAME: X'03'
    -IP V6 address: X'04'
   DST.ADDR: desired destination address
   DST.PORT: desired destination port in network octet order

The SOCKS server will typically evaluate the request based on source
and destination addresses, and return one or more reply messages, as
appropriate for the request type.
*/
/* Replies:
The SOCKS request information is sent by the client as soon as it has
established a connection to the SOCKS server, and completed the
authentication negotiations.  The server evaluates the request, and
returns a reply formed as follows:
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
Where:
    VER protocol version: X'05'
    REP    Reply field:
        -X'00' succeeded
        -X'01' general SOCKS server failure
        -X'02' connection not allowed by ruleset
        -X'03' Network unreachable
        -X'04' Host unreachable
        -X'05' Connection refused
        -X'06' TTL expired
        -X'07' Command not supported
        -X'08' Address type not supported
        -X'09' to X'FF' unassigned
    RSV    RESERVED
    ATYP   address type of following address

Fields marked RESERVED (RSV) must be set to X'00'.

If the chosen method includes encapsulation for purposes of
authentication, integrity and/or confidentiality, the replies are
encapsulated in the method-dependent encapsulation.
*/

#include "socks5.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <string.h>
#include <stdint.h>

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
        send(client_fd, resp, 2, 0);
        return -1;
    }

    uint8_t resp[2] = {0x05, METHOD_NO_AUTH_REQ};
    if (send(client_fd, resp, 2, 0) < 2)
        return -1;

    return 0;
}

int handle_socks5_request(int client_fd)
{
    struct socks5_header hdr;

    if (recv(client_fd, &hdr, sizeof(hdr), 0) < (ssize_t)(sizeof(hdr)))
        return -1;

    if (hdr.ver != 0x05 || hdr.cmd != CMD_CONNECT)
        return -1;
    
    if (hdr.atyp == ATYPE_IPv4) {
        uint8_t ipv4[4];
        uint16_t port;

        recv(client_fd, ipv4, sizeof(ipv4), 0);
        recv(client_fd, &port, sizeof(port), 0);

        int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (remote_fd < 0) return -1;

        struct sockaddr_in target_addr;
        memset(&target_addr, 0,sizeof(target_addr));

        target_addr.sin_family = AF_INET;
        target_addr.sin_port = port;
        memcpy(&target_addr.sin_addr.s_addr, ipv4, 4);

        /* По стандарту в ответе (массив reply) необходимо указывать локальные адрес и порт, с которых
        сервер вышел в сеть, но я просто забью все нулями и не буду указывать эти параметры.

        Память выделяется на 10 байт (reply[10]) т.к. VER, REP, RSV, ATYP всегда равны 1 байту,
        BND.PORT - всегда 2 байта, а размер BND.ADDR в нашем случае известен, так как у нас IPv4 (4 байта)*/
        uint8_t reply[10] = {0};

        reply[0] = 0x05;
        reply[1] = REP_SUCCEEDED;
        reply[2] = RSV;
        reply[3] = ATYPE_IPv4;

        if (connect(remote_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            reply[1] = REP_HOST_UNREACHABLE;
            send(client_fd, reply, sizeof(reply), 0);
            close(remote_fd);
            return -1;
        } else
            send(client_fd, reply, sizeof(reply), 0);

    } else if (hdr.atyp == ATYPE_DOMAINNAME) {
        uint8_t len;
        recv(client_fd, &len, sizeof(len), 0);

        char domain[256];
        recv(client_fd, domain, (size_t)len, 0);
        domain[len] = '\0';

        uint16_t port;
        recv(client_fd, &port, sizeof(port), 0);
    } else
        return -1;
    
        return 0;
}