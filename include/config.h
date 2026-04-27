/*
* config.h - Интерфейс работы с конфигурационным файлом.
*/

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#ifdef _WIN32
	#include <winsock2.h>
#else
	#include <netinet/in.h>
#endif /* _WIN32 */

struct config_t {
	struct in_addr listen_addr;
	uint16_t port;
};

/* Инициализирует конфиг с помощью cJSON */
int init_config(const char* path);
/* Заполняет cfg данными из main_config */
void fill_config(struct config_t* cfg);

#endif /* !CONFIG_H */