/*
* config.c - Реализация работы с конфигурационным файлом.
* Для парсинга используется cJSON [https://github.com/davegamble/cjson], MIT license.
* 
* Идея заключается в том, чтобы при запуске программы один раз загрузить конфиг
* в память в виде структуры, в статическую переменную, а затем просто копировать
* эту структуру в другие, не делая повторного чтения.
*/

#include "include/config.h"
#include "libs/cJSON/cJSON.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
#endif /* _WIN32 */

static struct config_t main_config;

int debug_info;

/* Читает файл конфига по пути path и записывает в кучу */
static char* read_config(const char* path);

int init_config(const char *path)
{
	char *data = read_config(path);
	if (data == NULL) {
		fprintf(stderr, "Error reading config\n");
		return -1;
	}

	cJSON* json = cJSON_Parse(data);
	if (!json) {
		fprintf(stderr, "Config parsing error\n");
		free(data);
		return -1;
	}

	cJSON* ip_json = cJSON_GetObjectItemCaseSensitive(json, "listen_addr");
	if (cJSON_IsString(ip_json) && (ip_json->valuestring != NULL)) {
		if (inet_pton(AF_INET, ip_json->valuestring, &(main_config.listen_addr)) <= 0) {
			fprintf(stderr, "Invalid IP address in config\n");
			cJSON_Delete(json);
			free(data);
			return -1;
		}
	} else fprintf(stderr, "IP validation error\n");

	cJSON* port_json = cJSON_GetObjectItemCaseSensitive(json, "port");
	if (cJSON_IsNumber(port_json)) {
		int p = port_json->valueint;
		if (p < 0 || p > 65535) {
			fprintf(stderr, "Port out of range\n");
			cJSON_Delete(json);
			free(data);
			return -1;
		}
		main_config.port = htons((uint16_t)p);
	} else fprintf(stderr, "Port must be a number\n");

	cJSON* debug_info_json = cJSON_GetObjectItemCaseSensitive(json, "debug_info");
	if (cJSON_IsNumber(debug_info_json)) {
		int di = debug_info_json->valueint;
		if (di != 0 && di != 1) {
			fprintf(stderr, "Debug_info must be 0 or 1\n");
			cJSON_Delete(json);
			free(data);
			return -1;
		}
		debug_info = di;
	} else fprintf(stderr, "Debug_info must be 0 or 1\n");

	cJSON_Delete(json);
	free(data);
	return 0;
}

static char* read_config(const char* path)
{
	FILE* f = fopen(path, "rb");
	if (!f) {
		perror("Can't open config");
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	rewind(f);

	if (size < 0) {
		fclose(f);
		return NULL;
	}

	char *data = calloc((size_t)size + 1, 1);
	if (!data) {
		fclose(f);
		return NULL;
	}

	size_t read = fread(data, 1, size, f);
	fclose(f);
	if (read != size) {
		printf("The read portion of the file did not match the file size.\n");
		free(data);
		return NULL;
	}
	data[size] = '\0';

	return data;
}

void fill_config(struct config_t* cfg)
{
	if (cfg != NULL) {
		*cfg = main_config;
	}
}