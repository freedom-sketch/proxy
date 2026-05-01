# SOCKS5 Proxy Server
> Минималистичный SOCKS5-прокси для POSIX совместимых ОС на языке C. Поддерживает IPv4 запросы на подключение.
---
## ⚡ Быстрый старт
### 1. Клонируйте репозиторий
```bash
git clone https://github.com/freedom-sketch/socks5-proxy
cd socks5-proxy
```
### 2. Соберите
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```
### 3. Настройте и запустите
Отредактируйте config.json в папке с исполняемым файлом. Шаблон возьмите из config.json.example.
Далее запустите:
```bash
# Linux
./not_proxy_srv
# Windows
.\not_proxy_srv.exe
```
### 4. Проверьте
```bash
curl -v --socks5 127.0.0.1:<port> google.com
```

## TODO
**Поддержка:**
* IPv6
* UDP
* TLS
