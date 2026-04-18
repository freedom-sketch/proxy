# SOCKS5 Proxy Server
> Минималистичный SOCKS5-прокси для POSIX совместимых ОС на языке C. Поддерживает IPv4 запросы на подключение.
---
## ⚡ Быстрый старт
### 1. Клонируйте репозиторий
```bash
git clone https://github.com/freedom-sketch/socks5-proxy
```
### 2. Скомпилируйте
Рекомендуется использовать GCC
```bash
cc main.c socks5.c -o a.out
```
### 3. Запустите
```bash
./a.out <порт>
```
### 4. Проверьте
```bash
curl -v --socks5 127.0.0.1:<порт> 1.1.1.1
```
