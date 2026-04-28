cmake_minimum_required(VERSION 3.10)
project(not_proxy_server LANGUAGES C)

include_directories(${CMAKE_SOURCE_DIR})

set(SOURCES "src/main.c")

if(WIN32)
    set(CONFIG_PATH "config.json")
    list(APPEND SOURCES "src/platform/win32_socks5.c")
    set(PLATFORM_LIBS Ws2_32)
elseif(UNIX)
    set(CONFIG_PATH "/etc/not-proxy/srv/config.json")
    list(APPEND SOURCES "src/platform/unix_socks5.c")
    set(PLATFORM_LIBS "")
endif()

add_definitions(-DDEFAULT_CONFIG_PATH="${CONFIG_PATH}")
add_executable(not_proxy_srv ${SOURCES}   "libs/cJSON/cJSON.c" "libs/cJSON/cJSON.h" "src/config.c" "include/config.h")
target_link_libraries(not_proxy_srv ${PLATFORM_LIBS})