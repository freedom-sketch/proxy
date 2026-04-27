cmake_minimum_required(VERSION 3.10)
project(socks5_server LANGUAGES C)

include_directories(${CMAKE_SOURCE_DIR})

set(SOURCES "src/main.c")

if(WIN32)
    list(APPEND SOURCES "src/platform/win32_socks5.c")
    set(PLATFORM_LIBS Ws2_32)
elseif(UNIX)
    list(APPEND SOURCES "src/platform/unix_socks5.c")
    set(PLATFORM_LIBS "")
endif()

add_executable(socks5_srv ${SOURCES}   "libs/cJSON/cJSON.c" "libs/cJSON/cJSON.h")
target_link_libraries(socks5_srv ${PLATFORM_LIBS})