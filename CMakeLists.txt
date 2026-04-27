cmake_minimum_required(VERSION 3.10)
project(Socks5 LANGUAGES C)

include_directories(${CMAKE_SOURCE_DIR})

set(SOURCES main.c)

if(WIN32)
    list(APPEND SOURCES platform/win32_socks5.c)
    set(PLATFORM_LIBS Ws2_32)
elseif(UNIX)
    list(APPEND SOURCES platform/unix_socks5.c)
    set(PLATFORM_LIBS "")
endif()

add_executable(socks5_app ${SOURCES})
target_link_libraries(socks5_app ${PLATFORM_LIBS})