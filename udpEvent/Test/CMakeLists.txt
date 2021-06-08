cmake_minimum_required(VERSION 3.10)

if (MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Werror -D_FILE_OFFSET_BITS=64)
endif()

project(udpEventTest DESCRIPTION "udp intreceptor test")

message("test udp Interceptor")

add_executable(udpEventTest mainer.c)
target_link_libraries(udpEventTest ${CMAKE_DL_LIBS})

install(
    TARGETS udpEventTest
    RUNTIME DESTINATION /tmp
)


