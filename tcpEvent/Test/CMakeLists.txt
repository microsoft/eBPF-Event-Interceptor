cmake_minimum_required(VERSION 3.10)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wextra -Werror -D_FILE_OFFSET_BITS=64)
endif()

project(tcpEventTest DESCRIPTION "tcp intreceptor test")

message("test tcp Interceptor")

add_executable(tcpEventTest mainer.c)
target_link_libraries(tcpEventTest ${CMAKE_DL_LIBS})

install(
    TARGETS tcpEventTest
    RUNTIME DESTINATION /tmp
)

