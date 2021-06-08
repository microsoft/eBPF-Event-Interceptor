cmake_minimum_required(VERSION 3.10)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Werror -D_FILE_OFFSET_BITS=64)
endif()

# Project name
project(udpEvent DESCRIPTION "udp intreceptor")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

message("udp Interceptor")
add_library(udpEvent SHARED udpTracer.cc)
include_directories("/usr/include/bcc")

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-pthread")
else(  message( FATAL_ERROR "We need pthread!"))
endif()
target_link_libraries (udpEvent ${CMAKE_C_FLAGS} bcc)

set(MYLIB_VERSION_MAJOR 1)
set(MYLIB_VERSION_MINOR 03a)
set(MYLIB_VERSION_STRING ${MYLIB_VERSION_MAJOR}.${MYLIB_VERSION_MINOR})


install(
    TARGETS udpEvent
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)


if (SETUP_TESTS)
	message("Setting up Tests for UDP Tracer")
	add_subdirectory(Test)
	add_dependencies(udpEventTest udpEvent)
endif()



