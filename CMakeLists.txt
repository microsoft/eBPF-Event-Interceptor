cmake_minimum_required(VERSION 3.10)
project(ebpfInterceptor VERSION 1.0)

find_library(BCC
        NAMES bcc
)

option (SETUP_TESTS "Setup Tests")


if (BCC)
        message("Found BCC")

	add_subdirectory(tcpEvent)
        add_subdirectory(udpEvent)
else()  
        message("BCC not found")

	set(BCC_HAS_BEEN_SETUP "/tmp/bccInstalled.ok")

	add_custom_command(OUTPUT ${BCC_HAS_BEEN_SETUP}
		COMMENT "Setting up bcc and pre-requisite packages"
		COMMAND ${CMAKE_SOURCE_DIR}/scripts/extended.sh
		COMMAND ${CMAKE_COMMAND} -E touch ${BCC_HAS_BEEN_SETUP}
		VERBATIM
	)

	add_custom_target(bccSetup ALL
	    DEPENDS ${BCC_HAS_BEEN_SETUP})


        add_subdirectory(udpEvent)
	add_dependencies(udpEvent bccSetup)

	add_subdirectory(tcpEvent)
	add_dependencies(tcpEvent bccSetup)

endif()

