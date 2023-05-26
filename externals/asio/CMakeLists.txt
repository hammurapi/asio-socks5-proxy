cmake_minimum_required( VERSION 3.2 )
project( asio )

#Generate the shared library from the sources
add_library( ${PROJECT_NAME} INTERFACE )

target_include_directories( ${PROJECT_NAME} INTERFACE "include" )

#Standalone Asio
target_compile_definitions( ${PROJECT_NAME} INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED )
if( APPLE )
    target_compile_definitions( ${PROJECT_NAME} INTERFACE ASIO_HAS_STD_STRING_VIEW )
endif()

install (
    DIRECTORY "include/asio"
    DESTINATION "include"
    FILES_MATCHING PATTERN "*.hpp"
)

install (
    FILES "include/asio.hpp"	
    DESTINATION "include"
)
