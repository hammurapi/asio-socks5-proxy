cmake_minimum_required(VERSION 3.2)
project(sidis-pduapi)

#include_directories(include)
include_directories(src)

if(WIN32)
	set(PLATFORM_NAME "win32")

	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		set( CMAKE_C_FLAGS "-DWIN64" )
	endif()
elseif(UNIX)
	set(PLATFORM_NAME "unix")
else()
	message( SEND_ERROR "unsuported platform!" )
endif()

set (CMAKE_CXX_STANDARD 14)

#However, the file(GLOB...) allows for wildcard additions:
file( GLOB COMMON_SOURCES "src/*.cpp" "src/*.hpp" )

file( GLOB PLATFORM_SOURCES 
	"src/${PLATFORM_NAME}/*.cpp" "src/${PLATFORM_NAME}/*.h"
)

if(WIN32)
	file(GLOB PLATFORM_RESOURCES "res/*.rc")
else()
	file(GLOB PLATFORM_RESOURCES "res/*.invalid")
endif()
set(SOURCES ${COMMON_SOURCES} ${PLATFORM_SOURCES} ${PLATFORM_RESOURCES} )

set( CMAKE_BUILD_WITH_INSTALL_RPATH TRUE )
set( CMAKE_INSTALL_RPATH "$ORIGIN/" )

if( WIN32 )
	set( CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi" )
	set( CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF" )
endif()

#Generate the shared library from the sources
add_executable( ${PROJECT_NAME} ${SOURCES} )

target_link_libraries( ${PROJECT_NAME} PUBLIC asio )

# fixup export names for MINGW32
if( (MINGW) AND ( CMAKE_SIZEOF_VOID_P EQUAL 4 ) )
	set_target_properties( ${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,--add-stdcall-alias")
endif()

target_include_directories( ${PROJECT_NAME} PRIVATE res)
#target_include_directories( ${PROJECT_NAME} PUBLIC "include")

#file(GLOB PUBLIC_HEADERS "include/*.h")
#set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")
