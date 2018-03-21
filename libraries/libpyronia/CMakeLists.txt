cmake_minimum_required(VERSION 2.6)
project(pyr)

#set(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_C_FLAGS "-O0 -g")

if(APPLE)
	set(CMAKE_OSX_ARCHITECTURES i386 x86_64)
endif()
##set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -g")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -g")
#set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(pyronia_lib SHARED pyronia_lib.c)
add_library(pyronia SHARED pyronia_lib.c)

target_link_libraries(pyronia pyronia_lib smv) 

