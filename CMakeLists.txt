cmake_minimum_required(VERSION 3.10)

project(WVOPRF)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(C_FLAGS "-Wall -march=native -Wfatal-errors ")

add_subdirectory(src)

install(TARGETS WVOPRF DESTINATION ${PROJECT_SOURCE_DIR}/bin)