cmake_minimum_required(VERSION 3.15)
project(dmod CXX)

set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE SOURCES source/*.cpp)

add_library(dmod STATIC ${SOURCES})

target_compile_options(dmod PRIVATE -static)

target_link_libraries(dmod PRIVATE libz.a)

target_link_options(dmod PRIVATE -static)


install(TARGETS dmod DESTINATION lib)