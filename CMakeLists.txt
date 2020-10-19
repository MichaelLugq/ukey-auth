cmake_minimum_required (VERSION 3.8)

set(PACKAGE_NAME "ukey-auth")

project(${PACKAGE_NAME} C CXX)

add_compile_options("/std:c++17")

find_package(openssl REQUIRED)
find_package(protobuf REQUIRED)

set(CMAKE_INCLUDE_CURRENT_DIR TRUE)

include_directories(
  ${CMAKE_SOURCE_DIR}/3rdparty
)

add_subdirectory(3rdparty/u03-ukey)
add_subdirectory(src)