cmake_minimum_required (VERSION 3.8)

set(PACKAGE_NAME "ukey-auth")

project(${PACKAGE_NAME} C CXX)

find_package(openssl REQUIRED)

include_directories(
  .
  ${CMAKE_SOURCE_DIR}/3rdparty
)

add_subdirectory(3rdparty/u03-ukey)
add_subdirectory(src)