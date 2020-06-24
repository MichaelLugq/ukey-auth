cmake_minimum_required (VERSION 3.8)

set(PACKAGE_NAME "ukey-auth")

project(${PACKAGE_NAME} C CXX)

find_package(openssl REQUIRED)

add_subdirectory(src)