# test
add_executable(utils_test 
  utils.cpp
  utils_test.cpp
)

add_executable(crypto_test
  utils.cpp
  crypto.cpp
  crypto_test.cpp
)
target_link_libraries(crypto_test PUBLIC
  OpenSSL::Crypto
  OpenSSL::SSL
  u03ukey
)

# proto
protobuf_generate_cpp(secret_PROTO_SRCS secret_PROTO_HDR protos/secret.proto)
protobuf_generate_cpp(index_PROTO_SRCS index_PROTO_HDR protos/index.proto)

# Qt Begin
list(APPEND CMAKE_PREFIX_PATH ${QT56_PATH})
find_package(Qt5 COMPONENTS Widgets LinguistTools REQUIRED)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
# Qt End

# proto_test
add_executable(proto_test 
  utils.cpp
  crypto.cpp
  proto.cpp
  proto_test.cpp
  ${secret_PROTO_SRCS}
  ${secret_PROTO_HDR}
  ${index_PROTO_SRCS}
  ${index_PROTO_HDR}
)
target_include_directories(proto_test PUBLIC 
  ${PROTOBUF_INCLUDE_DIRS}
)
target_link_libraries(proto_test PUBLIC
  OpenSSL::Crypto
  OpenSSL::SSL
  protobuf::libprotobuf
  u03ukey
)

# admin
add_executable(admin WIN32
  utils.cpp
  crypto.cpp
  proto.cpp
  admin/main.cpp
  admin/mainwidget.cpp
  admin/mainwidget.h
  admin/mainwidget.ui
  ${secret_PROTO_SRCS}
  ${secret_PROTO_HDR}
  ${index_PROTO_SRCS}
  ${index_PROTO_HDR}
)
target_include_directories(admin PUBLIC 
  ${PROTOBUF_INCLUDE_DIRS}
)
target_link_libraries(admin PUBLIC
  OpenSSL::Crypto
  OpenSSL::SSL
  protobuf::libprotobuf
  Qt5::Widgets
  u03ukey
)
add_custom_command(TARGET admin POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt5::Core> $<TARGET_FILE_DIR:admin>
  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt5::Gui> $<TARGET_FILE_DIR:admin>
  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt5::Widgets> $<TARGET_FILE_DIR:admin>
  COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:Qt5::QWindowsIntegrationPlugin> 
    $<TARGET_FILE_DIR:admin>/platforms/$<TARGET_FILE_NAME:Qt5::QWindowsIntegrationPlugin>
)

# user
add_executable(user
  utils.cpp
  crypto.cpp
  user/main.cpp
  ${secret_PROTO_SRCS}
  ${secret_PROTO_HDR}
  ${index_PROTO_SRCS}
  ${index_PROTO_HDR}
)
target_link_libraries(user PUBLIC
  OpenSSL::Crypto
  OpenSSL::SSL
  protobuf::libprotobuf
  u03ukey
)

