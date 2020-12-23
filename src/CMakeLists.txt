# test
add_executable(utils_test 
  utils.cpp
  utils_test.cpp
)

add_executable(single_process_instance_test
  single_process_instance_test.cpp
  single_process_instance.cpp
)

add_executable(device_monitor_test
  device_monitor.h
  device_monitor.cpp
  device_monitor_test.cpp
)

add_executable(local_auth_test
  utils.cpp
  crypto.cpp
  local_auth.cpp
  local_auth_test.cpp
)
target_link_libraries(local_auth_test PUBLIC
  OpenSSL::Crypto
  OpenSSL::SSL
  u03ukey
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
message(STATUS "------------${CMAKE_SOURCE_DIR}/src/admin------------")
qt5_create_translation(ADMIN_QM_FILES admin admin/admin_zh-cn.ts)
message(STATUS "------------${ADMIN_QM_FILES}------------")
message(STATUS "------------CMAKE_BINARY_DIR: ${CMAKE_BINARY_DIR}------------")
configure_file(admin/admin.qrc ${CMAKE_BINARY_DIR}/src COPYONLY)
#qt5_add_resources(ADMIN_RC admin/admin.qrc)
#message(STATUS "------------ADMIN_RC: ${ADMIN_RC}------------")
add_executable(admin WIN32
  utils.cpp
  crypto.cpp
  proto.cpp
  local_auth.cpp
  single_process_instance.cpp
  device_monitor.cpp
  admin/main.cpp
  admin/mainwidget.cpp
  admin/mainwidget.h
  admin/mainwidget.ui
  ${secret_PROTO_SRCS}
  ${secret_PROTO_HDR}
  ${index_PROTO_SRCS}
  ${index_PROTO_HDR}
  ${ADMIN_QM_FILES}
  ${CMAKE_BINARY_DIR}/src/admin.qrc
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
qt5_create_translation(USER_QM_FILES user user/user_zh-cn.ts)
configure_file(user/user.qrc ${CMAKE_BINARY_DIR}/src COPYONLY)
add_executable(user WIN32
  utils.cpp
  crypto.cpp
  proto.cpp
  single_process_instance.cpp
  device_monitor.cpp
  user/main.cpp
  user/mainwidget.cpp
  user/mainwidget.h
  user/mainwidget.ui
  ${secret_PROTO_SRCS}
  ${secret_PROTO_HDR}
  ${index_PROTO_SRCS}
  ${index_PROTO_HDR}
  ${USER_QM_FILES}
  ${CMAKE_BINARY_DIR}/src/user.qrc
)
target_include_directories(user PUBLIC 
  ${PROTOBUF_INCLUDE_DIRS}
)
target_link_libraries(user PUBLIC
  OpenSSL::Crypto
  OpenSSL::SSL
  protobuf::libprotobuf
  Qt5::Widgets
  u03ukey
)

