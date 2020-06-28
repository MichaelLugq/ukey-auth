add_executable(utils_test 
  utils.cpp
  utils_test.cpp
)

add_executable(crypto_test
  utils.cpp
  crypto.cpp
  crypto_test.cpp
)
target_link_libraries(crypto_test 
  OpenSSL::Crypto
  OpenSSL::SSL
  u03ukey
)

add_executable(publisher
  utils.cpp
  crypto.cpp
  publisher.cpp
)
target_link_libraries(publisher
  OpenSSL::Crypto
  OpenSSL::SSL
  u03ukey
)

add_executable(user
  utils.cpp
  crypto.cpp
  user.cpp
)
target_link_libraries(user
  OpenSSL::Crypto
  OpenSSL::SSL
  u03ukey
)

