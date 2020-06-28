add_executable(utils_test 
  utils.cpp
  utils_test.cpp
)

add_executable(crypto_test
  crypto.cpp
  crypto_test.cpp
)
target_link_libraries(crypto_test 
  OpenSSL::Crypto
  OpenSSL::SSL
)

add_executable(ukey-auth
  utils.cpp
  crypto.cpp
  main.cpp
)
target_link_libraries(ukey-auth
  OpenSSL::Crypto
  OpenSSL::SSL
)
