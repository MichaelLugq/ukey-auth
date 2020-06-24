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
)

add_library(utils SHARED
  utils.cpp
  utils.def
)

add_library(crypto SHARED
  crypto.cpp
  crypto.def
)
target_link_libraries(crypto 
  OpenSSL::Crypto
  OpenSSL::SSL
  utils
)

add_executable(ukey-auth
  main.cpp
)
target_link_libraries(ukey-auth PUBLIC
  crypto
)