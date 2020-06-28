#include "utils.h"
#include "crypto.h"
#include "u03-ukey/u03ukey/u03ukey.h"

#include <windows.h>

#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <vector>

#pragma region InitOpenssl

static CRITICAL_SECTION *lock_cs;

void win32_openssl_locking_callback(int mode, int type, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    EnterCriticalSection(&lock_cs[type]);
  } else {
    LeaveCriticalSection(&lock_cs[type]);
  }
}

unsigned long win32_openssl_thread_id_cb(void) {
  return (unsigned long)::GetCurrentThreadId();
}

void InitOpenssl() {
  int i;
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(nullptr);
  SSL_library_init();
  SSL_load_error_strings();
  lock_cs = (CRITICAL_SECTION*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(CRITICAL_SECTION));
  if (!lock_cs) {
    return;
  }
  for (i = 0; i < CRYPTO_num_locks(); i++) {
    InitializeCriticalSection(&lock_cs[i]);
  }
  CRYPTO_set_locking_callback(win32_openssl_locking_callback);
  CRYPTO_set_id_callback(win32_openssl_thread_id_cb);
}

#pragma endregion InitOpenssl

template<typename T, typename D>
std::unique_ptr<T, D> make_handle(T* handle, D deleter) {
  return std::unique_ptr<T, D> {handle, deleter};
}

int GenSM2KeyPair(std::vector<BYTE>& pub_key, std::vector<BYTE>& priv_key) {
  auto ec_key = make_handle(EC_KEY_new_by_curve_name(NID_sm2), EC_KEY_free);

  EC_KEY* x = ec_key.get();

  if (1 != EC_KEY_generate_key(x)) {
    return -1;
  }

  unsigned char *priv = NULL, *pub = NULL;
  int publen = 0, prilen =0;
  publen = EC_KEY_key2buf(x, EC_KEY_get_conv_form(x), &pub, NULL);
  if (publen != 65) {
    return -2;
  }
  prilen = EC_KEY_priv2buf(x, &priv);
  if (prilen != 32) {
    return -3;
  }

  pub_key.assign(pub + 1, pub + 1 + publen - 1);
  priv_key.assign(priv, priv + prilen);

  return 0;
}

int ConnectUSBKey(HANDLE& handle) {
  ULONG name_list_size = 0;
  if (LS_EnumDev(nullptr, &name_list_size) != LS_SUCCESS) {
    return -1;
  }

  auto name_list = std::shared_ptr<char>(new char[name_list_size], [](char* p) {delete[] p; });
  if (LS_EnumDev(name_list.get(), &name_list_size) != LS_SUCCESS) {
    return -2;
  }

  std::vector<std::string> name_vector;
  std::vector<std::string> u03_devices;
  if (StrToVector(name_list.get(), name_list_size, name_vector) != 0) {
    return -3;
  }

  if (GetLSSDDevice(name_vector, u03_devices) != 1) {
    return -4;
  }

  ULONG ec;
  ec = LS_ConnectDev((LPSTR)u03_devices[0].c_str(), &handle);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return LS_SUCCESS;
}

int SetPIN(const std::vector<BYTE>& pin) {
  HANDLE handle;
  ULONG ec = ConnectUSBKey(handle);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  auto handle_ptr = make_handle(handle, LS_DisConnectDev);

  ULONG max_retry_count = 10;
  ec = LS_SetPin(handle, (BYTE*)&pin[0], pin.size(), max_retry_count);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return 0;
}

int VerifyPIN(const std::vector<BYTE>& pin) {
  HANDLE handle;
  ULONG ec = ConnectUSBKey(handle);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  auto handle_ptr = make_handle(handle, LS_DisConnectDev);

  ULONG retry_count = 0;
  ec = LS_VerifyPIN(handle, (BYTE*)&pin[0], pin.size(), &retry_count);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return 0;
}

int ImportKeyPairToU03Key(const std::vector<BYTE>& pub_key, const std::vector<BYTE>& priv_key) {
  HANDLE handle;
  ULONG ec = ConnectUSBKey(handle);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  auto handle_ptr = make_handle(handle, LS_DisConnectDev);

  ec = LS_ImportKeyPair(handle, (BYTE*)pub_key.data(), pub_key.size(),
                        (BYTE*)priv_key.data(), priv_key.size());
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return 0;
}

int ImportAllPubKey(const std::vector<PubkeyInfo>& pubkey_info) {
  return 0;
}

// template<typename T, typename D>
// std::unique_ptr<T, D> make_handle(T* handle, D deleter) {
//   return std::unique_ptr<T, D> {handle, deleter};
// }
//
// void print_openssl_error(std::string const& function) {
//   char buffer[1024];
//   ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
//   std::cerr << "openssl function " << function << " failed with " << buffer << "\n";
// }
//
// bool create_ec_private_key() {
//   // Create the context for the key generation
//   auto kctx = make_handle(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
//   if(!kctx) {
//     print_openssl_error("EVP_PKEY_CTX_new");
//     return false;
//   }
//
//   // Generate the key
//   if(1 != EVP_PKEY_keygen_init(kctx.get())) {
//     print_openssl_error("EVP_PKEY_keygen_init");
//     return false;
//   }
//
//   //  We're going to use the ANSI X9.62 Prime 256v1 curve
//   if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), NID_sm2)) {
//     print_openssl_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
//     return false;
//   }
//
//   EVP_PKEY *pkey_temp = nullptr;
//   if (1 != EVP_PKEY_keygen(kctx.get(), &pkey_temp)) {
//     print_openssl_error("EVP_PKEY_keygen");
//     return false;
//   }
//
//   // write out to pem file
//   auto pkey = make_handle(pkey_temp, EVP_PKEY_free);
//
//   auto file = make_handle(BIO_new_file("ecprivatekey.pem", "w"), BIO_free);
//   if(!file) {
//     print_openssl_error("BIO_new_file");
//     return false;
//   }
//
//   if(!PEM_write_bio_PrivateKey(file.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
//     print_openssl_error("PEM_write_bio_PrivateKey");
//     return false;
//   }
//   BIO_flush(file.get());
//
//   {
//     unsigned char *priv = NULL, *pub = NULL;
//     EC_KEY* x = EVP_PKEY_get1_EC_KEY(pkey.get());
//     int publen = EC_KEY_key2buf(x, EC_KEY_get_conv_form(x), &pub, NULL);
//     int prilen = EC_KEY_priv2buf(x, &priv);
//     return true;
//   }
//
//   return true;
// }

