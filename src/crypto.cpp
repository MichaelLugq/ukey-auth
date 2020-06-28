#include "utils.h"
#include "crypto.h"

#include <windows.h>

#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <vector>

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

template<typename T, typename D>
std::unique_ptr<T, D> make_handle(T* handle, D deleter) {
  return std::unique_ptr<T, D> {handle, deleter};
}

int GenSM2KeyPair(std::vector<unsigned char> pub_key, std::vector<unsigned char> priv_key) {
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

