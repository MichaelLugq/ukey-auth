#include "utils.h"
#include "crypto.h"
#include <windows.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static CRITICAL_SECTION *lock_cs;

int encode(const std::string& s) {
  add(1, 2);
  return 0;
}

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

int GenKeyPair() {
  create_ec_private_key();
  return 0;
}

template<typename T, typename D>
std::unique_ptr<T, D> make_handle(T* handle, D deleter) {
  return std::unique_ptr<T, D> {handle, deleter};
}

void print_openssl_error(std::string const& function) {
  char buffer[1024];
  ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
  std::cerr << "openssl function " << function << " failed with " << buffer << "\n";
}

bool create_ec_private_key() {
  // Create the context for the key generation
  auto kctx = make_handle(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
  if(!kctx) {
    print_openssl_error("EVP_PKEY_CTX_new");
    return false;
  }

  // Generate the key
  if(1 != EVP_PKEY_keygen_init(kctx.get())) {
    print_openssl_error("EVP_PKEY_keygen_init");
    return false;
  }

  //  We're going to use the ANSI X9.62 Prime 256v1 curve
  if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), NID_sm2)) {
    print_openssl_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
    return false;
  }

  EVP_PKEY *pkey_temp = nullptr;
  if (1 != EVP_PKEY_keygen(kctx.get(), &pkey_temp)) {
    print_openssl_error("EVP_PKEY_keygen");
    return false;
  }

  // write out to pem file
  auto pkey = make_handle(pkey_temp, EVP_PKEY_free);

  auto file = make_handle(BIO_new_file("ecprivatekey.pem", "w"), BIO_free);
  if(!file) {
    print_openssl_error("BIO_new_file");
    return false;
  }

  if(!PEM_write_bio_PrivateKey(file.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
    print_openssl_error("PEM_write_bio_PrivateKey");
    return false;
  }

  pkey_temp->pkey;
  return true;
}
