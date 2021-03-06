#include "consts.h"
#include "crypto.h"
#include "utils.h"
#include "u03-ukey/u03ukey/u03ukey.h"

#include <windows.h>

#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <vector>
#include <sstream>
#include <cassert>

static const unsigned char *iv = (unsigned char *)"0123456789012345";

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

void UninitOpenSSL() {

}

#pragma endregion InitOpenssl

#pragma region OpenSSL

template<typename T, typename D>
std::unique_ptr<T, D> make_handle(T* handle, D deleter) {
  return std::unique_ptr<T, D> {handle, deleter};
}

int GenSM2KeyPair(SM2KeyPair& keypair) {
  auto ec_key = make_handle(EC_KEY_new_by_curve_name(NID_sm2), EC_KEY_free);

  EC_KEY* x = ec_key.get();

  if (1 != EC_KEY_generate_key(x)) {
    return -1;
  }

  unsigned char *priv = NULL, *pub = NULL;
  int publen = 0, prilen = 0;
  publen = EC_KEY_key2buf(x, EC_KEY_get_conv_form(x), &pub, NULL);
  if (publen != kOpenSSLSM2PublicKeySize) {
    return -2;
  }
  prilen = EC_KEY_priv2buf(x, &priv);
  if (prilen != kSM2PrivateKeySize) {
    return -3;
  }

  keypair.pub_key.assign(pub + 1, pub + 1 + publen - 1);
  keypair.priv_key.assign(priv, priv + prilen);

  return 0;
}

int GenRandom(std::vector<BYTE>& random, int num) {
  random.clear();
  random.resize(num);
  if (RAND_bytes(random.data(), num) != 1) {
    return -1;
  }
  return 0;
}

int CalcMD5(const std::vector<BYTE>& message, std::vector<BYTE>& digest) {
  EVP_MD_CTX *mdctx;

  if ((mdctx = EVP_MD_CTX_new()) == NULL)
    return -1;

  auto lm = [](EVP_MD_CTX* ctx) {
    EVP_MD_CTX_free(ctx);
  };
  std::unique_ptr<EVP_MD_CTX, decltype(lm)> ctx_ptr(mdctx, lm);

  if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), NULL))
    return -1;

  if (1 != EVP_DigestUpdate(mdctx, message.data(), message.size()))
    return -1;

  unsigned int digest_len = EVP_MD_size(EVP_md5());
  digest.resize(digest_len);
  if (1 != EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len))
    return -1;

  return kSuccess;
}

#pragma endregion OpenSSL

#pragma region U03Key

#define GetHandle()                 \
  HANDLE handle;                    \
  ULONG ec = ConnectUSBKey(handle); \
  if (ec != kSuccess) {             \
    return ec;                      \
  }                                 \
  auto handle_ptr = make_handle(handle, LS_DisConnectDev);

int ConnectUSBKey(HANDLE& handle) {
  ULONG ec;

  ULONG name_list_size = 0;
  ec = LS_EnumDev(nullptr, &name_list_size);
  if (ec != LS_SUCCESS) {
    if (ec == LS_NO_DEVICES) {
      return kNoDevice;
    }
    return ec;
  }

  auto name_list = std::shared_ptr<char>(new char[name_list_size], [](char* p) {delete[] p; });
  ec = LS_EnumDev(name_list.get(), &name_list_size);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  std::vector<std::string> name_vector;
  std::vector<std::string> u03_devices;
  if (StrToVector(name_list.get(), name_list_size, name_vector) != 0) {
    return -3;
  }

  if (GetLSSDDevice(name_vector, u03_devices) != 1) {
    return kTooManyDevice;
  }

  ec = LS_ConnectDev((LPSTR)u03_devices[0].c_str(), &handle);
  if (ec != LS_SUCCESS) {
    return kErrConnect;
  }

  return kSuccess;
}

int SetPIN(const std::vector<BYTE>& pin) {
  GetHandle();

  ULONG max_retry_count = 8;
  ec = LS_SetPin(handle, (BYTE*)&pin[0], pin.size(), max_retry_count);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return kSuccess;
}

int VerifyPIN(const std::vector<BYTE>& pin) {
  GetHandle();

  ULONG retry_count = 0;
  ec = LS_VerifyPIN(handle, (BYTE*)&pin[0], pin.size(), &retry_count);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return kSuccess;
}

int ChangePIN(const std::vector<BYTE>& old_pin, const std::vector<BYTE>& new_pin) {
  GetHandle();

  ULONG retry_count = 0;
  ULONG max_retry_count = 8;
  ec = LS_ChangePIN(handle, (BYTE*)&old_pin[0], old_pin.size(),
                    (BYTE*)&new_pin[0], new_pin.size(),
                    max_retry_count, &retry_count);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return kSuccess;
}

int SetAdminPIN(const std::vector<BYTE>& pin) {
  GetHandle();

  ULONG max_retry_count = 8;
  ec = LS_SetAdminPin(handle, (BYTE*)&pin[0], pin.size(), max_retry_count);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return 0;
}

int VerifyAdminPIN(const std::vector<BYTE>& pin) {
  GetHandle();

  ULONG retry_count = 0;
  ec = LS_VerifyAdminPIN(handle, (BYTE*)&pin[0], pin.size(), &retry_count);
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return 0;
}

int ImportKeyPairToUKey(const SM2KeyPair& keypair) {
  GetHandle();

  ec = LS_ImportKeyPair(handle, (BYTE*)keypair.pub_key.data(), keypair.pub_key.size(),
                        (BYTE*)keypair.priv_key.data(), keypair.priv_key.size());
  if (ec != LS_SUCCESS) {
    return ec;
  }

  return 0;
}

int WriteToUKey(int sector_offset, const std::vector<BYTE>& data) {
  if (data.size() % 4096 != 0) {
    return -1;
  }
  GetHandle();

  ULONG sector_size = data.size() / 4096;
  ULONG sectors_written = 0;
  ec = LS_Write(handle, sector_offset, sector_size, (BYTE*)data.data(), &sectors_written);
  if (ec != 0) {
    return ec;
  }
  if (sectors_written != sector_size) {
    return -2;
  }
  return 0;
}

int ReadFromUKey(int sector_offset, int sector_size, std::vector<BYTE>& data) {
  data.clear();
  GetHandle();

  ULONG sector_read = 0;
  data.resize(sector_size * 4096);
  ec = LS_Read(handle, sector_offset, sector_size, data.data(), &sector_read);
  if (ec != 0) {
    return ec;
  }
  if (sector_read != sector_size) {
    return -2;
  }
  return 0;
}

int WritePrivate(int offset, const std::vector<BYTE>& data) {
  GetHandle();
  ec = LS_WritePrivate(handle, data.size(), (BYTE*)data.data());
  if (ec != LS_SUCCESS) {
    return ec;
  }
  return kSuccess;
}

int ReadPrivate(int offset, int bytes, std::vector<BYTE>& data) {
  GetHandle();
  data.resize(bytes);
  ec = LS_ReadPrivate(handle, 0, bytes, (BYTE*)data.data());
  if (ec != LS_SUCCESS) {
    return ec;
  }
  return kSuccess;
}

int GetPublicKey(std::vector<BYTE>& pubkey) {
  GetHandle();
  pubkey.resize(kSM2PublicKeySize);
  ULONG len = 100;
  ec = LS_ExportPublicKey(handle, pubkey.data(), &len);
  if (ec != LS_SUCCESS) {
    return ec;
  }
  assert(len == kSM2PublicKeySize);
  return kSuccess;
}

int SM2Encrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out) {
  GetHandle();

  out.clear();
  ULONG outlen = in.size() + kSM2EncIncreaseLen;
  out.resize(outlen);
  ec = LS_AsymEncrypt(handle, (BYTE*)in.data(), in.size(), out.data(), &outlen);
  if (ec != LS_SUCCESS) {
    out.resize(0);
    return ec;
  }
  out.resize(outlen);

  return 0;
}

int SM2Encrypt(const std::vector<BYTE>& pubkey,
               const std::vector<BYTE>& in,
               std::vector<BYTE>& out
              ) {
  GetHandle();

  out.clear();
  ULONG outlen = in.size() + kSM2EncIncreaseLen;
  out.resize(outlen);
  ec = LS_AsymEncryptUseImportedKey(handle, (BYTE*)pubkey.data(), pubkey.size(),
                                    (BYTE*)in.data(), in.size(), out.data(), &outlen);
  if (ec != LS_SUCCESS) {
    out.resize(0);
    return ec;
  }
  out.resize(outlen);

  return 0;
}

int SM2Decrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out) {
  GetHandle();

  out.clear();
  ULONG outlen = in.size();
  out.resize(outlen);
  ec = LS_AsymDecrypt(handle, (BYTE*)in.data(), in.size(), out.data(), &outlen);
  if (ec != LS_SUCCESS) {
    out.resize(0);
    return ec;
  }
  out.resize(outlen);

  return 0;
}

int UKeySM4Encrypt(
  const std::vector<BYTE>& key,
  const std::vector<BYTE>& in,
  std::vector<BYTE>& out
) {
  GetHandle();

  LS_SymmCipherParam param;
  param.group_type = LS_ECB;
  param.iv_len = 16;
  param.padding_type = LS_PADDING_PKCS_5;
  std::memset(param.iv, 0, param.iv_len);
  ec = LS_SymmEncryptInit(handle, param, (BYTE*)key.data(), key.size());
  if (ec != LS_SUCCESS) {
    return ec;
  }

  out.clear();
  ULONG outlen = in.size() + 16;
  out.resize(outlen);
  ec = LS_SymmEncrypt(handle, (BYTE*)in.data(), in.size(), out.data(), &outlen);
  if (ec != LS_SUCCESS) {
    out.resize(0);
    return ec;
  }
  out.resize(outlen);

  return 0;
}

int UKeySM4Decrypt(
  const std::vector<BYTE>& key,
  const std::vector<BYTE>& in,
  std::vector<BYTE>& out
) {
  GetHandle();

  LS_SymmCipherParam param;
  param.group_type = LS_ECB;
  param.iv_len = 16;
  param.padding_type = LS_PADDING_PKCS_5;
  std::memset(param.iv, 0, param.iv_len);
  ec = LS_SymmDecryptInit(handle, param, (BYTE*)key.data(), key.size());
  if (ec != LS_SUCCESS) {
    return ec;
  }

  out.clear();
  ULONG outlen = in.size();
  out.resize(outlen);
  ec = LS_SymmDecrypt(handle, (BYTE*)in.data(), in.size(), out.data(), &outlen);
  if (ec != LS_SUCCESS) {
    out.resize(0);
    return ec;
  }
  out.resize(outlen);

  return 0;
}

int OpenSSLSM4Encrypt(
  const std::vector<BYTE>& key,
  const std::vector<BYTE>& in,
  std::vector<BYTE>& out
) {
  return kSuccess;
}

int OpenSSLSM4Decrypt(
  const std::vector<BYTE>& key,
  const std::vector<BYTE>& in,
  std::vector<BYTE>& out
) {
  return kSuccess;
}

int SM4Encrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out) {
  return UKeySM4Encrypt(key, in, out);
}

int SM4Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out) {
  return UKeySM4Decrypt(key, in, out);
}

#pragma endregion U03Key
