#include "crypto.h"

#include <cassert>

int main() {
  int ec;
  InitOpenssl();

  SM2KeyPair skp;
  ec = GenSM2KeyPair(skp);
  if (0 != ec) {
    return ec;
  }

  std::vector<BYTE> random;
  ec = GenRandom(random, 16);
  if (0 != ec) {
    return ec;
  }

  std::vector<BYTE> pin(6, '0');
  ec = SetPIN(pin);
  if (0 != ec) {
    return ec;
  }

  ec = VerifyPIN(pin);
  if (0 != ec) {
    return ec;
  }

  ec = ImportKeyPairToUKey(skp);
  if (0 != ec) {
    return ec;
  }

  std::vector<BYTE> data(36, 0);
  std::vector<BYTE> enc;
  ec = SM2Encrypt(data, enc);
  if (0 != ec) {
    return ec;
  }

  std::vector<BYTE> plain;
  ec = SM2Decrypt(enc, plain);
  if (0 != ec) {
    return ec;
  }
  assert(data == plain);

  std::vector<BYTE> key(16, 0);
  ec = SM4Encrypt(key, data, enc);
  if (0 != ec) {
    return ec;
  }

  ec = SM4Decrypt(key, enc, plain);
  if (0 != ec) {
    return ec;
  }
  assert(data == plain);

  std::vector<BYTE> priv_data(512, 'A');
  ec = WritePrivate(0, priv_data);
  if (0 != ec) {
    return ec;
  }

  std::vector<BYTE> priv_data_copy;
  ec = ReadPrivate(0, 512, priv_data_copy);
  if (0 != ec) {
    return ec;
  }
  assert(priv_data == priv_data_copy);

  return 0;
}