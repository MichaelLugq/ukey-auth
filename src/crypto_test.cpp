#include "crypto.h"

int main() {
  InitOpenssl();

  SM2KeyPair skp;
  int ec = GenSM2KeyPair(skp);
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

  std::vector<BYTE> key(16, 0);
  ec = SM4Encrypt(key, data, enc);
  if (0 != ec) {
    return ec;
  }

  ec = SM4Decrypt(key, enc, plain);
  if (0 != ec) {
    return ec;
  }

  return 0;
}