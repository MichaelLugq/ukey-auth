#include "crypto.h"
#include "consts.h"
#include <cassert>

int main() {
  int ec;
  InitOpenssl();

  SM2KeyPair skp;
  ec = GenSM2KeyPair(skp);
  assert(ec == kSuccess);

  std::vector<BYTE> random;
  ec = GenRandom(random, 16);
  assert(ec == kSuccess);

  std::vector<BYTE> message(1000, 'y');
  std::vector<BYTE> digest;
  ec = CalcMD5(message, digest);
  assert(ec == kSuccess);

  {
    std::vector<BYTE> pin(6, '0');
    ec = SetPIN(pin);
    assert(ec == kSuccess);

    ec = VerifyPIN(pin);
    assert(ec == kSuccess);

    std::vector<BYTE> new_pin(6, '2');
    ec = ChangePIN(pin, new_pin);
    assert(ec == kSuccess);

    ec = VerifyPIN(new_pin);
    assert(ec == kSuccess);

    std::vector<BYTE> admin_pin(6, '1');
    ec = SetAdminPIN(admin_pin);
    assert(ec == kSuccess);

    ec = VerifyAdminPIN(admin_pin);
    assert(ec == kSuccess);
  }

  ec = ImportKeyPairToUKey(skp);
  assert(ec == kSuccess);

  std::vector<BYTE> public_key;
  ec = GetPublicKey(public_key);
  assert(ec == kSuccess);

  std::vector<BYTE> data(36, 0);
  std::vector<BYTE> enc;
  ec = SM2Encrypt(public_key, data, enc);
  assert(ec == kSuccess);

  std::vector<BYTE> plain;
  ec = SM2Decrypt(enc, plain);
  assert(ec == kSuccess);
  assert(data == plain);

  std::vector<BYTE> key(16, 0);
  ec = SM4Encrypt(key, data, enc);
  assert(ec == kSuccess);

  ec = SM4Decrypt(key, enc, plain);
  assert(ec == kSuccess);
  assert(data == plain);

  std::vector<BYTE> priv_data(512, 'A');
  ec = WritePrivate(0, priv_data);
  assert(ec == kSuccess);

  std::vector<BYTE> priv_data_copy;
  ec = ReadPrivate(0, 512, priv_data_copy);
  assert(ec == kSuccess);
  assert(priv_data == priv_data_copy);

  return 0;
}