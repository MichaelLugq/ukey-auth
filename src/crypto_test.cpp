#include "crypto.h"

int main() {
  InitOpenssl();
  std::vector<BYTE> pub_key, priv_key;
  int ec = GenSM2KeyPair(pub_key, priv_key);
  if (0 != ec) {
    return ec;
  }
  return 0;
}