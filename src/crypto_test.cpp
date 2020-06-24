#include "crypto.h"

int main() {
  InitOpenssl();
  GenKeyPair();
  return 0;
}