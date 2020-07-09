#include "local_auth.h"
#include "consts.h"

#include <cassert>

int main() {
  LocalAuth auth("auth.dat");

  std::string pwd("123456");
  int ec = auth.SetPassword("123456");
  assert(ec == kSuccess);

  ec = auth.VerifyPassword(pwd);
  assert(ec == kSuccess);

  std::string newp("456789");
  ec = auth.ChangePassword(pwd, newp);
  assert(ec == kSuccess);

  ec = auth.VerifyPassword(newp);
  assert(ec == kSuccess);

  return 0;
}