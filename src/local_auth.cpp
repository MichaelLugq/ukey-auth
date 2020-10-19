#include "local_auth.h"

#include "consts.h"
#include "crypto.h"

#include <fstream>

LocalAuth::LocalAuth(const std::string& file_name /*= kFileName*/) : file_name_(file_name) {

}

bool LocalAuth::HavePassword() {
  std::ifstream infile(file_name_, std::ios::in | std::ios::binary);
  return !!infile;
}

int LocalAuth::SetPassword(const std::string& pwd) {
  std::ofstream outfile(file_name_, std::ios::out | std::ios::trunc | std::ios::binary);
  if (!outfile) {
    return -1;
  }

  std::vector<BYTE> digest;
  int ec = CalcMD5(std::vector<BYTE>(pwd.begin(), pwd.end()), digest);
  if (ec != kSuccess) {
    return ec;
  }

  outfile.write((const char*)digest.data(), digest.size());

  return kSuccess;
}

int LocalAuth::VerifyPassword(const std::string& pwd) {
  std::ifstream infile(file_name_, std::ios::in | std::ios::binary);
  if (!infile) {
    return -1;
  }

  std::vector<BYTE> md5(kMD5Size);
  auto readlen = infile.read((char*)md5.data(), kMD5Size).gcount();
  if (readlen != kMD5Size) {
    return -2;
  }

  std::vector<BYTE> digest;
  int ec = CalcMD5(std::vector<BYTE>(pwd.begin(), pwd.end()), digest);
  if (ec != kSuccess) {
    return ec;
  }

  if (md5 != digest) {
    return -2;
  }
  return kSuccess;
}

int LocalAuth::ChangePassword(const std::string& oldp, const std::string& newp) {
  int ec = VerifyPassword(oldp);
  if (ec != kSuccess) {
    return ec;
  }
  return SetPassword(newp);
}
