#include "local_auth.h"

#include "consts.h"

#include <fstream>

LocalAuth::LocalAuth(const std::string& file_name /*= kFileName*/) : file_name_(file_name) {

}

bool LocalAuth::HavePassword() {
  std::ifstream infile(file_name_, std::ios::in | std::ios::binary);
  return !!infile;
}

int LocalAuth::SetPassword(const std::string& pwd) {
  std::ofstream outfile(file_name_, std::ios::out | std::ios::binary);
  if (!outfile) {
    return -1;
  }
  outfile << pwd;
  return kSuccess;
}

int LocalAuth::VerifyPassword(const std::string& pwd) {
  std::ifstream infile(file_name_, std::ios::in | std::ios::binary);
  if (!infile) {
    return -1;
  }
  std::string ss;
  infile >> ss;
  if (ss != pwd) {
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
