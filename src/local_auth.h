#pragma once

#include <string>

static const std::string kFileName = "auth.dat";

class LocalAuth {
 public:
  LocalAuth(const std::string& file_name = kFileName);
  ~LocalAuth() = default;

  bool HavePassword();
  int SetPassword(const std::string& pwd);
  int VerifyPassword(const std::string& pwd);
  int ChangePassword(const std::string& oldp, const std::string& newp);

 private:
  std::string file_name_;
};