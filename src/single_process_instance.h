#pragma once

#include <string>

typedef void* HANDLE;

class SingleProcessInstance {
 public:
  SingleProcessInstance(const std::string& instance_name,
                        const std::string& class_name,
                        const std::string& title);
  ~SingleProcessInstance();

  bool Opened() { return opened_; }

 private:
  std::string instance_name_ = "";
  HANDLE hMutex = NULL;
  bool opened_ = false;
};