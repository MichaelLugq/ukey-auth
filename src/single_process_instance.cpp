#include "single_process_instance.h"

#include <windows.h>

SingleProcessInstance::SingleProcessInstance(
  const std::string& instance_name,
  const std::string& class_name,
  const std::string& title
) {
  instance_name_ = instance_name;

  try {
    // Try to open the mutex.
    hMutex = OpenMutexA(MUTEX_ALL_ACCESS, 0, instance_name_.c_str());

    // If hMutex is 0 then the mutex doesn't exist.
    if (!hMutex) {
      hMutex = CreateMutex(0, 0, instance_name_.c_str());
      opened_ = false;
    } else {
      opened_ = true;
      // This is a second instance. Bring the
      // original instance to the top.
      HWND hWnd = FindWindow(class_name.c_str(), title.c_str());
      if (hWnd) {
        SetForegroundWindow(hWnd);
      }
    }

  } catch (const std::exception& e) {

  }
}

SingleProcessInstance::~SingleProcessInstance() {
  try {
    if (hMutex) {
      ReleaseMutex(hMutex);
    }
  } catch (const std::exception& e) {

  }
}

