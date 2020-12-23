#include "device_monitor.h"

#include <iostream>

int main() {
  volatile bool quit = false;

  auto th = std::thread([&quit]() {

    while (1) {
      std::string name;
      bool insert;
      utils::WaitForDevEvent(name, insert);
      std::cout << "-----------------------------------------------" << std::endl;
      std::cout << "Dev " << (insert ? "insert" : "eject") << std::endl;
      std::cout << "Name: " << name << std::endl;
      std::cout << "-----------------------------------------------" << std::endl;
      if (quit) {
        break;
      }
    }

    quit = false;
  });

  while (1) {
    auto c = getchar();
    if (c == 'q') {
      quit = true;
      utils::CancelWaitForDevEvent();
      break;
    }
  }

  if (th.joinable()) {
    th.join();
  }

  return 0;
}