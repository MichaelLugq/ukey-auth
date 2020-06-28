#include "utils.h"
#include <algorithm>

const std::string& kLSSDFlag = "lssd";

std::string HexEncode(const void* bytes, size_t size) {
  static const char kHexChars[] = "0123456789ABCDEF";

  // Each input byte creates two output hex characters.
  std::string ret(size * 2, '\0');

  for (size_t i = 0; i < size; ++i) {
    char b = reinterpret_cast<const char*>(bytes)[i];
    ret[(i * 2)] = kHexChars[(b >> 4) & 0xf];
    ret[(i * 2) + 1] = kHexChars[b & 0xf];
  }
  return ret;
}

int StrToVector(LPSTR str, ULONG size, std::vector<std::string>& output) {
  if (!str || size == 0) {
    return -1;
  }

  char* begin = str;
  char* end = str + size - 1;

  char* index1 = begin;
  char* index2 = index1;
  while (index2 != end) {
    index2 = std::find_if(index1, end, [](char c)->bool { return c == '\0'; });
    output.push_back(std::string(index1, index2));
    index2++;
    index1 = index2;
  }

  return 0;
}

int GetLSSDDevice(const std::vector<std::string>& devs, std::vector<std::string>& lssd_devs) {
  lssd_devs.clear();
  for (const auto& dev : devs) {
    if (dev.find(kLSSDFlag) != std::string::npos) {
      lssd_devs.push_back(dev);
    }
  }
  return lssd_devs.size();
}
