#pragma once

#include <string>
#include <vector>

typedef char CHAR;
typedef CHAR *LPSTR;
typedef const CHAR *LPCSTR;
typedef unsigned long ULONG;

std::string HexEncode(const void* bytes, size_t size);

int StrToVector(LPSTR str, ULONG size, std::vector<std::string>& output);

int GetLSSDDevice(const std::vector<std::string>& devs, std::vector<std::string>& lssd_devs);

std::string TimeString();