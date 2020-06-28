#pragma once

#include <string>
#include <vector>

void InitOpenssl();

int GenSM2KeyPair(std::vector<unsigned char> pub_key, std::vector<unsigned char> priv_key);
