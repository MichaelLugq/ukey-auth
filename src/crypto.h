#pragma once

#include <string>

int encode(const std::string& s);

void InitOpenssl();

int GenKeyPair();

bool create_ec_private_key();