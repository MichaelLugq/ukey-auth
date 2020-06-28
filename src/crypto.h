#pragma once

#include <vector>

typedef unsigned char BYTE;

typedef struct _tagPubkeyInfo {
  std::vector<BYTE> pub_key;
  int index;
  std::string name;
} PubkeyInfo;

void InitOpenssl();

int GenSM2KeyPair(std::vector<BYTE>& pub_key, std::vector<BYTE>& priv_key);

int SetPIN(const std::vector<BYTE>& pin);

int VerifyPIN(const std::vector<BYTE>& pin);

int ImportKeyPairToU03Key(const std::vector<BYTE>& pub_key, const std::vector<BYTE>& priv_key);

int ImportAllPubKey(const std::vector<PubkeyInfo>& pubkey_info);

