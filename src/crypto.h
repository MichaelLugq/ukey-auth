#pragma once

#include <vector>

typedef unsigned char BYTE;

typedef struct _tagPubkeyInfo {
  // 索引，从0开始，可以通过该索引寻找公钥
  int index;
  // 使用者姓名
  std::string name;
} PubkeyInfo;

typedef struct _tagSM2KeyPair {
  std::vector<BYTE> pub_key;
  std::vector<BYTE> priv_key;
} SM2KeyPair;

// 初始化OpenSSL
void InitOpenssl();

// 销毁OpenSSL
void UninitOpenSSL();

// 生成SM2密钥对（通过OpenSSL）
int GenSM2KeyPair(std::vector<BYTE>& pub_key, std::vector<BYTE>& priv_key);
int GenSM2KeyPair(SM2KeyPair& keypair);

// 随机数
int GenRandom(std::vector<BYTE>& random, int num);

// 单次设置PIN码，一般用于发行者发行USB Key
int SetPIN(const std::vector<BYTE>& pin);

// 单次验证PIN码，一般用于发行者发行USB Key
int VerifyPIN(const std::vector<BYTE>& pin);

// 导入密钥对
int ImportKeyPairToU03Key(const std::vector<BYTE>& pub_key, const std::vector<BYTE>& priv_key);

// 导入所有公私钥信息（仅管理员可用）
int WriteAllKeyPairsToFile(const std::vector<SM2KeyPair>& keypairs);

// 读取所有公私钥信息
int ReadAllKeyPairsFromFile(std::vector<SM2KeyPair>& keypairs);

// 导入所有的公钥信息
int WriteAllPubKeyToU03Key(const std::vector<std::vector<BYTE>>& pubkeys);

// 读取用户名+索引
int ReadAllNameIndexInfoFromFile();

// 写入用户名+索引
int WriteAllNameIndexInfoFromFile();

// SM2加密
int SM2Encrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM2解密
int SM2Decrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4加密
int SM4Encrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4解密
int SM4Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

//// 签名
//int SignData(const std::vector<BYTE>& priv_key, const std::vector<BYTE>& in,
//             std::vector<BYTE>& out);
//
//// 验签
//int VerifyData(const std::vector<BYTE>& priv_key, const std::vector<BYTE>& data,
//               const std::vector<BYTE>& sign);

