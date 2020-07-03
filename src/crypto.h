#pragma once

#include <vector>

typedef unsigned char BYTE;

typedef struct _tagSM2KeyPair {
  std::vector<BYTE> pub_key;
  std::vector<BYTE> priv_key;
} SM2KeyPair;

#pragma region OpenSSL

// 初始化OpenSSL
void InitOpenssl();

// 销毁OpenSSL
void UninitOpenSSL();

// 生成SM2密钥对（通过OpenSSL）
int GenSM2KeyPair(SM2KeyPair& keypair);

// 随机数
int GenRandom(std::vector<BYTE>& random, int num);

#pragma endregion OpenSSL

// 设置PIN码（仅管理员可用）
int SetPIN(const std::vector<BYTE>& pin);

// 验证PIN码（都可用）
int VerifyPIN(const std::vector<BYTE>& pin);

// 导入密钥对（仅管理员可用）
int ImportKeyPairToUKey(const SM2KeyPair& keypair);

// 写入存储区
int WriteToUKey(int sector_offset, const std::vector<BYTE>& data);

// 读取存储区
int ReadFromUKey(int sector_offset, int sector_size, std::vector<BYTE>& data);

// 写私有区
int WritePrivate(int offset, const std::vector<BYTE>& data);

// 读私有区
int ReadPrivate(int offset, int bytes, std::vector<BYTE>& data);

// SM2加密
int SM2Encrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM2解密
int SM2Decrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4加密
int SM4Encrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4解密
int SM4Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);
