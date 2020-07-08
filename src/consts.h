#pragma once

// static const vs. const, when to use each?
//
// If the constant will be the same every time the function is called, use static const.
// If the constant is only constant for the lifetime of the function and may change depending on on how / when the function is called, use const.

#include <string>

// 错误码
static const int kSuccess = 0;
static const int kNoDevice = -101;
static const int kTooManyDevice = -102;
static const int kErrConnect = -103;
static const int kNoWrittenFlag = -104;
static const int kNoIndexDB = -105;
static const int kErrParseProto = -106;
static const int kNoSecretDB = -107;

// 由于OpenSSL导出的公钥中存在0x04标记，因此增加了一个字节
static const int kOpenSSLSM2PublicKeySize = 65;

// SM2的公钥长度
static const int kSM2PublicKeySize = 64;

// SM2的私钥长度
static const int kSM2PrivateKeySize = 32;

// SM2加密后的比原文增加的长度
static const int kSM2EncIncreaseLen = 96;

// 生成的密钥对总个数
static const int kSM2KeyPairCount = 1024;

// 用户区大小
static const int kUserRegionSize = 512;

// SM4密钥长度
static const int kSM4KeySize = 16;

// 公钥的存储起始位置
//
// 4K Byte为单位,
static const int kPublicKeyStartPosition = 256 * 0;

// 本用户的用户名和索引的存储起始位置
static const int kLocalUserInfoStartPosition  = 256 * 8;

// 其他用户的用户名和索引的存储起始位置
static const int kOtherUsersInfoStartPosition = 256 * 16;
