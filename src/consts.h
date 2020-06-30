#pragma once

// static const vs. const, when to use each?
//
// If the constant will be the same every time the function is called, use static const.
// If the constant is only constant for the lifetime of the function and may change depending on on how / when the function is called, use const.

#include <string>

// 由于OpenSSL导出的公钥中存在0x04标记，因此增加了一个字节
static const int kOpenSSLSM2PublicKeySize = 65;

// SM2的公钥长度
static const int kSM2PublicKeySize = 64;

// SM2的私钥长度
static const int kSM2PrivateKeySize = 32;

// 标识信息的存储位置
// 标识信息包括身份信息、是否已经生成密钥对等信息
//
// 身份信息：4K字节(一个扇区)
// 公钥个数：4K字节
// 是否已生成n个密钥对：4K字节
// 公私钥对个数：4K字节
// 根证书的私钥
// 根证书
static const int kHasGenKeyPairsFlagStartPosition = 0;  // 0M Bytes

static const int kIdentifyOffset = 0;

static const int kPublicKeyCountOffset = 4;

static const int kHasGenOffset = 8;

static const int kKeyPairCountOffset = 12;

static const std::string kAdminFlag = "lord";

static const std::string kUserFlag  = "user";

static const std::string kHasGenFlag = "have";

static const std::string kNotGenFlag = "none";

// 公私钥对的存储起始位置
//
// 之所以和存放公钥的位置分开，是防止导入时，误写极其重要的公私钥信息
static const int kKeyPairStartPosition = 256 * 8;        // 8M Bytes

// 公钥的存储起始位置
//
// 4K Byte为单位
static const int kPublicKeyStartPosition = 256 * 16;     // 16M Bytes

// 用户名和索引的存储起始位置
static const int kUserInfoStartPosition  = 256 * 24;

// 其他信息的存储起始位置
static const int kOtherInfoStartPosition = 256 * 32;