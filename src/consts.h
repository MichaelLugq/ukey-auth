#pragma once

// static const vs. const, when to use each?
//
// If the constant will be the same every time the function is called, use static const.
// If the constant is only constant for the lifetime of the function and may change depending on on how / when the function is called, use const.

#include <string>

// ����OpenSSL�����Ĺ�Կ�д���0x04��ǣ����������һ���ֽ�
static const int kOpenSSLSM2PublicKeySize = 65;

// SM2�Ĺ�Կ����
static const int kSM2PublicKeySize = 64;

// SM2��˽Կ����
static const int kSM2PrivateKeySize = 32;

// ��ʶ��Ϣ�Ĵ洢λ��
// ��ʶ��Ϣ���������Ϣ���Ƿ��Ѿ�������Կ�Ե���Ϣ
//
// �����Ϣ��4K�ֽ�(һ������)
// ��Կ������4K�ֽ�
// �Ƿ�������n����Կ�ԣ�4K�ֽ�
// ��˽Կ�Ը�����4K�ֽ�
// ��֤���˽Կ
// ��֤��
static const int kHasGenKeyPairsFlagStartPosition = 0;  // 0M Bytes

static const int kIdentifyOffset = 0;

static const int kPublicKeyCountOffset = 4;

static const int kHasGenOffset = 8;

static const int kKeyPairCountOffset = 12;

static const std::string kAdminFlag = "lord";

static const std::string kUserFlag  = "user";

static const std::string kHasGenFlag = "have";

static const std::string kNotGenFlag = "none";

// ��˽Կ�ԵĴ洢��ʼλ��
//
// ֮���Ժʹ�Ź�Կ��λ�÷ֿ����Ƿ�ֹ����ʱ����д������Ҫ�Ĺ�˽Կ��Ϣ
static const int kKeyPairStartPosition = 256 * 8;        // 8M Bytes

// ��Կ�Ĵ洢��ʼλ��
//
// 4K ByteΪ��λ
static const int kPublicKeyStartPosition = 256 * 16;     // 16M Bytes

// �û����������Ĵ洢��ʼλ��
static const int kUserInfoStartPosition  = 256 * 24;

// ������Ϣ�Ĵ洢��ʼλ��
static const int kOtherInfoStartPosition = 256 * 32;