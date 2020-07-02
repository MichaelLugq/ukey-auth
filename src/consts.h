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

// ���ɵ���Կ���ܸ���
static const int kSM2KeyPairCount = 1024;

// ��Կ�Ĵ洢��ʼλ��
//
// 4K ByteΪ��λ,
static const int kPublicKeyStartPosition = 256 * 0;

// �û����������Ĵ洢��ʼλ��
static const int kUserInfoStartPosition  = 256 * 10;
