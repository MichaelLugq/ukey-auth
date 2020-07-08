#pragma once

// static const vs. const, when to use each?
//
// If the constant will be the same every time the function is called, use static const.
// If the constant is only constant for the lifetime of the function and may change depending on on how / when the function is called, use const.

#include <string>

// ������
static const int kSuccess = 0;
static const int kNoDevice = -101;
static const int kTooManyDevice = -102;
static const int kErrConnect = -103;
static const int kNoWrittenFlag = -104;
static const int kNoIndexDB = -105;
static const int kErrParseProto = -106;
static const int kNoSecretDB = -107;

// ����OpenSSL�����Ĺ�Կ�д���0x04��ǣ����������һ���ֽ�
static const int kOpenSSLSM2PublicKeySize = 65;

// SM2�Ĺ�Կ����
static const int kSM2PublicKeySize = 64;

// SM2��˽Կ����
static const int kSM2PrivateKeySize = 32;

// SM2���ܺ�ı�ԭ�����ӵĳ���
static const int kSM2EncIncreaseLen = 96;

// ���ɵ���Կ���ܸ���
static const int kSM2KeyPairCount = 1024;

// �û�����С
static const int kUserRegionSize = 512;

// SM4��Կ����
static const int kSM4KeySize = 16;

// ��Կ�Ĵ洢��ʼλ��
//
// 4K ByteΪ��λ,
static const int kPublicKeyStartPosition = 256 * 0;

// ���û����û����������Ĵ洢��ʼλ��
static const int kLocalUserInfoStartPosition  = 256 * 8;

// �����û����û����������Ĵ洢��ʼλ��
static const int kOtherUsersInfoStartPosition = 256 * 16;
