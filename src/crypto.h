#pragma once

#include <vector>

typedef unsigned char BYTE;

typedef struct _tagPubkeyInfo {
  // ��������0��ʼ������ͨ��������Ѱ�ҹ�Կ
  int index;
  // ʹ��������
  std::string name;
} PubkeyInfo;

typedef struct _tagSM2KeyPair {
  std::vector<BYTE> pub_key;
  std::vector<BYTE> priv_key;
} SM2KeyPair;

// ��ʼ��OpenSSL
void InitOpenssl();

// ����OpenSSL
void UninitOpenSSL();

// ����SM2��Կ�ԣ�ͨ��OpenSSL��
int GenSM2KeyPair(std::vector<BYTE>& pub_key, std::vector<BYTE>& priv_key);
int GenSM2KeyPair(SM2KeyPair& keypair);

// �����
int GenRandom(std::vector<BYTE>& random, int num);

// ��������PIN�룬һ�����ڷ����߷���USB Key
int SetPIN(const std::vector<BYTE>& pin);

// ������֤PIN�룬һ�����ڷ����߷���USB Key
int VerifyPIN(const std::vector<BYTE>& pin);

// ������Կ��
int ImportKeyPairToU03Key(const std::vector<BYTE>& pub_key, const std::vector<BYTE>& priv_key);

// �������й�˽Կ��Ϣ��������Ա���ã�
int WriteAllKeyPairsToFile(const std::vector<SM2KeyPair>& keypairs);

// ��ȡ���й�˽Կ��Ϣ
int ReadAllKeyPairsFromFile(std::vector<SM2KeyPair>& keypairs);

// �������еĹ�Կ��Ϣ
int WriteAllPubKeyToU03Key(const std::vector<std::vector<BYTE>>& pubkeys);

// ��ȡ�û���+����
int ReadAllNameIndexInfoFromFile();

// д���û���+����
int WriteAllNameIndexInfoFromFile();

// SM2����
int SM2Encrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM2����
int SM2Decrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4����
int SM4Encrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4����
int SM4Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

//// ǩ��
//int SignData(const std::vector<BYTE>& priv_key, const std::vector<BYTE>& in,
//             std::vector<BYTE>& out);
//
//// ��ǩ
//int VerifyData(const std::vector<BYTE>& priv_key, const std::vector<BYTE>& data,
//               const std::vector<BYTE>& sign);

