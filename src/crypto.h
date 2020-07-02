#pragma once

#include <vector>

typedef unsigned char BYTE;

typedef struct _tagPubkeyInfo {
  // ��������0��ʼ������ͨ��������Ѱ�ҹ�Կ
  int index;
  // ʹ��������
  std::string name;
} IndexInfo;

typedef struct _tagSM2KeyPair {
  std::vector<BYTE> pub_key;
  std::vector<BYTE> priv_key;
} SM2KeyPair;

#pragma region OpenSSL

// ��ʼ��OpenSSL
void InitOpenssl();

// ����OpenSSL
void UninitOpenSSL();

// ����SM2��Կ�ԣ�ͨ��OpenSSL��
int GenSM2KeyPair(SM2KeyPair& keypair);

// �����
int GenRandom(std::vector<BYTE>& random, int num);

#pragma endregion OpenSSL

// ����PIN�루������Ա���ã�
int SetPIN(const std::vector<BYTE>& pin);

// ��֤PIN�루�����ã�
int VerifyPIN(const std::vector<BYTE>& pin);

// ������Կ�ԣ�������Ա���ã�
int ImportKeyPairToUKey(const SM2KeyPair& keypair);

// д��洢��
int WriteToUKey(int sector_offset, const std::vector<BYTE>& data);

// ��ȡ�洢��
int ReadFromUKey(int sector_offset, int sector_size, std::vector<BYTE>& data);

// SM2����
int SM2Encrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM2����
int SM2Decrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4����
int SM4Encrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4����
int SM4Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);
