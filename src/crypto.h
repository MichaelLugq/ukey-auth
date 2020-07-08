#pragma once

#include <vector>

typedef unsigned char BYTE;

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

#pragma region U03

// ����PIN�루������Ա���ã�
int SetPIN(const std::vector<BYTE>& pin);

// ��֤PIN�루�����ã�
int VerifyPIN(const std::vector<BYTE>& pin);

// ��֤PIN�루�����ã�
int ChangePIN(const std::vector<BYTE>& old_pin, const std::vector<BYTE>& new_pin);

// ���ù���ԱPIN�루������Ա���ã�
int SetAdminPIN(const std::vector<BYTE>& pin);

// ��֤����ԱPIN�루������Ա���ã�
int VerifyAdminPIN(const std::vector<BYTE>& pin);

// ������Կ�ԣ�������Ա���ã�
int ImportKeyPairToUKey(const SM2KeyPair& keypair);

// д��洢��
int WriteToUKey(int sector_offset, const std::vector<BYTE>& data);

// ��ȡ�洢��
int ReadFromUKey(int sector_offset, int sector_size, std::vector<BYTE>& data);

// д˽����
int WritePrivate(int offset, const std::vector<BYTE>& data);

// ��˽����
int ReadPrivate(int offset, int bytes, std::vector<BYTE>& data);

// ��ȡ��Կ
int GetPublicKey(std::vector<BYTE>& pubkey);

// SM2����
int SM2Encrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM2����(�ⲿ��Կ)
int SM2Encrypt(const std::vector<BYTE>& pubkey,
               const std::vector<BYTE>& in,
               std::vector<BYTE>& out);

// SM2����
int SM2Decrypt(const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4����
int SM4Encrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

// SM4����
int SM4Decrypt(const std::vector<BYTE>& key, const std::vector<BYTE>& in, std::vector<BYTE>& out);

#pragma endregion U03