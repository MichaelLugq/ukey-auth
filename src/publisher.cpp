#include "utils.h"
#include "crypto.h"

#include "secret.pb.h"

#include <fstream>

int main() {
  InitOpenssl();

  int ec = 0;

  // 1����װ�ͻ���

  // 2���������ڼ�����Կ�Ե������Կ
  std::vector<BYTE> random;
  ec = GenRandom(random, 16);
  if (0 != ec) {
    return ec;
  }

  // 3������n����Կ��
  const int keypair_count = 2;
  std::vector<SM2KeyPair> keypairs;
  for (int i = 0; i < keypair_count; ++i) {
    SM2KeyPair keypair;
    ec = GenSM2KeyPair(keypair);
    if (0 != ec) {
      return ec;
    }
    keypairs.emplace_back(std::move(keypair));
  }

  // 3.1��TODO: ���ɸ�֤��

  // 3.2��TODO: ʹ�������Կ����(n����Կ��+��֤��Ĺ�˽Կ��Ϣ)�洢������
  secret::SecretInfo info;
  for (auto& v : keypairs) {
    auto kp = info.add_keypair();
    kp->set_pub_key(v.pub_key.data(), v.pub_key.size());
    kp->set_priv_key(v.priv_key.data(), v.priv_key.size());
  }

  std::fstream output("secret.db", std::ios::out | std::ios::trunc | std::ios::binary);
  if (!info.SerializeToOstream(&output)) {
    return 0;
  }

  // 4���·�������Կ�ԡ����й�Կ����֤�鵽USB Key����Կ�ԡ���Կ��˳�����һ�£�

  // 5���û�����+������Ϣ д�뵽��ϵ�ļ�

  // 6�����յĹ�ϵ�ļ�����ÿ���û�

  return 0;
}