#include "consts.h"
#include "utils.h"
#include "crypto.h"

#include "secret.pb.h"
#include "index.pb.h"

#include <iostream>
#include <fstream>
#include <filesystem>

#include <ctime>

namespace fs = std::filesystem;

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
  std::vector<SM2KeyPair> keypairs;

  {
    for (int i = 0; i < kSM2KeyPairCount; ++i) {
      SM2KeyPair keypair;
      ec = GenSM2KeyPair(keypair);
      if (0 != ec) {
        return ec;
      }
      keypairs.emplace_back(std::move(keypair));
    }
  }

  // 3.1��TODO: ���ɸ�֤��

  // 3.2��TODO: ʹ�������Կ����(n����Կ��+��֤��Ĺ�˽Կ��Ϣ)�洢������
  proto::SecretInfo secrets;

  {
    for (auto& k : keypairs) {
      auto kp = secrets.add_keypair();
      kp->set_pub_key(k.pub_key.data(), k.pub_key.size());
      kp->set_priv_key(k.priv_key.data(), k.priv_key.size());
    }

    std::fstream output("secret.db", std::ios::out | std::ios::trunc | std::ios::binary);
    if (!secrets.SerializeToOstream(&output)) {
      return 0;
    }
  }

  // 5���û�����+������Ϣ д�뵽��ϵ�ļ�
  proto::IndexInfo indexs;
  bool index_file_exist = false;

  // 5.1����ȡԭ��Ϣ
  {
    std::fstream input("index.db", std::ios::in | std::ios::binary);
    if (!input) {
      // Create file
      std::cerr << "File not found" << std::endl;
      index_file_exist = false;
    } else {
      index_file_exist = true;
      if (!indexs.ParseFromIstream(&input)) {
        std::cerr << "Failed to parse index info" << std::endl;
        return -1;
      }
    }
  }

  // �û���Ϣ
  std::string name("name");
  int index = indexs.index_size();

  // 4���������룻�޸����룻�·�������Կ�ԡ����й�Կ����֤�顢�����Ϣ��name+index����USB Key����Կ�ԡ���Կ��˳�����һ�£�
  {
    std::vector<BYTE> password(6, '0');
    ec = SetPIN(password);
    if (0 != ec) {
      return ec;
    }
    ec = VerifyPIN(password);
    if (0 != ec) {
      return ec;
    }

    // 4.1�����ļ��ж�ȡ��Կ����Ϣ
    proto::SecretInfo secrets_in;
    std::fstream input("secret.db", std::ios::in | std::ios::binary);
    if (!input) {
      return -1;
    } else if (!secrets_in.ParseFromIstream(&input)) {
      return -1;
    }

    // 4.2��ת����vector��
    std::vector<SM2KeyPair> kp_read;
    for (int i = 0; i < secrets_in.keypair_size(); ++i) {
      SM2KeyPair kp;
      const std::string& pubkey = secrets_in.keypair(i).pub_key();
      const std::string& privkey = secrets_in.keypair(i).priv_key();
      kp.pub_key.assign(pubkey.begin(), pubkey.end());
      kp.priv_key.assign(privkey.begin(), privkey.end());
      kp_read.emplace_back(std::move(kp));
    }

    // �·���Կ��
    SM2KeyPair to_import = kp_read[index];
    ec = ImportKeyPairToU03Key(to_import);
    if (0 != ec) {
      return ec;
    }

    // �·����й�Կ
    std::vector<BYTE> pubs;
    for (auto& x : kp_read) {
      pubs.insert(pubs.begin(), x.pub_key.begin(), x.pub_key.end());
    }
    size_t len = (pubs.size() / 4096 + 1) * 4096;
    pubs.resize(len);


    // TODO: �·���֤��

    // �����Ϣ��name+index��
  }

  // 5.2����������Ϣ
  {
    auto nameindex = indexs.add_index();
    nameindex->set_name(name);
    nameindex->set_index(index);
  }

  // 5.3��д�룬д��ǰ��Ҫ���б���

  // 5.3.1 ����
  {
    // ��������ļ�����������Ϊ �ļ�����+ʱ�䣨��ȷ���룩
    if (index_file_exist) {
      fs::path old_path = fs::current_path().append("index.db");
      std::time_t tmt = std::time(nullptr);
      std::tm* stdtm = std::localtime(&tmt);
      char mbstr[100];
      std::strftime(mbstr, sizeof(mbstr), "%F %T", stdtm);
      std::string smsbstr(mbstr);
      std::transform(smsbstr.begin(), smsbstr.end(), smsbstr.begin(),
      [](unsigned char c) -> unsigned char {
        if (c == ':')
          return '-';
        return c;
      });
      fs::path new_path = fs::current_path().append("index-" + smsbstr + ".db");
      fs::rename(old_path, new_path);
    }
  }

  // 5.3.2 д��
  {
    std::fstream output("index.db", std::ios::out | std::ios::trunc | std::ios::binary);
    if (!indexs.SerializeToOstream(&output)) {
      return -1;
    }
  }

  // 6�����յĹ�ϵ�ļ�����ÿ���û�

  return 0;
}