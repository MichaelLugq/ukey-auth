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

  // 1、安装客户端

  // 2、生成用于加密密钥对的随机密钥
  std::vector<BYTE> random;
  ec = GenRandom(random, 16);
  if (0 != ec) {
    return ec;
  }

  // 3、生成n个密钥对
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

  // 3.1、TODO: 生成根证书

  // 3.2、TODO: 使用随机密钥加密(n个密钥对+根证书的公私钥信息)存储到本地
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

  // 5、用户姓名+索引信息 写入到关系文件
  proto::IndexInfo indexs;
  bool index_file_exist = false;

  // 5.1、读取原信息
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

  // 用户信息
  std::string name("name");
  int index = indexs.index_size();

  // 4、设置密码；修改密码；下发单个密钥对、所有公钥、根证书、身份信息（name+index）到USB Key（密钥对、公钥的顺序必须一致）
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

    // 4.1、从文件中读取密钥对信息
    proto::SecretInfo secrets_in;
    std::fstream input("secret.db", std::ios::in | std::ios::binary);
    if (!input) {
      return -1;
    } else if (!secrets_in.ParseFromIstream(&input)) {
      return -1;
    }

    // 4.2、转换到vector中
    std::vector<SM2KeyPair> kp_read;
    for (int i = 0; i < secrets_in.keypair_size(); ++i) {
      SM2KeyPair kp;
      const std::string& pubkey = secrets_in.keypair(i).pub_key();
      const std::string& privkey = secrets_in.keypair(i).priv_key();
      kp.pub_key.assign(pubkey.begin(), pubkey.end());
      kp.priv_key.assign(privkey.begin(), privkey.end());
      kp_read.emplace_back(std::move(kp));
    }

    // 下发密钥对
    SM2KeyPair to_import = kp_read[index];
    ec = ImportKeyPairToU03Key(to_import);
    if (0 != ec) {
      return ec;
    }

    // 下发所有公钥
    std::vector<BYTE> pubs;
    for (auto& x : kp_read) {
      pubs.insert(pubs.begin(), x.pub_key.begin(), x.pub_key.end());
    }
    size_t len = (pubs.size() / 4096 + 1) * 4096;
    pubs.resize(len);


    // TODO: 下发根证书

    // 身份信息（name+index）
  }

  // 5.2、插入新信息
  {
    auto nameindex = indexs.add_index();
    nameindex->set_name(name);
    nameindex->set_index(index);
  }

  // 5.3、写入，写入前需要进行备份

  // 5.3.1 备份
  {
    // 如果存在文件，则重命名为 文件名称+时间（精确到秒）
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

  // 5.3.2 写入
  {
    std::fstream output("index.db", std::ios::out | std::ios::trunc | std::ios::binary);
    if (!indexs.SerializeToOstream(&output)) {
      return -1;
    }
  }

  // 6、最终的关系文件发给每个用户

  return 0;
}