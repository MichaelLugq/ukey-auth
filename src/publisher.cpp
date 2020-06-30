#include "utils.h"
#include "crypto.h"

#include "secret.pb.h"

#include <fstream>

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

  // 3.1、TODO: 生成根证书

  // 3.2、TODO: 使用随机密钥加密(n个密钥对+根证书的公私钥信息)存储到本地
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

  // 4、下发单个密钥对、所有公钥、根证书到USB Key（密钥对、公钥的顺序必须一致）

  // 5、用户姓名+索引信息 写入到关系文件

  // 6、最终的关系文件发给每个用户

  return 0;
}