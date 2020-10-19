#include "proto.h"

#include "consts.h"
#include "utils.h"

#include <fstream>
#include <sstream>
#include <filesystem>

#include <system_error>

namespace fs = std::filesystem;

static const int kHasWrittenFlag = 0xFECB;

static const int kFlagOccupySize = 4;

static const int kIndexOccupySize = 4;

int WriteUserIndex(const proto::NameIndex& name_index) {
  std::ostringstream output;
  if (!name_index.SerializeToOstream(&output)) {
    return -1;
  }

  std::string str = output.str();
  int bytes = str.size();

  std::vector<BYTE> info(kUserRegionSize, 0);
  std::memcpy(info.data(), &kHasWrittenFlag, kFlagOccupySize);
  std::memcpy(info.data() + kFlagOccupySize, &bytes, kIndexOccupySize);
  std::memcpy(info.data() + kFlagOccupySize + kIndexOccupySize, str.data(), bytes);

  int ec = WritePrivate(bytes, info);
  if (ec != kSuccess) {
    return ec;
  }

  return kSuccess;
}

int ReadUserIndex(proto::NameIndex& name_index) {
  std::vector<BYTE> info;
  int ec = ReadPrivate(0, kUserRegionSize, info);
  if (ec != kSuccess) {
    return ec;
  }

  int flag = 0;
  int bytes = 0;
  std::memcpy(&flag, info.data(), kFlagOccupySize);
  if (flag != kHasWrittenFlag) {
    return kNoWrittenFlag;
  }
  std::memcpy(&bytes, info.data() + kFlagOccupySize, kIndexOccupySize);
  std::string str(bytes, 0);
  std::memcpy(str.data(), info.data() + kFlagOccupySize + kIndexOccupySize, bytes);

  std::istringstream input;
  input.str(str);
  if (!name_index.ParseFromIstream(&input)) {
    return kErrParseProto;
  }

  return kSuccess;
}

int ClearUserIndex() {
  std::vector<BYTE> info(kUserRegionSize, 0);
  int ec = WritePrivate(0, info);
  if (ec != kSuccess) {
    return ec;
  }
  return kSuccess;
}

int WriteOthersIndex(const proto::IndexInfo& others) {
  std::ostringstream output;
  if (!others.SerializeToOstream(&output)) {
    return -1;
  }

  std::vector<BYTE> info(4096 * 4, 0);

  std::string str = output.str();
  int write_bytes = str.size();
  int write_offset = sizeof(int);
  std::memcpy(info.data(), &write_bytes, write_offset);
  std::memcpy(info.data() + write_offset, str.data(), write_bytes);

  int sector_offset = kOtherUsersInfoStartPosition;
  int ec = WriteToUKey(sector_offset, info);
  if (ec != kSuccess) {
    return ec;
  }

  return kSuccess;
}

int ReadOthersIndex(proto::IndexInfo& others) {
  std::vector<BYTE> info(4096 * 4, 0);
  int sector_offset = kOtherUsersInfoStartPosition;
  int ec = ReadFromUKey(sector_offset, 4, info);
  if (ec != kSuccess) {
    return ec;
  }

  int read_bytes = 0;
  int read_offset = sizeof(int);
  std::memcpy(&read_bytes, info.data(), read_offset);
  std::string str(read_bytes, 0);
  std::memcpy(str.data(), info.data() + read_offset, read_bytes);

  std::istringstream input;
  input.str(str);
  if (!others.ParseFromIstream(&input)) {
    return -1;
  }

  return kSuccess;
}

bool LocalIndexExists() {
  std::fstream check_exists("index.db", std::ios::in | std::ios::binary);
  return !!check_exists;
}

int WriteLocalIndexs(const proto::IndexInfo& local) {
  // ±¸·Ý
  if (LocalIndexExists()) {
    fs::path old_path = fs::current_path().append("index.db");
    fs::path new_path = fs::current_path().append("index-" + TimeString() + ".db");
    std::error_code ec;
    fs::rename(old_path, new_path, ec);
    if (ec) {
      auto msg = ec.message();
      std::cout << msg << std::endl;
      return -1;
    }
  }

  // Ð´Èëindex.db
  {
    std::fstream output("index.db", std::ios::out | std::ios::trunc | std::ios::binary);
    if (!local.SerializeToOstream(&output)) {
      return kErrParseProto;
    }
  }

  return kSuccess;
}

int ReadLocalIndexs(proto::IndexInfo& local) {

  std::fstream input("index.db", std::ios::in | std::ios::binary);
  if (!input) {
    return kNoIndexDB;
  }

  if (!local.ParseFromIstream(&input)) {
    return kErrParseProto;
  }

  return kSuccess;
}

int WriteSecrets(const std::vector<SM2KeyPair>& keys) {
  proto::SecretInfo secrets;

  for (auto& key : keys) {
    auto kp = secrets.add_keypair();
    kp->set_pub_key(key.pub_key.data(), key.pub_key.size());
    kp->set_priv_key(key.priv_key.data(), key.priv_key.size());
  }

  std::fstream output("secret.db", std::ios::out | std::ios::trunc | std::ios::binary);
  if (!secrets.SerializeToOstream(&output)) {
    return kErrParseProto;
  }

  return kSuccess;
}

int ReadSecrets(std::vector<SM2KeyPair>& keys) {
  proto::SecretInfo secrets;

  std::fstream input("secret.db", std::ios::in | std::ios::binary);
  if (!input) {
    return kNoSecretDB;
  } else if (!secrets.ParseFromIstream(&input)) {
    return kErrParseProto;
  }

  for (int i = 0; i < secrets.keypair_size(); ++i) {
    SM2KeyPair key;
    key.pub_key.assign(secrets.keypair(i).pub_key().begin(), secrets.keypair(i).pub_key().end());
    key.priv_key.assign(secrets.keypair(i).priv_key().begin(), secrets.keypair(i).priv_key().end());
    keys.emplace_back(std::move(key));
  }

  return kSuccess;
}

int WritePublicKeysToUKey(const std::vector<SM2KeyPair>& keys) {
  std::vector<BYTE> pubs;

  for (const auto& key : keys) {
    pubs.insert(pubs.end(), key.pub_key.begin(), key.pub_key.end());
  }
  assert(pubs.size() % 4096 == 0);

  int sector_offset = kPublicKeyStartPosition;
  int ec = WriteToUKey(sector_offset, pubs);
  if (ec != kSuccess) {
    return ec;
  }

  return kSuccess;
}

int ReadPublicKeysFromUKey(std::vector<std::vector<BYTE>>& public_keys) {
  std::vector<BYTE> test_pub;

  auto sector_offset = kPublicKeyStartPosition;
  ULONG sector_read = kSM2KeyPairCount * kSM2PublicKeySize / 4096;
  auto ec = ReadFromUKey(sector_offset, sector_read, test_pub);
  if (ec != kSuccess) {
    return ec;
  }

  assert(test_pub.size() % kSM2PublicKeySize == 0);
  int pubkey_count = test_pub.size() / kSM2PublicKeySize;
  for (int i = 0; i < pubkey_count; ++i) {
    std::vector<BYTE> one(test_pub.begin() + i * kSM2PublicKeySize,
                          test_pub.begin() + (i + 1) * kSM2PublicKeySize);
    public_keys.emplace_back(std::move(one));
  }

  return kSuccess;
}
