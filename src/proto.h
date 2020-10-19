#pragma once

#include "index.pb.h"
#include "secret.pb.h"
#include "crypto.h"

#include <vector>

int WriteUserIndex(const proto::NameIndex& name_index);

int ReadUserIndex(proto::NameIndex& name_index);

int ClearUserIndex();

int WriteOthersIndex(const proto::IndexInfo& others);

int ReadOthersIndex(proto::IndexInfo& others);

bool LocalIndexExists();

int WriteLocalIndexs(const proto::IndexInfo& local);

int ReadLocalIndexs(proto::IndexInfo& local);

int WriteSecrets(const std::vector<SM2KeyPair>& keys);

int ReadSecrets(std::vector<SM2KeyPair>& keys);

int WritePublicKeysToUKey(const std::vector<SM2KeyPair>& keys);

int ReadPublicKeysFromUKey(std::vector<std::vector<BYTE>>& public_keys);