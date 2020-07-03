#include "proto.h"

#include "consts.h"
#include "utils.h"
#include "crypto.h"

#include <sstream>

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
    return -1;
  }

  return kSuccess;
}
