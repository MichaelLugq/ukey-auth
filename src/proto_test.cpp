#include "proto.h"

#include "consts.h"
#include "index.pb.h"
#include "secret.pb.h"

int main() {
  int ec;

  {
    proto::NameIndex name_index;

    {
      name_index.set_name("name");
      name_index.set_index(65);
      ec = WriteUserIndex(name_index);
      if (ec != kSuccess) {
        return ec;
      }
    }

    {
      proto::NameIndex ni_copy;
      ec = ReadUserIndex(ni_copy);
      if (ec != kSuccess) {
        return ec;
      }
      assert(ni_copy.name() == name_index.name());
      assert(ni_copy.index() == name_index.index());
    }

    {
      ClearUserIndex();
      ec = ReadUserIndex(name_index);
      assert(ec == kNoWrittenFlag);
    }
  }

  proto::IndexInfo info;
  {
    for (int i = 0; i < 10; ++i) {
      auto index = info.add_index();
      index->set_name("name");
      index->set_index(i);
    }
  }

  {
    {
      ec = WriteOthersIndex(info);
      if (ec != kSuccess) {
        return ec;
      }
    }

    {
      proto::IndexInfo copy_info;
      ec = ReadOthersIndex(copy_info);
      if (ec != kSuccess) {
        return ec;
      }
      assert(copy_info.index_size() == info.index_size());
    }
  }

  {
    {
      ec = WriteLocalIndexs(info);
      if (ec != kSuccess) {
        return ec;
      }
    }

    {
      proto::IndexInfo copy_info;
      ec = ReadLocalIndexs(copy_info);
      if (ec != kSuccess) {
        return ec;
      }
      assert(copy_info.index_size() == info.index_size());
    }
  }

  return 0;
}