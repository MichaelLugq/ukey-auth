#include "proto.h"

#include "consts.h"
#include "index.pb.h"
#include "secret.pb.h"

int main() {
  proto::NameIndex name_index;
  name_index.set_name("name");
  name_index.set_index(65);
  auto ec = WriteUserIndex(name_index);
  if (ec != kSuccess) {
    return ec;
  }

  proto::NameIndex ni_copy;
  ec = ReadUserIndex(ni_copy);
  if (ec != kSuccess) {
    return ec;
  }
  assert(ni_copy.name() == name_index.name());
  assert(ni_copy.index() == name_index.index());

  return 0;
}