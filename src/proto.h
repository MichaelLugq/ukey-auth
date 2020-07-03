#pragma once

#include "index.pb.h"
#include "secret.pb.h"

#include <vector>

int WriteUserIndex(const proto::NameIndex& name_index);

int ReadUserIndex(proto::NameIndex& name_index);
