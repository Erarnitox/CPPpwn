#pragma once

#include "Stream.hpp"
#include <memory>

namespace cpppwn {

void connect_shell(Stream& io);
void connect_popen(Stream& io);

}
