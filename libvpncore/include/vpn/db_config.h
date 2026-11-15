#pragma once

#include "vpn/config.h"
#include "vpn/db.h"

namespace vpn {

DbConfig make_db_config(const Config& config);

} // namespace vpn