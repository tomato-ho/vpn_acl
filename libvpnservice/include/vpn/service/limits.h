#pragma once

#include "vpn/db.h"

#include <cstddef>

namespace vpn::service {

// 在写入/启用规则或服务后调用；若有用户超过配置上限则抛 ServiceError。
void ensure_rule_limits(Db& db, std::size_t maximum);
void ensure_service_limits(Db& db, std::size_t maximum);

} // namespace vpn::service