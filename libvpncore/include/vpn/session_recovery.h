#pragma once

#include <ctime>
#include <string>

namespace vpn {

struct RecoveryIdentity {
    std::string session_id;
    std::string acct_session_id;
};

// 为一个没有 connect-hook marker 的恢复会话生成身份。
// connected_since 必须来自 OpenVPN status 的 time_t；同一连接重试得到同一个
// ID，不同连接（不同 connected_since）得到不同 ID，避免覆盖历史记录。
RecoveryIdentity recovery_identity(const std::string& username,
                                   const std::string& virtual_ip,
                                   std::time_t connected_since);

// status 快照里的连接是否已经归档过（避免用过期 status 造出重复历史）。
bool recovery_is_stale(std::time_t connected_since, std::time_t last_stop);

} // namespace vpn