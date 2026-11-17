#include "vpn/session_recovery.h"

#include "vpn/nft.h"

namespace vpn {

RecoveryIdentity recovery_identity(const std::string& username,
                                   const std::string& virtual_ip,
                                   std::time_t connected_since) {
    const std::string key =
        std::to_string(connected_since > 0 ? connected_since : 0);
    const std::string hash =
        nft_chain_hash(username + "@" + virtual_ip + "@" + key);
    return RecoveryIdentity{"recover-" + hash, "vpn-recover-" + hash};
}

bool recovery_is_stale(std::time_t connected_since, std::time_t last_stop) {
    // 如果 status 中的连接开始时间早于该用户/IP 最后一条已归档记录的结束时间，
    // 说明这是重启前残留的 status，不应再恢复。
    return connected_since > 0 && last_stop > 0 && connected_since < last_stop;
}

} // namespace vpn