#pragma once

#include "vpn/db.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vpn::service {

struct AuthHistoryPoint {
    std::string bucket;
    std::uint64_t accept{0};
    std::uint64_t reject{0};
};

struct SessionHistoryPoint {
    std::string bucket;
    std::uint64_t started{0};
    std::uint64_t stopped{0};
    std::uint64_t session_time{0};
    std::uint64_t bytes_in{0};
    std::uint64_t bytes_out{0};
};

struct TopUser {
    std::string username;
    std::uint64_t sessions{0};
    std::uint64_t bytes_in{0};
    std::uint64_t bytes_out{0};
    std::uint64_t session_time{0};
    bool user_exists{true};
};

struct MetricsHistory {
    std::vector<AuthHistoryPoint> auth;
    std::vector<SessionHistoryPoint> sessions;
};

MetricsHistory load_metrics_history(Db& db,
                                    const std::string& range,
                                    const std::string& step);
std::vector<TopUser> load_top_users(Db& db,
                                    const std::string& range,
                                    std::uint32_t limit,
                                    bool include_deleted = false);

} // namespace vpn::service