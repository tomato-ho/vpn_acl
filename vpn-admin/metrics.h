#pragma once

#include "admin_config.h"
#include "db_pool.h"

#include "vpn/service/admin_read.h"

#include <nlohmann/json.hpp>

#include <ctime>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace vpn::admin {

struct PolicydStats {
    bool available{false};
    std::uint64_t refresh_total{0};
    std::uint64_t refresh_errors{0};
    std::uint64_t refresh_fallback_total{0};
    std::uint64_t refresh_nft_calls_total{0};
    std::uint64_t last_refresh_duration_ms{0};
    std::uint64_t last_refresh_time{0};
    std::uint64_t reconcile_total{0};
    std::uint64_t reconcile_errors{0};
    std::uint64_t last_reconcile_duration_ms{0};
    std::uint64_t last_reconcile_time{0};
};

struct MetricsSnapshot {
    service::DashboardSummary dashboard;
    std::vector<service::SessionInfo> sessions;
    std::uint64_t radacct_open{0};
    std::uint64_t radacct_closed{0};
    std::uint64_t auth_last_success{0};
    bool database_up{false};
    bool policyd_up{false};
    PolicydStats policyd;
    std::time_t collected_at{0};
};

class MetricsCollector {
public:
    MetricsCollector(const AdminConfig& config, DbPool& pool);

    MetricsSnapshot get();
    std::string prometheus();
    nlohmann::json json();

private:
    MetricsSnapshot collect();

    const AdminConfig& config_;
    DbPool& pool_;
    std::mutex mutex_;
    MetricsSnapshot cache_;
    bool has_cache_{false};
};

} // namespace vpn::admin