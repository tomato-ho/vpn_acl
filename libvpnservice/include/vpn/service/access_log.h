#pragma once

#include "vpn/db.h"
#include "vpn/service/types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vpn::service {

struct AccessLogQuery {
    // all / today / 24h / 7d / 30d / 90d / 180d / custom
    std::string range{"7d"};
    std::string from;
    std::string to;
    std::string username;
    std::string session_id;
    std::string dest_ip;
    // 按目标网段反查（例如 192.168.140.0/24）。
    std::string dest_cidr;
    std::string action;
    std::uint32_t page{1};
    std::uint32_t page_size{50};
};

struct AccessLogRow {
    std::uint64_t id{0};
    std::string session_id;
    std::string username;
    std::string virtual_ip;
    std::string dest_ip;
    std::string action;
    std::uint64_t bytes_up{0};
    std::uint64_t bytes_down{0};
    std::string first_seen;
    std::string last_seen;
};

struct AccessLogStats {
    std::uint64_t records{0};
    std::uint64_t users{0};
    std::uint64_t targets{0};
    std::uint64_t bytes_up{0};
    std::uint64_t bytes_down{0};
};

PagedResult<AccessLogRow> query_access_log(Db& db, const AccessLogQuery& query);
AccessLogStats query_access_log_stats(Db& db, const AccessLogQuery& query);
std::vector<AccessLogRow> export_access_log(Db& db,
                                            const AccessLogQuery& query,
                                            std::size_t max_rows);

} // namespace vpn::service