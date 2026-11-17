#pragma once

#include "vpn/db.h"
#include "vpn/service/openvpn_status.h"
#include "vpn/service/types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vpn::service {

struct UserSummary {
    std::string username;
    std::string display_name;
    std::string group_name;
    std::string fixed_ip;
    bool enabled{false};
    std::string created_at;
    std::string updated_at;
};

struct UserQuery {
    std::string query;
    std::string group;
    PageRequest page;
};

struct GroupSummary {
    std::uint32_t id{0};
    std::string name;
    std::string ip_start;
    std::string ip_end;
    std::string description;
    std::uint64_t user_count{0};
    std::uint64_t rule_count{0};
};

struct SessionInfo {
    std::string session_id;
    std::string username;
    std::string virtual_ip;
    std::string remote_ip;
    std::string start_time;
    std::uint64_t duration_seconds{0};
    std::uint64_t bytes_in{0};
    std::uint64_t bytes_out{0};
    bool online{false};
};

struct AuditEntry {
    std::uint64_t id{0};
    std::string operator_name;
    std::string action;
    std::string target;
    std::string before_json;
    std::string after_json;
    std::string created_at;
};

struct DashboardSummary {
    std::uint64_t users_total{0};
    std::uint64_t users_enabled{0};
    std::uint64_t groups_total{0};
    std::uint64_t active_sessions{0};
    std::uint64_t audit_entries{0};
    std::uint64_t policy_version{0};
    std::uint64_t auth_accept_total{0};
    std::uint64_t auth_reject_total{0};
};

PagedResult<UserSummary> list_users(Db& db, const UserQuery& query);
std::optional<UserSummary> get_user(Db& db, const std::string& username);
std::vector<GroupSummary> list_groups(Db& db);
std::vector<SessionInfo> list_sessions(Db& db,
                                       const StatusSnapshot& status);
std::vector<AuditEntry> list_audit(Db& db,
                                   std::uint32_t limit,
                                   std::uint32_t offset);
DashboardSummary dashboard_summary(Db& db, const StatusSnapshot& status);

} // namespace vpn::service