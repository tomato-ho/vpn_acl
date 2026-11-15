#include "vpn/service/admin_read.h"

#include "vpn/util.h"

#include <algorithm>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn::service {
namespace {

std::uint64_t parse_u64(const std::string& value) {
    if (value.empty()) {
        return 0;
    }
    try {
        return static_cast<std::uint64_t>(std::stoull(value));
    } catch (const std::exception&) {
        return 0;
    }
}

std::uint32_t parse_u32(const std::string& value) {
    return static_cast<std::uint32_t>(parse_u64(value));
}

constexpr const char* kUserColumns =
    "u.username, u.display_name, IFNULL(g.name, ''), IFNULL(u.fixed_ip, ''), "
    "u.enabled, u.must_change_password, "
    "DATE_FORMAT(u.created_at, '%Y-%m-%d %H:%i:%s'), "
    "DATE_FORMAT(u.updated_at, '%Y-%m-%d %H:%i:%s')";

UserSummary user_from_row(const std::vector<std::string>& row) {
    UserSummary user;
    if (row.size() < 8) {
        return user;
    }
    user.username = row[0];
    user.display_name = row[1];
    user.group_name = row[2];
    user.fixed_ip = row[3];
    user.enabled = parse_bool(row[4], false);
    user.must_change_password = parse_bool(row[5], false);
    user.created_at = row[6];
    user.updated_at = row[7];
    return user;
}

PageRequest normalize_page(const PageRequest& page) {
    PageRequest normalized;
    normalized.page = std::max<std::uint32_t>(1, page.page);
    normalized.page_size = std::clamp<std::uint32_t>(page.page_size, 1, 200);
    return normalized;
}

} // namespace

PagedResult<UserSummary> list_users(Db& db, const UserQuery& query) {
    const PageRequest page = normalize_page(query.page);

    std::string where = " WHERE 1=1";
    if (!query.query.empty()) {
        const std::string pattern = "%" + db.quote(query.query) + "%";
        where += " AND (u.username LIKE '" + pattern +
                 "' OR u.display_name LIKE '" + pattern + "')";
    }
    if (!query.group.empty()) {
        where += " AND g.name = '" + db.quote(query.group) + "'";
    }

    const auto count_rows = db.query(
        "SELECT COUNT(*) FROM vpn_users u "
        "LEFT JOIN vpn_groups g ON g.id = u.group_id" +
        where);
    PagedResult<UserSummary> result;
    result.page = page.page;
    result.page_size = page.page_size;
    if (!count_rows.empty() && !count_rows[0].empty()) {
        result.total = parse_u64(count_rows[0][0]);
    }

    const std::uint64_t offset =
        static_cast<std::uint64_t>(page.page - 1) * page.page_size;
    const auto rows = db.query(
        std::string("SELECT ") + kUserColumns +
        " FROM vpn_users u LEFT JOIN vpn_groups g ON g.id = u.group_id" +
        where + " ORDER BY u.username LIMIT " +
        std::to_string(page.page_size) + " OFFSET " + std::to_string(offset));

    result.items.reserve(rows.size());
    for (const auto& row : rows) {
        result.items.push_back(user_from_row(row));
    }
    return result;
}

std::optional<UserSummary> get_user(Db& db, const std::string& username) {
    const auto rows = db.query(
        std::string("SELECT ") + kUserColumns +
        " FROM vpn_users u LEFT JOIN vpn_groups g ON g.id = u.group_id"
        " WHERE u.username = '" +
        db.quote(username) + "'");
    if (rows.empty()) {
        return std::nullopt;
    }
    return user_from_row(rows[0]);
}

std::vector<GroupSummary> list_groups(Db& db) {
    const auto rows = db.query(
        "SELECT g.id, g.name, g.ip_start, g.ip_end, g.description, "
        "(SELECT COUNT(*) FROM vpn_users u WHERE u.group_id = g.id), "
        "(SELECT COUNT(*) FROM vpn_group_rules r WHERE r.group_id = g.id) "
        "FROM vpn_groups g ORDER BY g.name");

    std::vector<GroupSummary> groups;
    groups.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 7) {
            continue;
        }
        GroupSummary group;
        group.id = parse_u32(row[0]);
        group.name = row[1];
        group.ip_start = row[2];
        group.ip_end = row[3];
        group.description = row[4];
        group.user_count = parse_u64(row[5]);
        group.rule_count = parse_u64(row[6]);
        groups.push_back(group);
    }
    return groups;
}

std::vector<SessionInfo> list_sessions(Db& db,
                                       const StatusSnapshot& status) {
    const auto rows = db.query(
        "SELECT session_id, username, virtual_ip, remote_ip, "
        "DATE_FORMAT(start_time, '%Y-%m-%d %H:%i:%s'), "
        "UNIX_TIMESTAMP(start_time), bytes_in, bytes_out "
        "FROM vpn_sessions ORDER BY start_time DESC");

    const std::time_t now = std::time(nullptr);
    std::vector<SessionInfo> sessions;
    sessions.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 8) {
            continue;
        }
        SessionInfo session;
        session.session_id = row[0];
        session.username = row[1];
        session.virtual_ip = row[2];
        session.remote_ip = row[3];
        session.start_time = row[4];
        const std::time_t start = static_cast<std::time_t>(parse_u64(row[5]));
        session.duration_seconds =
            now > start ? static_cast<std::uint64_t>(now - start) : 0;
        session.bytes_in = parse_u64(row[6]);
        session.bytes_out = parse_u64(row[7]);

        const auto online = status.clients.find(session.virtual_ip);
        if (online != status.clients.end()) {
            session.online = true;
            session.bytes_in = online->second.bytes_received;
            session.bytes_out = online->second.bytes_sent;
        }
        sessions.push_back(session);
    }
    return sessions;
}

std::vector<AuditEntry> list_audit(Db& db,
                                   std::uint32_t limit,
                                   std::uint32_t offset) {
    const std::uint32_t normalized_limit = std::clamp<std::uint32_t>(limit, 1, 500);
    const auto rows = db.query(
        "SELECT id, operator, action, target, IFNULL(before_json, ''), "
        "IFNULL(after_json, ''), DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_audit_log ORDER BY id DESC LIMIT " +
        std::to_string(normalized_limit) + " OFFSET " + std::to_string(offset));

    std::vector<AuditEntry> entries;
    entries.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 7) {
            continue;
        }
        AuditEntry entry;
        entry.id = parse_u64(row[0]);
        entry.operator_name = row[1];
        entry.action = row[2];
        entry.target = row[3];
        entry.before_json = row[4];
        entry.after_json = row[5];
        entry.created_at = row[6];
        entries.push_back(entry);
    }
    return entries;
}

DashboardSummary dashboard_summary(Db& db, const StatusSnapshot& status) {
    DashboardSummary summary;

    const auto user_rows = db.query(
        "SELECT COUNT(*), IFNULL(SUM(enabled = 1), 0) FROM vpn_users");
    if (!user_rows.empty() && user_rows[0].size() >= 2) {
        summary.users_total = parse_u64(user_rows[0][0]);
        summary.users_enabled = parse_u64(user_rows[0][1]);
    }

    const auto group_rows = db.query("SELECT COUNT(*) FROM vpn_groups");
    if (!group_rows.empty() && !group_rows[0].empty()) {
        summary.groups_total = parse_u64(group_rows[0][0]);
    }

    const auto audit_rows = db.query("SELECT COUNT(*) FROM vpn_audit_log");
    if (!audit_rows.empty() && !audit_rows[0].empty()) {
        summary.audit_entries = parse_u64(audit_rows[0][0]);
    }

    const auto version_rows =
        db.query("SELECT version FROM vpn_policy_version WHERE id = 1");
    if (!version_rows.empty() && !version_rows[0].empty()) {
        summary.policy_version = parse_u64(version_rows[0][0]);
    }

    const auto auth_rows = db.query(
        "SELECT IFNULL(SUM(success = 1), 0), "
        "IFNULL(SUM(success = 0), 0) FROM vpn_auth_log");
    if (!auth_rows.empty() && auth_rows[0].size() >= 2) {
        summary.auth_accept_total = parse_u64(auth_rows[0][0]);
        summary.auth_reject_total = parse_u64(auth_rows[0][1]);
    }

    if (status.valid) {
        summary.active_sessions = status.clients.size();
    } else {
        const auto session_rows = db.query("SELECT COUNT(*) FROM vpn_sessions");
        if (!session_rows.empty() && !session_rows[0].empty()) {
            summary.active_sessions = parse_u64(session_rows[0][0]);
        }
    }

    return summary;
}

} // namespace vpn::service