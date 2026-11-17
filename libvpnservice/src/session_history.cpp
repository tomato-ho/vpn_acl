#include "vpn/service/session_history.h"

#include "history_source.h"
#include "vpn/service/errors.h"
#include "vpn/util.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn::service {
namespace {

[[noreturn]] void fail(const std::string& message) {
    throw ServiceError(ErrorCode::validation, message);
}

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

std::optional<std::time_t> parse_date(const std::string& value) {
    if (value.size() != 10 || value[4] != '-' || value[7] != '-') {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 4 || i == 7) {
            continue;
        }
        if (value[i] < '0' || value[i] > '9') {
            return std::nullopt;
        }
    }

    std::tm tm{};
    std::istringstream stream(value);
    stream >> std::get_time(&tm, "%Y-%m-%d");
    if (stream.fail()) {
        return std::nullopt;
    }

    const std::time_t epoch = ::timegm(&tm);
    std::tm check{};
    ::gmtime_r(&epoch, &check);
    if (check.tm_year != tm.tm_year || check.tm_mon != tm.tm_mon ||
        check.tm_mday != tm.tm_mday) {
        return std::nullopt;
    }
    return epoch;
}

std::string range_condition(const std::string& column,
                            const SessionHistoryQuery& query) {
    const std::string range = to_lower(query.range);
    if (range.empty() || range == "today") {
        return column + " >= CURDATE() AND " + column +
               " < CURDATE() + INTERVAL 1 DAY";
    }
    if (range == "24h") {
        return column + " >= NOW() - INTERVAL 24 HOUR";
    }
    if (range == "7d") {
        return column + " >= NOW() - INTERVAL 7 DAY";
    }
    if (range == "30d") {
        return column + " >= NOW() - INTERVAL 30 DAY";
    }
    if (range != "custom") {
        fail("range must be today, 24h, 7d, 30d or custom");
    }

    const auto from = parse_date(query.from);
    const auto to = parse_date(query.to);
    if (!from || !to) {
        fail("custom range requires valid from and to dates");
    }
    if (*from > *to) {
        fail("from date is after to date");
    }
    if ((*to - *from) / 86400 > 90) {
        fail("custom range must not exceed 90 days");
    }

    return column + " >= '" + query.from + " 00:00:00' AND " + column +
           " < DATE_ADD('" + query.to + " 00:00:00', INTERVAL 1 DAY)";
}

std::string username_condition(Db& db,
                               const std::string& alias,
                               const SessionHistoryQuery& query) {
    if (query.username.empty()) {
        return {};
    }
    return " AND " + alias + ".username LIKE '%" + db.quote(query.username) +
           "%'";
}

std::string deleted_condition(const SessionHistoryQuery& query) {
    return query.include_deleted ? "" : " AND u.username IS NOT NULL";
}

PageRequest normalize_page(std::uint32_t page, std::uint32_t page_size) {
    PageRequest result;
    result.page = std::max<std::uint32_t>(1, page);
    result.page_size = std::clamp<std::uint32_t>(page_size, 1, 200);
    return result;
}

// 在线会话与历史会话合并成一个数据源，列与原先 radacct 查询保持一致。
std::string history_source() {
    return detail::history_source();
}

std::string session_where(Db& db, const SessionHistoryQuery& query) {
    return " WHERE " + range_condition("r.start_time", query) +
           username_condition(db, "r", query) + deleted_condition(query);
}

std::string auth_where(Db& db, const SessionHistoryQuery& query) {
    return " WHERE a.success = 0 AND " +
           range_condition("a.created_at", query) +
           username_condition(db, "a", query) + deleted_condition(query);
}

std::vector<HistorySession> load_session_rows(Db& db,
                                              const SessionHistoryQuery& query,
                                              std::uint32_t limit,
                                              std::uint64_t offset) {
    const std::string where = session_where(db, query);
    const auto rows = db.query(
        "SELECT r.session_id, r.username, IFNULL(r.virtual_ip, ''), "
        "IFNULL(r.remote_ip, ''), "
        "DATE_FORMAT(r.start_time, '%Y-%m-%d %H:%i:%s'), "
        "r.stop_time_text, "
        "IFNULL(r.duration_seconds, 0), "
        "IFNULL(r.bytes_in, 0), "
        "IFNULL(r.bytes_out, 0), "
        "IFNULL(r.terminate_cause, ''), "
        "r.is_open, "
        "IF(u.username IS NULL, 0, 1) "
        "FROM " + history_source() +
        " LEFT JOIN vpn_users u ON u.username = r.username" + where +
        " ORDER BY r.start_time DESC LIMIT " + std::to_string(limit) +
        " OFFSET " + std::to_string(offset));

    std::set<std::string> online_ips;
    std::set<std::string> online_users;
    const auto online_rows =
        db.query("SELECT username, virtual_ip FROM vpn_sessions");
    for (const auto& row : online_rows) {
        if (row.size() >= 2) {
            online_users.insert(row[0]);
            online_ips.insert(row[1]);
        }
    }

    std::vector<HistorySession> sessions;
    sessions.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 12) {
            continue;
        }
        HistorySession session;
        session.session_id = row[0];
        session.username = row[1];
        session.virtual_ip = row[2];
        session.remote_ip = row[3];
        session.start_time = row[4];
        session.stop_time = row[5];
        session.duration_seconds = parse_u64(row[6]);
        session.bytes_in = parse_u64(row[7]);
        session.bytes_out = parse_u64(row[8]);
        session.terminate_cause = row[9];
        const bool is_open = parse_u64(row[10]) != 0;
        session.user_exists = parse_u64(row[11]) != 0;

        if (!is_open) {
            session.state = "closed";
        } else if (online_ips.find(session.virtual_ip) != online_ips.end() ||
                   online_users.find(session.username) != online_users.end()) {
            session.state = "online";
        } else {
            session.state = "stale_open";
        }
        sessions.push_back(session);
    }
    return sessions;
}

std::vector<AuthFailure> load_auth_rows(Db& db,
                                        const SessionHistoryQuery& query,
                                        std::uint32_t limit,
                                        std::uint64_t offset) {
    const std::string where = auth_where(db, query);
    const auto rows = db.query(
        "SELECT a.id, a.username, "
        "IF(a.reason = '', 'Access-Reject', a.reason), "
        "DATE_FORMAT(a.created_at, '%Y-%m-%d %H:%i:%s'), "
        "IF(u.username IS NULL, 0, 1) "
        "FROM vpn_auth_log a LEFT JOIN vpn_users u ON u.username = a.username" +
        where + " ORDER BY a.created_at DESC LIMIT " + std::to_string(limit) +
        " OFFSET " + std::to_string(offset));

    std::vector<AuthFailure> failures;
    failures.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 5) {
            continue;
        }
        AuthFailure failure;
        failure.id = parse_u64(row[0]);
        failure.username = row[1];
        failure.reply = row[2];
        failure.auth_time = row[3];
        failure.user_exists = parse_u64(row[4]) != 0;
        failures.push_back(failure);
    }
    return failures;
}

} // namespace

PagedResult<HistorySession> query_session_history(
    Db& db, const SessionHistoryQuery& query) {
    const PageRequest page = normalize_page(query.page, query.page_size);
    const std::string where = session_where(db, query);

    PagedResult<HistorySession> result;
    result.page = page.page;
    result.page_size = page.page_size;

    const auto count_rows = db.query(
        "SELECT COUNT(*) FROM " + history_source() +
        " LEFT JOIN vpn_users u ON u.username = r.username" + where);
    if (!count_rows.empty() && !count_rows[0].empty()) {
        result.total = parse_u64(count_rows[0][0]);
    }

    const std::uint64_t offset =
        static_cast<std::uint64_t>(page.page - 1) * page.page_size;
    result.items =
        load_session_rows(db, query, page.page_size, offset);
    return result;
}

SessionHistoryStats query_session_history_stats(
    Db& db, const SessionHistoryQuery& query) {
    const std::string where = session_where(db, query);
    SessionHistoryStats stats;

    const auto rows = db.query(
        "SELECT COUNT(*), COUNT(DISTINCT r.username), "
        "IFNULL(SUM(r.duration_seconds), 0), "
        "IFNULL(SUM(r.bytes_in), 0), "
        "IFNULL(SUM(r.bytes_out), 0) "
        "FROM " + history_source() +
        " LEFT JOIN vpn_users u ON u.username = r.username" + where);
    if (!rows.empty() && rows[0].size() >= 5) {
        stats.session_count = parse_u64(rows[0][0]);
        stats.unique_users = parse_u64(rows[0][1]);
        stats.total_seconds = parse_u64(rows[0][2]);
        stats.bytes_in = parse_u64(rows[0][3]);
        stats.bytes_out = parse_u64(rows[0][4]);
    }

    std::string online_sql = "SELECT COUNT(*) FROM vpn_sessions s";
    std::string online_where;
    if (!query.username.empty()) {
        online_where += " WHERE s.username LIKE '%" + db.quote(query.username) +
                        "%'";
    }
    if (!query.include_deleted) {
        online_where += online_where.empty() ? " WHERE " : " AND ";
        online_where +=
            "s.username IN (SELECT username FROM vpn_users)";
    }
    const auto online_rows = db.query(online_sql + online_where);
    if (!online_rows.empty() && !online_rows[0].empty()) {
        stats.online_sessions = parse_u64(online_rows[0][0]);
    }
    return stats;
}

PagedResult<AuthFailure> query_auth_failures(
    Db& db, const SessionHistoryQuery& query) {
    const PageRequest page = normalize_page(query.page, query.page_size);
    const std::string where = auth_where(db, query);

    PagedResult<AuthFailure> result;
    result.page = page.page;
    result.page_size = page.page_size;

    const auto count_rows = db.query(
        "SELECT COUNT(*) FROM vpn_auth_log a "
        "LEFT JOIN vpn_users u ON u.username = a.username" +
        where);
    if (!count_rows.empty() && !count_rows[0].empty()) {
        result.total = parse_u64(count_rows[0][0]);
    }

    const std::uint64_t offset =
        static_cast<std::uint64_t>(page.page - 1) * page.page_size;
    result.items = load_auth_rows(db, query, page.page_size, offset);
    return result;
}

std::vector<HistorySession> export_session_history(
    Db& db, const SessionHistoryQuery& query, std::size_t max_rows) {
    const std::uint32_t limit = static_cast<std::uint32_t>(max_rows + 1);
    auto rows = load_session_rows(db, query, limit, 0);
    if (rows.size() > max_rows) {
        fail("too many rows to export, narrow the range");
    }
    return rows;
}

std::vector<AuthFailure> export_auth_failures(
    Db& db, const SessionHistoryQuery& query, std::size_t max_rows) {
    const std::uint32_t limit = static_cast<std::uint32_t>(max_rows + 1);
    auto rows = load_auth_rows(db, query, limit, 0);
    if (rows.size() > max_rows) {
        fail("too many rows to export, narrow the range");
    }
    return rows;
}

} // namespace vpn::service