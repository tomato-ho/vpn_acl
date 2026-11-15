#include "vpn/service/metrics_read.h"

#include "history_source.h"
#include "vpn/service/errors.h"

#include <algorithm>
#include <cstdint>
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

std::string resolve_range(const std::string& value) {
    if (value.empty() || value == "24h") {
        return "24 HOUR";
    }
    if (value == "1h") {
        return "1 HOUR";
    }
    if (value == "6h") {
        return "6 HOUR";
    }
    if (value == "7d") {
        return "7 DAY";
    }
    if (value == "30d") {
        return "30 DAY";
    }
    fail("range must be 1h, 6h, 24h, 7d or 30d");
}

std::uint64_t resolve_step(const std::string& value,
                           const std::string& range) {
    if (value.empty()) {
        return range == "7d" || range == "30d" ? 86400 : 3600;
    }
    if (value == "5m") {
        return 300;
    }
    if (value == "1h") {
        return 3600;
    }
    if (value == "1d") {
        return 86400;
    }
    fail("step must be 5m, 1h or 1d");
}

} // namespace

MetricsHistory load_metrics_history(Db& db,
                                    const std::string& range,
                                    const std::string& step) {
    const std::string interval = resolve_range(range);
    const std::uint64_t seconds = resolve_step(step, range);

    MetricsHistory history;

    const auto auth_rows = db.query(
        "SELECT FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(created_at)/" +
        std::to_string(seconds) + ")*" + std::to_string(seconds) +
        ") AS bucket, "
        "IFNULL(SUM(success = 1), 0), "
        "IFNULL(SUM(success = 0), 0) "
        "FROM vpn_auth_log WHERE created_at >= NOW() - INTERVAL " + interval +
        " GROUP BY bucket ORDER BY bucket");
    for (const auto& row : auth_rows) {
        if (row.size() < 3 || row[0].empty()) {
            continue;
        }
        AuthHistoryPoint point;
        point.bucket = row[0];
        point.accept = parse_u64(row[1]);
        point.reject = parse_u64(row[2]);
        history.auth.push_back(point);
    }

    const auto session_rows = db.query(
        "SELECT FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(r.start_time)/" +
        std::to_string(seconds) + ")*" + std::to_string(seconds) +
        ") AS bucket, "
        "COUNT(*), IFNULL(SUM(r.is_open = 0), 0), "
        "IFNULL(SUM(r.duration_seconds), 0), "
        "IFNULL(SUM(r.bytes_in), 0), "
        "IFNULL(SUM(r.bytes_out), 0) "
        "FROM " + detail::history_source() +
        " WHERE r.start_time >= NOW() - INTERVAL " + interval +
        " GROUP BY bucket ORDER BY bucket");
    for (const auto& row : session_rows) {
        if (row.size() < 6 || row[0].empty()) {
            continue;
        }
        SessionHistoryPoint point;
        point.bucket = row[0];
        point.started = parse_u64(row[1]);
        point.stopped = parse_u64(row[2]);
        point.session_time = parse_u64(row[3]);
        point.bytes_in = parse_u64(row[4]);
        point.bytes_out = parse_u64(row[5]);
        history.sessions.push_back(point);
    }

    return history;
}

std::vector<TopUser> load_top_users(Db& db,
                                    const std::string& range,
                                    std::uint32_t limit,
                                    bool include_deleted) {
    const std::string interval = resolve_range(range);
    const std::uint32_t normalized_limit =
        std::clamp<std::uint32_t>(limit, 1, 100);

    std::string where = " WHERE r.start_time >= NOW() - INTERVAL " + interval;
    if (!include_deleted) {
        where += " AND u.username IS NOT NULL";
    }

    const auto rows = db.query(
        "SELECT r.username, COUNT(*), "
        "IFNULL(SUM(r.bytes_in), 0), "
        "IFNULL(SUM(r.bytes_out), 0), "
        "IFNULL(SUM(r.duration_seconds), 0), "
        "IFNULL(MAX(u.username IS NOT NULL), 0) "
        "FROM " + detail::history_source() +
        " LEFT JOIN vpn_users u ON u.username = r.username" + where +
        " GROUP BY r.username "
        "ORDER BY (IFNULL(SUM(r.bytes_in), 0) + "
        "IFNULL(SUM(r.bytes_out), 0)) DESC LIMIT " +
        std::to_string(normalized_limit));

    std::vector<TopUser> users;
    users.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 6) {
            continue;
        }
        TopUser user;
        user.username = row[0];
        user.sessions = parse_u64(row[1]);
        user.bytes_in = parse_u64(row[2]);
        user.bytes_out = parse_u64(row[3]);
        user.session_time = parse_u64(row[4]);
        user.user_exists = parse_u64(row[5]) != 0;
        users.push_back(user);
    }
    return users;
}

} // namespace vpn::service