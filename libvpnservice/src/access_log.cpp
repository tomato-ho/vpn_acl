#include "vpn/service/access_log.h"

#include "vpn/cidr.h"
#include "vpn/service/errors.h"
#include "vpn/util.h"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

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

std::string range_condition(const AccessLogQuery& query) {
    const std::string range = to_lower(query.range);
    if (range == "all") {
        return {};
    }
    if (range.empty() || range == "today") {
        return "last_seen >= CURDATE() AND last_seen < CURDATE() + INTERVAL 1 DAY";
    }
    if (range == "24h") {
        return "last_seen >= NOW() - INTERVAL 24 HOUR";
    }
    if (range == "7d") {
        return "last_seen >= NOW() - INTERVAL 7 DAY";
    }
    if (range == "30d") {
        return "last_seen >= NOW() - INTERVAL 30 DAY";
    }
    if (range == "90d") {
        return "last_seen >= NOW() - INTERVAL 90 DAY";
    }
    if (range == "180d") {
        return "last_seen >= NOW() - INTERVAL 180 DAY";
    }
    if (range != "custom") {
        fail("range must be all, today, 24h, 7d, 30d, 90d, 180d or custom");
    }

    const auto from = parse_date(query.from);
    const auto to = parse_date(query.to);
    if (!from || !to) {
        fail("custom range requires valid from and to dates");
    }
    if (*from > *to) {
        fail("from date is after to date");
    }
    if ((*to - *from) / 86400 > 366) {
        fail("custom range must not exceed 366 days");
    }
    return "last_seen >= '" + query.from + " 00:00:00' AND last_seen < DATE_ADD('" +
           query.to + " 00:00:00', INTERVAL 1 DAY)";
}

std::string where_clause(Db& db, const AccessLogQuery& query) {
    std::vector<std::string> parts;
    const std::string range = range_condition(query);
    if (!range.empty()) {
        parts.push_back(range);
    }
    if (!query.session_id.empty()) {
        parts.push_back("session_id = '" + db.quote(query.session_id) + "'");
    }
    if (!query.username.empty()) {
        parts.push_back("username LIKE '%" + db.quote(query.username) + "%'");
    }
    if (!query.action.empty()) {
        const std::string action = to_lower(query.action);
        if (action != "allow" && action != "deny") {
            fail("action must be allow or deny");
        }
        parts.push_back("action = '" + action + "'");
    }
    if (!query.dest_ip.empty()) {
        const auto ip = parse_ipv4(query.dest_ip);
        if (!ip) {
            fail("dest_ip must be a valid IPv4 address");
        }
        parts.push_back("dest_ip = '" + format_ipv4(*ip) + "'");
    }
    if (!query.dest_cidr.empty()) {
        const auto cidr = parse_cidr(query.dest_cidr);
        if (!cidr) {
            fail("dest_cidr must be a valid CIDR");
        }
        parts.push_back("INET_ATON(dest_ip) BETWEEN " +
                        std::to_string(cidr->start) + " AND " +
                        std::to_string(cidr->end));
    }
    if (parts.empty()) {
        return {};
    }
    std::string out = " WHERE ";
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out += " AND ";
        }
        out += parts[i];
    }
    return out;
}

std::vector<AccessLogRow> load_rows(Db& db,
                                    const std::string& where,
                                    std::uint32_t limit,
                                    std::uint64_t offset) {
    const auto rows = db.query(
        "SELECT id, session_id, username, virtual_ip, dest_ip, action, "
        "IFNULL(bytes_up, 0), IFNULL(bytes_down, 0), "
        "DATE_FORMAT(first_seen, '%Y-%m-%d %H:%i:%s'), "
        "DATE_FORMAT(last_seen, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_access_log" +
        where + " ORDER BY last_seen DESC, id DESC LIMIT " +
        std::to_string(limit) + " OFFSET " + std::to_string(offset));

    std::vector<AccessLogRow> items;
    items.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 10) {
            continue;
        }
        AccessLogRow item;
        item.id = parse_u64(row[0]);
        item.session_id = row[1];
        item.username = row[2];
        item.virtual_ip = row[3];
        item.dest_ip = row[4];
        item.action = row[5];
        item.bytes_up = parse_u64(row[6]);
        item.bytes_down = parse_u64(row[7]);
        item.first_seen = row[8];
        item.last_seen = row[9];
        items.push_back(item);
    }
    return items;
}

PageRequest normalize_page(std::uint32_t page, std::uint32_t page_size) {
    PageRequest result;
    result.page = std::max<std::uint32_t>(1, page);
    result.page_size = std::clamp<std::uint32_t>(page_size, 1, 200);
    return result;
}

} // namespace

PagedResult<AccessLogRow> query_access_log(Db& db,
                                           const AccessLogQuery& query) {
    const PageRequest page = normalize_page(query.page, query.page_size);
    const std::string where = where_clause(db, query);

    PagedResult<AccessLogRow> result;
    result.page = page.page;
    result.page_size = page.page_size;

    const auto count_rows =
        db.query("SELECT COUNT(*) FROM vpn_access_log" + where);
    if (!count_rows.empty() && !count_rows[0].empty()) {
        result.total = parse_u64(count_rows[0][0]);
    }
    const std::uint64_t offset =
        static_cast<std::uint64_t>(page.page - 1) * page.page_size;
    result.items = load_rows(db, where, page.page_size, offset);
    return result;
}

AccessLogStats query_access_log_stats(Db& db, const AccessLogQuery& query) {
    AccessLogStats stats;
    const std::string where = where_clause(db, query);
    const auto rows = db.query(
        "SELECT COUNT(*), COUNT(DISTINCT username), COUNT(DISTINCT dest_ip), "
        "IFNULL(SUM(bytes_up), 0), IFNULL(SUM(bytes_down), 0) "
        "FROM vpn_access_log" +
        where);
    if (!rows.empty() && rows[0].size() >= 5) {
        stats.records = parse_u64(rows[0][0]);
        stats.users = parse_u64(rows[0][1]);
        stats.targets = parse_u64(rows[0][2]);
        stats.bytes_up = parse_u64(rows[0][3]);
        stats.bytes_down = parse_u64(rows[0][4]);
    }
    return stats;
}

std::vector<AccessLogRow> export_access_log(Db& db,
                                            const AccessLogQuery& query,
                                            std::size_t max_rows) {
    const std::string where = where_clause(db, query);
    const auto limit = static_cast<std::uint32_t>(max_rows + 1);
    auto rows = load_rows(db, where, limit, 0);
    if (rows.size() > max_rows) {
        fail("too many rows to export, narrow the range");
    }
    return rows;
}

} // namespace vpn::service