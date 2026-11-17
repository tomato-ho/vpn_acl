#include "vpn/service/limits.h"

#include "vpn/service/errors.h"

#include <cstddef>
#include <string>

namespace vpn::service {
namespace {

[[noreturn]] void fail(const std::string& message) {
    throw ServiceError(ErrorCode::validation, message);
}

} // namespace

void ensure_rule_limits(Db& db, std::size_t maximum) {
    const auto rows = db.query(
        "SELECT u.username, "
        "((SELECT COUNT(*) FROM vpn_group_rules gr "
        "  WHERE gr.group_id = u.group_id AND gr.enabled = 1) + "
        " (SELECT COUNT(*) FROM vpn_user_rules ur "
        "  WHERE ur.username = u.username AND ur.enabled = 1)) AS rule_count "
        "FROM vpn_users u "
        "HAVING rule_count > " +
        std::to_string(maximum) + " ORDER BY u.username LIMIT 1");
    if (!rows.empty() && !rows[0].empty()) {
        fail("user " + rows[0][0] + " would exceed max_rules_per_user (" +
             std::to_string(maximum) + ")");
    }
}

void ensure_service_limits(Db& db, std::size_t maximum) {
    const auto rows = db.query(
        "SELECT u.username, "
        "(SELECT COUNT(DISTINCT s.service) FROM vpn_server_services s "
        " WHERE s.enabled = 1 AND ("
        "   s.scope_type = 'global' OR "
        "   (s.scope_type = 'group' AND s.scope_id = "
        "      (SELECT g.name FROM vpn_groups g WHERE g.id = u.group_id)) OR "
        "   (s.scope_type = 'user' AND s.scope_id = u.username))) AS service_count "
        "FROM vpn_users u "
        "HAVING service_count > " +
        std::to_string(maximum) + " ORDER BY u.username LIMIT 1");
    if (!rows.empty() && !rows[0].empty()) {
        fail("user " + rows[0][0] +
             " would exceed max_services_per_user (" +
             std::to_string(maximum) + ")");
    }
}

} // namespace vpn::service