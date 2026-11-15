#include "vpn/policy_store.h"

#include "vpn/cidr.h"
#include "vpn/parse.h"
#include "vpn/util.h"

#include <stdexcept>
#include <string>

namespace vpn {

ValidationConfig load_validation_config(Db& db) {
    ValidationConfig config;
    config.allowed_target_networks = {
        cidr_or_throw("10.0.0.0/8", "allowed target network"),
        cidr_or_throw("172.16.0.0/12", "allowed target network"),
        cidr_or_throw("192.168.0.0/16", "allowed target network"),
    };
    config.allowed_service_ips = {
        ip_or_throw("10.9.100.1", "allowed service IP"),
    };
    config.tunnel_network = cidr_or_throw("10.9.100.0/24", "tunnel network");
    config.has_tunnel_network = true;
    config.max_rules_per_user = 128;
    config.max_services_per_user = 16;

    const auto rows = db.query("SELECT name, value FROM vpn_settings");
    for (const auto& row : rows) {
        if (row.size() < 2) {
            continue;
        }
        if (row[0] == "allowed_target_networks") {
            config.allowed_target_networks.clear();
            for (const auto& part : split(row[1], ',')) {
                const std::string value = trim(part);
                if (!value.empty()) {
                    config.allowed_target_networks.push_back(
                        cidr_or_throw(value, "allowed target network"));
                }
            }
        } else if (row[0] == "allowed_service_ips") {
            config.allowed_service_ips.clear();
            for (const auto& part : split(row[1], ',')) {
                const std::string value = trim(part);
                if (!value.empty()) {
                    config.allowed_service_ips.push_back(
                        ip_or_throw(value, "allowed service IP"));
                }
            }
        } else if (row[0] == "tunnel_network") {
            config.tunnel_network = cidr_or_throw(row[1], "tunnel network");
            config.has_tunnel_network = true;
        } else if (row[0] == "max_rules_per_user") {
            config.max_rules_per_user = parse_u32_or_throw(row[1], "max rules");
        } else if (row[0] == "max_services_per_user") {
            config.max_services_per_user =
                parse_u32_or_throw(row[1], "max services");
        }
    }
    return config;
}

void ensure_cidr_allowed(const Cidr& cidr, const ValidationConfig& config) {
    if (config.allowed_target_networks.empty()) {
        return;
    }
    for (const auto& target : config.allowed_target_networks) {
        if (cidr_contains(target, cidr)) {
            return;
        }
    }
    throw ValidationError("CIDR " + cidr.to_string() +
                          " is outside allowed target networks");
}

void ensure_service_allowed(const Service& service,
                            const ValidationConfig& config) {
    if (config.allowed_service_ips.empty()) {
        return;
    }
    for (const std::uint32_t ip : config.allowed_service_ips) {
        if (ip == service.ip) {
            return;
        }
    }
    throw ValidationError("service IP is not allowed: " + format_ipv4(service.ip));
}

std::optional<GroupRow> find_group(Db& db, const std::string& name) {
    const auto rows = db.query(
        "SELECT id, name, ip_start, ip_end FROM vpn_groups WHERE name='" +
        db.quote(name) + "'");
    if (rows.empty() || rows[0].size() < 4) {
        return std::nullopt;
    }
    GroupRow group;
    group.id = parse_u32_or_throw(rows[0][0], "group id");
    group.name = rows[0][1];
    group.ip_start = ip_or_throw(rows[0][2], "group ip_start");
    group.ip_end = ip_or_throw(rows[0][3], "group ip_end");
    return group;
}

void bump_policy_version(Db& db) {
    db.execute(
        "UPDATE vpn_policy_version SET version = version + 1, updated_at = NOW() "
        "WHERE id = 1");
}

void write_audit(Db& db,
                 const std::string& action,
                 const std::string& target,
                 const std::string& after) {
    db.execute(
        "INSERT INTO vpn_audit_log (operator, action, target, after_json) VALUES "
        "('cli', '" + db.quote(action) + "', '" + db.quote(target) + "', '" +
        db.quote(after) + "')");
}

void write_audit_as(Db& db,
                    const std::string& operator_name,
                    const std::string& action,
                    const std::string& target,
                    const std::string& before,
                    const std::string& after) {
    const std::string before_sql =
        before.empty() ? "NULL" : "'" + db.quote(before) + "'";
    const std::string after_sql =
        after.empty() ? "NULL" : "'" + db.quote(after) + "'";
    db.execute(
        "INSERT INTO vpn_audit_log "
        "(operator, action, target, before_json, after_json) VALUES ('" +
        db.quote(operator_name) + "', '" + db.quote(action) + "', '" +
        db.quote(target) + "', " + before_sql + ", " + after_sql + ")");
}

PolicyData load_policy(Db& db, const std::string& username) {
    const auto rows = db.query(
        "SELECT u.username, u.display_name, IFNULL(u.group_id, 0), "
        "IFNULL(u.fixed_ip, ''), u.enabled, u.must_change_password, "
        "IFNULL(g.id, 0), IFNULL(g.name, ''), IFNULL(g.ip_start, ''), "
        "IFNULL(g.ip_end, ''), IFNULL(g.description, '') "
        "FROM vpn_users u LEFT JOIN vpn_groups g ON g.id = u.group_id "
        "WHERE u.username = '" + db.quote(username) + "'");
    if (rows.empty() || rows[0].size() < 11) {
        throw std::runtime_error("user not found: " + username);
    }

    const auto& row = rows[0];
    PolicyData data;
    data.user.username = row[0];
    data.user.display_name = row[1];
    data.user.group_id = parse_u32_or_throw(row[2], "group id");
    if (!row[3].empty()) {
        data.user.fixed_ip = ip_or_throw(row[3], "fixed IP");
        data.user.has_fixed_ip = true;
    }
    data.user.enabled = parse_bool(row[4], false);
    data.user.must_change_password = parse_bool(row[5], false);

    data.group.id = parse_u32_or_throw(row[6], "group id");
    data.group.name = row[7];
    if (!row[8].empty()) {
        data.group.ip_start = ip_or_throw(row[8], "group ip_start");
    }
    if (!row[9].empty()) {
        data.group.ip_end = ip_or_throw(row[9], "group ip_end");
    }
    data.group.description = row[10];
    data.user.group_name = data.group.name;

    const auto group_rules = db.query(
        "SELECT rule_type, cidr, enabled FROM vpn_group_rules "
        "WHERE group_id = " + std::to_string(data.group.id));
    for (const auto& rule_row : group_rules) {
        Rule rule;
        rule.type = rule_type_or_throw(rule_row[0]);
        rule.cidr = cidr_or_throw(rule_row[1], "group rule CIDR");
        rule.enabled = parse_bool(rule_row[2], true);
        data.group_rules.push_back(rule);
    }

    const auto user_rules = db.query(
        "SELECT rule_type, cidr, enabled FROM vpn_user_rules "
        "WHERE username = '" + db.quote(username) + "'");
    for (const auto& rule_row : user_rules) {
        Rule rule;
        rule.type = rule_type_or_throw(rule_row[0]);
        rule.cidr = cidr_or_throw(rule_row[1], "user rule CIDR");
        rule.enabled = parse_bool(rule_row[2], true);
        data.user_rules.push_back(rule);
    }

    const auto services = db.query(
        "SELECT scope_type, scope_id, service, enabled FROM vpn_server_services "
        "WHERE enabled = 1 AND (scope_type = 'global' OR "
        "(scope_type = 'group' AND scope_id = '" + db.quote(data.group.name) +
        "') OR (scope_type = 'user' AND scope_id = '" + db.quote(username) +
        "'))");
    for (const auto& service_row : services) {
        const auto service = parse_service(service_row[2]);
        if (!service) {
            throw std::runtime_error("invalid service in database: " +
                                     service_row[2]);
        }
        ServiceRule rule;
        rule.scope_type = service_row[0];
        rule.scope_id = service_row[1];
        rule.service = *service;
        rule.enabled = parse_bool(service_row[3], true);
        data.services.push_back(rule);
    }

    return data;
}

} // namespace vpn