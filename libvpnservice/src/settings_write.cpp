#include "vpn/service/settings_write.h"

#include "vpn/cidr.h"
#include "vpn/parse.h"
#include "vpn/policy_store.h"
#include "vpn/service/errors.h"
#include "vpn/service/transaction.h"
#include "vpn/util.h"
#include "vpn/validation.h"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace vpn::service {
namespace {

using json = nlohmann::json;

constexpr const char* kAllowedTargets = "allowed_target_networks";
constexpr const char* kAllowedServiceIps = "allowed_service_ips";
constexpr const char* kTunnelNetwork = "tunnel_network";
constexpr const char* kMaxRules = "max_rules_per_user";
constexpr const char* kMaxServices = "max_services_per_user";

[[noreturn]] void fail(ErrorCode code, const std::string& message) {
    throw ServiceError(code, message);
}

std::string get_value(const SettingsMap& settings,
                      const std::string& key,
                      const std::string& fallback) {
    const auto found = settings.find(key);
    return found == settings.end() ? fallback : found->second;
}

std::vector<Cidr> parse_cidr_list(const std::string& value,
                                  const std::string& label) {
    std::vector<Cidr> result;
    for (const auto& part : split(value, ',')) {
        const std::string item = trim(part);
        if (item.empty()) {
            continue;
        }
        try {
            result.push_back(cidr_or_throw(item, label));
        } catch (const std::exception& error) {
            fail(ErrorCode::validation, error.what());
        }
    }
    if (result.empty()) {
        fail(ErrorCode::validation, label + " must not be empty");
    }
    return result;
}

std::vector<std::uint32_t> parse_ip_list(const std::string& value,
                                         const std::string& label) {
    std::vector<std::uint32_t> result;
    for (const auto& part : split(value, ',')) {
        const std::string item = trim(part);
        if (item.empty()) {
            continue;
        }
        try {
            result.push_back(ip_or_throw(item, label));
        } catch (const std::exception& error) {
            fail(ErrorCode::validation, error.what());
        }
    }
    if (result.empty()) {
        fail(ErrorCode::validation, label + " must not be empty");
    }
    return result;
}

std::string join_cidrs(const std::vector<Cidr>& cidrs) {
    std::string output;
    for (const auto& cidr : cidrs) {
        if (!output.empty()) {
            output += ',';
        }
        output += cidr.to_string();
    }
    return output;
}

std::string join_ips(const std::vector<std::uint32_t>& ips) {
    std::string output;
    for (const auto ip : ips) {
        if (!output.empty()) {
            output += ',';
        }
        output += format_ipv4(ip);
    }
    return output;
}

std::string normalize_positive(const std::string& value,
                               const std::string& label) {
    std::uint32_t parsed = 0;
    try {
        parsed = parse_u32_or_throw(value, label);
    } catch (const std::exception& error) {
        fail(ErrorCode::validation, error.what());
    }
    if (parsed == 0 || parsed > 100000) {
        fail(ErrorCode::validation, label + " is out of range");
    }
    return std::to_string(parsed);
}

bool cidr_allowed(const Cidr& cidr, const std::vector<Cidr>& allowed) {
    for (const auto& target : allowed) {
        if (cidr_contains(target, cidr)) {
            return true;
        }
    }
    return false;
}

void validate_tunnel_network(Db& db, const Cidr& tunnel) {
    const auto groups = db.query(
        "SELECT name, ip_start, ip_end FROM vpn_groups");
    for (const auto& row : groups) {
        if (row.size() < 3) {
            continue;
        }
        std::uint32_t start = 0;
        std::uint32_t end = 0;
        try {
            start = ip_or_throw(row[1], "group ip_start");
            end = ip_or_throw(row[2], "group ip_end");
        } catch (const std::exception& error) {
            fail(ErrorCode::validation, error.what());
        }
        if (!cidr_contains(tunnel, start) || !cidr_contains(tunnel, end)) {
            fail(ErrorCode::conflict,
                 "group " + row[0] +
                     " is outside the new tunnel network");
        }
        if (is_reserved_tunnel_address(tunnel, start) ||
            is_reserved_tunnel_address(tunnel, end)) {
            fail(ErrorCode::conflict,
                 "group " + row[0] +
                     " uses a network/broadcast/gateway address");
        }
    }

    const auto users = db.query(
        "SELECT username, IFNULL(fixed_ip, '') FROM vpn_users");
    for (const auto& row : users) {
        if (row.size() < 2 || row[1].empty()) {
            continue;
        }
        std::uint32_t fixed_ip = 0;
        try {
            fixed_ip = ip_or_throw(row[1], "fixed IP");
        } catch (const std::exception& error) {
            fail(ErrorCode::validation, error.what());
        }
        if (!cidr_contains(tunnel, fixed_ip)) {
            fail(ErrorCode::conflict,
                 "user " + row[0] +
                     " fixed IP is outside the new tunnel network");
        }
        if (is_reserved_tunnel_address(tunnel, fixed_ip)) {
            fail(ErrorCode::conflict,
                 "user " + row[0] +
                     " fixed IP is a reserved tunnel address");
        }
    }
}

void validate_allowed_targets(Db& db, const std::vector<Cidr>& allowed) {
    const auto rows = db.query(
        "SELECT cidr FROM vpn_group_rules "
        "UNION SELECT cidr FROM vpn_user_rules");
    for (const auto& row : rows) {
        if (row.empty()) {
            continue;
        }
        Cidr cidr;
        try {
            cidr = cidr_or_throw(row[0], "rule CIDR");
        } catch (const std::exception& error) {
            fail(ErrorCode::validation, error.what());
        }
        if (!cidr_allowed(cidr, allowed)) {
            fail(ErrorCode::conflict,
                 "existing rule " + cidr.to_string() +
                     " is outside the new allowed target networks");
        }
    }
}

void validate_allowed_services(Db& db,
                               const std::vector<std::uint32_t>& allowed) {
    const auto rows = db.query("SELECT service FROM vpn_server_services");
    for (const auto& row : rows) {
        if (row.empty()) {
            continue;
        }
        const auto service = parse_service(row[0]);
        if (!service) {
            fail(ErrorCode::validation,
                 "invalid service in database: " + row[0]);
        }
        bool found = false;
        for (const auto ip : allowed) {
            if (ip == service->ip) {
                found = true;
                break;
            }
        }
        if (!found) {
            fail(ErrorCode::conflict,
                 "existing service " + service->to_string() +
                     " is outside the new allowed service IPs");
        }
    }
}

void validate_max_services(Db& db, std::uint32_t maximum) {
    const auto rows = db.query(
        "SELECT u.username, COUNT(DISTINCT s.service) "
        "FROM vpn_users u "
        "LEFT JOIN vpn_groups g ON g.id = u.group_id "
        "LEFT JOIN vpn_server_services s ON s.enabled = 1 AND "
        "(s.scope_type = 'global' OR "
        " (s.scope_type = 'group' AND s.scope_id = g.name) OR "
        " (s.scope_type = 'user' AND s.scope_id = u.username)) "
        "GROUP BY u.username");
    for (const auto& row : rows) {
        if (row.size() < 2) {
            continue;
        }
        try {
            if (std::stoull(row[1]) > maximum) {
                fail(ErrorCode::conflict,
                     "user " + row[0] +
                         " has more services than the new maximum");
            }
        } catch (const ServiceError&) {
            throw;
        } catch (const std::exception&) {
        }
    }
}

void validate_max_rules(Db& db, std::uint32_t maximum) {
    const auto rows = db.query(
        "SELECT u.username, "
        "(SELECT COUNT(*) FROM vpn_group_rules gr "
        " WHERE gr.group_id = u.group_id AND gr.enabled = 1) + "
        "(SELECT COUNT(*) FROM vpn_user_rules ur "
        " WHERE ur.username = u.username AND ur.enabled = 1) "
        "FROM vpn_users u");
    for (const auto& row : rows) {
        if (row.size() < 2) {
            continue;
        }
        try {
            if (std::stoull(row[1]) > maximum) {
                fail(ErrorCode::conflict,
                     "user " + row[0] +
                         " has more rules than the new maximum");
            }
        } catch (const ServiceError&) {
            throw;
        } catch (const std::exception&) {
        }
    }
}

} // namespace

SettingsMap load_settings(Db& db) {
    SettingsMap settings;
    const auto rows = db.query(
        "SELECT name, value FROM vpn_settings ORDER BY name");
    for (const auto& row : rows) {
        if (row.size() >= 2) {
            settings[row[0]] = row[1];
        }
    }
    return settings;
}

SettingsMap update_settings(Db& db,
                            const UpdateSettingsInput& input,
                            const std::string& operator_name) {
    if (!input.allowed_target_networks && !input.allowed_service_ips &&
        !input.tunnel_network && !input.max_rules_per_user &&
        !input.max_services_per_user) {
        fail(ErrorCode::validation, "no fields to update");
    }

    SettingsMap current = load_settings(db);
    SettingsMap next = current;

    if (input.allowed_target_networks) {
        next[kAllowedTargets] =
            join_cidrs(parse_cidr_list(*input.allowed_target_networks,
                                       "allowed_target_networks"));
    }
    if (input.allowed_service_ips) {
        next[kAllowedServiceIps] =
            join_ips(parse_ip_list(*input.allowed_service_ips,
                                   "allowed_service_ips"));
    }
    if (input.tunnel_network) {
        try {
            next[kTunnelNetwork] =
                cidr_or_throw(*input.tunnel_network, "tunnel_network")
                    .to_string();
        } catch (const std::exception& error) {
            fail(ErrorCode::validation, error.what());
        }
    }
    if (input.max_rules_per_user) {
        next[kMaxRules] =
            normalize_positive(*input.max_rules_per_user,
                               "max_rules_per_user");
    }
    if (input.max_services_per_user) {
        next[kMaxServices] =
            normalize_positive(*input.max_services_per_user,
                               "max_services_per_user");
    }

    ValidationConfig validation;
    validation.allowed_target_networks =
        parse_cidr_list(get_value(next, kAllowedTargets, ""),
                        "allowed_target_networks");
    validation.allowed_service_ips =
        parse_ip_list(get_value(next, kAllowedServiceIps, ""),
                      "allowed_service_ips");
    try {
        validation.tunnel_network = cidr_or_throw(
            get_value(next, kTunnelNetwork, "10.9.100.0/24"),
            "tunnel_network");
    } catch (const std::exception& error) {
        fail(ErrorCode::validation, error.what());
    }
    validation.has_tunnel_network = true;
    validation.max_rules_per_user = static_cast<std::size_t>(
        parse_u32_or_throw(get_value(next, kMaxRules, "128"),
                           "max_rules_per_user"));
    validation.max_services_per_user = static_cast<std::size_t>(
        parse_u32_or_throw(get_value(next, kMaxServices, "16"),
                           "max_services_per_user"));

    validate_tunnel_network(db, validation.tunnel_network);
    validate_allowed_targets(db, validation.allowed_target_networks);
    validate_allowed_services(db, validation.allowed_service_ips);
    validate_max_rules(db, static_cast<std::uint32_t>(
                               validation.max_rules_per_user));
    validate_max_services(db, static_cast<std::uint32_t>(
                                  validation.max_services_per_user));

    try {
        Transaction tx(db);
        for (const auto& entry : next) {
            db.execute(
                "INSERT INTO vpn_settings (name, value) VALUES ('" +
                db.quote(entry.first) + "', '" + db.quote(entry.second) +
                "') ON DUPLICATE KEY UPDATE value = VALUES(value)");
        }
        write_audit_as(db, operator_name, "settings-update", "vpn_settings",
                       json(current).dump(), json(next).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception&) {
        throw;
    }

    return next;
}

} // namespace vpn::service