#include "vpn/service/group_write.h"

#include "vpn/cidr.h"
#include "vpn/parse.h"
#include "vpn/policy_store.h"
#include "vpn/service/errors.h"
#include "vpn/service/limits.h"
#include "vpn/service/transaction.h"
#include "vpn/util.h"
#include "vpn/validation.h"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vpn::service {
namespace {

using json = nlohmann::json;

[[noreturn]] void fail(ErrorCode code, const std::string& message) {
    throw ServiceError(code, message);
}

std::uint32_t parse_u32_value(const std::string& value) {
    try {
        return parse_u32_or_throw(value, "value");
    } catch (const std::exception&) {
        return 0;
    }
}

json group_json(const GroupSummary& group) {
    return json{{"id", group.id},
                {"name", group.name},
                {"ip_start", group.ip_start},
                {"ip_end", group.ip_end},
                {"description", group.description}};
}

json rule_json(const GroupRule& rule) {
    return json{{"id", rule.id},
                {"rule_type", rule.rule_type},
                {"cidr", rule.cidr},
                {"enabled", rule.enabled}};
}

std::string rule_type_name(RuleType type) {
    return type == RuleType::Allow ? "allow" : "deny";
}

RuleType parse_rule_type(const std::string& value) {
    try {
        return rule_type_or_throw(value);
    } catch (const std::exception&) {
        fail(ErrorCode::validation, "rule_type must be allow or deny");
    }
}

void validate_name(const std::string& value) {
    if (value.empty() || value.size() > 64) {
        fail(ErrorCode::validation, "group name must be 1-64 bytes");
    }
}

void validate_description(const std::string& value) {
    if (value.size() > 255) {
        fail(ErrorCode::validation, "description is too long");
    }
}

std::pair<std::string, std::string> validate_range(
    const std::string& start_text,
    const std::string& end_text,
    const ValidationConfig& config) {
    std::uint32_t start = 0;
    std::uint32_t end = 0;
    try {
        start = ip_or_throw(start_text, "group ip_start");
        end = ip_or_throw(end_text, "group ip_end");
    } catch (const std::exception& error) {
        fail(ErrorCode::validation, error.what());
    }
    if (start > end) {
        fail(ErrorCode::validation, "group IP range start is after end");
    }
    if (config.has_tunnel_network &&
        (!cidr_contains(config.tunnel_network, start) ||
         !cidr_contains(config.tunnel_network, end))) {
        fail(ErrorCode::validation,
             "group IP range is outside the tunnel network");
    }
    if (config.has_tunnel_network &&
        (is_reserved_tunnel_address(config.tunnel_network, start) ||
         is_reserved_tunnel_address(config.tunnel_network, end))) {
        fail(ErrorCode::validation,
             "group IP range must not use network/broadcast/gateway addresses");
    }
    return {format_ipv4(start), format_ipv4(end)};
}

std::optional<GroupSummary> get_group_summary(Db& db, std::uint32_t group_id) {
    const auto rows = db.query(
        "SELECT g.id, g.name, g.ip_start, g.ip_end, g.description, "
        "(SELECT COUNT(*) FROM vpn_users u WHERE u.group_id = g.id), "
        "(SELECT COUNT(*) FROM vpn_group_rules r WHERE r.group_id = g.id) "
        "FROM vpn_groups g WHERE g.id = " +
        std::to_string(group_id));
    if (rows.empty() || rows[0].size() < 7) {
        return std::nullopt;
    }
    GroupSummary group;
    group.id = parse_u32_value(rows[0][0]);
    group.name = rows[0][1];
    group.ip_start = rows[0][2];
    group.ip_end = rows[0][3];
    group.description = rows[0][4];
    group.user_count = 0;
    group.rule_count = 0;
    try {
        group.user_count = std::stoull(rows[0][5]);
        group.rule_count = std::stoull(rows[0][6]);
    } catch (const std::exception&) {
    }
    return group;
}

bool group_name_exists(Db& db,
                       const std::string& name,
                       std::uint32_t exclude_id) {
    std::string sql = "SELECT 1 FROM vpn_groups WHERE name = '" +
                      db.quote(name) + "'";
    if (exclude_id != 0) {
        sql += " AND id <> " + std::to_string(exclude_id);
    }
    return !db.query(sql).empty();
}

std::vector<GroupRule> load_rules(Db& db, std::uint32_t group_id) {
    const auto rows = db.query(
        "SELECT id, rule_type, cidr, enabled, "
        "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_group_rules WHERE group_id = " +
        std::to_string(group_id) + " ORDER BY id");
    std::vector<GroupRule> rules;
    rules.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 5) {
            continue;
        }
        GroupRule rule;
        rule.id = parse_u32_value(row[0]);
        rule.rule_type = row[1];
        rule.cidr = row[2];
        rule.enabled = parse_bool(row[3], true);
        rule.created_at = row[4];
        rules.push_back(rule);
    }
    return rules;
}

void ensure_users_fit_range(Db& db,
                            std::uint32_t group_id,
                            const std::string& ip_start,
                            const std::string& ip_end,
                            const ValidationConfig& config) {
    const std::uint32_t start = ip_or_throw(ip_start, "group ip_start");
    const std::uint32_t end = ip_or_throw(ip_end, "group ip_end");
    const auto users = db.query(
        "SELECT username, IFNULL(fixed_ip, '') FROM vpn_users "
        "WHERE group_id = " +
        std::to_string(group_id));
    for (const auto& row : users) {
        if (row.size() < 2 || row[1].empty()) {
            continue;
        }
        std::uint32_t fixed_ip = 0;
        try {
            fixed_ip = ip_or_throw(row[1], "fixed IP");
        } catch (const std::exception&) {
            fail(ErrorCode::conflict,
                 "user " + row[0] + " has an invalid fixed IP");
        }
        if (fixed_ip < start || fixed_ip > end) {
            fail(ErrorCode::conflict,
                 "user " + row[0] +
                     " fixed IP is outside the new group range");
        }
        if (config.has_tunnel_network &&
            !cidr_contains(config.tunnel_network, fixed_ip)) {
            fail(ErrorCode::conflict,
                 "user " + row[0] +
                     " fixed IP is outside the tunnel network");
        }
    }
}

void throw_duplicate(const std::exception& error,
                     const std::string& message) {
    if (std::string(error.what()).find("Duplicate entry") !=
        std::string::npos) {
        fail(ErrorCode::conflict, message);
    }
    throw;
}

} // namespace

GroupSummary create_group(Db& db,
                          const CreateGroupInput& input,
                          const std::string& operator_name) {
    validate_name(input.name);
    validate_description(input.description);
    const auto validation = load_validation_config(db);
    const auto range =
        validate_range(input.ip_start, input.ip_end, validation);

    if (group_name_exists(db, input.name, 0)) {
        fail(ErrorCode::conflict, "group name already exists");
    }

    GroupSummary group;
    group.name = input.name;
    group.ip_start = range.first;
    group.ip_end = range.second;
    group.description = input.description;

    try {
        Transaction tx(db);
        db.execute(
            "INSERT INTO vpn_groups (name, ip_start, ip_end, description) "
            "VALUES ('" +
            db.quote(input.name) + "', '" + range.first + "', '" +
            range.second + "', '" + db.quote(input.description) + "')");
        group.id = static_cast<std::uint32_t>(db.last_insert_id());
        write_audit_as(db, operator_name, "group-create", input.name, "",
                       group_json(group).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "group name already exists");
    }
    return group;
}

GroupSummary update_group(Db& db,
                          std::uint32_t group_id,
                          const UpdateGroupInput& input,
                          const std::string& operator_name) {
    const auto current = get_group_summary(db, group_id);
    if (!current) {
        fail(ErrorCode::not_found, "group not found");
    }
    if (!input.name && !input.ip_start && !input.ip_end &&
        !input.description) {
        fail(ErrorCode::validation, "no fields to update");
    }

    const std::string name = input.name.value_or(current->name);
    const std::string start_text =
        input.ip_start.value_or(current->ip_start);
    const std::string end_text = input.ip_end.value_or(current->ip_end);
    const std::string description =
        input.description.value_or(current->description);

    validate_name(name);
    validate_description(description);
    const auto validation = load_validation_config(db);
    const auto range = validate_range(start_text, end_text, validation);

    if (name != current->name && group_name_exists(db, name, group_id)) {
        fail(ErrorCode::conflict, "group name already exists");
    }
    if (range.first != current->ip_start || range.second != current->ip_end) {
        ensure_users_fit_range(db, group_id, range.first, range.second,
                               validation);
    }

    GroupSummary after = *current;
    after.name = name;
    after.ip_start = range.first;
    after.ip_end = range.second;
    after.description = description;

    try {
        Transaction tx(db);
        if (name != current->name) {
            db.execute(
                "UPDATE vpn_server_services SET scope_id = '" + db.quote(name) +
                "' WHERE scope_type = 'group' AND scope_id = '" +
                db.quote(current->name) + "'");
        }
        db.execute(
            "UPDATE vpn_groups SET name = '" + db.quote(name) +
            "', ip_start = '" + range.first + "', ip_end = '" +
            range.second + "', description = '" + db.quote(description) +
            "' WHERE id = " + std::to_string(group_id));
        write_audit_as(db, operator_name, "group-update", std::to_string(group_id),
                       group_json(*current).dump(), group_json(after).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "group name already exists");
    }

    const auto updated = get_group_summary(db, group_id);
    return updated ? *updated : after;
}

void delete_group(Db& db,
                  std::uint32_t group_id,
                  const std::string& operator_name) {
    const auto current = get_group_summary(db, group_id);
    if (!current) {
        fail(ErrorCode::not_found, "group not found");
    }
    if (current->user_count > 0) {
        fail(ErrorCode::conflict,
             "group still has users, move or delete them first");
    }

    try {
        Transaction tx(db);
        db.execute(
            "DELETE FROM vpn_server_services WHERE scope_type = 'group' "
            "AND scope_id = '" +
            db.quote(current->name) + "'");
        db.execute("DELETE FROM vpn_groups WHERE id = " +
                   std::to_string(group_id));
        write_audit_as(db, operator_name, "group-delete",
                       std::to_string(group_id), group_json(*current).dump(),
                       json{{"deleted", true}}.dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "failed to delete group");
    }
}

std::optional<GroupDetail> get_group_detail(Db& db, std::uint32_t group_id) {
    const auto group = get_group_summary(db, group_id);
    if (!group) {
        return std::nullopt;
    }
    GroupDetail detail;
    detail.group = *group;
    detail.rules = load_rules(db, group_id);
    return detail;
}

std::vector<GroupRule> list_group_rules(Db& db, std::uint32_t group_id) {
    if (!get_group_summary(db, group_id)) {
        fail(ErrorCode::not_found, "group not found");
    }
    return load_rules(db, group_id);
}

GroupRule add_group_rule(Db& db,
                         std::uint32_t group_id,
                         const GroupRuleInput& input,
                         const std::string& operator_name) {
    const auto group = get_group_summary(db, group_id);
    if (!group) {
        fail(ErrorCode::not_found, "group not found");
    }

    const RuleType type = parse_rule_type(input.rule_type);
    Cidr cidr;
    try {
        cidr = cidr_or_throw(input.cidr, "CIDR");
    } catch (const std::exception& error) {
        fail(ErrorCode::validation, error.what());
    }

    const auto validation = load_validation_config(db);
    try {
        ensure_cidr_allowed(cidr, validation);
    } catch (const std::exception& error) {
        fail(ErrorCode::validation, error.what());
    }

    const auto duplicate = db.query(
        "SELECT 1 FROM vpn_group_rules WHERE group_id = " +
        std::to_string(group_id) + " AND rule_type = '" +
        rule_type_name(type) + "' AND cidr = '" + cidr.to_string() + "'");
    if (!duplicate.empty()) {
        fail(ErrorCode::conflict, "rule already exists");
    }

    GroupRule rule;
    rule.rule_type = rule_type_name(type);
    rule.cidr = cidr.to_string();
    rule.enabled = input.enabled;

    try {
        Transaction tx(db);
        db.execute(
            "INSERT INTO vpn_group_rules "
            "(group_id, rule_type, cidr, enabled) VALUES (" +
            std::to_string(group_id) + ", '" + rule.rule_type + "', '" +
            rule.cidr + "', " + (input.enabled ? "1" : "0") + ")");
        rule.id = static_cast<std::uint32_t>(db.last_insert_id());
        ensure_rule_limits(db, validation.max_rules_per_user);
        write_audit_as(db, operator_name, "group-rule-add",
                       std::to_string(group_id), "", rule_json(rule).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "rule already exists");
    }
    return rule;
}

GroupRule update_group_rule(Db& db,
                            std::uint32_t group_id,
                            std::uint32_t rule_id,
                            bool enabled,
                            const std::string& operator_name) {
    const auto rows = db.query(
        "SELECT id, rule_type, cidr, enabled, "
        "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_group_rules WHERE id = " +
        std::to_string(rule_id) + " AND group_id = " +
        std::to_string(group_id));
    if (rows.empty()) {
        fail(ErrorCode::not_found, "rule not found");
    }

    GroupRule before;
    before.id = rule_id;
    if (rows[0].size() >= 5) {
        before.rule_type = rows[0][1];
        before.cidr = rows[0][2];
        before.enabled = parse_bool(rows[0][3], true);
        before.created_at = rows[0][4];
    }
    if (before.enabled == enabled) {
        return before;
    }

    GroupRule after = before;
    after.enabled = enabled;

    Transaction tx(db);
    db.execute(
        "UPDATE vpn_group_rules SET enabled = " +
        std::string(enabled ? "1" : "0") + " WHERE id = " +
        std::to_string(rule_id) + " AND group_id = " +
        std::to_string(group_id));
    if (enabled) {
        const auto validation = load_validation_config(db);
        ensure_rule_limits(db, validation.max_rules_per_user);
    }
    write_audit_as(db, operator_name, "group-rule-update",
                   std::to_string(group_id), rule_json(before).dump(),
                   rule_json(after).dump());
    bump_policy_version(db);
    tx.commit();
    return after;
}

void delete_group_rule(Db& db,
                       std::uint32_t group_id,
                       std::uint32_t rule_id,
                       const std::string& operator_name) {
    const auto rows = db.query(
        "SELECT id, rule_type, cidr, enabled FROM vpn_group_rules "
        "WHERE id = " + std::to_string(rule_id) + " AND group_id = " +
        std::to_string(group_id));
    if (rows.empty()) {
        fail(ErrorCode::not_found, "rule not found");
    }

    GroupRule rule;
    rule.id = rule_id;
    if (rows[0].size() >= 4) {
        rule.rule_type = rows[0][1];
        rule.cidr = rows[0][2];
        rule.enabled = parse_bool(rows[0][3], true);
    }

    Transaction tx(db);
    db.execute("DELETE FROM vpn_group_rules WHERE id = " +
               std::to_string(rule_id) + " AND group_id = " +
               std::to_string(group_id));
    write_audit_as(db, operator_name, "group-rule-delete",
                   std::to_string(group_id), rule_json(rule).dump(), "");
    bump_policy_version(db);
    tx.commit();
}

} // namespace vpn::service