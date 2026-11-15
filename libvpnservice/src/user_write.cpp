#include "vpn/service/user_write.h"

#include "vpn/cidr.h"
#include "vpn/parse.h"
#include "vpn/password.h"
#include "vpn/policy_store.h"
#include "vpn/service/errors.h"
#include "vpn/service/transaction.h"
#include "vpn/util.h"
#include "vpn/validation.h"

#include <nlohmann/json.hpp>

#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
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

json user_json(const UserSummary& user) {
    return json{{"username", user.username},
                {"display_name", user.display_name},
                {"group", user.group_name},
                {"fixed_ip", user.fixed_ip},
                {"enabled", user.enabled},
                {"must_change_password", user.must_change_password}};
}

json rule_json(const UserRule& rule) {
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

void validate_display_name(const std::string& value) {
    if (value.size() > 128) {
        fail(ErrorCode::validation, "display_name is too long");
    }
}

void validate_password(const std::string& value) {
    if (value.size() < 8 || value.size() > 256) {
        fail(ErrorCode::validation, "password must be 8-256 bytes");
    }
}

GroupRow require_group(Db& db, const std::string& name) {
    const auto group = find_group(db, name);
    if (!group) {
        fail(ErrorCode::validation, "group not found: " + name);
    }
    return *group;
}

std::string validate_fixed_ip(const std::string& value,
                              const GroupRow& group,
                              const ValidationConfig& config) {
    std::uint32_t fixed_ip = 0;
    try {
        fixed_ip = ip_or_throw(value, "fixed IP");
    } catch (const std::exception& error) {
        fail(ErrorCode::validation, error.what());
    }
    if (fixed_ip < group.ip_start || fixed_ip > group.ip_end) {
        fail(ErrorCode::validation,
             "fixed IP is outside the group IP range");
    }
    if (config.has_tunnel_network &&
        !cidr_contains(config.tunnel_network, fixed_ip)) {
        fail(ErrorCode::validation,
             "fixed IP is outside the tunnel network");
    }
    return format_ipv4(fixed_ip);
}

bool user_exists(Db& db, const std::string& username) {
    const auto rows = db.query(
        "SELECT 1 FROM vpn_users WHERE username = '" + db.quote(username) + "'");
    return !rows.empty();
}

bool fixed_ip_in_use(Db& db,
                     const std::string& fixed_ip,
                     const std::string& exclude_username) {
    std::string sql =
        "SELECT username FROM vpn_users WHERE fixed_ip = '" +
        db.quote(fixed_ip) + "'";
    if (!exclude_username.empty()) {
        sql += " AND username <> '" + db.quote(exclude_username) + "'";
    }
    sql += " LIMIT 1";
    return !db.query(sql).empty();
}

std::vector<UserRule> load_rules(Db& db, const std::string& username) {
    const auto rows = db.query(
        "SELECT id, rule_type, cidr, enabled, "
        "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_user_rules WHERE username = '" + db.quote(username) +
        "' ORDER BY id");
    std::vector<UserRule> rules;
    rules.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 5) {
            continue;
        }
        UserRule rule;
        rule.id = parse_u32_value(row[0]);
        rule.rule_type = row[1];
        rule.cidr = row[2];
        rule.enabled = parse_bool(row[3], true);
        rule.created_at = row[4];
        rules.push_back(rule);
    }
    return rules;
}

std::uint64_t active_sessions(Db& db, const std::string& username) {
    const auto rows = db.query(
        "SELECT COUNT(*) FROM vpn_sessions WHERE username = '" +
        db.quote(username) + "'");
    if (rows.empty() || rows[0].empty()) {
        return 0;
    }
    try {
        return std::stoull(rows[0][0]);
    } catch (const std::exception&) {
        return 0;
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

UserSummary create_user(Db& db,
                        const CreateUserInput& input,
                        const std::string& operator_name) {
    if (!validate_username(input.username)) {
        fail(ErrorCode::validation, "invalid username");
    }
    validate_display_name(input.display_name);
    validate_password(input.password);

    const auto validation = load_validation_config(db);
    const GroupRow group = require_group(db, input.group);
    const std::string fixed_ip =
        validate_fixed_ip(input.fixed_ip, group, validation);

    if (user_exists(db, input.username)) {
        fail(ErrorCode::conflict, "username already exists");
    }
    if (fixed_ip_in_use(db, fixed_ip, "")) {
        fail(ErrorCode::conflict, "fixed IP is already in use");
    }

    UserSummary user;
    user.username = input.username;
    user.display_name = input.display_name;
    user.group_name = group.name;
    user.fixed_ip = fixed_ip;
    user.enabled = true;
    user.must_change_password = input.must_change_password;

    const std::string hash = pbkdf2_sha256_user(input.password);
    try {
        Transaction tx(db);
        db.execute(
            "INSERT INTO vpn_users "
            "(username, display_name, group_id, fixed_ip, enabled, "
            "must_change_password, password_hash, password_updated_at) VALUES ('" +
            db.quote(input.username) + "', '" + db.quote(input.display_name) +
            "', " + std::to_string(group.id) + ", '" +
            db.quote(fixed_ip) + "', 1, " +
            (input.must_change_password ? "1" : "0") + ", '" +
            db.quote(hash) + "', NOW())");
        write_audit_as(db, operator_name, "user-create", input.username, "",
                       user_json(user).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "user or fixed IP already exists");
    }

    const auto created = get_user(db, input.username);
    return created ? *created : user;
}

UserSummary update_user(Db& db,
                        const std::string& username,
                        const UpdateUserInput& input,
                        const std::string& operator_name) {
    const auto current = get_user(db, username);
    if (!current) {
        fail(ErrorCode::not_found, "user not found: " + username);
    }
    if (!input.display_name && !input.group && !input.fixed_ip &&
        !input.enabled && !input.must_change_password) {
        fail(ErrorCode::validation, "no fields to update");
    }

    const std::string display_name =
        input.display_name.value_or(current->display_name);
    const std::string group_name =
        input.group.value_or(current->group_name);
    const std::string fixed_ip_input =
        input.fixed_ip.value_or(current->fixed_ip);
    const bool enabled = input.enabled.value_or(current->enabled);
    const bool must_change =
        input.must_change_password.value_or(current->must_change_password);

    validate_display_name(display_name);
    if (fixed_ip_input.empty()) {
        fail(ErrorCode::validation, "fixed IP must not be empty");
    }

    const auto validation = load_validation_config(db);
    const GroupRow group = require_group(db, group_name);
    const std::string fixed_ip =
        validate_fixed_ip(fixed_ip_input, group, validation);
    if (fixed_ip != current->fixed_ip &&
        fixed_ip_in_use(db, fixed_ip, username)) {
        fail(ErrorCode::conflict, "fixed IP is already in use");
    }

    UserSummary after = *current;
    after.display_name = display_name;
    after.group_name = group.name;
    after.fixed_ip = fixed_ip;
    after.enabled = enabled;
    after.must_change_password = must_change;

    try {
        Transaction tx(db);
        db.execute(
            "UPDATE vpn_users SET display_name = '" + db.quote(display_name) +
            "', group_id = " + std::to_string(group.id) + ", fixed_ip = '" +
            db.quote(fixed_ip) + "', enabled = " + (enabled ? "1" : "0") +
            ", must_change_password = " + (must_change ? "1" : "0") +
            " WHERE username = '" + db.quote(username) + "'");
        write_audit_as(db, operator_name, "user-update", username,
                       user_json(*current).dump(), user_json(after).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "fixed IP is already in use");
    }

    const auto updated = get_user(db, username);
    return updated ? *updated : after;
}

void reset_user_password(Db& db,
                         const std::string& username,
                         const PasswordResetInput& input,
                         const std::string& operator_name) {
    if (!user_exists(db, username)) {
        fail(ErrorCode::not_found, "user not found: " + username);
    }
    validate_password(input.password);
    const std::string hash = pbkdf2_sha256_user(input.password);

    try {
        Transaction tx(db);
        db.execute(
            "UPDATE vpn_users SET password_hash = '" + db.quote(hash) +
            "', password_updated_at = NOW(), must_change_password = " +
            std::string(input.must_change_password ? "1" : "0") +
            " WHERE username = '" + db.quote(username) + "'");
        write_audit_as(db, operator_name, "user-password-reset", username, "",
                       json{{"password_reset", true},
                            {"must_change_password",
                             input.must_change_password}}
                           .dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "failed to reset password");
    }
}

std::vector<UserRule> list_user_rules(Db& db, const std::string& username) {
    if (!user_exists(db, username)) {
        fail(ErrorCode::not_found, "user not found: " + username);
    }
    return load_rules(db, username);
}

UserRule add_user_rule(Db& db,
                       const std::string& username,
                       const UserRuleInput& input,
                       const std::string& operator_name) {
    if (!user_exists(db, username)) {
        fail(ErrorCode::not_found, "user not found: " + username);
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
        "SELECT 1 FROM vpn_user_rules WHERE username = '" +
        db.quote(username) + "' AND rule_type = '" + rule_type_name(type) +
        "' AND cidr = '" + cidr.to_string() + "'");
    if (!duplicate.empty()) {
        fail(ErrorCode::conflict, "rule already exists");
    }

    const auto policy = load_policy(db, username);
    std::size_t rule_count = 0;
    for (const auto& rule : policy.group_rules) {
        if (rule.enabled) {
            ++rule_count;
        }
    }
    for (const auto& rule : policy.user_rules) {
        if (rule.enabled) {
            ++rule_count;
        }
    }
    if (rule_count >= validation.max_rules_per_user) {
        fail(ErrorCode::validation, "too many rules for user");
    }

    UserRule rule;
    rule.rule_type = rule_type_name(type);
    rule.cidr = cidr.to_string();
    rule.enabled = input.enabled;

    try {
        Transaction tx(db);
        db.execute(
            "INSERT INTO vpn_user_rules "
            "(username, rule_type, cidr, enabled) VALUES ('" +
            db.quote(username) + "', '" + rule.rule_type + "', '" +
            rule.cidr + "', " + (input.enabled ? "1" : "0") + ")");
        rule.id = static_cast<std::uint32_t>(db.last_insert_id());
        write_audit_as(db, operator_name, "user-rule-add", username, "",
                       rule_json(rule).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "rule already exists");
    }
    return rule;
}

void delete_user_rule(Db& db,
                      const std::string& username,
                      std::uint32_t rule_id,
                      const std::string& operator_name) {
    const auto rows = db.query(
        "SELECT id, rule_type, cidr, enabled FROM vpn_user_rules "
        "WHERE id = " + std::to_string(rule_id) + " AND username = '" +
        db.quote(username) + "'");
    if (rows.empty()) {
        fail(ErrorCode::not_found, "rule not found");
    }

    UserRule rule;
    rule.id = rule_id;
    if (rows[0].size() >= 4) {
        rule.rule_type = rows[0][1];
        rule.cidr = rows[0][2];
        rule.enabled = parse_bool(rows[0][3], true);
    }

    Transaction tx(db);
    db.execute("DELETE FROM vpn_user_rules WHERE id = " +
               std::to_string(rule_id) + " AND username = '" +
               db.quote(username) + "'");
    write_audit_as(db, operator_name, "user-rule-delete", username,
                   rule_json(rule).dump(), "");
    bump_policy_version(db);
    tx.commit();
}

UserRule update_user_rule(Db& db,
                          const std::string& username,
                          std::uint32_t rule_id,
                          bool enabled,
                          const std::string& operator_name) {
    const auto rows = db.query(
        "SELECT id, rule_type, cidr, enabled, "
        "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_user_rules WHERE id = " +
        std::to_string(rule_id) + " AND username = '" +
        db.quote(username) + "'");
    if (rows.empty()) {
        fail(ErrorCode::not_found, "rule not found");
    }

    UserRule before;
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

    UserRule after = before;
    after.enabled = enabled;

    Transaction tx(db);
    db.execute(
        "UPDATE vpn_user_rules SET enabled = " +
        std::string(enabled ? "1" : "0") + " WHERE id = " +
        std::to_string(rule_id) + " AND username = '" +
        db.quote(username) + "'");
    write_audit_as(db, operator_name, "user-rule-update", username,
                   rule_json(before).dump(), rule_json(after).dump());
    bump_policy_version(db);
    tx.commit();
    return after;
}

void delete_user(Db& db,
                 const std::string& username,
                 const std::string& operator_name) {
    const auto current = get_user(db, username);
    if (!current) {
        fail(ErrorCode::not_found, "user not found: " + username);
    }
    if (active_sessions(db, username) > 0) {
        fail(ErrorCode::conflict, "user has an active session");
    }

    try {
        Transaction tx(db);
        db.execute("DELETE FROM vpn_user_rules WHERE username = '" +
                   db.quote(username) + "'");
        db.execute(
            "DELETE FROM vpn_server_services WHERE scope_type = 'user' "
            "AND scope_id = '" +
            db.quote(username) + "'");
        db.execute("DELETE FROM vpn_users WHERE username = '" +
                   db.quote(username) + "'");
        write_audit_as(db, operator_name, "user-delete", username,
                       user_json(*current).dump(), json{{"deleted", true}}.dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error, "failed to delete user");
    }
}

std::optional<UserDetail> get_user_detail(Db& db,
                                          const std::string& username) {
    const auto user = get_user(db, username);
    if (!user) {
        return std::nullopt;
    }

    UserDetail detail;
    detail.user = *user;
    detail.rules = load_rules(db, username);
    try {
        const auto data = load_policy(db, username);
        const auto validation = load_validation_config(db);
        detail.policy = compute_effective_policy(data, validation);
    } catch (const ValidationError& error) {
        detail.policy_error = error.what();
    }
    return detail;
}

} // namespace vpn::service