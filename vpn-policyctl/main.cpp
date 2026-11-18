#include "vpn/cidr.h"
#include "vpn/config.h"
#include "vpn/db.h"
#include "vpn/db_config.h"
#include "vpn/ipc.h"
#include "vpn/parse.h"
#include "vpn/password.h"
#include "vpn/policy_store.h"
#include "vpn/retention.h"
#include "vpn/service/limits.h"
#include "vpn/util.h"
#include "vpn/validation.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace vpn;

struct Flags {
    std::map<std::string, std::string> values;
    std::set<std::string> switches;
    std::vector<std::string> positional;
};

class Transaction {
public:
    explicit Transaction(Db& db) : db_(db) { db_.begin(); }
    ~Transaction() {
        if (!committed_) {
            try {
                db_.rollback();
            } catch (const std::exception&) {
            }
        }
    }
    void commit() {
        db_.commit();
        committed_ = true;
    }

private:
    Db& db_;
    bool committed_{false};
};

void usage() {
    std::cout
        << "Usage: vpn-policyctl [--config PATH] <command> [options]\n"
        << "\n"
        << "Commands:\n"
        << "  admin-create <username>\n"
        << "  admin-password-reset <username>\n"
        << "  group-add <name> --ip-start IP --ip-end IP [--description TEXT]\n"
        << "  group-rule-add <group> <allow|deny> <cidr>\n"
        << "  user-add <username> --group GROUP [--fixed-ip IP] [--display-name TEXT]\n"
        << "  user-set <username> [--group GROUP] [--fixed-ip IP] [--enable|--disable]\n"
        << "  user-rule-add <username> <allow|deny> <cidr>\n"
        << "  service-add <global|group|user> [scope_id] <service>\n"
        << "  service-remove <global|group|user> [scope_id] <service>\n"
        << "  service-list\n"
        << "  group-list\n"
        << "  group-show <name>\n"
        << "  user-list [--group GROUP]\n"
        << "  validate <username>\n"
        << "  show <username>\n"
        << "  password-reset <username>\n"
        << "  retention-cleanup [--apply] [--session-days N] [--auth-log-days N]\n"
        << "                    [--audit-days N] [--access-days N]\n"
        << "                    [--batch-size N]\n"
        << "  settings-show\n";
}

bool is_help_command(const std::string& command) {
    return command == "--help" || command == "-h" || command == "help";
}

bool is_known_command(const std::string& command) {
    static const std::set<std::string> commands = {
        "admin-create", "admin-password-reset", "group-add", "group-rule-add",
        "user-add", "user-set", "user-rule-add",
        "service-add", "service-remove", "service-list",
        "group-list", "group-show", "user-list",
        "validate", "show", "password-reset", "retention-cleanup",
        "settings-show",
    };
    return commands.find(command) != commands.end();
}

Flags parse_flags(int argc, char** argv, int start) {
    Flags flags;
    for (int i = start; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg.rfind("--", 0) == 0) {
            const auto equal = arg.find('=');
            if (equal != std::string::npos) {
                flags.values[arg.substr(2, equal - 2)] = arg.substr(equal + 1);
                continue;
            }
            const std::string name = arg.substr(2);
            if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
                flags.values[name] = argv[++i];
            } else {
                flags.switches.insert(name);
            }
        } else {
            flags.positional.push_back(arg);
        }
    }
    return flags;
}

std::string flag_value(const Flags& flags,
                       const std::string& name,
                       const std::string& fallback = "") {
    const auto found = flags.values.find(name);
    return found == flags.values.end() ? fallback : found->second;
}

bool has_switch(const Flags& flags, const std::string& name) {
    return flags.switches.find(name) != flags.switches.end();
}

std::string read_password(const std::string& prompt) {
    std::cout << prompt << std::flush;
    termios old_settings{};
    if (tcgetattr(STDIN_FILENO, &old_settings) != 0) {
        throw std::runtime_error("tcgetattr failed");
    }
    termios new_settings = old_settings;
    new_settings.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_settings) != 0) {
        throw std::runtime_error("tcsetattr failed");
    }
    std::string password;
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    std::cout << "\n";
    return password;
}

std::string obtain_password(const Flags& flags) {
    if (flags.values.find("password") != flags.values.end()) {
        return flags.values.at("password");
    }
    if (has_switch(flags, "password-stdin")) {
        std::string password;
        std::getline(std::cin, password);
        return password;
    }

    const std::string first = read_password("Password: ");
    const std::string second = read_password("Confirm: ");
    if (first != second) {
        throw std::runtime_error("passwords do not match");
    }
    return first;
}

void validate_password_value(const std::string& password) {
    if (password.size() < 8 || password.size() > 256) {
        throw std::runtime_error("password must be 8-256 bytes");
    }
}

void print_policy(const EffectivePolicy& policy) {
    std::cout << "fixed_ip=" << format_ipv4(policy.fixed_ip) << "\n";
    std::cout << "group=" << policy.group_name << "\n";
    for (const auto& cidr : policy.allow) {
        std::cout << "allow=" << cidr.to_string() << "\n";
    }
    for (const auto& cidr : policy.deny) {
        std::cout << "deny=" << cidr.to_string() << "\n";
    }
    for (const auto& cidr : policy.push_routes) {
        std::cout << "push_route=" << cidr.to_string() << "\n";
    }
    for (const auto& service : policy.services) {
        std::cout << "service=" << service.to_string() << "\n";
    }
}

void cmd_admin_create(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("admin-create requires <username>");
    }
    const std::string username = flags.positional[0];
    if (!validate_username(username)) {
        throw std::runtime_error("invalid username");
    }
    const std::string password = obtain_password(flags);
    validate_password_value(password);
    const std::string hash = pbkdf2_sha256_admin(password);

    Transaction tx(db);
    db.execute(
        "INSERT INTO vpn_admins (username, password_hash, enabled) VALUES ('" +
        db.quote(username) + "', '" + db.quote(hash) + "', 1)");
    write_audit(db, "admin-create", username, "enabled=1");
    tx.commit();
    std::cout << "admin created: " << username << "\n";
}

void cmd_admin_password_reset(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error(
            "admin-password-reset requires <username>");
    }
    const std::string username = flags.positional[0];
    const auto rows = db.query(
        "SELECT 1 FROM vpn_admins WHERE username = '" + db.quote(username) +
        "'");
    if (rows.empty()) {
        throw std::runtime_error("admin not found: " + username);
    }

    const std::string password = obtain_password(flags);
    validate_password_value(password);
    const std::string hash = pbkdf2_sha256_admin(password);

    Transaction tx(db);
    db.execute(
        "UPDATE vpn_admins SET password_hash = '" + db.quote(hash) +
        "' WHERE username = '" + db.quote(username) + "'");
    write_audit(db, "admin-password-reset", username,
                "algorithm=pbkdf2-sha256");
    tx.commit();
    std::cout << "admin password reset: " << username << "\n";
}

void cmd_group_add(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("group-add requires <name>");
    }
    const std::string name = flags.positional[0];
    if (name.empty() || name.size() > 64) {
        throw std::runtime_error("invalid group name");
    }
    const std::string start_text = flag_value(flags, "ip-start");
    const std::string end_text = flag_value(flags, "ip-end");
    if (start_text.empty() || end_text.empty()) {
        throw std::runtime_error("group-add requires --ip-start and --ip-end");
    }
    const uint32_t start = ip_or_throw(start_text, "group ip_start");
    const uint32_t end = ip_or_throw(end_text, "group ip_end");
    if (start > end) {
        throw std::runtime_error("group IP range start is after end");
    }
    const auto validation = load_validation_config(db);
    if (validation.has_tunnel_network &&
        (!cidr_contains(validation.tunnel_network, start) ||
         !cidr_contains(validation.tunnel_network, end))) {
        throw std::runtime_error(
            "group IP range is outside the tunnel network");
    }
    if (validation.has_tunnel_network &&
        (is_reserved_tunnel_address(validation.tunnel_network, start) ||
         is_reserved_tunnel_address(validation.tunnel_network, end))) {
        throw std::runtime_error(
            "group IP range must not use network/broadcast/gateway addresses");
    }
    const std::string description = flag_value(flags, "description");

    Transaction tx(db);
    db.execute(
        "INSERT INTO vpn_groups (name, ip_start, ip_end, description) VALUES ('" +
        db.quote(name) + "', '" + format_ipv4(start) + "', '" +
        format_ipv4(end) + "', '" + db.quote(description) + "')");
    bump_policy_version(db);
    write_audit(db, "group-add", name,
                "ip_start=" + format_ipv4(start) + ",ip_end=" + format_ipv4(end));
    tx.commit();
    std::cout << "group created: " << name << "\n";
}

void cmd_group_rule_add(Db& db, const Flags& flags, const ValidationConfig& vc) {
    if (flags.positional.size() != 3) {
        throw std::runtime_error("group-rule-add requires <group> <allow|deny> <cidr>");
    }
    const std::string group_name = flags.positional[0];
    const RuleType type = rule_type_or_throw(flags.positional[1]);
    const Cidr cidr = cidr_or_throw(flags.positional[2], "CIDR");
    ensure_cidr_allowed(cidr, vc);

    const auto group = find_group(db, group_name);
    if (!group) {
        throw std::runtime_error("group not found: " + group_name);
    }

    Transaction tx(db);
    db.execute(
        "INSERT INTO vpn_group_rules (group_id, rule_type, cidr, enabled) VALUES (" +
        std::to_string(group->id) + ", '" +
        (type == RuleType::Allow ? "allow" : "deny") + "', '" +
        cidr.to_string() + "', 1)");
    vpn::service::ensure_rule_limits(db, vc.max_rules_per_user);
    bump_policy_version(db);
    write_audit(db, "group-rule-add", group_name,
                (type == RuleType::Allow ? "allow=" : "deny=") + cidr.to_string());
    tx.commit();
    std::cout << "group rule added\n";
}

void cmd_user_add(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("user-add requires <username>");
    }
    const std::string username = flags.positional[0];
    if (!validate_username(username)) {
        throw std::runtime_error("invalid username");
    }
    const std::string group_name = flag_value(flags, "group");
    if (group_name.empty()) {
        throw std::runtime_error("user-add requires --group");
    }
    const auto group = find_group(db, group_name);
    if (!group) {
        throw std::runtime_error("group not found: " + group_name);
    }

    const std::string fixed_ip_text = flag_value(flags, "fixed-ip");
    std::string fixed_ip_sql = "NULL";
    std::string audit_value;
    if (!fixed_ip_text.empty()) {
        const uint32_t fixed_ip = ip_or_throw(fixed_ip_text, "fixed IP");
        if (fixed_ip < group->ip_start || fixed_ip > group->ip_end) {
            throw std::runtime_error("fixed IP is outside the group IP range");
        }
        const auto validation = load_validation_config(db);
        if (validation.has_tunnel_network &&
            !cidr_contains(validation.tunnel_network, fixed_ip)) {
            throw std::runtime_error(
                "fixed IP is outside the tunnel network");
        }
        if (validation.has_tunnel_network &&
            is_reserved_tunnel_address(validation.tunnel_network, fixed_ip)) {
            throw std::runtime_error(
                "fixed IP is a reserved tunnel address "
                "(network/broadcast/gateway)");
        }
        for (const auto service_ip : validation.allowed_service_ips) {
            if (fixed_ip == service_ip) {
                throw std::runtime_error(
                    "fixed IP conflicts with a configured server service IP");
            }
        }
        fixed_ip_sql = "'" + format_ipv4(fixed_ip) + "'";
        audit_value = "fixed_ip=" + format_ipv4(fixed_ip);
    }

    const std::string display_name = flag_value(flags, "display-name");

    Transaction tx(db);
    db.execute(
        "INSERT INTO vpn_users (username, display_name, group_id, fixed_ip, enabled) "
        "VALUES ('" + db.quote(username) + "', '" + db.quote(display_name) + "', " +
        std::to_string(group->id) + ", " + fixed_ip_sql + ", 1)");
    bump_policy_version(db);
    write_audit(db, "user-add", username,
                "group=" + group_name + (audit_value.empty() ? "" : "," + audit_value));
    tx.commit();
    std::cout << "user created: " << username << "\n";
}

void cmd_user_set(Db& db, const Flags& flags,
                  const std::string& socket_path) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("user-set requires <username>");
    }
    const std::string username = flags.positional[0];
    const auto rows = db.query(
        "SELECT IFNULL(group_id, 0), IFNULL(fixed_ip, ''), enabled "
        "FROM vpn_users WHERE username = '" + db.quote(username) + "'");
    if (rows.empty() || rows[0].size() < 3) {
        throw std::runtime_error("user not found: " + username);
    }

    uint32_t group_id = parse_u32_or_throw(rows[0][0], "group id");
    std::string fixed_ip_text = rows[0][1];
    bool enabled = parse_bool(rows[0][2], true);
    const uint32_t old_group_id = group_id;
    const std::string old_fixed_ip = fixed_ip_text;
    const bool old_enabled = enabled;

    const std::string new_group_name = flag_value(flags, "group");
    GroupRow group;
    if (!new_group_name.empty()) {
        const auto found = find_group(db, new_group_name);
        if (!found) {
            throw std::runtime_error("group not found: " + new_group_name);
        }
        group = *found;
    } else {
        const auto found = db.query(
            "SELECT id, name, ip_start, ip_end FROM vpn_groups WHERE id = " +
            std::to_string(group_id));
        if (found.empty() || found[0].size() < 4) {
            throw std::runtime_error("current group not found");
        }
        group.id = parse_u32_or_throw(found[0][0], "group id");
        group.name = found[0][1];
        group.ip_start = ip_or_throw(found[0][2], "group ip_start");
        group.ip_end = ip_or_throw(found[0][3], "group ip_end");
    }

    if (flags.values.find("fixed-ip") != flags.values.end()) {
        fixed_ip_text = flags.values.at("fixed-ip");
    }
    if (has_switch(flags, "enable")) {
        enabled = true;
    }
    if (has_switch(flags, "disable")) {
        enabled = false;
    }

    std::string fixed_ip_sql = "NULL";
    if (!fixed_ip_text.empty()) {
        const uint32_t fixed_ip = ip_or_throw(fixed_ip_text, "fixed IP");
        if (fixed_ip < group.ip_start || fixed_ip > group.ip_end) {
            throw std::runtime_error("fixed IP is outside the group IP range");
        }
        const auto validation = load_validation_config(db);
        if (validation.has_tunnel_network &&
            !cidr_contains(validation.tunnel_network, fixed_ip)) {
            throw std::runtime_error(
                "fixed IP is outside the tunnel network");
        }
        if (validation.has_tunnel_network &&
            is_reserved_tunnel_address(validation.tunnel_network, fixed_ip)) {
            throw std::runtime_error(
                "fixed IP is a reserved tunnel address "
                "(network/broadcast/gateway)");
        }
        for (const auto service_ip : validation.allowed_service_ips) {
            if (fixed_ip == service_ip) {
                throw std::runtime_error(
                    "fixed IP conflicts with a configured server service IP");
            }
        }
        fixed_ip_sql = "'" + format_ipv4(fixed_ip) + "'";
    }

    Transaction tx(db);
    db.execute(
        "UPDATE vpn_users SET group_id = " + std::to_string(group.id) +
        ", fixed_ip = " + fixed_ip_sql + ", enabled = " +
        (enabled ? "1" : "0") + " WHERE username = '" + db.quote(username) + "'");
    const auto limits = load_validation_config(db);
    vpn::service::ensure_rule_limits(db, limits.max_rules_per_user);
    vpn::service::ensure_service_limits(db, limits.max_services_per_user);
    bump_policy_version(db);
    write_audit(db, "user-set", username,
                "group=" + group.name + ",enabled=" + (enabled ? "1" : "0"));
    tx.commit();
    if (enabled != old_enabled || group.id != old_group_id ||
        fixed_ip_text != old_fixed_ip) {
        IpcFields fields;
        fields["username"] = username;
        std::string response;
        std::string error;
        if (!ipc_request(socket_path, "KICK", fields, &response, &error)) {
            std::cerr << "warning: user updated but kick failed: " << error
                      << "\n";
        }
    }
    std::cout << "user updated: " << username << "\n";
}

void cmd_user_rule_add(Db& db, const Flags& flags, const ValidationConfig& vc) {
    if (flags.positional.size() != 3) {
        throw std::runtime_error("user-rule-add requires <username> <allow|deny> <cidr>");
    }
    const std::string username = flags.positional[0];
    const RuleType type = rule_type_or_throw(flags.positional[1]);
    const Cidr cidr = cidr_or_throw(flags.positional[2], "CIDR");
    ensure_cidr_allowed(cidr, vc);

    const auto rows = db.query(
        "SELECT 1 FROM vpn_users WHERE username = '" + db.quote(username) + "'");
    if (rows.empty()) {
        throw std::runtime_error("user not found: " + username);
    }

    Transaction tx(db);
    db.execute(
        "INSERT INTO vpn_user_rules (username, rule_type, cidr, enabled) VALUES ('" +
        db.quote(username) + "', '" +
        (type == RuleType::Allow ? "allow" : "deny") + "', '" +
        cidr.to_string() + "', 1)");
    vpn::service::ensure_rule_limits(db, vc.max_rules_per_user);
    bump_policy_version(db);
    write_audit(db, "user-rule-add", username,
                (type == RuleType::Allow ? "allow=" : "deny=") + cidr.to_string());
    tx.commit();
    std::cout << "user rule added\n";
}

struct ServiceTarget {
    std::string scope_type;
    std::string scope_id;
    std::string service;
};

ServiceTarget parse_service_target(const Flags& flags) {
    if (flags.positional.size() < 2) {
        throw std::runtime_error(
            "service command requires <global|group|user> [scope_id] <service>");
    }

    ServiceTarget target;
    target.scope_type = to_lower(flags.positional[0]);
    if (target.scope_type == "global") {
        if (flags.positional.size() != 2) {
            throw std::runtime_error("service-add global requires <service>");
        }
        target.service = flags.positional[1];
    } else if (target.scope_type == "group" ||
               target.scope_type == "user") {
        if (flags.positional.size() != 3) {
            throw std::runtime_error(
                "service command requires <group|user> <scope_id> <service>");
        }
        target.scope_id = flags.positional[1];
        target.service = flags.positional[2];
    } else {
        throw std::runtime_error("scope type must be global, group or user");
    }
    return target;
}

void validate_service_target(Db& db, const ServiceTarget& target) {
    if (target.scope_type == "group") {
        if (!find_group(db, target.scope_id)) {
            throw std::runtime_error("group not found: " + target.scope_id);
        }
    } else if (target.scope_type == "user") {
        const auto rows = db.query(
            "SELECT 1 FROM vpn_users WHERE username = '" +
            db.quote(target.scope_id) + "'");
        if (rows.empty()) {
            throw std::runtime_error("user not found: " + target.scope_id);
        }
    }
}

void cmd_service_add(Db& db, const Flags& flags, const ValidationConfig& vc) {
    const ServiceTarget target = parse_service_target(flags);
    const auto service = parse_service(target.service);
    if (!service) {
        throw std::runtime_error("invalid service: " + target.service);
    }
    ensure_service_allowed(*service, vc);
    validate_service_target(db, target);

    Transaction tx(db);
    db.execute(
        "INSERT INTO vpn_server_services (scope_type, scope_id, service, enabled) "
        "VALUES ('" + db.quote(target.scope_type) + "', '" +
        db.quote(target.scope_id) + "', '" + service->to_string() + "', 1)");
    vpn::service::ensure_service_limits(db, vc.max_services_per_user);
    bump_policy_version(db);
    write_audit(db, "service-add",
                target.scope_type + ":" +
                    (target.scope_id.empty() ? "-" : target.scope_id),
                service->to_string());
    tx.commit();
    std::cout << "service added: " << service->to_string() << "\n";
}

void cmd_service_remove(Db& db, const Flags& flags) {
    const ServiceTarget target = parse_service_target(flags);
    const auto service = parse_service(target.service);
    if (!service) {
        throw std::runtime_error("invalid service: " + target.service);
    }

    const auto rows = db.query(
        "SELECT id FROM vpn_server_services WHERE scope_type = '" +
        db.quote(target.scope_type) + "' AND scope_id = '" +
        db.quote(target.scope_id) + "' AND service = '" +
        db.quote(service->to_string()) + "'");
    if (rows.empty()) {
        throw std::runtime_error("service not found");
    }

    Transaction tx(db);
    db.execute(
        "DELETE FROM vpn_server_services WHERE scope_type = '" +
        db.quote(target.scope_type) + "' AND scope_id = '" +
        db.quote(target.scope_id) + "' AND service = '" +
        db.quote(service->to_string()) + "'");
    bump_policy_version(db);
    write_audit(db, "service-remove",
                target.scope_type + ":" +
                    (target.scope_id.empty() ? "-" : target.scope_id),
                service->to_string());
    tx.commit();
    std::cout << "service removed: " << service->to_string() << "\n";
}

void cmd_service_list(Db& db) {
    const auto rows = db.query(
        "SELECT scope_type, scope_id, service, enabled FROM vpn_server_services "
        "ORDER BY scope_type, scope_id, service");
    for (const auto& row : rows) {
        if (row.size() >= 4) {
            std::cout << row[0] << " "
                      << (row[1].empty() ? "-" : row[1]) << " "
                      << row[2] << " enabled=" << row[3] << "\n";
        }
    }
}

void cmd_group_list(Db& db) {
    const auto rows = db.query(
        "SELECT g.id, g.name, g.ip_start, g.ip_end, "
        "(SELECT COUNT(*) FROM vpn_users u WHERE u.group_id = g.id), "
        "(SELECT COUNT(*) FROM vpn_group_rules r WHERE r.group_id = g.id) "
        "FROM vpn_groups g ORDER BY g.name");
    std::cout << "id\tname\tip_start\tip_end\tusers\trules\n";
    for (const auto& row : rows) {
        if (row.size() >= 6) {
            std::cout << row[0] << '\t' << row[1] << '\t' << row[2] << '\t'
                      << row[3] << '\t' << row[4] << '\t' << row[5] << '\n';
        }
    }
}

void cmd_group_show(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("group-show requires <name>");
    }
    const std::string name = flags.positional[0];
    const auto group_rows = db.query(
        "SELECT id, name, ip_start, ip_end, description FROM vpn_groups "
        "WHERE name = '" + db.quote(name) + "'");
    if (group_rows.empty() || group_rows[0].size() < 5) {
        throw std::runtime_error("group not found: " + name);
    }

    const auto& group = group_rows[0];
    const std::string group_id = group[0];
    std::cout << "name=" << group[1] << "\n";
    std::cout << "ip_range=" << group[2] << "-" << group[3] << "\n";
    std::cout << "description=" << group[4] << "\n";

    std::cout << "users:\n";
    const auto users = db.query(
        "SELECT username, IFNULL(fixed_ip, ''), enabled "
        "FROM vpn_users WHERE group_id = " + group_id +
        " ORDER BY username");
    for (const auto& row : users) {
        if (row.size() >= 3) {
            std::cout << "  " << row[0] << " " << row[1]
                      << " enabled=" << row[2] << "\n";
        }
    }

    std::cout << "rules:\n";
    const auto rules = db.query(
        "SELECT rule_type, cidr, enabled FROM vpn_group_rules "
        "WHERE group_id = " + group_id +
        " ORDER BY rule_type, cidr");
    for (const auto& row : rules) {
        if (row.size() >= 3) {
            std::cout << "  " << row[0] << " " << row[1]
                      << " enabled=" << row[2] << "\n";
        }
    }

    std::cout << "services:\n";
    const auto services = db.query(
        "SELECT service, enabled FROM vpn_server_services "
        "WHERE scope_type = 'group' AND scope_id = '" + db.quote(name) +
        "' ORDER BY service");
    for (const auto& row : services) {
        if (row.size() >= 2) {
            std::cout << "  " << row[0] << " enabled=" << row[1] << "\n";
        }
    }
}

void cmd_user_list(Db& db, const Flags& flags) {
    const std::string group = flag_value(flags, "group");
    if (!group.empty() && !find_group(db, group)) {
        throw std::runtime_error("group not found: " + group);
    }

    std::string sql =
        "SELECT u.username, IFNULL(g.name, ''), IFNULL(u.fixed_ip, ''), "
        "u.enabled "
        "FROM vpn_users u LEFT JOIN vpn_groups g ON g.id = u.group_id";
    if (!group.empty()) {
        sql += " WHERE g.name = '" + db.quote(group) + "'";
    }
    sql += " ORDER BY g.name, u.username";

    const auto rows = db.query(sql);
    std::cout << "username\tgroup\tfixed_ip\tenabled\n";
    for (const auto& row : rows) {
        if (row.size() >= 4) {
            std::cout << row[0] << '\t' << row[1] << '\t' << row[2] << '\t'
                      << row[3] << '\n';
        }
    }
}

void cmd_validate(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("validate requires <username>");
    }
    const std::string username = flags.positional[0];
    const auto data = load_policy(db, username);
    const auto vc = load_validation_config(db);
    const auto policy = compute_effective_policy(data, vc);
    std::cout << "OK\n";
    print_policy(policy);
}

void cmd_show(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("show requires <username>");
    }
    const std::string username = flags.positional[0];
    const auto data = load_policy(db, username);
    const auto vc = load_validation_config(db);
    const auto policy = compute_effective_policy(data, vc);

    std::cout << "username=" << data.user.username << "\n";
    std::cout << "display_name=" << data.user.display_name << "\n";
    std::cout << "group=" << data.group.name << "\n";
    std::cout << "enabled=" << (data.user.enabled ? "1" : "0") << "\n";
    print_policy(policy);
}

void cmd_password_reset(Db& db, const Flags& flags) {
    if (flags.positional.size() != 1) {
        throw std::runtime_error("password-reset requires <username>");
    }
    const std::string username = flags.positional[0];
    const auto rows = db.query(
        "SELECT 1 FROM vpn_users WHERE username = '" + db.quote(username) + "'");
    if (rows.empty()) {
        throw std::runtime_error("user not found: " + username);
    }
    const std::string password = obtain_password(flags);
    validate_password_value(password);
    const std::string hash = pbkdf2_sha256_user(password);

    Transaction tx(db);
    db.execute(
        "UPDATE vpn_users SET password_hash = '" + db.quote(hash) +
        "', password_updated_at = NOW() "
        "WHERE username = '" + db.quote(username) + "'");
    write_audit(db, "password-reset", username, "algorithm=pbkdf2-sha256");
    tx.commit();
    std::cout << "password reset: " << username << "\n";
}

void cmd_settings_show(Db& db) {
    const auto rows = db.query("SELECT name, value FROM vpn_settings ORDER BY name");
    for (const auto& row : rows) {
        if (row.size() >= 2) {
            std::cout << row[0] << "=" << row[1] << "\n";
        }
    }
}

RetentionPolicy retention_policy(const Flags& flags) {
    RetentionPolicy policy;
    policy.apply = has_switch(flags, "apply");
    // --radacct-days / --radpostauth-days 是旧名字，保留为别名。
    const std::string session_days =
        flag_value(flags, "session-days").empty()
            ? flag_value(flags, "radacct-days")
            : flag_value(flags, "session-days");
    if (!session_days.empty()) {
        policy.session_days =
            parse_u32_or_throw(session_days, "session-days");
    }
    const std::string auth_days =
        flag_value(flags, "auth-log-days").empty()
            ? flag_value(flags, "radpostauth-days")
            : flag_value(flags, "auth-log-days");
    if (!auth_days.empty()) {
        policy.auth_log_days = parse_u32_or_throw(auth_days, "auth-log-days");
    }
    if (!flag_value(flags, "audit-days").empty()) {
        policy.audit_days =
            parse_u32_or_throw(flag_value(flags, "audit-days"), "audit-days");
    }
    if (!flag_value(flags, "access-days").empty()) {
        policy.access_days = parse_u32_or_throw(
            flag_value(flags, "access-days"), "access-days");
    }
    if (!flag_value(flags, "batch-size").empty()) {
        policy.batch_size = parse_u32_or_throw(
            flag_value(flags, "batch-size"), "batch-size");
    }
    validate_retention_policy(policy);
    return policy;
}

std::uint64_t count_old_rows(Db& db,
                             const std::string& table,
                             const std::string& condition) {
    const auto rows =
        db.query("SELECT COUNT(*) FROM " + table + " WHERE " + condition);
    if (rows.empty() || rows[0].empty()) {
        return 0;
    }
    return static_cast<std::uint64_t>(std::stoull(rows[0][0]));
}

std::uint64_t delete_old_rows(Db& db,
                              const std::string& table,
                              const std::string& condition,
                              std::uint32_t batch_size,
                              bool apply) {
    if (!apply) {
        return count_old_rows(db, table, condition);
    }

    std::uint64_t total = 0;
    while (true) {
        db.execute("DELETE FROM " + table + " WHERE " + condition +
                   " LIMIT " + std::to_string(batch_size));
        const std::uint64_t affected = db.affected_rows();
        total += affected;
        if (affected < batch_size) {
            break;
        }
    }
    return total;
}

void cmd_retention_cleanup(Db& db, const Flags& flags) {
    if (!flags.positional.empty()) {
        throw std::runtime_error("retention-cleanup takes no positional arguments");
    }

    const RetentionPolicy policy = retention_policy(flags);
    const std::string session_condition =
        retention_session_condition(policy.session_days);
    const std::string auth_log_condition =
        retention_auth_log_condition(policy.auth_log_days);
    const std::string audit_condition =
        retention_audit_condition(policy.audit_days);
    const std::string access_condition =
        retention_access_condition(policy.access_days);
    const std::string flow_state_condition =
        retention_flow_state_condition(policy.access_days);

    const auto session_rows = delete_old_rows(
        db, "vpn_session_history", session_condition, policy.batch_size,
        policy.apply);
    const auto auth_log_rows =
        delete_old_rows(db, "vpn_auth_log", auth_log_condition,
                        policy.batch_size, policy.apply);
    const auto audit_rows =
        delete_old_rows(db, "vpn_audit_log", audit_condition,
                        policy.batch_size, policy.apply);
    const auto access_rows =
        delete_old_rows(db, "vpn_access_log", access_condition,
                        policy.batch_size, policy.apply);
    const auto flow_state_rows =
        delete_old_rows(db, "vpn_flow_state", flow_state_condition,
                        policy.batch_size, policy.apply);

    const std::string prefix = policy.apply ? "deleted" : "would delete";
    std::cout << "vpn_session_history " << prefix << "=" << session_rows
              << " older_than_days=" << policy.session_days << "\n";
    std::cout << "vpn_auth_log " << prefix << "=" << auth_log_rows
              << " older_than_days=" << policy.auth_log_days << "\n";
    std::cout << "vpn_audit_log " << prefix << "=" << audit_rows
              << " older_than_days=" << policy.audit_days << "\n";
    std::cout << "vpn_access_log " << prefix << "=" << access_rows
              << " older_than_days=" << policy.access_days << "\n";
    std::cout << "vpn_flow_state " << prefix << "=" << flow_state_rows
              << " older_than_days=" << policy.access_days << "\n";
    if (!policy.apply) {
        std::cout << "dry-run: no rows were deleted; pass --apply to delete\n";
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string config_path = "/etc/vpn-policy/config";
        int index = 1;
        if (index < argc && std::string(argv[index]) == "--config") {
            if (index + 1 >= argc) {
                throw std::runtime_error("--config requires a path");
            }
            config_path = argv[index + 1];
            index += 2;
        }
        if (index >= argc) {
            usage();
            return 1;
        }

        const std::string command = argv[index++];
        if (is_help_command(command)) {
            usage();
            return 0;
        }
        if (!is_known_command(command)) {
            usage();
            return 1;
        }

        const Flags flags = parse_flags(argc, argv, index);
        const std::string resolved_config = resolve_config_path(config_path);
        if (!config_file_exists(resolved_config) &&
            std::getenv("VPN_DB_PASSWORD") == nullptr) {
            throw std::runtime_error("config file not found: " + resolved_config);
        }
        const Config config = Config::load(resolved_config);

        Db db(make_db_config(config));
        db.connect();

        if (command == "admin-create") {
            cmd_admin_create(db, flags);
        } else if (command == "admin-password-reset") {
            cmd_admin_password_reset(db, flags);
        } else if (command == "group-add") {
            cmd_group_add(db, flags);
        } else if (command == "group-rule-add") {
            cmd_group_rule_add(db, flags, load_validation_config(db));
        } else if (command == "user-add") {
            cmd_user_add(db, flags);
        } else if (command == "user-set") {
            cmd_user_set(db, flags,
                         config.get("socket_path",
                                    "/run/vpn-policyd/policyd.sock"));
        } else if (command == "user-rule-add") {
            cmd_user_rule_add(db, flags, load_validation_config(db));
        } else if (command == "service-add") {
            cmd_service_add(db, flags, load_validation_config(db));
        } else if (command == "service-remove") {
            cmd_service_remove(db, flags);
        } else if (command == "service-list") {
            cmd_service_list(db);
        } else if (command == "group-list") {
            cmd_group_list(db);
        } else if (command == "group-show") {
            cmd_group_show(db, flags);
        } else if (command == "user-list") {
            cmd_user_list(db, flags);
        } else if (command == "validate") {
            cmd_validate(db, flags);
        } else if (command == "show") {
            cmd_show(db, flags);
        } else if (command == "password-reset") {
            cmd_password_reset(db, flags);
        } else if (command == "retention-cleanup") {
            cmd_retention_cleanup(db, flags);
        } else if (command == "settings-show") {
            cmd_settings_show(db);
        } else {
            usage();
            return 1;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
}