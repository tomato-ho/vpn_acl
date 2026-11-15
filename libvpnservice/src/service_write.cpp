#include "vpn/service/service_write.h"

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

[[noreturn]] void fail(ErrorCode code, const std::string& message) {
    throw ServiceError(code, message);
}

std::uint32_t parse_u32_value(const std::string& value) {
    try {
        std::size_t consumed = 0;
        const unsigned long parsed = std::stoul(value, &consumed, 10);
        if (consumed != value.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(parsed);
    } catch (const std::exception&) {
        return 0;
    }
}

json service_json(const ServiceRow& row) {
    return json{{"id", row.id},
                {"scope_type", row.scope_type},
                {"scope_id", row.scope_id},
                {"service", row.service},
                {"enabled", row.enabled}};
}

std::string normalize_scope_type(const std::string& value) {
    const std::string scope = to_lower(value);
    if (scope != "global" && scope != "group" && scope != "user") {
        fail(ErrorCode::validation,
             "scope_type must be global, group or user");
    }
    return scope;
}

std::string resolve_scope_id(Db& db,
                             const std::string& scope_type,
                             const std::string& scope_id) {
    if (scope_type == "global") {
        if (!scope_id.empty()) {
            fail(ErrorCode::validation,
                 "global service must not have a scope_id");
        }
        return {};
    }
    if (scope_type == "group") {
        const auto group = find_group(db, scope_id);
        if (!group) {
            fail(ErrorCode::validation, "group not found: " + scope_id);
        }
        return group->name;
    }

    const auto rows = db.query(
        "SELECT 1 FROM vpn_users WHERE username = '" + db.quote(scope_id) +
        "'");
    if (rows.empty()) {
        fail(ErrorCode::validation, "user not found: " + scope_id);
    }
    return scope_id;
}

void throw_duplicate(const std::exception& error) {
    if (std::string(error.what()).find("Duplicate entry") !=
        std::string::npos) {
        fail(ErrorCode::conflict, "service already exists");
    }
    throw;
}

} // namespace

std::vector<ServiceRow> list_services(Db& db,
                                      const std::string& scope_type,
                                      const std::string& scope_id) {
    std::string where;
    if (!scope_type.empty()) {
        const std::string normalized = normalize_scope_type(scope_type);
        where = " WHERE scope_type = '" + db.quote(normalized) + "'";
        if (normalized != "global" && !scope_id.empty()) {
            where += " AND scope_id = '" + db.quote(scope_id) + "'";
        }
    }

    const auto rows = db.query(
        "SELECT id, scope_type, scope_id, service, enabled, "
        "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_server_services" +
        where + " ORDER BY scope_type, scope_id, service");

    std::vector<ServiceRow> services;
    services.reserve(rows.size());
    for (const auto& row : rows) {
        if (row.size() < 6) {
            continue;
        }
        ServiceRow service;
        service.id = parse_u32_value(row[0]);
        service.scope_type = row[1];
        service.scope_id = row[2];
        service.service = row[3];
        service.enabled = parse_bool(row[4], true);
        service.created_at = row[5];
        services.push_back(service);
    }
    return services;
}

ServiceRow add_service(Db& db,
                       const CreateServiceInput& input,
                       const std::string& operator_name) {
    const std::string scope_type = normalize_scope_type(input.scope_type);
    const std::string scope_id =
        resolve_scope_id(db, scope_type, input.scope_id);

    const auto parsed = parse_service(input.service);
    if (!parsed) {
        fail(ErrorCode::validation, "invalid service: " + input.service);
    }

    const auto validation = load_validation_config(db);
    try {
        ensure_service_allowed(*parsed, validation);
    } catch (const std::exception& error) {
        fail(ErrorCode::validation, error.what());
    }

    const auto duplicate = db.query(
        "SELECT 1 FROM vpn_server_services WHERE scope_type = '" +
        db.quote(scope_type) + "' AND scope_id = '" + db.quote(scope_id) +
        "' AND service = '" + db.quote(parsed->to_string()) + "'");
    if (!duplicate.empty()) {
        fail(ErrorCode::conflict, "service already exists");
    }

    ServiceRow row;
    row.scope_type = scope_type;
    row.scope_id = scope_id;
    row.service = parsed->to_string();
    row.enabled = input.enabled;

    try {
        Transaction tx(db);
        db.execute(
            "INSERT INTO vpn_server_services "
            "(scope_type, scope_id, service, enabled) VALUES ('" +
            db.quote(scope_type) + "', '" + db.quote(scope_id) + "', '" +
            db.quote(row.service) + "', " + (input.enabled ? "1" : "0") + ")");
        row.id = static_cast<std::uint32_t>(db.last_insert_id());
        write_audit_as(db, operator_name, "service-add",
                       scope_type + ":" +
                           (scope_id.empty() ? "-" : scope_id),
                       "", service_json(row).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error);
    }
    return row;
}

void delete_service(Db& db,
                    std::uint32_t service_id,
                    const std::string& operator_name) {
    const auto rows = db.query(
        "SELECT id, scope_type, scope_id, service, enabled "
        "FROM vpn_server_services WHERE id = " +
        std::to_string(service_id));
    if (rows.empty()) {
        fail(ErrorCode::not_found, "service not found");
    }

    ServiceRow row;
    row.id = service_id;
    if (rows[0].size() >= 5) {
        row.scope_type = rows[0][1];
        row.scope_id = rows[0][2];
        row.service = rows[0][3];
        row.enabled = parse_bool(rows[0][4], true);
    }

    Transaction tx(db);
    db.execute("DELETE FROM vpn_server_services WHERE id = " +
               std::to_string(service_id));
    write_audit_as(db, operator_name, "service-delete",
                   row.scope_type + ":" +
                       (row.scope_id.empty() ? "-" : row.scope_id),
                   service_json(row).dump(), "");
    bump_policy_version(db);
    tx.commit();
}

ServiceRow update_service(Db& db,
                          std::uint32_t service_id,
                          std::optional<bool> enabled,
                          std::optional<std::string> service,
                          const std::string& operator_name) {
    if (!enabled && !service) {
        fail(ErrorCode::validation, "no fields to update");
    }

    const auto rows = db.query(
        "SELECT id, scope_type, scope_id, service, enabled, "
        "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') "
        "FROM vpn_server_services WHERE id = " +
        std::to_string(service_id));
    if (rows.empty() || rows[0].size() < 6) {
        fail(ErrorCode::not_found, "service not found");
    }

    ServiceRow before;
    before.id = service_id;
    before.scope_type = rows[0][1];
    before.scope_id = rows[0][2];
    before.service = rows[0][3];
    before.enabled = parse_bool(rows[0][4], true);
    before.created_at = rows[0][5];

    ServiceRow after = before;
    bool changed = false;

    if (enabled) {
        after.enabled = *enabled;
        changed = changed || after.enabled != before.enabled;
    }
    if (service) {
        const auto parsed = parse_service(*service);
        if (!parsed) {
            fail(ErrorCode::validation, "invalid service: " + *service);
        }
        const auto validation = load_validation_config(db);
        try {
            ensure_service_allowed(*parsed, validation);
        } catch (const std::exception& error) {
            fail(ErrorCode::validation, error.what());
        }
        after.service = parsed->to_string();
        changed = changed || after.service != before.service;
    }
    if (!changed) {
        return before;
    }

    if (after.service != before.service) {
        const auto duplicate = db.query(
            "SELECT 1 FROM vpn_server_services WHERE scope_type = '" +
            db.quote(after.scope_type) + "' AND scope_id = '" +
            db.quote(after.scope_id) + "' AND service = '" +
            db.quote(after.service) + "' AND id <> " +
            std::to_string(service_id));
        if (!duplicate.empty()) {
            fail(ErrorCode::conflict, "service already exists");
        }
    }

    try {
        Transaction tx(db);
        db.execute(
            "UPDATE vpn_server_services SET service = '" +
            db.quote(after.service) + "', enabled = " +
            (after.enabled ? "1" : "0") + " WHERE id = " +
            std::to_string(service_id));
        write_audit_as(db, operator_name, "service-update",
                       after.scope_type + ":" +
                           (after.scope_id.empty() ? "-" : after.scope_id),
                       service_json(before).dump(), service_json(after).dump());
        bump_policy_version(db);
        tx.commit();
    } catch (const ServiceError&) {
        throw;
    } catch (const std::exception& error) {
        throw_duplicate(error);
    }
    return after;
}

} // namespace vpn::service