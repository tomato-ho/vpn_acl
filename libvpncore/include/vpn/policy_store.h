#pragma once

#include "vpn/db.h"
#include "vpn/types.h"
#include "vpn/validation.h"

#include <cstdint>
#include <optional>
#include <string>

namespace vpn {

struct GroupRow {
    std::uint32_t id{0};
    std::string name;
    std::uint32_t ip_start{0};
    std::uint32_t ip_end{0};
};

ValidationConfig load_validation_config(Db& db);
std::optional<GroupRow> find_group(Db& db, const std::string& name);

void ensure_cidr_allowed(const Cidr& cidr, const ValidationConfig& config);
void ensure_service_allowed(const Service& service,
                            const ValidationConfig& config);

void bump_policy_version(Db& db);
void write_audit(Db& db,
                 const std::string& action,
                 const std::string& target,
                 const std::string& after);
void write_audit_as(Db& db,
                    const std::string& operator_name,
                    const std::string& action,
                    const std::string& target,
                    const std::string& before,
                    const std::string& after);

PolicyData load_policy(Db& db, const std::string& username);

} // namespace vpn