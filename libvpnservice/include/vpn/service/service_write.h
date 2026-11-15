#pragma once

#include "vpn/db.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vpn::service {

struct ServiceRow {
    std::uint32_t id{0};
    std::string scope_type;
    std::string scope_id;
    std::string service;
    bool enabled{true};
    std::string created_at;
};

struct CreateServiceInput {
    std::string scope_type;
    std::string scope_id;
    std::string service;
    bool enabled{true};
};

std::vector<ServiceRow> list_services(Db& db,
                                      const std::string& scope_type,
                                      const std::string& scope_id);
ServiceRow add_service(Db& db,
                       const CreateServiceInput& input,
                       const std::string& operator_name);
void delete_service(Db& db,
                    std::uint32_t service_id,
                    const std::string& operator_name);
ServiceRow update_service(Db& db,
                          std::uint32_t service_id,
                          std::optional<bool> enabled,
                          std::optional<std::string> service,
                          const std::string& operator_name);

} // namespace vpn::service