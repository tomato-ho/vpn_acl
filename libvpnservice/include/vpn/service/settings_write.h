#pragma once

#include "vpn/db.h"

#include <map>
#include <optional>
#include <string>

namespace vpn::service {

using SettingsMap = std::map<std::string, std::string>;

struct UpdateSettingsInput {
    std::optional<std::string> allowed_target_networks;
    std::optional<std::string> allowed_service_ips;
    std::optional<std::string> tunnel_network;
    std::optional<std::string> max_rules_per_user;
    std::optional<std::string> max_services_per_user;
};

SettingsMap load_settings(Db& db);
SettingsMap update_settings(Db& db,
                            const UpdateSettingsInput& input,
                            const std::string& operator_name);

} // namespace vpn::service