#pragma once

#include <cstdint>
#include <string>

namespace vpn {

struct RetentionPolicy {
    bool apply{false};
    std::uint32_t session_days{180};
    std::uint32_t auth_log_days{180};
    std::uint32_t audit_days{365};
    std::uint32_t batch_size{1000};
};

void validate_retention_policy(const RetentionPolicy& policy);
std::string retention_session_condition(std::uint32_t days);
std::string retention_auth_log_condition(std::uint32_t days);
std::string retention_audit_condition(std::uint32_t days);

} // namespace vpn