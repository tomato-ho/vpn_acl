#include "vpn/retention.h"

#include <stdexcept>
#include <string>

namespace vpn {
namespace {

void validate_days(std::uint32_t days, const char* name) {
    if (days == 0 || days > 36500) {
        throw std::runtime_error(std::string(name) +
                                 " must be between 1 and 36500");
    }
}

} // namespace

void validate_retention_policy(const RetentionPolicy& policy) {
    validate_days(policy.session_days, "session days");
    validate_days(policy.auth_log_days, "auth log days");
    validate_days(policy.audit_days, "audit days");
    if (policy.batch_size == 0 || policy.batch_size > 10000) {
        throw std::runtime_error("batch size must be between 1 and 10000");
    }
}

std::string retention_session_condition(std::uint32_t days) {
    return "start_time < NOW() - INTERVAL " + std::to_string(days) + " DAY";
}

std::string retention_auth_log_condition(std::uint32_t days) {
    return "created_at < NOW() - INTERVAL " + std::to_string(days) + " DAY";
}

std::string retention_audit_condition(std::uint32_t days) {
    return "created_at < NOW() - INTERVAL " + std::to_string(days) + " DAY";
}

} // namespace vpn