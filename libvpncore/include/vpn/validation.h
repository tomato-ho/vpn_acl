#pragma once

#include "vpn/types.h"

#include <optional>
#include <stdexcept>
#include <string>

namespace vpn {

class ValidationError : public std::runtime_error {
public:
    explicit ValidationError(const std::string& message)
        : std::runtime_error(message) {}
};

bool validate_username(const std::string& username);
std::optional<Service> parse_service(const std::string& value);

EffectivePolicy compute_effective_policy(const PolicyData& data,
                                         const ValidationConfig& config);

} // namespace vpn