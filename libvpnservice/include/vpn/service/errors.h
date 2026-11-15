#pragma once

#include <stdexcept>
#include <string>

namespace vpn::service {

enum class ErrorCode {
    validation,
    not_found,
    conflict,
    unavailable,
    internal,
};

class ServiceError : public std::runtime_error {
public:
    ServiceError(ErrorCode code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

} // namespace vpn::service