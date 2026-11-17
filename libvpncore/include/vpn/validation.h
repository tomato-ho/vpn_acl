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

// OpenVPN 保留地址：网络地址、广播地址，以及 server 指令使用的第一个主机地址。
bool is_reserved_tunnel_address(const Cidr& tunnel_network, std::uint32_t ip);

EffectivePolicy compute_effective_policy(const PolicyData& data,
                                         const ValidationConfig& config);

} // namespace vpn