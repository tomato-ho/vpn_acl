#pragma once

#include "vpn/types.h"

#include <cstdint>
#include <string>

namespace vpn {

std::uint32_t parse_u32_or_throw(const std::string& value,
                                 const std::string& label);
std::uint32_t ip_or_throw(const std::string& value, const std::string& label);
Cidr cidr_or_throw(const std::string& value, const std::string& label);
RuleType rule_type_or_throw(const std::string& value);

} // namespace vpn