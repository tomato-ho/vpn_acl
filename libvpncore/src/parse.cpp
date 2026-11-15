#include "vpn/parse.h"

#include "vpn/cidr.h"
#include "vpn/util.h"

#include <stdexcept>

namespace vpn {

std::uint32_t parse_u32_or_throw(const std::string& value,
                                 const std::string& label) {
    std::size_t consumed = 0;
    unsigned long parsed = 0;
    try {
        parsed = std::stoul(value, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error("invalid " + label + ": " + value);
    }
    if (consumed != value.size()) {
        throw std::runtime_error("invalid " + label + ": " + value);
    }
    return static_cast<std::uint32_t>(parsed);
}

std::uint32_t ip_or_throw(const std::string& value, const std::string& label) {
    const auto parsed = parse_ipv4(value);
    if (!parsed) {
        throw std::runtime_error("invalid " + label + ": " + value);
    }
    return *parsed;
}

Cidr cidr_or_throw(const std::string& value, const std::string& label) {
    const auto parsed = parse_cidr(value);
    if (!parsed) {
        throw std::runtime_error("invalid " + label + ": " + value);
    }
    return *parsed;
}

RuleType rule_type_or_throw(const std::string& value) {
    const std::string normalized = to_lower(value);
    if (normalized == "allow") {
        return RuleType::Allow;
    }
    if (normalized == "deny") {
        return RuleType::Deny;
    }
    throw std::runtime_error("rule type must be allow or deny");
}

} // namespace vpn