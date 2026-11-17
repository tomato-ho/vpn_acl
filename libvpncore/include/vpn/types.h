#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vpn {

struct Ipv4Range {
    uint32_t start{0};
    uint32_t end{0};
};

struct Cidr {
    uint32_t network{0};
    uint8_t prefix{32};
    uint32_t start{0};
    uint32_t end{0};

    std::string to_string() const;
};

enum class RuleType {
    Allow,
    Deny,
};

struct Rule {
    RuleType type{RuleType::Allow};
    Cidr cidr;
    bool enabled{true};
};

struct Group {
    uint32_t id{0};
    std::string name;
    uint32_t ip_start{0};
    uint32_t ip_end{0};
    std::string description;
};

struct User {
    std::string username;
    std::string display_name;
    uint32_t group_id{0};
    std::string group_name;
    uint32_t fixed_ip{0};
    bool has_fixed_ip{false};
    bool enabled{true};
};

struct Service {
    uint32_t ip{0};
    uint16_t port{0};
    std::string protocol;

    std::string to_string() const;
};

struct ServiceRule {
    std::string scope_type;
    std::string scope_id;
    Service service;
    bool enabled{true};
};

struct EffectivePolicy {
    uint32_t fixed_ip{0};
    std::string group_name;
    std::vector<Cidr> allow;
    std::vector<Cidr> deny;
    std::vector<Cidr> push_routes;
    std::vector<Service> services;
};

struct ValidationConfig {
    std::vector<Cidr> allowed_target_networks;
    std::vector<uint32_t> allowed_service_ips;
    Cidr tunnel_network;
    bool has_tunnel_network{false};
    std::size_t max_rules_per_user{128};
    std::size_t max_services_per_user{16};
};

struct PolicyData {
    User user;
    Group group;
    std::vector<Rule> group_rules;
    std::vector<Rule> user_rules;
    std::vector<ServiceRule> services;
};

} // namespace vpn