#include "vpn/validation.h"

#include "vpn/cidr.h"
#include "vpn/util.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <string>

namespace vpn {

bool validate_username(const std::string& username) {
    if (username.empty() || username.size() > 64) {
        return false;
    }
    for (const unsigned char ch : username) {
        if (!(std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' || ch == '@')) {
            return false;
        }
    }
    return true;
}

std::string Service::to_string() const {
    return format_ipv4(ip) + ":" + std::to_string(port) + "/" + protocol;
}

std::optional<Service> parse_service(const std::string& value) {
    const auto colon = value.find(':');
    const auto slash = value.find('/', colon == std::string::npos ? 0 : colon + 1);
    if (colon == std::string::npos || slash == std::string::npos || colon > slash) {
        return std::nullopt;
    }

    const std::string ip_text = value.substr(0, colon);
    const std::string port_text = value.substr(colon + 1, slash - colon - 1);
    const std::string protocol = to_lower(value.substr(slash + 1));

    const auto ip = parse_ipv4(ip_text);
    if (!ip) {
        return std::nullopt;
    }
    if (protocol != "tcp" && protocol != "udp") {
        return std::nullopt;
    }

    std::size_t consumed = 0;
    unsigned long port = 0;
    try {
        port = std::stoul(port_text, &consumed, 10);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (consumed != port_text.size() || port == 0 || port > 65535) {
        return std::nullopt;
    }

    Service service;
    service.ip = *ip;
    service.port = static_cast<uint16_t>(port);
    service.protocol = protocol;
    return service;
}

namespace {

bool is_within_allowed_targets(const Cidr& cidr,
                               const std::vector<Cidr>& allowed_targets) {
    if (allowed_targets.empty()) {
        return true;
    }
    for (const auto& target : allowed_targets) {
        if (cidr_contains(target, cidr)) {
            return true;
        }
    }
    return false;
}

void validate_rule(const Rule& rule,
                   const std::vector<Cidr>& allowed_targets,
                   const std::string& scope_name) {
    if (!rule.enabled) {
        return;
    }
    if (!is_within_allowed_targets(rule.cidr, allowed_targets)) {
        throw ValidationError(scope_name + " rule " + rule.cidr.to_string() +
                              " is outside allowed target networks");
    }
}

} // namespace

EffectivePolicy compute_effective_policy(const PolicyData& data,
                                         const ValidationConfig& config) {
    if (!validate_username(data.user.username)) {
        throw ValidationError("invalid username");
    }
    if (!data.user.enabled) {
        throw ValidationError("user is disabled");
    }
    if (data.group.name.empty() || data.group.id == 0) {
        throw ValidationError("user has no primary group");
    }
    if (data.group.ip_start > data.group.ip_end) {
        throw ValidationError("group IP range is invalid");
    }
    if (!data.user.has_fixed_ip) {
        throw ValidationError("user has no fixed tunnel IP");
    }
    if (data.user.fixed_ip < data.group.ip_start ||
        data.user.fixed_ip > data.group.ip_end) {
        throw ValidationError("fixed IP is outside the group IP range");
    }
    if (config.has_tunnel_network &&
        !cidr_contains(config.tunnel_network, data.user.fixed_ip)) {
        throw ValidationError("fixed IP is outside the tunnel network");
    }

    std::size_t enabled_rules = 0;
    for (const auto& rule : data.group_rules) {
        if (rule.enabled) {
            ++enabled_rules;
        }
    }
    for (const auto& rule : data.user_rules) {
        if (rule.enabled) {
            ++enabled_rules;
        }
    }
    if (enabled_rules > config.max_rules_per_user) {
        throw ValidationError("too many rules for user: " +
                              std::to_string(enabled_rules));
    }

    std::vector<Cidr> allow;
    std::vector<Cidr> deny;

    auto add_rule = [&](const Rule& rule, const std::string& scope_name) {
        if (!rule.enabled) {
            return;
        }
        validate_rule(rule, config.allowed_target_networks, scope_name);
        if (rule.type == RuleType::Allow) {
            allow.push_back(rule.cidr);
        } else {
            deny.push_back(rule.cidr);
        }
    };

    for (const auto& rule : data.group_rules) {
        add_rule(rule, "group");
    }
    for (const auto& rule : data.user_rules) {
        add_rule(rule, "user");
    }

    std::vector<Service> services;
    std::set<std::string> seen_services;

    for (const auto& entry : data.services) {
        if (!entry.enabled) {
            continue;
        }
        const bool matches =
            entry.scope_type == "global" ||
            (entry.scope_type == "group" && entry.scope_id == data.group.name) ||
            (entry.scope_type == "user" && entry.scope_id == data.user.username);
        if (!matches) {
            continue;
        }

        if (!config.allowed_service_ips.empty()) {
            const bool ip_allowed = std::find(config.allowed_service_ips.begin(),
                                              config.allowed_service_ips.end(),
                                              entry.service.ip) !=
                                    config.allowed_service_ips.end();
            if (!ip_allowed) {
                throw ValidationError("service IP is not allowed: " +
                                      format_ipv4(entry.service.ip));
            }
        }

        const std::string key = entry.service.to_string();
        if (seen_services.insert(key).second) {
            services.push_back(entry.service);
        }
    }

    if (services.size() > config.max_services_per_user) {
        throw ValidationError("too many server services for user: " +
                              std::to_string(services.size()));
    }

    std::sort(services.begin(), services.end(), [](const Service& a, const Service& b) {
        if (a.ip != b.ip) {
            return a.ip < b.ip;
        }
        if (a.port != b.port) {
            return a.port < b.port;
        }
        return a.protocol < b.protocol;
    });

    EffectivePolicy policy;
    policy.fixed_ip = data.user.fixed_ip;
    policy.group_name = data.group.name;
    policy.allow = merge_cidrs(allow);
    policy.deny = merge_cidrs(deny);
    policy.push_routes = subtract_cidrs(policy.allow, policy.deny);
    policy.services = std::move(services);
    return policy;
}

} // namespace vpn