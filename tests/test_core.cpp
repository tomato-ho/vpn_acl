#include "vpn/cidr.h"
#include "vpn/nft.h"
#include "vpn/password.h"
#include "vpn/util.h"
#include "vpn/validation.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        ++failures;
    }
}

vpn::Cidr cidr(const std::string& value) {
    const auto parsed = vpn::parse_cidr(value);
    if (!parsed) {
        std::cerr << "invalid test CIDR: " << value << "\n";
        std::exit(1);
    }
    return *parsed;
}

vpn::Ipv4Range range(const std::string& value) {
    const auto parsed = vpn::parse_cidr(value);
    if (!parsed) {
        std::cerr << "invalid test range: " << value << "\n";
        std::exit(1);
    }
    return vpn::Ipv4Range{parsed->start, parsed->end};
}

void test_cidr() {
    const auto ip = vpn::parse_ipv4("192.168.100.109");
    check(ip.has_value(), "parse IPv4");
    check(vpn::format_ipv4(*ip) == "192.168.100.109", "format IPv4");
    check(!vpn::parse_ipv4("192.168.100.999"), "reject invalid IPv4");

    const auto cidr_value = vpn::parse_cidr("192.168.100.109/24");
    check(cidr_value.has_value(), "parse CIDR with host bits");
    check(cidr_value->to_string() == "192.168.100.0/24", "normalize CIDR");
    check(!vpn::parse_cidr("192.168.100.0/33"), "reject invalid prefix");

    check(vpn::cidr_contains(cidr("10.0.0.0/8"), cidr("10.8.0.0/24")),
          "CIDR contains CIDR");
    check(!vpn::cidr_contains(cidr("10.8.0.0/24"), cidr("10.0.0.0/8")),
          "CIDR does not contain larger network");

    const auto merged = vpn::merge_cidrs({cidr("10.0.0.0/25"), cidr("10.0.0.128/25")});
    check(merged.size() == 1 && merged[0].to_string() == "10.0.0.0/24",
          "merge adjacent CIDRs");

    const auto subtracted = vpn::subtract_cidrs(
        {cidr("192.168.10.0/24")}, {cidr("192.168.10.128/25")});
    check(subtracted.size() == 1 && subtracted[0].to_string() == "192.168.10.0/25",
          "subtract deny range");

    const auto full = vpn::subtract_cidrs({cidr("0.0.0.0/0")}, {cidr("10.0.0.0/8")});
    check(!full.empty(), "subtract from default route");
    for (const auto& value : full) {
        check(!vpn::ranges_overlap(
                  vpn::Ipv4Range{value.start, value.end}, range("10.0.0.0/8")),
              "subtracted CIDR does not overlap deny range");
    }
}

void test_validation() {
    check(vpn::validate_username("alice_01"), "valid username");
    check(!vpn::validate_username("alice/01"), "invalid username");

    const auto service = vpn::parse_service("10.8.0.1:53/udp");
    check(service.has_value(), "parse service");
    check(service->to_string() == "10.8.0.1:53/udp", "format service");
    check(!vpn::parse_service("10.8.0.1:0/udp"), "reject port zero");
    check(!vpn::parse_service("10.8.0.1:53/icmp"), "reject invalid protocol");

    vpn::PolicyData data;
    data.user.username = "alice";
    data.user.display_name = "Alice";
    data.user.group_id = 1;
    data.user.group_name = "group_a";
    data.user.has_fixed_ip = true;
    data.user.fixed_ip = *vpn::parse_ipv4("10.8.0.11");
    data.user.enabled = true;

    data.group.id = 1;
    data.group.name = "group_a";
    data.group.ip_start = *vpn::parse_ipv4("10.8.0.10");
    data.group.ip_end = *vpn::parse_ipv4("10.8.0.49");

    data.group_rules.push_back(vpn::Rule{vpn::RuleType::Allow, cidr("192.168.10.0/24"), true});
    data.group_rules.push_back(vpn::Rule{vpn::RuleType::Allow, cidr("192.168.20.0/24"), true});
    data.group_rules.push_back(vpn::Rule{vpn::RuleType::Deny, cidr("192.168.20.128/25"), true});
    data.user_rules.push_back(vpn::Rule{vpn::RuleType::Allow, cidr("192.168.30.0/24"), true});
    data.user_rules.push_back(vpn::Rule{vpn::RuleType::Deny, cidr("192.168.10.128/25"), true});

    data.services.push_back(vpn::ServiceRule{
        "global", "", *vpn::parse_service("192.168.100.109:22/tcp"), true});
    data.services.push_back(vpn::ServiceRule{
        "group", "group_a", *vpn::parse_service("10.8.0.1:22/tcp"), true});

    vpn::ValidationConfig config;
    config.allowed_target_networks = {cidr("192.168.0.0/16")};
    config.allowed_service_ips = {
        *vpn::parse_ipv4("10.8.0.1"),
        *vpn::parse_ipv4("192.168.100.109"),
    };
    config.tunnel_network = cidr("10.8.0.0/24");
    config.has_tunnel_network = true;
    config.max_rules_per_user = 128;

    const auto policy = vpn::compute_effective_policy(data, config);
    check(policy.allow.size() == 3, "effective allow count");
    check(policy.deny.size() == 2, "effective deny count");
    check(policy.services.size() == 2, "effective services count");
    check(policy.push_routes.size() == 3, "effective push route count");
}

void test_nft() {
    const auto script = vpn::nft_session_script(
        "vpn_acl", "tun0", "alice", *vpn::parse_ipv4("10.8.0.31"),
        {cidr("192.168.100.0/24")},
        {*vpn::parse_service("192.168.100.109:22/tcp")});
    check(script.find("ip daddr { 192.168.100.0/24 } update @flows "
                      "{ ip saddr . ip daddr } accept") != std::string::npos,
          "nft forward allow rule");
    check(script.find("ip daddr 192.168.100.109 tcp dport 22 update @flows "
                      "{ ip saddr . ip daddr } accept") !=
              std::string::npos,
          "nft input service rule");
    check(script.find("10.8.0.31 : jump uf_") != std::string::npos,
          "nft forward map element");
    check(script.find("10.8.0.31 : jump ui_") != std::string::npos,
          "nft input map element");

    const auto cleanup = vpn::nft_cleanup_scripts(
        "vpn_acl", "alice", *vpn::parse_ipv4("10.8.0.31"));
    check(cleanup.size() == 4, "nft cleanup script count");
    check(vpn::netmask_from_prefix(24) == "255.255.255.0", "CIDR netmask");
}

void test_password() {
    const auto admin = vpn::pbkdf2_sha256_admin("TestPass123!", 1000);
    check(vpn::verify_admin_password("TestPass123!", admin), "verify admin password");
    check(!vpn::verify_admin_password("wrong", admin), "reject wrong admin password");

    const auto radius = vpn::pbkdf2_sha256_freeradius("TestPass123!", 1000);
    const auto parts = vpn::split(radius, '$');
    check(parts.size() == 3, "RADIUS PBKDF2 format");

    const std::string prefix = "{PBKDF2-SHA256}";
    const auto header = vpn::pbkdf2_sha256_freeradius_header("TestPass123!", 1000);
    check(header.rfind(prefix, 0) == 0, "RADIUS PBKDF2 header prefix");
    const auto header_parts = vpn::split(header.substr(prefix.size()), '$');
    check(header_parts.size() == 3, "RADIUS PBKDF2 header format");
}

} // namespace

int main() {
    test_cidr();
    test_validation();
    test_nft();
    test_password();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "all tests passed\n";
    return 0;
}