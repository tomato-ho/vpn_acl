#include "vpn/nft.h"

#include "vpn/cidr.h"

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

void check_contains(const std::string& text,
                    const std::string& needle,
                    const std::string& message) {
    check(text.find(needle) != std::string::npos, message + ": " + needle);
}

void test_base_script() {
    const std::string script = vpn::nft_base_script("vpn_acl", "tun0");
    check_contains(script, "add set inet vpn_acl flows {",
                   "base has allow-up set");
    check_contains(script, "add set inet vpn_acl flows_rev {",
                   "base has allow-down set");
    check_contains(script, "add set inet vpn_acl flows_deny {",
                   "base has deny set");
    check_contains(script, "type ipv4_addr . ipv4_addr",
                   "flows sets use address pairs");
    check_contains(script, "counter", "flows sets have per-element counters");
    check_contains(script,
                   "oifname \"tun0\" ct state established,related update "
                   "@flows_rev { ip daddr . ip saddr } accept",
                   "reverse accounting rule");

    const auto reverse = script.find("update @flows_rev");
    const auto established = script.find("forward ct state established,related accept");
    check(reverse != std::string::npos && established != std::string::npos &&
              reverse < established,
          "reverse accounting runs before the generic established accept");
}

void test_rule_scripts() {
    const auto allowed = vpn::parse_cidr("192.168.140.0/24");
    check(allowed.has_value(), "test cidr parses");
    const std::vector<vpn::Cidr> allow = {*allowed};
    const std::string forward = vpn::nft_forward_rules("vpn_acl", "uf_x", allow);
    check_contains(forward,
                   "ip daddr { 192.168.140.0/24 } update @flows "
                   "{ ip saddr . ip daddr } accept",
                   "allow rule updates the up set");
    check_contains(forward,
                   "update @flows_deny { ip saddr . ip daddr } counter drop",
                   "deny rule updates the deny set");

    const std::string empty_forward =
        vpn::nft_forward_rules("vpn_acl", "uf_x", {});
    check(empty_forward.find("update @flows {") == std::string::npos,
          "no allow rule when the allow list is empty");

    std::vector<vpn::Service> services;
    vpn::Service service;
    service.ip = 0x0A096401; // 10.9.100.1
    service.protocol = "udp";
    service.port = 53;
    services.push_back(service);
    const std::string input = vpn::nft_input_rules("vpn_acl", "ui_x", services);
    check_contains(input,
                   "ip daddr 10.9.100.1 udp dport 53 update @flows "
                   "{ ip saddr . ip daddr } accept",
                   "service rule updates the up set");
    check_contains(input,
                   "update @flows_deny { ip saddr . ip daddr } counter drop",
                   "input deny rule updates the deny set");
}

const char* kJson = R"({
  "nftables": [
    {"metainfo": {"version": "1.1.5"}},
    {"set": {"name": "user_fwd", "table": "vpn_acl", "type": "ipv4_addr",
             "elem": []}},
    {"set": {"name": "flows", "table": "vpn_acl",
             "type": "ipv4_addr . ipv4_addr",
             "elem": [
               {"elem": {"val": {"concat": ["10.9.100.10", "192.168.140.129"]},
                         "expires": 540,
                         "counter": {"packets": 12, "bytes": 4096}}},
               {"elem": {"val": {"concat": ["10.9.100.10", "10.20.0.5"]},
                         "counter": {"packets": 3, "bytes": 512}}}
             ]}},
    {"set": {"name": "flows_rev", "table": "vpn_acl",
             "type": "ipv4_addr . ipv4_addr",
             "elem": [
               {"elem": {"val": {"concat": ["10.9.100.10", "192.168.140.129"]},
                         "counter": {"packets": 20, "bytes": 8192}}}
             ]}},
    {"set": {"name": "flows_deny", "table": "vpn_acl",
             "type": "ipv4_addr . ipv4_addr",
             "elem": [
               {"elem": {"val": {"concat": ["10.9.100.21", "8.8.8.8"]},
                         "counter": {"packets": 1, "bytes": 60}}}
             ]}},
    {"chain": {"name": "forward", "table": "vpn_acl"}}
  ]
})";

void test_parse_flow_counters() {
    std::string error;
    const auto counters = vpn::parse_flow_counters_json(kJson, &error);
    check(error.empty(), "valid json has no error");
    check(counters.size() == 4, "parses four flow elements");
    if (counters.size() != 4) {
        return;
    }
    check(counters[0].set_name == "flows", "first set name");
    check(counters[0].src_ip == "10.9.100.10", "first src ip");
    check(counters[0].dest_ip == "192.168.140.129", "first dest ip");
    check(counters[0].bytes == 4096 && counters[0].packets == 12,
          "first counters");
    check(counters[2].set_name == "flows_rev", "reverse set parsed");
    check(counters[2].bytes == 8192, "reverse bytes");
    check(counters[3].set_name == "flows_deny", "deny set parsed");
    check(counters[3].src_ip == "10.9.100.21" &&
              counters[3].dest_ip == "8.8.8.8",
          "deny pair");
}

void test_parse_rejects_garbage() {
    std::string error;
    const auto counters = vpn::parse_flow_counters_json("not json", &error);
    check(counters.empty(), "garbage yields no counters");
    check(!error.empty(), "garbage reports an error");

    error.clear();
    const auto empty =
        vpn::parse_flow_counters_json(R"({"nftables": []})", &error);
    check(empty.empty() && error.empty(), "empty table is valid");
}

} // namespace

int main() {
    test_base_script();
    test_rule_scripts();
    test_parse_flow_counters();
    test_parse_rejects_garbage();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "nft flow tests passed\n";
    return 0;
}