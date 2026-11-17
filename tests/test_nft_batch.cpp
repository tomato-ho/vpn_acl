#include "nft_batch.h"
#include "nft_manager.h"

#include "vpn/cidr.h"
#include "vpn/parse.h"
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

vpn::Service service(const std::string& value) {
    const auto parsed = vpn::parse_service(value);
    if (!parsed) {
        std::cerr << "invalid test service: " << value << "\n";
        std::exit(1);
    }
    return *parsed;
}

vpn::NftSessionUpdate allow_http(const std::string& username,
                                 const std::string& ip) {
    vpn::NftSessionUpdate update;
    update.username = username;
    update.virtual_ip = *vpn::parse_ipv4(ip);
    update.allow = {cidr("192.168.100.0/24")};
    update.services = {service("192.168.100.109:22/tcp")};
    return update;
}

void test_new_session() {
    vpn::NftState state;
    const auto plan = vpn::plan_nft_batch(
        "vpn_acl", state, {allow_http("alice", "10.8.0.31")}, nullptr);
    check(plan.applied == 1, "new session applied count");
    check(plan.removed == 0, "new session removed count");
    check(plan.script.find("add chain inet vpn_acl uf_") != std::string::npos,
          "new session forward chain");
    check(plan.script.find("add chain inet vpn_acl ui_") != std::string::npos,
          "new session input chain");
    check(plan.script.find("ip daddr { 192.168.100.0/24 } update @flows "
                           "{ ip saddr . ip daddr } accept") !=
              std::string::npos,
          "new session allow rule");
    check(plan.script.find("192.168.100.109 tcp dport 22 update @flows "
                           "{ ip saddr . ip daddr } accept") !=
              std::string::npos,
          "new session service rule");
    check(plan.script.find("10.8.0.31 : jump uf_") != std::string::npos,
          "new session forward map element");
    check(plan.script.find("10.8.0.31 : jump ui_") != std::string::npos,
          "new session input map element");
}

void test_existing_session_flushes() {
    const auto update = allow_http("alice", "10.8.0.31");
    const std::string hash = vpn::nft_chain_hash("alice");
    vpn::NftState state;
    state.user_fwd["10.8.0.31"] = "uf_" + hash;
    state.user_in["10.8.0.31"] = "ui_" + hash;
    state.chains.insert("uf_" + hash);
    state.chains.insert("ui_" + hash);

    const auto plan = vpn::plan_nft_batch("vpn_acl", state, {update}, nullptr);
    check(plan.script.find("flush chain inet vpn_acl uf_" + hash) !=
              std::string::npos,
          "existing forward chain flushed");
    check(plan.script.find("flush chain inet vpn_acl ui_" + hash) !=
              std::string::npos,
          "existing input chain flushed");
    check(plan.script.find("add chain inet vpn_acl uf_" + hash) ==
              std::string::npos,
          "existing forward chain not re-added");
    check(plan.script.find("add element inet vpn_acl user_fwd") ==
              std::string::npos,
          "existing forward element not re-added");
}

void test_remove_session() {
    const auto update = allow_http("alice", "10.8.0.31");
    const std::string hash = vpn::nft_chain_hash("alice");
    vpn::NftState state;
    state.user_fwd["10.8.0.31"] = "uf_" + hash;
    state.user_in["10.8.0.31"] = "ui_" + hash;
    state.chains.insert("uf_" + hash);
    state.chains.insert("ui_" + hash);

    vpn::NftSessionUpdate remove;
    remove.username = "alice";
    remove.virtual_ip = *vpn::parse_ipv4("10.8.0.31");
    remove.remove = true;

    const auto plan = vpn::plan_nft_batch("vpn_acl", state, {remove}, nullptr);
    check(plan.removed == 1, "remove count");
    check(plan.script.find("delete element inet vpn_acl user_fwd { 10.8.0.31 }") !=
              std::string::npos,
          "remove forward element");
    check(plan.script.find("delete element inet vpn_acl user_in { 10.8.0.31 }") !=
              std::string::npos,
          "remove input element");
    check(plan.script.find("delete chain inet vpn_acl uf_" + hash) !=
              std::string::npos,
          "remove forward chain");
    check(plan.script.find("delete chain inet vpn_acl ui_" + hash) !=
              std::string::npos,
          "remove input chain");
    check(plan.deleted_chains.size() == 2, "remove chain verification list");
}

void test_shared_chain_is_rejected() {
    const std::string hash = vpn::nft_chain_hash("alice");
    vpn::NftState state;
    state.user_fwd["10.8.0.31"] = "uf_" + hash;
    state.user_in["10.8.0.31"] = "ui_" + hash;
    state.user_fwd["10.8.0.32"] = "uf_" + hash;
    state.user_in["10.8.0.32"] = "ui_" + hash;
    state.chains.insert("uf_" + hash);
    state.chains.insert("ui_" + hash);

    std::string error;
    const auto plan = vpn::plan_nft_batch(
        "vpn_acl", state, {allow_http("alice", "10.8.0.31")}, &error);
    check(!error.empty(), "shared chain reports an error");
    check(plan.script.empty(), "shared chain produces no script");
}

void test_empty_batch() {
    vpn::NftState state;
    const auto plan = vpn::plan_nft_batch("vpn_acl", state, {}, nullptr);
    check(plan.script.empty(), "empty batch has no script");
    check(plan.applied == 0 && plan.removed == 0, "empty batch counts");
}

void test_large_batch() {
    std::vector<vpn::NftSessionUpdate> updates;
    for (std::uint32_t i = 0; i < 300; ++i) {
        const std::string username = "user" + std::to_string(i);
        const std::string ip =
            "10.8." + std::to_string(i / 250) + "." +
            std::to_string(1 + (i % 250));
        updates.push_back(allow_http(username, ip));
    }

    vpn::NftState state;
    const auto plan = vpn::plan_nft_batch("vpn_acl", state, updates, nullptr);
    check(plan.applied == 300, "large batch applied count");
    check(plan.script.find("add table") == std::string::npos,
          "large batch does not create the base table");
    check(plan.script.find("add chain inet vpn_acl uf_") != std::string::npos,
          "large batch has session chains");
}

} // namespace

int main() {
    test_new_session();
    test_existing_session_flushes();
    test_remove_session();
    test_shared_chain_is_rejected();
    test_empty_batch();
    test_large_batch();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "nft batch tests passed\n";
    return 0;
}