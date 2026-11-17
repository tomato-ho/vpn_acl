#include "vpn/retention.h"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        ++failures;
    }
}

void expect_invalid(const vpn::RetentionPolicy& policy,
                    const std::string& message) {
    try {
        vpn::validate_retention_policy(policy);
        check(false, message);
    } catch (const std::exception&) {
    }
}

void test_defaults() {
    vpn::RetentionPolicy policy;
    vpn::validate_retention_policy(policy);
    check(vpn::retention_session_condition(policy.session_days) ==
              "start_time < NOW() - INTERVAL 180 DAY",
          "session condition");
    check(vpn::retention_auth_log_condition(policy.auth_log_days) ==
              "created_at < NOW() - INTERVAL 180 DAY",
          "auth log condition");
    check(vpn::retention_audit_condition(policy.audit_days) ==
              "created_at < NOW() - INTERVAL 365 DAY",
          "audit condition");
    check(vpn::retention_access_condition(policy.access_days) ==
              "last_seen < NOW() - INTERVAL 180 DAY",
          "access condition");
    check(vpn::retention_flow_state_condition(policy.access_days) ==
              "updated_at < NOW() - INTERVAL 180 DAY",
          "flow state condition");
}

void test_invalid_values() {
    vpn::RetentionPolicy policy;
    policy.session_days = 0;
    expect_invalid(policy, "reject zero session days");

    policy = vpn::RetentionPolicy{};
    policy.batch_size = 0;
    expect_invalid(policy, "reject zero batch size");

    policy = vpn::RetentionPolicy{};
    policy.access_days = 0;
    expect_invalid(policy, "reject zero access days");

    policy = vpn::RetentionPolicy{};
    policy.batch_size = 10001;
    expect_invalid(policy, "reject oversized batch");
}

} // namespace

int main() {
    test_defaults();
    test_invalid_values();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "retention tests passed\n";
    return 0;
}