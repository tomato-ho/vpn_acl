#include "vpn/session_recovery.h"

#include <iostream>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        ++failures;
    }
}

void test_identity() {
    const auto first =
        vpn::recovery_identity("alice", "10.9.100.10", 1794897166);
    const auto again =
        vpn::recovery_identity("alice", "10.9.100.10", 1794897166);
    const auto other =
        vpn::recovery_identity("alice", "10.9.100.10", 1794897177);
    const auto other_ip =
        vpn::recovery_identity("alice", "10.9.100.11", 1794897166);

    check(first.session_id == again.session_id,
          "same connection yields the same session id");
    check(first.acct_session_id == again.acct_session_id,
          "same connection yields the same acct session id");
    check(first.session_id != other.session_id,
          "different connect time yields a different session id");
    check(first.session_id != other_ip.session_id,
          "different IP yields a different session id");
    check(first.session_id.rfind("recover-", 0) == 0,
          "recovered session id prefix");
    check(first.acct_session_id.rfind("vpn-recover-", 0) == 0,
          "recovered acct session id prefix");
    check(first.session_id.size() <= 32, "session id fits CHAR(32)");
    check(first.acct_session_id.size() <= 64, "acct session id fits VARCHAR(64)");
}

void test_stale() {
    check(vpn::recovery_is_stale(100, 200),
          "status older than the last archived stop is stale");
    check(!vpn::recovery_is_stale(300, 200),
          "new connection after the archived stop is not stale");
    check(!vpn::recovery_is_stale(200, 200),
          "same-second reconnect is not treated as stale");
    check(!vpn::recovery_is_stale(0, 200),
          "unknown connected_since is not treated as stale");
    check(!vpn::recovery_is_stale(100, 0),
          "no archived stop is not stale");
}

} // namespace

int main() {
    test_identity();
    test_stale();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "session recovery tests passed\n";
    return 0;
}