#include "vpn/session_marker.h"

#include <unistd.h>

#include <cstdlib>
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

void test_path() {
    check(vpn::session_marker_path("/run/vpn-policyd/policyd.sock", "alice",
                                   "10.9.100.10", "1700000000") ==
              "/run/vpn-policyd/clients/alice@10.9.100.10@1700000000",
          "marker path with connection key");
    check(vpn::session_marker_path("/run/vpn-policyd/policyd.sock", "alice",
                                   "10.9.100.10", "") ==
              "/run/vpn-policyd/clients/alice@10.9.100.10@0",
          "empty connection key falls back to 0");
    check(vpn::session_marker_path("/tmp/x.sock", "a/b", "1.2.3.4", "7") ==
              "/tmp/clients/a_b@1.2.3.4@7",
          "marker path sanitizes slashes");
    check(vpn::session_marker_path("policyd.sock", "alice", "10.0.0.1", "1") ==
              "./clients/alice@10.0.0.1@1",
          "marker path without directory");
}

void test_roundtrip() {
    char dir[] = "/tmp/vpn-marker-XXXXXX";
    char* made = ::mkdtemp(dir);
    if (made == nullptr) {
        check(false, "mkdtemp failed");
        return;
    }
    const std::string base(made);
    const std::string socket = base + "/policyd.sock";

    const std::string old_path =
        vpn::session_marker_path(socket, "alice", "10.9.100.10", "100");
    const std::string new_path =
        vpn::session_marker_path(socket, "alice", "10.9.100.10", "200");

    check(vpn::write_session_marker(old_path, "oldsession"), "write old marker");
    check(vpn::write_session_marker(new_path, "newsession"), "write new marker");

    // 每个连接只读自己的 marker：旧连接不会读到新连接的 id
    check(vpn::read_session_marker(old_path) == "oldsession",
          "old marker keeps own session id");
    check(vpn::read_session_marker(new_path) == "newsession",
          "new marker keeps own session id");

    // reconcile 恢复时按 user@ip 取最新一个
    check(vpn::find_session_marker(socket, "alice", "10.9.100.10") ==
              "newsession",
          "find_session_marker returns newest");
    check(vpn::find_session_marker(socket, "bob", "10.9.100.11").empty(),
          "find_session_marker missing is empty");

    ::unlink(old_path.c_str());
    ::unlink(new_path.c_str());
    ::rmdir((base + "/clients").c_str());
    ::rmdir(base.c_str());
}

} // namespace

int main() {
    test_path();
    test_roundtrip();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "session marker tests passed\n";
    return 0;
}