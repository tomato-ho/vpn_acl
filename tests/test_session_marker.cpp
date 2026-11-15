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
                                   "10.9.100.10") ==
              "/run/vpn-policyd/clients/alice@10.9.100.10",
          "marker path");
    check(vpn::session_marker_path("/tmp/x.sock", "a/b", "1.2.3.4") ==
              "/tmp/clients/a_b@1.2.3.4",
          "marker path sanitizes slashes");
    check(vpn::session_marker_path("policyd.sock", "alice", "10.0.0.1") ==
              "./clients/alice@10.0.0.1",
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
    const std::string path = vpn::session_marker_path(
        base + "/policyd.sock", "alice", "10.9.100.10");

    check(vpn::write_session_marker(path, "abc123"), "write marker");
    check(vpn::read_session_marker(path) == "abc123", "read marker");
    check(vpn::read_session_marker(path + ".missing").empty(),
          "missing marker is empty");

    ::unlink(path.c_str());
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