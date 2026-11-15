#include "vpn/service/openvpn_status.h"

#include <unistd.h>

#include <fstream>
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

const char* kStatus =
    "TITLE,OpenVPN 2.7.8 x86_64-redhat-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]\n"
    "TIME,2026-11-11 15:31:10,1794382270\n"
    "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\n"
    "CLIENT_LIST,testvpn,udp4:114.253.9.70:56596,10.8.0.2,,661829986,168920591,2026-11-10 19:48:21,1794311301,testvpn,9,0,AES-256-GCM\n"
    "HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)\n"
    "ROUTING_TABLE,10.8.0.2,testvpn,udp4:114.253.9.70:56596,2026-11-11 15:30:58,1794382258\n"
    "GLOBAL_STATS,Max bcast/mcast queue length,1\n"
    "GLOBAL_STATS,dco_enabled,0\n"
    "END\n";

void test_real_status() {
    char path[] = "/tmp/vpn-service-status-test-XXXXXX";
    const int fd = ::mkstemp(path);
    check(fd >= 0, "mkstemp");
    if (fd < 0) {
        return;
    }
    ::close(fd);

    {
        std::ofstream output(path, std::ios::trunc);
        output << kStatus;
    }

    const auto snapshot = vpn::service::parse_openvpn_status(path);
    ::unlink(path);

    check(snapshot.valid, "status snapshot is valid");
    check(snapshot.clients.size() == 1, "one status client");
    const auto found = snapshot.clients.find("10.8.0.2");
    check(found != snapshot.clients.end(), "virtual IP parsed");
    if (found == snapshot.clients.end()) {
        return;
    }

    check(found->second.username == "testvpn", "username parsed");
    check(found->second.virtual_ip == "10.8.0.2", "virtual IP value");
    check(found->second.client_id == "9", "client ID parsed");
    check(found->second.bytes_received == 661829986, "bytes received parsed");
    check(found->second.bytes_sent == 168920591, "bytes sent parsed");
}

void test_missing_status() {
    const auto snapshot = vpn::service::parse_openvpn_status(
        "/tmp/does-not-exist-vpn-service-status");
    check(!snapshot.valid, "missing status is invalid");
    check(snapshot.clients.empty(), "missing status has no clients");
}

} // namespace

int main() {
    test_real_status();
    test_missing_status();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "service status tests passed\n";
    return 0;
}