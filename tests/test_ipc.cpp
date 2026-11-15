#include "vpn/ipc.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        ++failures;
    }
}

void test_stats_response() {
    const std::string path =
        "/tmp/vpn-ipc-test-" + std::to_string(::getpid()) + ".sock";
    ::unlink(path.c_str());

    const int server = ::socket(AF_UNIX, SOCK_STREAM, 0);
    check(server >= 0, "create server socket");
    if (server < 0) {
        return;
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                  path.c_str());
    check(::bind(server, reinterpret_cast<sockaddr*>(&address),
                 sizeof(address)) == 0,
          "bind server socket");
    check(::listen(server, 1) == 0, "listen server socket");

    std::thread worker([server]() {
        const int fd = ::accept(server, nullptr, nullptr);
        if (fd < 0) {
            return;
        }
        std::string request;
        char buffer[256];
        while (request.find("END\n") == std::string::npos) {
            const ssize_t received = ::read(fd, buffer, sizeof(buffer));
            if (received <= 0) {
                ::close(fd);
                return;
            }
            request.append(buffer, static_cast<std::size_t>(received));
        }
        vpn::ipc_write_response(fd, true,
                                "refresh_total=3;refresh_errors=0");
        ::close(fd);
    });

    std::string response;
    std::string error;
    const bool ok =
        vpn::ipc_request(path, "STATS", {}, &response, &error, 2);
    worker.join();
    ::close(server);
    ::unlink(path.c_str());

    check(ok, "STATS request succeeds");
    check(response == "refresh_total=3;refresh_errors=0",
          "STATS response payload parsed");
    check(error.empty(), "STATS request has no error");
}

} // namespace

int main() {
    test_stats_response();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "ipc tests passed\n";
    return 0;
}