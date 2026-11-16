#include "vpn/config.h"
#include "vpn/ipc.h"
#include "vpn/session_marker.h"
#include "vpn/util.h"

#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

using namespace vpn;

std::string get_env(const char* name) {
    const char* value = std::getenv(name);
    return value ? value : "";
}

std::uint64_t parse_counter(const std::string& value) {
    if (value.empty()) {
        return 0;
    }
    std::size_t consumed = 0;
    unsigned long long parsed = 0;
    try {
        parsed = std::stoull(value, &consumed, 10);
    } catch (const std::exception&) {
        return 0;
    }
    return consumed == value.size() ? parsed : 0;
}

} // namespace

int main() {
    try {
        std::string username = get_env("common_name");
        if (username.empty()) {
            username = get_env("username");
        }
        if (username.empty()) {
            return 0;
        }

        const std::string config_path =
            resolve_config_path("/etc/vpn-policy/config");
        if (!config_file_exists(config_path)) {
            std::cerr << "vpn-client-disconnect: config file not found\n";
            return 0;
        }
        const Config config = Config::load(config_path);
        const std::string socket_path =
            config.get("socket_path", "/run/vpn-policyd/policyd.sock");

        IpcFields fields;
        fields["username"] = username;
        const std::string time_unix = get_env("time_unix");
        const std::string virtual_ip = get_env("ifconfig_pool_remote_ip");
        if (!virtual_ip.empty()) {
            fields["virtual_ip"] = virtual_ip;

            // 优先用 connect hook 留下的 session_id 精确匹配，避免 start_time
            // 在"同用户同 IP 快速重连"时匹配到错误会话。
            const std::string marker = session_marker_path(
                socket_path, username, virtual_ip, time_unix);
            const std::string session_id = read_session_marker(marker);
            if (!session_id.empty()) {
                fields["session_id"] = session_id;
                ::unlink(marker.c_str());
            }
        }
        if (!time_unix.empty()) {
            fields["start_time"] = time_unix;
        }
        fields["bytes_in"] = std::to_string(parse_counter(get_env("bytes_received")));
        fields["bytes_out"] = std::to_string(parse_counter(get_env("bytes_sent")));
        fields["session_time"] = std::to_string(parse_counter(get_env("time_duration")));

        std::string response;
        std::string error;
        if (!ipc_request(socket_path, "DISCONNECT", fields, &response, &error)) {
            std::cerr << "vpn-client-disconnect: " << error << "\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "vpn-client-disconnect: " << error.what() << "\n";
        return 0;
    }
}