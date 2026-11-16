#include "vpn/cidr.h"
#include "vpn/config.h"
#include "vpn/db.h"
#include "vpn/db_config.h"
#include "vpn/ipc.h"
#include "vpn/policy_store.h"
#include "vpn/session_marker.h"
#include "vpn/util.h"
#include "vpn/validation.h"

#include <openssl/rand.h>

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace vpn;

// 获取环境变量的值，如果不存在则返回空字符串
std::string get_env(const char* name) {
    const char* value = std::getenv(name);
    return value ? value : "";
}

std::string random_hex(std::size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    std::ostringstream out;
    out << std::hex;
    for (const unsigned char value : buffer) {
        out << (value < 16 ? "0" : "") << static_cast<int>(value);
    }
    return out.str();
}

std::string join_cidrs(const std::vector<Cidr>& cidrs) {
    std::ostringstream out;
    bool first = true;
    for (const auto& cidr : cidrs) {
        if (!first) {
            out << ',';
        }
        out << cidr.to_string();
        first = false;
    }
    return out.str();
}

std::string join_services(const std::vector<Service>& services) {
    std::ostringstream out;
    bool first = true;
    for (const auto& service : services) {
        if (!first) {
            out << ',';
        }
        out << service.to_string();
        first = false;
    }
    return out.str();
}

void write_client_config(const std::string& path,
                         const EffectivePolicy& policy,
                         const ValidationConfig& validation) {
    std::ofstream output(path, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to open client config: " + path);
    }
    const std::string netmask =
        validation.has_tunnel_network
            ? netmask_from_prefix(validation.tunnel_network.prefix)
            : "255.255.255.0";
    output << "ifconfig-push " << format_ipv4(policy.fixed_ip) << ' '
           << netmask << '\n';
    for (const auto& route : policy.push_routes) {
        output << "push \"route " << format_ipv4(route.network) << ' '
               << netmask_from_prefix(route.prefix) << "\"\n";
    }
    output.flush();
    if (!output) {
        throw std::runtime_error("failed to write client config: " + path);
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            throw std::runtime_error("missing OpenVPN client config path");
        }
        const std::string client_config_path = argv[argc - 1];

        std::string username = get_env("common_name");
        if (username.empty()) {
            username = get_env("username");
        }
        if (username.empty()) {
            throw std::runtime_error("missing common_name");
        }

        std::string remote_ip = get_env("untrusted_ip");
        if (remote_ip.empty()) {
            remote_ip = get_env("trusted_ip");
        }
        if (remote_ip.empty()) {
            remote_ip = "unknown";
        }

        const std::string config_path =
            resolve_config_path("/etc/vpn-policy/config");
        if (!config_file_exists(config_path)) {
            throw std::runtime_error("config file not found: " + config_path);
        }
        const Config config = Config::load(config_path);
        const std::string socket_path =
            config.get("socket_path", "/run/vpn-policyd/policyd.sock");

        Db db(make_db_config(config));
        db.connect();

        const auto data = load_policy(db, username);
        const auto validation = load_validation_config(db);
        const auto policy = compute_effective_policy(data, validation);

        const std::string session_id = random_hex(16);
        const std::string time_unix = get_env("time_unix");
        IpcFields fields;
        fields["username"] = username;
        fields["session_id"] = session_id;
        fields["acct_session_id"] = "vpn-" + session_id;
        fields["virtual_ip"] = format_ipv4(policy.fixed_ip);
        fields["remote_ip"] = remote_ip;
        fields["allow"] = join_cidrs(policy.push_routes);
        fields["services"] = join_services(policy.services);

        if (!time_unix.empty()) {
            fields["start_time"] = time_unix;
        }

        std::string response;
        std::string error;
        if (!ipc_request(socket_path, "CONNECT", fields, &response, &error)) {
            throw std::runtime_error("policyd connect failed: " + error);
        }

        try {
            write_client_config(client_config_path, policy, validation);
        } catch (const std::exception& write_error) {
            IpcFields rollback;
            rollback["username"] = username;
            rollback["session_id"] = session_id;
            rollback["virtual_ip"] = format_ipv4(policy.fixed_ip);
            std::string ignored_response;
            std::string ignored_error;
            ipc_request(socket_path, "DISCONNECT", rollback, &ignored_response,
                        &ignored_error);
            throw std::runtime_error(write_error.what());
        }

        const std::string marker =
            session_marker_path(socket_path, username,
                                format_ipv4(policy.fixed_ip), time_unix);
        if (!write_session_marker(marker, session_id)) {
            std::cerr << "vpn-client-connect: warning: cannot write session "
                         "marker "
                      << marker << "\n";
        }

        std::cout << "connected " << username << " " << format_ipv4(policy.fixed_ip)
                  << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "vpn-client-connect: " << error.what() << "\n";
        return 1;
    }
}