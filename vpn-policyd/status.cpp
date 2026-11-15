#include "status.h"

#include "vpn/util.h"

#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace vpn {
namespace {

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

StatusSnapshot parse_openvpn_status(const std::string& path) {
    StatusSnapshot snapshot;
    std::ifstream input(path);
    if (!input) {
        return snapshot;
    }

    std::map<std::string, std::size_t> indexes;
    std::string line;
    bool saw_client_header = false;

    while (std::getline(input, line)) {
        if (line.rfind("HEADER,CLIENT_LIST,", 0) == 0) {
            const auto fields = split(line, ',');
            for (std::size_t i = 2; i < fields.size(); ++i) {
                indexes[trim(fields[i])] = i;
            }
            saw_client_header = true;
            snapshot.valid = true;
            continue;
        }
        if (!saw_client_header || line.rfind("CLIENT_LIST,", 0) != 0) {
            continue;
        }

        const auto fields = split(line, ',');
        const auto field = [&](const std::string& name) -> std::string {
            const auto found = indexes.find(name);
            if (found == indexes.end() || found->second == 0 ||
                found->second - 1 >= fields.size()) {
                return {};
            }
            return fields[found->second - 1];
        };

        StatusClient client;
        client.virtual_ip = trim(field("Virtual Address"));
        if (client.virtual_ip.empty()) {
            continue;
        }
        client.username = trim(field("Username"));
        if (client.username.empty()) {
            client.username = trim(field("Common Name"));
        }
        client.client_id = trim(field("Client ID"));
        client.bytes_received = parse_counter(trim(field("Bytes Received")));
        client.bytes_sent = parse_counter(trim(field("Bytes Sent")));
        snapshot.clients[client.virtual_ip] = client;
    }

    return snapshot;
}

} // namespace vpn