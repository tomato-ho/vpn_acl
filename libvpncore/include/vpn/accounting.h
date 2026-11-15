#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace vpn {

enum class AcctStatus {
    Start,
    Interim,
    Stop,
};

struct AcctRecord {
    std::string username;
    std::string session_id;
    std::uint32_t framed_ip{0};
    std::uint32_t nas_ip{0};
    std::string calling_station_id;
    std::uint32_t session_time{0};
    std::uint64_t input_octets{0};
    std::uint64_t output_octets{0};
    int terminate_cause{0};
};

// RADIUS accounting server connection parameters. The secret is the shared
// secret configured for this NAS in FreeRADIUS clients.conf.
struct RadiusServerConfig {
    std::string host{"127.0.0.1"};
    std::uint16_t port{1813};
    std::string secret;
    std::uint32_t timeout_ms{2000};
    std::uint32_t retries{2};
};

class RadiusClient;

class RadiusAccounting {
public:
    explicit RadiusAccounting(RadiusServerConfig config);
    ~RadiusAccounting();

    RadiusAccounting(const RadiusAccounting&) = delete;
    RadiusAccounting& operator=(const RadiusAccounting&) = delete;

    bool send(AcctStatus status,
              const AcctRecord& record,
              std::string* error = nullptr);

private:
    std::unique_ptr<RadiusClient> client_;
};

} // namespace vpn