#pragma once

#include "vpn/accounting.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace vpn {

// A fully encoded RADIUS Accounting-Request. The authenticator lives in
// bytes[4..19] and is required to verify the matching response.
struct RadiusRequest {
    std::vector<std::uint8_t> bytes;
    std::uint8_t identifier{0};
};

// Builds an RFC 2866 Accounting-Request. `event_timestamp` is the value of the
// Event-Timestamp attribute and `acct_delay` the Acct-Delay-Time attribute
// (seconds this request has been delayed, used on retransmissions). Returns an
// empty request and fills `error` when the record cannot be encoded.
RadiusRequest build_accounting_request(std::uint8_t identifier,
                                       const AcctRecord& record,
                                       AcctStatus status,
                                       std::uint32_t event_timestamp,
                                       std::uint32_t acct_delay,
                                       const std::string& secret,
                                       std::string* error);

// Validates an Accounting-Response against the request that produced it:
// code, length, identifier and response authenticator.
bool verify_accounting_response(const std::vector<std::uint8_t>& response,
                                const RadiusRequest& request,
                                const std::string& secret,
                                std::string* error);

// Sends accounting requests to a RADIUS server over UDP with retransmission.
// Thread-safe; one instance serializes its own requests.
class RadiusClient {
public:
    explicit RadiusClient(RadiusServerConfig config);
    ~RadiusClient();

    RadiusClient(const RadiusClient&) = delete;
    RadiusClient& operator=(const RadiusClient&) = delete;

    bool send_accounting(AcctStatus status,
                         const AcctRecord& record,
                         std::string* error = nullptr);

private:
    RadiusServerConfig config_;
    std::mutex mutex_;
    std::uint8_t next_identifier_{0};
};

} // namespace vpn