#include "vpn/radius.h"

#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vpn {
namespace {

constexpr std::size_t kHeaderSize = 20;
constexpr std::size_t kMaxPacketSize = 4096;
constexpr std::size_t kMaxAttributeValue = 253;

constexpr std::uint8_t kCodeAccountingRequest = 4;
constexpr std::uint8_t kCodeAccountingResponse = 5;

enum : std::uint8_t {
    kAttrUserName = 1,
    kAttrNasIpAddress = 4,
    kAttrServiceType = 6,
    kAttrFramedProtocol = 7,
    kAttrFramedIpAddress = 8,
    kAttrCallingStationId = 28,
    kAttrAcctStatusType = 40,
    kAttrAcctDelayTime = 41,
    kAttrAcctInputOctets = 42,
    kAttrAcctOutputOctets = 43,
    kAttrAcctSessionId = 44,
    kAttrAcctAuthentic = 45,
    kAttrAcctSessionTime = 46,
    kAttrAcctTerminateCause = 49,
    kAttrAcctInputGigawords = 52,
    kAttrAcctOutputGigawords = 53,
    kAttrEventTimestamp = 55,
    kAttrNasPortType = 61,
};

constexpr std::uint32_t kAcctStatusStart = 1;
constexpr std::uint32_t kAcctStatusStop = 2;
constexpr std::uint32_t kAcctStatusInterim = 3;
constexpr std::uint32_t kAcctAuthenticRadius = 1;
constexpr std::uint32_t kServiceTypeFramed = 2;
constexpr std::uint32_t kFramedProtocolPpp = 1;
constexpr std::uint32_t kNasPortTypeVirtual = 5;
constexpr std::uint32_t kTerminateUserRequest = 1;

bool md5_digest(const std::string& data, std::array<std::uint8_t, 16>* out) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        return false;
    }
    unsigned int length = 0;
    const bool ok = EVP_DigestInit_ex(context, EVP_md5(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(context, out->data(), &length) == 1 &&
                    length == 16;
    EVP_MD_CTX_free(context);
    return ok;
}

void append_u32(std::vector<std::uint8_t>* out,
                std::uint8_t type,
                std::uint32_t value) {
    const std::uint32_t network = htonl(value);
    out->push_back(type);
    out->push_back(6);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&network);
    out->insert(out->end(), bytes, bytes + sizeof(network));
}

bool append_string(std::vector<std::uint8_t>* out,
                   std::uint8_t type,
                   const std::string& value,
                   std::string* error) {
    if (value.size() > kMaxAttributeValue) {
        if (error) {
            *error = "RADIUS attribute " + std::to_string(type) +
                     " exceeds 253 octets";
        }
        return false;
    }
    out->push_back(type);
    out->push_back(static_cast<std::uint8_t>(value.size() + 2));
    out->insert(out->end(), value.begin(), value.end());
    return true;
}

int open_socket(const RadiusServerConfig& config, std::string* error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    const std::string port = std::to_string(config.port);
    addrinfo* result = nullptr;
    const int resolved =
        ::getaddrinfo(config.host.c_str(), port.c_str(), &hints, &result);
    if (resolved != 0) {
        if (error) {
            *error = "cannot resolve radius_server " + config.host + ": " +
                     ::gai_strerror(resolved);
        }
        return -1;
    }

    int fd = -1;
    for (addrinfo* entry = result; entry != nullptr; entry = entry->ai_next) {
        fd = ::socket(entry->ai_family, entry->ai_socktype | SOCK_CLOEXEC,
                      entry->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, entry->ai_addr, entry->ai_addrlen) == 0) {
            break;
        }
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(result);

    if (fd < 0) {
        if (error) {
            *error = "cannot connect to radius_server " + config.host + ":" + port;
        }
        return -1;
    }

    timeval timeout{};
    timeout.tv_sec = static_cast<time_t>(config.timeout_ms / 1000);
    timeout.tv_usec = static_cast<suseconds_t>((config.timeout_ms % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return fd;
}

bool send_all(int fd, const std::vector<std::uint8_t>& data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t written =
            ::send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

} // namespace

RadiusRequest build_accounting_request(std::uint8_t identifier,
                                       const AcctRecord& record,
                                       AcctStatus status,
                                       std::uint32_t event_timestamp,
                                       std::uint32_t acct_delay,
                                       const std::string& secret,
                                       std::string* error) {
    RadiusRequest request;
    std::vector<std::uint8_t> packet(kHeaderSize, 0);
    packet[0] = kCodeAccountingRequest;
    packet[1] = identifier;

    std::uint32_t status_value = kAcctStatusInterim;
    if (status == AcctStatus::Start) {
        status_value = kAcctStatusStart;
    } else if (status == AcctStatus::Stop) {
        status_value = kAcctStatusStop;
    }

    append_u32(&packet, kAttrAcctStatusType, status_value);
    if (!append_string(&packet, kAttrUserName, record.username, error) ||
        !append_string(&packet, kAttrAcctSessionId, record.session_id, error)) {
        return RadiusRequest{};
    }
    append_u32(&packet, kAttrFramedIpAddress, record.framed_ip);
    append_u32(&packet, kAttrNasIpAddress, record.nas_ip);
    append_u32(&packet, kAttrNasPortType, kNasPortTypeVirtual);
    append_u32(&packet, kAttrServiceType, kServiceTypeFramed);
    append_u32(&packet, kAttrFramedProtocol, kFramedProtocolPpp);
    if (!append_string(&packet, kAttrCallingStationId,
                       record.calling_station_id, error)) {
        return RadiusRequest{};
    }
    append_u32(&packet, kAttrEventTimestamp, event_timestamp);

    if (status == AcctStatus::Start) {
        append_u32(&packet, kAttrAcctAuthentic, kAcctAuthenticRadius);
    } else {
        append_u32(&packet, kAttrAcctSessionTime, record.session_time);
        append_u32(&packet, kAttrAcctInputOctets,
                   static_cast<std::uint32_t>(record.input_octets & 0xffffffffu));
        append_u32(&packet, kAttrAcctInputGigawords,
                   static_cast<std::uint32_t>(record.input_octets >> 32));
        append_u32(&packet, kAttrAcctOutputOctets,
                   static_cast<std::uint32_t>(record.output_octets & 0xffffffffu));
        append_u32(&packet, kAttrAcctOutputGigawords,
                   static_cast<std::uint32_t>(record.output_octets >> 32));
    }

    if (status == AcctStatus::Stop) {
        const std::uint32_t cause =
            record.terminate_cause > 0
                ? static_cast<std::uint32_t>(record.terminate_cause)
                : kTerminateUserRequest;
        append_u32(&packet, kAttrAcctTerminateCause, cause);
    }

    append_u32(&packet, kAttrAcctDelayTime, acct_delay);

    if (packet.size() > kMaxPacketSize) {
        if (error) {
            *error = "RADIUS packet exceeds 4096 octets";
        }
        return RadiusRequest{};
    }

    const auto length = static_cast<std::uint16_t>(packet.size());
    packet[2] = static_cast<std::uint8_t>((length >> 8) & 0xff);
    packet[3] = static_cast<std::uint8_t>(length & 0xff);

    std::string material(reinterpret_cast<const char*>(packet.data()),
                         packet.size());
    material += secret;
    std::array<std::uint8_t, 16> digest{};
    if (!md5_digest(material, &digest)) {
        if (error) {
            *error = "MD5 is unavailable";
        }
        return RadiusRequest{};
    }
    std::copy(digest.begin(), digest.end(), packet.begin() + 4);

    request.identifier = identifier;
    request.bytes = std::move(packet);
    return request;
}

bool verify_accounting_response(const std::vector<std::uint8_t>& response,
                                const RadiusRequest& request,
                                const std::string& secret,
                                std::string* error) {
    auto fail = [error](const std::string& message) {
        if (error) {
            *error = message;
        }
        return false;
    };

    if (response.size() < kHeaderSize) {
        return fail("RADIUS response is too short");
    }
    if (response[0] != kCodeAccountingResponse) {
        return fail("unexpected RADIUS response code " +
                    std::to_string(response[0]));
    }
    const std::size_t length =
        (static_cast<std::size_t>(response[2]) << 8) | response[3];
    if (length != response.size()) {
        return fail("RADIUS response length does not match the datagram");
    }
    if (response[1] != request.identifier) {
        return fail("RADIUS response identifier does not match the request");
    }
    if (request.bytes.size() < kHeaderSize) {
        return fail("RADIUS request is invalid");
    }

    std::string material(reinterpret_cast<const char*>(response.data()), 4);
    material.append(
        reinterpret_cast<const char*>(request.bytes.data() + 4), 16);
    material.append(
        reinterpret_cast<const char*>(response.data() + kHeaderSize),
        response.size() - kHeaderSize);
    material += secret;

    std::array<std::uint8_t, 16> digest{};
    if (!md5_digest(material, &digest)) {
        return fail("MD5 is unavailable");
    }
    if (!std::equal(digest.begin(), digest.end(), response.begin() + 4)) {
        return fail("RADIUS response authenticator mismatch");
    }
    return true;
}

RadiusClient::RadiusClient(RadiusServerConfig config)
    : config_(std::move(config)) {
    if (config_.host.empty()) {
        throw std::runtime_error("radius_server is empty");
    }
    if (config_.port == 0) {
        throw std::runtime_error("radius_port is invalid");
    }
    if (config_.secret.empty()) {
        throw std::runtime_error("radius_secret is empty");
    }
    config_.timeout_ms =
        std::clamp<std::uint32_t>(config_.timeout_ms, 100, 60000);
    config_.retries = std::clamp<std::uint32_t>(config_.retries, 0, 10);
}

RadiusClient::~RadiusClient() = default;

bool RadiusClient::send_accounting(AcctStatus status,
                                   const AcctRecord& record,
                                   std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);

    const std::uint32_t event_timestamp =
        static_cast<std::uint32_t>(std::time(nullptr));
    const auto started = std::chrono::steady_clock::now();
    std::string last_error = "radius accounting request failed";

    for (std::uint32_t attempt = 0; attempt <= config_.retries; ++attempt) {
        std::uint32_t delay = 0;
        if (attempt > 0) {
            delay = static_cast<std::uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - started)
                    .count());
        }

        std::string build_error;
        const RadiusRequest request = build_accounting_request(
            next_identifier_++, record, status, event_timestamp, delay,
            config_.secret, &build_error);
        if (request.bytes.empty()) {
            if (error) {
                *error = build_error.empty() ? "failed to build RADIUS request"
                                             : build_error;
            }
            return false;
        }

        std::string socket_error;
        const int fd = open_socket(config_, &socket_error);
        if (fd < 0) {
            last_error = socket_error;
            continue;
        }

        if (!send_all(fd, request.bytes)) {
            last_error = std::string("radius send failed: ") +
                         std::strerror(errno);
            ::close(fd);
            continue;
        }

        std::vector<std::uint8_t> response(kMaxPacketSize);
        const ssize_t received =
            ::recv(fd, response.data(), response.size(), 0);
        const int receive_error = errno;
        ::close(fd);

        if (received < 0) {
            if (receive_error == EAGAIN || receive_error == EWOULDBLOCK) {
                last_error = "radius response timeout";
            } else if (receive_error == EINTR) {
                last_error = "radius receive interrupted";
            } else {
                last_error = std::string("radius receive failed: ") +
                             std::strerror(receive_error);
            }
            continue;
        }

        response.resize(static_cast<std::size_t>(received));
        std::string verify_error;
        if (verify_accounting_response(response, request, config_.secret,
                                       &verify_error)) {
            return true;
        }
        last_error = verify_error;
    }

    if (error) {
        *error = last_error;
    }
    return false;
}

} // namespace vpn