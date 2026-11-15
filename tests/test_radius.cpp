#include "vpn/radius.h"

#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        ++failures;
    }
}

std::string hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const std::uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return out.str();
}

void expect_hex(const std::vector<std::uint8_t>& actual,
                const std::string& expected,
                const std::string& message) {
    const std::string value = hex(actual);
    if (value != expected) {
        std::cerr << "FAIL: " << message << "\n  expected: " << expected
                  << "\n  actual:   " << value << "\n";
        ++failures;
    }
}

vpn::AcctRecord sample_record() {
    vpn::AcctRecord record;
    record.username = "alice";
    record.session_id = "vpn-5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5";
    record.framed_ip = 0x0a08000a;   // 10.8.0.10
    record.nas_ip = 0xc0a8646d;      // 192.168.100.109
    record.calling_station_id = "203.0.113.9";
    record.session_time = 120;
    record.input_octets = (1ULL << 32) + 5;
    record.output_octets = 200;
    record.terminate_cause = 1;
    return record;
}

constexpr std::uint32_t kEventTimestamp = 1700000000;
const std::string kSecret = "testing123";

void test_start_request() {
    std::string error;
    const auto request = vpn::build_accounting_request(
        7, sample_record(), vpn::AcctStatus::Start, kEventTimestamp, 0,
        kSecret, &error);
    check(error.empty(), "start request builds without error");
    check(request.identifier == 7, "start request identifier");
    expect_hex(request.bytes,
               "040700846e9fc05959798690b4a709e4d623d2c22806000000010107616c6963652c2676706e2d356630633164326533613462356336643765386639306131623263336434653508060a08000a0406c0a8646d3d06000000050606000000020706000000011c0d3230332e302e3131332e3937066553f1002d0600000001290600000000",
               "start request bytes");
}

void test_stop_request() {
    std::string error;
    const auto request = vpn::build_accounting_request(
        8, sample_record(), vpn::AcctStatus::Stop, kEventTimestamp, 0,
        kSecret, &error);
    check(error.empty(), "stop request builds without error");
    expect_hex(request.bytes,
               "040800a22a5de83c6ca6e0b8432dd6d2fda274c82806000000020107616c6963652c2676706e2d356630633164326533613462356336643765386639306131623263336434653508060a08000a0406c0a8646d3d06000000050606000000020706000000011c0d3230332e302e3131332e3937066553f1002e06000000782a06000000053406000000012b06000000c8350600000000310600000001290600000000",
               "stop request bytes");
}

void test_interim_request() {
    std::string error;
    const auto request = vpn::build_accounting_request(
        9, sample_record(), vpn::AcctStatus::Interim, kEventTimestamp, 4,
        kSecret, &error);
    check(error.empty(), "interim request builds without error");
    expect_hex(request.bytes,
               "0409009c7a1730da82125943f142fcb82005791e2806000000030107616c6963652c2676706e2d356630633164326533613462356336643765386639306131623263336434653508060a08000a0406c0a8646d3d06000000050606000000020706000000011c0d3230332e302e3131332e3937066553f1002e06000000782a06000000053406000000012b06000000c8350600000000290600000004",
               "interim request bytes");
}

void test_response_verification() {
    std::string error;
    const auto request = vpn::build_accounting_request(
        7, sample_record(), vpn::AcctStatus::Start, kEventTimestamp, 0,
        kSecret, &error);

    std::vector<std::uint8_t> response;
    const std::string response_hex = "0507001477e9b630e3502bceb01d5e128d7c195e";
    for (std::size_t i = 0; i < response_hex.size(); i += 2) {
        response.push_back(static_cast<std::uint8_t>(
            std::stoul(response_hex.substr(i, 2), nullptr, 16)));
    }

    check(vpn::verify_accounting_response(response, request, kSecret, &error),
          "valid response is accepted");

    auto tampered = response;
    tampered[4] ^= 0xff;
    check(!vpn::verify_accounting_response(tampered, request, kSecret, &error),
          "tampered authenticator is rejected");

    auto wrong_id = response;
    wrong_id[1] = static_cast<std::uint8_t>(wrong_id[1] + 1);
    check(!vpn::verify_accounting_response(wrong_id, request, kSecret, &error),
          "wrong identifier is rejected");

    auto wrong_code = response;
    wrong_code[0] = 2;
    check(!vpn::verify_accounting_response(wrong_code, request, kSecret, &error),
          "wrong code is rejected");

    std::vector<std::uint8_t> short_packet(response.begin(),
                                           response.begin() + 12);
    check(!vpn::verify_accounting_response(short_packet, request, kSecret,
                                           &error),
          "short response is rejected");

    check(!vpn::verify_accounting_response(response, request, "other-secret",
                                           &error),
          "wrong secret is rejected");
}

void test_limits() {
    std::string error;
    vpn::AcctRecord record = sample_record();
    record.username = std::string(300, 'a');
    const auto request = vpn::build_accounting_request(
        1, record, vpn::AcctStatus::Start, kEventTimestamp, 0, kSecret,
        &error);
    check(request.bytes.empty(), "overlong username is rejected");
    check(!error.empty(), "overlong username reports an error");

    vpn::RadiusServerConfig config;
    config.secret.clear();
    bool threw = false;
    try {
        vpn::RadiusClient client(config);
    } catch (const std::exception&) {
        threw = true;
    }
    check(threw, "empty radius_secret is rejected");
}

} // namespace

int main() {
    test_start_request();
    test_stop_request();
    test_interim_request();
    test_response_verification();
    test_limits();

    if (failures != 0) {
        std::cerr << failures << " radius test(s) failed\n";
        return 1;
    }
    std::cout << "radius tests passed\n";
    return 0;
}