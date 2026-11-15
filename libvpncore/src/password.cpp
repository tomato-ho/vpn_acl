#include "vpn/password.h"

#include "vpn/util.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace vpn {
namespace {

std::vector<unsigned char> random_bytes(std::size_t length) {
    std::vector<unsigned char> buffer(length);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return buffer;
}

std::vector<unsigned char> derive_key(const std::string& password,
                                      const std::vector<unsigned char>& salt,
                                      int iterations,
                                      std::size_t key_length) {
    std::vector<unsigned char> key(key_length);
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt.data(),
                          static_cast<int>(salt.size()),
                          iterations,
                          EVP_sha256(),
                          static_cast<int>(key_length),
                          key.data()) != 1) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
    return key;
}

int parse_iterations(const std::string& value) {
    std::size_t consumed = 0;
    int iterations = 0;
    try {
        iterations = std::stoi(value, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error("invalid PBKDF2 iteration count");
    }
    if (consumed != value.size() || iterations <= 0) {
        throw std::runtime_error("invalid PBKDF2 iteration count");
    }
    return iterations;
}

} // namespace

std::string base64_encode(const unsigned char* data, std::size_t length) {
    if (length == 0) {
        return {};
    }
    std::string output;
    output.resize(4 * ((length + 2) / 3));
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&output[0]),
        data,
        static_cast<int>(length));
    if (written < 0) {
        throw std::runtime_error("base64 encode failed");
    }
    output.resize(static_cast<std::size_t>(written));
    return output;
}

std::vector<unsigned char> base64_decode(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    std::vector<unsigned char> output(3 * value.size() / 4 + 4);
    const int written = EVP_DecodeBlock(
        output.data(),
        reinterpret_cast<const unsigned char*>(value.data()),
        static_cast<int>(value.size()));
    if (written < 0) {
        throw std::runtime_error("base64 decode failed");
    }

    std::size_t padding = 0;
    if (!value.empty() && value.back() == '=') {
        ++padding;
    }
    if (value.size() >= 2 && value[value.size() - 2] == '=') {
        ++padding;
    }
    if (static_cast<std::size_t>(written) < padding) {
        throw std::runtime_error("invalid base64 padding");
    }
    output.resize(static_cast<std::size_t>(written) - padding);
    return output;
}

std::string pbkdf2_sha256_freeradius(const std::string& password,
                                     int iterations) {
    const auto salt = random_bytes(16);
    const auto key = derive_key(password, salt, iterations, 32);
    return std::to_string(iterations) + "$" +
           base64_encode(salt.data(), salt.size()) + "$" +
           base64_encode(key.data(), key.size());
}

std::string pbkdf2_sha256_freeradius_header(const std::string& password,
                                            int iterations) {
    return "{PBKDF2-SHA256}" + pbkdf2_sha256_freeradius(password, iterations);
}

std::string pbkdf2_sha256_admin(const std::string& password,
                                int iterations) {
    return "pbkdf2-sha256$" + pbkdf2_sha256_freeradius(password, iterations);
}

std::string pbkdf2_sha256_user(const std::string& password, int iterations) {
    return "pbkdf2-sha256$" + pbkdf2_sha256_freeradius(password, iterations);
}

bool verify_admin_password(const std::string& password,
                           const std::string& encoded) {
    try {
        const auto parts = split(encoded, '$');
        if (parts.size() != 4 || parts[0] != "pbkdf2-sha256") {
            return false;
        }
        const int iterations = parse_iterations(parts[1]);
        const auto salt = base64_decode(parts[2]);
        const auto expected = base64_decode(parts[3]);
        const auto actual = derive_key(password, salt, iterations, expected.size());
        if (actual.size() != expected.size()) {
            return false;
        }
        return CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0;
    } catch (const std::exception&) {
        return false;
    }
}

bool verify_user_password(const std::string& password,
                          const std::string& encoded) {
    static const std::string kFreeRadiusPrefix = "{PBKDF2-SHA256}";
    if (encoded.compare(0, kFreeRadiusPrefix.size(), kFreeRadiusPrefix) == 0) {
        return verify_admin_password(
            password,
            "pbkdf2-sha256$" + encoded.substr(kFreeRadiusPrefix.size()));
    }
    return verify_admin_password(password, encoded);
}

} // namespace vpn