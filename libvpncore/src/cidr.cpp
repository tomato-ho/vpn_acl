#include "vpn/cidr.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace vpn {

std::optional<uint32_t> parse_ipv4(const std::string& value) {
    in_addr address{};
    if (inet_pton(AF_INET, value.c_str(), &address) != 1) {
        return std::nullopt;
    }
    return ntohl(address.s_addr);
}

std::string format_ipv4(uint32_t value) {
    in_addr address{};
    address.s_addr = htonl(value);
    char buffer[INET_ADDRSTRLEN]{};
    if (!inet_ntop(AF_INET, &address, buffer, sizeof(buffer))) {
        throw std::runtime_error("failed to format IPv4 address");
    }
    return std::string(buffer);
}

std::optional<Cidr> parse_cidr(const std::string& value) {
    const auto slash = value.find('/');
    if (slash != std::string::npos && value.find('/', slash + 1) != std::string::npos) {
        return std::nullopt;
    }

    const std::string ip_text = value.substr(0, slash);
    const auto ip = parse_ipv4(ip_text);
    if (!ip) {
        return std::nullopt;
    }

    unsigned int prefix = 32;
    if (slash != std::string::npos) {
        const std::string prefix_text = value.substr(slash + 1);
        if (prefix_text.empty()) {
            return std::nullopt;
        }
        std::size_t consumed = 0;
        try {
            prefix = static_cast<unsigned int>(std::stoul(prefix_text, &consumed, 10));
        } catch (const std::exception&) {
            return std::nullopt;
        }
        if (consumed != prefix_text.size() || prefix > 32) {
            return std::nullopt;
        }
    }

    const uint32_t mask = prefix == 0
                              ? 0u
                              : (0xFFFFFFFFu << (32 - prefix));
    const uint32_t network = *ip & mask;
    const uint64_t size = prefix == 0 ? (1ULL << 32) : (1ULL << (32 - prefix));

    Cidr cidr;
    cidr.network = network;
    cidr.prefix = static_cast<uint8_t>(prefix);
    cidr.start = network;
    cidr.end = static_cast<uint32_t>(network + size - 1);
    return cidr;
}

std::string format_cidr(uint32_t network, uint8_t prefix) {
    return format_ipv4(network) + "/" + std::to_string(prefix);
}

std::string netmask_from_prefix(uint8_t prefix) {
    if (prefix > 32) {
        throw std::runtime_error("invalid IPv4 prefix");
    }
    const uint32_t mask = prefix == 0
                              ? 0u
                              : (0xFFFFFFFFu << (32 - prefix));
    return format_ipv4(mask);
}

std::string Cidr::to_string() const {
    return format_cidr(network, prefix);
}

bool cidr_contains(const Cidr& outer, uint32_t ip) {
    return ip >= outer.start && ip <= outer.end;
}

bool cidr_contains(const Cidr& outer, const Cidr& inner) {
    return inner.start >= outer.start && inner.end <= outer.end;
}

bool ranges_overlap(const Ipv4Range& a, const Ipv4Range& b) {
    return a.start <= b.end && b.start <= a.end;
}

std::vector<Ipv4Range> cidrs_to_ranges(const std::vector<Cidr>& cidrs) {
    std::vector<Ipv4Range> ranges;
    ranges.reserve(cidrs.size());
    for (const auto& cidr : cidrs) {
        ranges.push_back(Ipv4Range{cidr.start, cidr.end});
    }
    return ranges;
}

std::vector<Cidr> ranges_to_cidrs(const std::vector<Ipv4Range>& ranges) {
    std::vector<Cidr> result;
    for (const auto& range : ranges) {
        uint64_t current = range.start;
        const uint64_t end = range.end;
        while (current <= end) {
            const uint32_t align_bits =
                current == 0 ? 32u : static_cast<uint32_t>(__builtin_ctzll(current));
            const uint64_t remaining = end - current + 1;
            const uint32_t size_bits =
                static_cast<uint32_t>(63u - __builtin_clzll(remaining));
            const uint32_t bits = std::min(align_bits, size_bits);
            const uint64_t block_size = 1ULL << bits;

            Cidr cidr;
            cidr.network = static_cast<uint32_t>(current);
            cidr.prefix = static_cast<uint8_t>(32 - bits);
            cidr.start = static_cast<uint32_t>(current);
            cidr.end = static_cast<uint32_t>(current + block_size - 1);
            result.push_back(cidr);
            current += block_size;
        }
    }
    return result;
}

std::vector<Cidr> merge_cidrs(const std::vector<Cidr>& cidrs) {
    auto ranges = cidrs_to_ranges(cidrs);
    if (ranges.empty()) {
        return {};
    }

    std::sort(ranges.begin(), ranges.end(), [](const Ipv4Range& a, const Ipv4Range& b) {
        if (a.start != b.start) {
            return a.start < b.start;
        }
        return a.end < b.end;
    });

    std::vector<Ipv4Range> merged;
    merged.push_back(ranges.front());
    for (std::size_t i = 1; i < ranges.size(); ++i) {
        auto& last = merged.back();
        const uint64_t next_after_last = static_cast<uint64_t>(last.end) + 1;
        if (ranges[i].start <= next_after_last) {
            last.end = std::max(last.end, ranges[i].end);
        } else {
            merged.push_back(ranges[i]);
        }
    }

    return ranges_to_cidrs(merged);
}

std::vector<Cidr> subtract_cidrs(const std::vector<Cidr>& allow,
                                 const std::vector<Cidr>& deny) {
    auto allow_ranges = cidrs_to_ranges(merge_cidrs(allow));
    const auto deny_ranges = cidrs_to_ranges(merge_cidrs(deny));
    std::vector<Ipv4Range> result;

    for (const auto& allowed : allow_ranges) {
        uint64_t cursor = allowed.start;
        const uint64_t end = allowed.end;
        bool exhausted = false;

        for (const auto& blocked : deny_ranges) {
            if (blocked.end < cursor || blocked.start > end) {
                continue;
            }
            if (blocked.start > cursor) {
                result.push_back(Ipv4Range{
                    static_cast<uint32_t>(cursor),
                    static_cast<uint32_t>(blocked.start - 1)});
            }
            cursor = static_cast<uint64_t>(blocked.end) + 1;
            if (cursor > end) {
                exhausted = true;
                break;
            }
        }

        if (!exhausted && cursor <= end) {
            result.push_back(Ipv4Range{
                static_cast<uint32_t>(cursor),
                static_cast<uint32_t>(end)});
        }
    }

    if (result.empty()) {
        return {};
    }
    return ranges_to_cidrs(result);
}

} // namespace vpn