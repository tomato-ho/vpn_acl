#pragma once

#include "vpn/types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vpn {

std::optional<uint32_t> parse_ipv4(const std::string& value);
std::string format_ipv4(uint32_t value);

std::optional<Cidr> parse_cidr(const std::string& value);
std::string format_cidr(uint32_t network, uint8_t prefix);
std::string netmask_from_prefix(uint8_t prefix);

bool cidr_contains(const Cidr& outer, uint32_t ip);
bool cidr_contains(const Cidr& outer, const Cidr& inner);
bool ranges_overlap(const Ipv4Range& a, const Ipv4Range& b);

std::vector<Ipv4Range> cidrs_to_ranges(const std::vector<Cidr>& cidrs);
std::vector<Cidr> ranges_to_cidrs(const std::vector<Ipv4Range>& ranges);
std::vector<Cidr> merge_cidrs(const std::vector<Cidr>& cidrs);
std::vector<Cidr> subtract_cidrs(const std::vector<Cidr>& allow,
                                 const std::vector<Cidr>& deny);

} // namespace vpn