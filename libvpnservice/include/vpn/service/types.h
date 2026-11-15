#pragma once

#include <cstdint>
#include <vector>

namespace vpn::service {

struct PageRequest {
    std::uint32_t page{1};
    std::uint32_t page_size{50};
};

template <typename T>
struct PagedResult {
    std::vector<T> items;
    std::uint64_t total{0};
    std::uint32_t page{1};
    std::uint32_t page_size{50};
};

} // namespace vpn::service