#pragma once

#include "vpn/nft.h"
#include "vpn/types.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vpn {

struct NftState;

struct NftSessionUpdate {
    std::string username;
    std::uint32_t virtual_ip{0};
    bool remove{false};
    std::vector<Cidr> allow;
    std::vector<Service> services;
};

struct NftBatchStats {
    std::size_t applied{0};
    std::size_t removed{0};
    std::size_t nft_calls{0};
};

struct NftBatchPlan {
    std::string script;
    std::vector<std::string> deleted_chains;
    std::size_t applied{0};
    std::size_t removed{0};
};

NftBatchPlan plan_nft_batch(const std::string& table,
                            const NftState& current,
                            const std::vector<NftSessionUpdate>& updates,
                            std::string* error);

} // namespace vpn