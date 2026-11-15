#pragma once

#include "nft_batch.h"

#include "vpn/nft.h"
#include "vpn/types.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace vpn {

struct NftState {
    std::map<std::string, std::string> user_fwd;
    std::map<std::string, std::string> user_in;
    std::set<std::string> chains;
};

class NftManager {
public:
    NftManager(std::string nft_bin,
               std::string table,
               std::string tun_iface,
               std::string work_dir,
               bool dry_run);

    bool ensure_base(std::string* error);
    bool check_base(std::string* error);
    bool table_exists();
    bool apply_updates(const std::vector<NftSessionUpdate>& updates,
                       NftBatchStats* stats,
                       std::string* error);
    bool apply_session(const std::string& username,
                       std::uint32_t virtual_ip,
                       const std::vector<Cidr>& allow,
                       const std::vector<Service>& services,
                       std::string* error);
    bool remove_session(const std::string& username,
                        std::uint32_t virtual_ip,
                        std::string* error);
    bool read_state(NftState* state, std::string* error);
    bool cleanup_orphans(const std::set<std::string>& keep_ips,
                         const std::set<std::string>& keep_chains,
                         std::size_t* removed_elements,
                         std::size_t* removed_chains,
                         std::string* error);

private:
    bool run_script(const std::string& script,
                    std::string* error,
                    bool quiet = false,
                    bool check_only = false);
    bool run_args(const std::vector<std::string>& args,
                  std::string* error,
                  bool quiet = false);
    bool run_capture(const std::vector<std::string>& args,
                     std::string* output,
                     std::string* error);

    std::string nft_bin_;
    std::string table_;
    std::string tun_iface_;
    std::string work_dir_;
    bool dry_run_{false};
};

} // namespace vpn