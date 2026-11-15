#pragma once

#include "vpn/db.h"
#include "vpn/service/admin_read.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vpn::service {

struct GroupRule {
    std::uint32_t id{0};
    std::string rule_type;
    std::string cidr;
    bool enabled{true};
    std::string created_at;
};

struct GroupDetail {
    GroupSummary group;
    std::vector<GroupRule> rules;
};

struct CreateGroupInput {
    std::string name;
    std::string ip_start;
    std::string ip_end;
    std::string description;
};

struct UpdateGroupInput {
    std::optional<std::string> name;
    std::optional<std::string> ip_start;
    std::optional<std::string> ip_end;
    std::optional<std::string> description;
};

struct GroupRuleInput {
    std::string rule_type;
    std::string cidr;
    bool enabled{true};
};

GroupSummary create_group(Db& db,
                          const CreateGroupInput& input,
                          const std::string& operator_name);
GroupSummary update_group(Db& db,
                          std::uint32_t group_id,
                          const UpdateGroupInput& input,
                          const std::string& operator_name);
void delete_group(Db& db,
                  std::uint32_t group_id,
                  const std::string& operator_name);
std::optional<GroupDetail> get_group_detail(Db& db, std::uint32_t group_id);
std::vector<GroupRule> list_group_rules(Db& db, std::uint32_t group_id);
GroupRule add_group_rule(Db& db,
                         std::uint32_t group_id,
                         const GroupRuleInput& input,
                         const std::string& operator_name);
void delete_group_rule(Db& db,
                       std::uint32_t group_id,
                       std::uint32_t rule_id,
                       const std::string& operator_name);
GroupRule update_group_rule(Db& db,
                            std::uint32_t group_id,
                            std::uint32_t rule_id,
                            bool enabled,
                            const std::string& operator_name);

} // namespace vpn::service