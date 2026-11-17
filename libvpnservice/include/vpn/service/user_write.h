#pragma once

#include "vpn/service/admin_read.h"
#include "vpn/types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vpn::service {

struct UserRule {
    std::uint32_t id{0};
    std::string rule_type;
    std::string cidr;
    bool enabled{true};
    std::string created_at;
};

struct UserDetail {
    UserSummary user;
    std::vector<UserRule> rules;
    EffectivePolicy policy;
    std::string policy_error;
};

struct CreateUserInput {
    std::string username;
    std::string display_name;
    std::string group;
    std::string fixed_ip;
    std::string password;
};

struct UpdateUserInput {
    std::optional<std::string> display_name;
    std::optional<std::string> group;
    std::optional<std::string> fixed_ip;
    std::optional<bool> enabled;
};

struct PasswordResetInput {
    std::string password;
};

struct UserRuleInput {
    std::string rule_type;
    std::string cidr;
    bool enabled{true};
};

UserSummary create_user(Db& db,
                        const CreateUserInput& input,
                        const std::string& operator_name);
UserSummary update_user(Db& db,
                        const std::string& username,
                        const UpdateUserInput& input,
                        const std::string& operator_name);
void reset_user_password(Db& db,
                         const std::string& username,
                         const PasswordResetInput& input,
                         const std::string& operator_name);
std::vector<UserRule> list_user_rules(Db& db, const std::string& username);
UserRule add_user_rule(Db& db,
                       const std::string& username,
                       const UserRuleInput& input,
                       const std::string& operator_name);
void delete_user_rule(Db& db,
                      const std::string& username,
                      std::uint32_t rule_id,
                      const std::string& operator_name);
UserRule update_user_rule(Db& db,
                          const std::string& username,
                          std::uint32_t rule_id,
                          bool enabled,
                          const std::string& operator_name);
void delete_user(Db& db,
                 const std::string& username,
                 const std::string& operator_name);
std::optional<UserDetail> get_user_detail(Db& db, const std::string& username);

} // namespace vpn::service