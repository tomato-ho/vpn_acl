SET NAMES utf8mb4;

-- VPN 用户没有自助改密入口，密码完全由管理员维护；
-- must_change_password 只记录不生效，移除该字段。
ALTER TABLE vpn_users DROP COLUMN must_change_password;