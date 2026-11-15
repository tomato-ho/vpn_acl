SET NAMES utf8mb4;

-- 自有密码存储：替代 FreeRADIUS 的 radcheck。
-- 格式与 vpn_admins 一致：pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>
ALTER TABLE vpn_users
  ADD COLUMN IF NOT EXISTS password_hash VARCHAR(512) NOT NULL DEFAULT ''
    AFTER must_change_password,
  ADD COLUMN IF NOT EXISTS password_updated_at TIMESTAMP NULL DEFAULT NULL
    AFTER password_hash;

-- 认证审计：替代 radpostauth。由 vpn-auth-check 写入。
CREATE TABLE IF NOT EXISTS vpn_auth_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  remote_ip VARCHAR(45) NOT NULL DEFAULT '',
  success TINYINT(1) NOT NULL,
  reason VARCHAR(128) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_vpn_auth_log_user_time (username, created_at),
  KEY idx_vpn_auth_log_remote_time (remote_ip, created_at),
  KEY idx_vpn_auth_log_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;