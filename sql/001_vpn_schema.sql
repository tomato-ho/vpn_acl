SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS vpn_admins (
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(512) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_groups (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(64) NOT NULL,
  ip_start VARCHAR(15) NOT NULL,
  ip_end VARCHAR(15) NOT NULL,
  description VARCHAR(255) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_vpn_groups_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_users (
  username VARCHAR(64) NOT NULL,
  display_name VARCHAR(128) NOT NULL DEFAULT '',
  group_id INT UNSIGNED DEFAULT NULL,
  fixed_ip VARCHAR(15) DEFAULT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  must_change_password TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (username),
  UNIQUE KEY uk_vpn_users_fixed_ip (fixed_ip),
  KEY idx_vpn_users_group (group_id),
  CONSTRAINT fk_vpn_users_group FOREIGN KEY (group_id)
    REFERENCES vpn_groups (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_group_rules (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  group_id INT UNSIGNED NOT NULL,
  rule_type ENUM('allow','deny') NOT NULL,
  cidr VARCHAR(43) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_vpn_group_rules (group_id, rule_type, cidr),
  CONSTRAINT fk_vpn_group_rules_group FOREIGN KEY (group_id)
    REFERENCES vpn_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_user_rules (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  rule_type ENUM('allow','deny') NOT NULL,
  cidr VARCHAR(43) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_vpn_user_rules (username, rule_type, cidr),
  CONSTRAINT fk_vpn_user_rules_user FOREIGN KEY (username)
    REFERENCES vpn_users (username) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_server_services (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  scope_type ENUM('global','group','user') NOT NULL,
  scope_id VARCHAR(64) NOT NULL DEFAULT '',
  service VARCHAR(64) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_vpn_server_services (scope_type, scope_id, service)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_sessions (
  session_id CHAR(32) NOT NULL,
  username VARCHAR(64) NOT NULL,
  virtual_ip VARCHAR(15) NOT NULL,
  remote_ip VARCHAR(45) NOT NULL DEFAULT '',
  acct_session_id VARCHAR(64) NOT NULL,
  start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  bytes_in BIGINT UNSIGNED NOT NULL DEFAULT 0,
  bytes_out BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (session_id),
  UNIQUE KEY uk_vpn_sessions_virtual_ip (virtual_ip),
  KEY idx_vpn_sessions_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_audit_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  operator VARCHAR(64) NOT NULL DEFAULT 'cli',
  action VARCHAR(64) NOT NULL,
  target VARCHAR(128) NOT NULL DEFAULT '',
  before_json LONGTEXT NULL,
  after_json LONGTEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_vpn_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_policy_version (
  id TINYINT UNSIGNED NOT NULL,
  version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpn_settings (
  name VARCHAR(64) NOT NULL,
  value TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO vpn_policy_version (id, version)
VALUES (1, 1)
ON DUPLICATE KEY UPDATE id = id;

-- 只插入缺失的默认值，绝不覆盖已有配置（install.sh 可能重复执行）。
INSERT IGNORE INTO vpn_settings (name, value) VALUES
  ('allowed_target_networks', '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'),
  ('allowed_service_ips', '10.9.100.1'),
  ('tunnel_network', '10.9.100.0/24'),
  ('max_rules_per_user', '128'),
  ('max_services_per_user', '16');