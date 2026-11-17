SET NAMES utf8mb4;

-- 访问审计：每个会话 × 每个目标 × allow/deny 一行。
-- 只记录元数据（目标 IP、字节、时间），不采集内容。
CREATE TABLE IF NOT EXISTS vpn_access_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_id CHAR(32) NOT NULL,
  username VARCHAR(64) NOT NULL,
  virtual_ip VARCHAR(15) NOT NULL,
  dest_ip VARCHAR(15) NOT NULL,
  action ENUM('allow','deny') NOT NULL,
  bytes_up BIGINT UNSIGNED NOT NULL DEFAULT 0,
  bytes_down BIGINT UNSIGNED NOT NULL DEFAULT 0,
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uk_vpn_access_log (session_id, dest_ip, action),
  KEY idx_vpn_access_log_user (username, last_seen),
  KEY idx_vpn_access_log_dest (dest_ip, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 采样器的原始计数器快照，用于 policyd 重启后继续做差，
-- 避免把停机期间的增量当成基线丢掉。
CREATE TABLE IF NOT EXISTS vpn_flow_state (
  session_id CHAR(32) NOT NULL,
  dest_ip VARCHAR(15) NOT NULL,
  action ENUM('allow','deny') NOT NULL,
  bytes_up BIGINT UNSIGNED NOT NULL DEFAULT 0,
  bytes_down BIGINT UNSIGNED NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (session_id, dest_ip, action),
  KEY idx_vpn_flow_state_time (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;