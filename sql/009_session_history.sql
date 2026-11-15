SET NAMES utf8mb4;

-- 已结束会话的历史归档（替代 radacct）。
-- vpn_sessions 只保留在线会话，断开时由 vpn-policyd 归档到这里。
CREATE TABLE IF NOT EXISTS vpn_session_history (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  virtual_ip VARCHAR(45) NOT NULL DEFAULT '',
  remote_ip VARCHAR(45) NOT NULL DEFAULT '',
  acct_session_id VARCHAR(64) NOT NULL DEFAULT '',
  start_time DATETIME NOT NULL,
  stop_time DATETIME NOT NULL,
  duration_seconds INT UNSIGNED NOT NULL DEFAULT 0,
  bytes_in BIGINT UNSIGNED NOT NULL DEFAULT 0,
  bytes_out BIGINT UNSIGNED NOT NULL DEFAULT 0,
  terminate_cause VARCHAR(32) NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  UNIQUE KEY uk_vpn_session_history_acct (acct_session_id),
  KEY idx_vpn_session_history_start (start_time),
  KEY idx_vpn_session_history_user (username, start_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;