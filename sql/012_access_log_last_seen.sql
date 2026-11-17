SET NAMES utf8mb4;

-- 访问审计按 last_seen 做时间范围查询和留存清理。
ALTER TABLE vpn_access_log
  ADD KEY idx_vpn_access_log_last_seen (last_seen);