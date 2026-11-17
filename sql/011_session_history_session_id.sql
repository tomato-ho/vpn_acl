SET NAMES utf8mb4;

-- 历史会话保留原始 session_id，便于从「会话历史」直接查到该会话的访问记录。
-- 本迁移之前归档的行 session_id 为空，只能按用户名/时间关联。
ALTER TABLE vpn_session_history
  ADD COLUMN session_id CHAR(32) NOT NULL DEFAULT '' AFTER username,
  ADD KEY idx_vpn_session_history_session (session_id);