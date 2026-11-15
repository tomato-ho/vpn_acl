-- 修改 OpenVPN 隧道网段（示例：10.9.100.0/24 -> 10.20.0.0/24）
--
-- 使用前必须：
--   1. 先停栈：podman-compose down      （让会话正常归档）
--   2. 同时修改 deploy/openvpn/server.conf 的 server 指令（netmask，不是 CIDR）
--   3. 逐行替换下面的示例值；有多个组/用户时，每个各写一条
--   4. 同步更新宿主的 firewalld masquerade / 回程路由（旧网段 -> 新网段）
--
-- 本文件只包含 DML，全部在一个事务里；任何一步失败都会整体回滚。
-- 执行前请先备份：
--   podman exec vpn-mariadb mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" radius > backup.sql

START TRANSACTION;

-- 1) 隧道网段与允许的网关服务 IP
UPDATE vpn_settings SET value = '10.20.0.0/24' WHERE name = 'tunnel_network';
UPDATE vpn_settings SET value = '10.20.0.1'   WHERE name = 'allowed_service_ips';

-- 2) 组地址池：保持原来的相对位置（多组时逐组写）
UPDATE vpn_groups
   SET ip_start = '10.20.0.10',
       ip_end   = '10.20.0.200'
 WHERE name = 'staff';

-- 3) 用户固定 IP：逐个更新，避免撞 uk_vpn_users_fixed_ip
UPDATE vpn_users SET fixed_ip = '10.20.0.10' WHERE username = 'alice';

-- 4) 指向旧网关的服务（如网关自身的 DNS）
UPDATE vpn_server_services
   SET service = REPLACE(service, '10.9.100.1:', '10.20.0.1:')
 WHERE service LIKE '10.9.100.1:%';

-- 5) 触发策略版本变更（policyd 启动时会重新加载）
UPDATE vpn_policy_version
   SET version = version + 1,
       updated_at = NOW()
 WHERE id = 1;

-- 提交前检查结果：
SELECT name, value FROM vpn_settings
 WHERE name IN ('tunnel_network', 'allowed_service_ips');
SELECT name, ip_start, ip_end FROM vpn_groups;
SELECT username, fixed_ip FROM vpn_users ORDER BY fixed_ip;
SELECT scope_type, scope_id, service FROM vpn_server_services;

COMMIT;
-- 发现问题时把上面的 COMMIT 换成 ROLLBACK;