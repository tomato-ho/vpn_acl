# 备份与恢复

## 1. 备份包含什么

`deploy/backup.sh` 生成 `/var/backups/vpn-acl/vpn-acl-<时间戳>.tar.gz`（权限 `0600`）：

```
db/radius.sql              数据库全量 dump（--single-transaction --routines --triggers）
files/env                  .env（含数据库密码）
files/vpn-policy/          /etc/vpn-policy 下的全部配置
files/openvpn-certs/       OpenVPN CA / 服务端证书 / ta.key
files/web-certs/           Web TLS 证书
files/openvpn-server.conf  OpenVPN server.conf
```

备份里有私钥和密码，等同于整套系统的控制权，务必离线保存并限制访问。

## 2. 手动备份

```bash
sudo ./deploy/backup.sh                     # 默认 7 份轮转
sudo ./deploy/backup.sh --out /data/backup --keep 14
sudo ./deploy/backup.sh --list
```

## 3. 定时备份

```cron
# 每天 02:15 备份，保留 14 份
15 2 * * * cd /opt/vpn-acl && ./deploy/backup.sh --out /var/backups/vpn-acl --keep 14 >>/var/log/vpn-backup.log 2>&1
```

建议再把 `--out` 目录同步到另一台机器或对象存储。备份放在同一块磁盘上
只能防误操作，不能防磁盘损坏。

## 4. 恢复

```bash
sudo ./deploy/backup.sh --restore /var/backups/vpn-acl/vpn-acl-20261118-021500.tar.gz --yes
```

流程：停止容器 → 启动 MariaDB → 导入 dump → 恢复配置/证书 → 启动全部服务 →
自动运行 `deploy/verify.sh`。

**注意：**

- 恢复**不会覆盖当前 `.env`**（MariaDB root 密码在数据目录初始化时写入，直接换
  会导致连不上）。备份里的 `.env` 另存为 `.env.restored`，需要时手工比对；
- 数据库恢复到备份时刻，备份之后新建的用户/规则/会话都会丢失；
- 管理员密码恢复为备份时刻的密码；
- 如果备份来自另一台机器，`deploy/openvpn/server.conf` 会被覆盖，注意
  `server` 指令的隧道网段是否与本机一致。

## 5. 恢复演练

不要等出事才第一次验证备份。`deploy/test-restore.sh` 会把备份导入一个临时
MariaDB 容器（`vpn-restore-test`），比对关键表后再销毁，**不触碰生产数据**：

```bash
sudo ./deploy/test-restore.sh
sudo ./deploy/test-restore.sh --keep   # 保留临时容器排查
```

比对项：

- 归档结构（db dump / `.env` / 配置 / 证书）；
- `vpn_users`、`vpn_groups`、`vpn_settings`、`vpn_admins` 内容哈希；
- `schema_migrations`、`vpn_session_history`、`vpn_access_log` 行数；
- 恢复库的关键 schema（`vpn_flow_state`、`vpn_session_history.session_id`）。

建议每次升级前跑一次，或至少每月一次。

## 6. 恢复后检查清单

1. `sudo ./deploy/verify.sh` 全部通过；
2. 用备份时刻的管理员账号登录 Web；
3. 抽查在线会话与历史会话是否与预期一致；
4. 用一个测试账号连接 VPN，确认能访问 allow 列表中的目标；
5. 查看 `podman logs vpn-policyd` 有无 ERROR；
6. 确认 `/run/openvpn-server/status.log` 在持续更新。