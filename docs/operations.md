# 运维手册

面向已经部署完成的实例：端口、资源、日志、留存、巡检、监控。

## 1. 端口

| 端口 | 协议 | 用途 | 暴露范围 |
|---|---|---|---|
| 1194 | UDP | OpenVPN | 公网 / 客户端可达 |
| 443 | TCP | Web 后台（nginx + TLS） | 管理网 |
| 80 | TCP | nginx 跳转 / ACME（若配置） | 可关闭 |
| 8080 | TCP | `vpn-admin` HTTP API | **仅 127.0.0.1** |
| 3306 | TCP | MariaDB | **仅 127.0.0.1** |

- `8080` 与 `3306` 由 compose 显式绑定到 `127.0.0.1`，不要改成 `0.0.0.0`；
- `/metrics` 只接受本机与 Podman 网关（`10.89.0.1`）访问；
- firewalld 需要放行 `http`、`https`、`1194/udp`，并把 `tun0` 加入 trusted 区；
- 路由型部署还要给隧道网段做 masquerade。

## 2. 资源建议

| 规模 | CPU | 内存 | 磁盘 |
|---|---|---|---|
| ≤ 50 在线 | 2 核 | 2 GB | 20 GB |
| ≤ 200 在线 | 4 核 | 4 GB | 50 GB |
| ≤ 500 在线 | 8 核 | 8 GB | 100 GB |

磁盘主要被 `mariadb/data`（会话、访问审计）和容器镜像占用。
访问审计默认保留 180 天，按「每会话 × 目标数 × 采样周期」增长，量大时先调
`flow_sample_interval` 或缩短 `--access-days`。

## 3. 目录与日志

| 内容 | 位置 |
|---|---|
| 数据库数据 | `./mariadb/data` |
| 服务配置 | `/etc/vpn-policy/{admin,policyd}.conf`、`/etc/vpn-policy/config/vpn-policy.conf` |
| OpenVPN 证书 | `/etc/openvpn/server/` |
| Web 证书 | `/etc/nginx/ssl/` |
| policyd 文件日志 | `/var/log/vpn-policyd/vpn-policyd.log` |
| 容器日志 | `podman logs vpn-<service>` |
| 备份 | `/var/backups/vpn-acl/` |

常用命令：

```bash
podman logs -f --tail 100 vpn-policyd
podman logs -f --tail 100 vpn-openvpn
tail -f /var/log/vpn-policyd/vpn-policyd.log
```

## 4. 时区

所有容器从 `.env` 的 `TZ` 继承时区（默认 `Asia/Shanghai`）。改 `TZ` 后必须
**重建**容器，而不是 `restart`：

```bash
podman-compose up -d --force-recreate
```

`vpn-policyd` 的旧日志（0.3.1 及更早）内容是 UTC，已重命名为
`vpn-policyd.log.utc`。

## 5. 数据留存

`vpn-retention` 容器每天执行一次：

| 数据 | 默认保留 |
|---|---|
| `vpn_session_history` | 180 天 |
| `vpn_auth_log` | 180 天 |
| `vpn_access_log` / `vpn_flow_state` | 180 天 |
| `vpn_audit_log` | 365 天 |

手动执行或调整：

```bash
podman exec vpn-retention /usr/local/sbin/vpn-policyctl \
  --config /etc/vpn-policy/config retention-cleanup --apply \
  --access-days 90
```

`--access-days` 同时作用于 `vpn_access_log` 和 `vpn_flow_state`。

## 6. 日常巡检

```bash
sudo ./deploy/verify.sh            # 30+ 项检查，退出码 0 表示通过
sudo ./deploy/verify.sh --quiet    # 只看警告/失败
```

覆盖：配置与密码分离、六个容器、镜像一致性、`/readyz`、迁移、nft 表与审计集合、
审计相关表、Web 证书与安全头、`/metrics`、未登录 401、时区、磁盘、policyd 日志、
OpenVPN status 新鲜度。

可选真实登录：

```bash
VPN_ADMIN_USER=admin VPN_ADMIN_PASSWORD='...' sudo -E ./deploy/verify.sh
```

建议接入定时任务，每天一次，非 0 退出时告警。

## 7. 监控

`/metrics` 暴露 Prometheus 指标（只允许本机抓取）。告警规则示例见
[`deploy/prometheus-vpn-alerts.yml`](../deploy/prometheus-vpn-alerts.yml)。

关键健康信号：

- `readyz` 三项（database / policyd / status_file）；
- policyd 日志中的 `refresh` / `reconcile` 错误；
- 审计集合容量告警：集合达到 90%（`65536`）或单会话目标数 ≥ 10000 时 `log_warn`；
- 磁盘使用率、数据库连接数。

## 8. 审计容量的含义

三个 nft 集合 `flows` / `flows_rev` / `flows_deny` 各上限 **65536 个元素**，
元素键是「客户端隧道 IP . 目标 IP」，所有用户共享。

- 允许目标通常占 2 个元素（上行 + 反向），deny 目标占 1 个；
- 端口、连接数不影响元素数量（不记端口）；
- 断开会删除该客户端 IP 的所有元素；允许/反向 24h 空闲过期，deny 10m；
- 集合满时新目标不会被审计记录，策略判定本身不受影响——所以需要监控告警。

单会话活跃目标 ≥ 10000 只是告警线，不阻断、不限行。

## 9. 开机自启

`install.sh` 会启用 `podman-restart.service`。若系统没有该 unit，重启后需要：

```bash
podman-compose up -d
```

## 10. 安全基线

- 数据库 root 与应用账号必须是不同密码（`verify.sh` 会检查）；
- `/metrics`、`8080`、`3306` 只监听本机；
- OpenVPN management socket 由 policyd 收紧为 `0660`；
- nginx 为 SPA 设置 CSP / HSTS / nosniff / X-Frame-Options；
- 管理员 API 使用会话 Cookie + `X-CSRF-Token`；
- VPN 认证失败按 `username + IP` 限流（5 次/5 分钟，单 IP 20 次/5 分钟）。

未实现（已知边界）：MFA、SSO/LDAP、RBAC、HA、审计 WORM。详见
[`docs/security.md`](security.md)。