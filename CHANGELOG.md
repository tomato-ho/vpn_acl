# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/)。

## [0.1.0] - 2026-11-16

首个公开版本。

### 功能

- **按用户/组的访问控制**：`push_routes = allow − deny`，同一份策略生成
  nftables 转发规则，在网关侧强制执行。
- **网关服务白名单**：每个用户可单独授权访问 VPN 网关自身的端口。
- **策略版本化**：数据库变更写 `vpn_policy_version`，在线会话原子刷新。
- **认证**：OpenVPN `auth-user-pass-verify` → `vpn-auth-check`，PBKDF2-SHA256，
  失败限速（用户名 5 次/5 分钟、来源 IP 20 次/5 分钟），失败原因回传客户端。
- **会话与用量**：在线会话在 `vpn_sessions`，断开后归档到 `vpn_session_history`。
- **认证审计**：`vpn_auth_log` 记录成功/失败及原因。
- **Web 后台**：用户、组、规则、服务、在线会话、历史会话、认证失败、审计、
  设置、指标（Prometheus `/metrics`）。
- **一键部署**：`deploy/install.sh` 支持 `--with-deps`、`--proxy`、`--offline`、
  `--check`、`--demo`；五个容器（mariadb / policyd / openvpn / admin / nginx）。
- **离线安装**：`deploy/save-images.sh` 导出镜像，目标机 `--offline` 安装。

### 已知限制

- 仅 IPv4；单实例，无 HA；不支持 WireGuard。
- `deny` 的真实语义是"不推送路由 + 网关侧 drop"，客户端从其他路径直达时无法阻止。
- VPN 用户没有自助改密页面；`must_change_password` 目前只记录不阻断。
- `install.sh` 不修改 firewalld，需要手工放行 80/443/1194。
- 用量/审计的数据留存需要手工或外部定时任务触发。
- 可选的 FreeRADIUS 容器依赖第三方仓库，不随本项目维护。

### 可靠性

- 数据库连接增加短退避重试（3 次，200/400ms），只针对连接类错误。
- `vpn-admin` 在数据库不可用时打印 `database unavailable: <原因>` 日志。
- `policyd` / `admin` 等待 MariaDB 健康后再启动（compose healthcheck）。
- `install.sh` 在等待 `readyz` 时会检测容器 DNS 解析，异常时自动
  `podman network reload --all` 重试（最多 3 次）。

### 文档

- README 增加「修改隧道网段」操作手册，配套 SQL 模板
  `deploy/examples/change-tunnel-network.sql`。

### 许可证

AGPL-3.0-only。