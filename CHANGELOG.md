# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/)。

## [0.3.2] - 2026-11-17

修复容器日志时区不一致。

### Fixed

- `compose.yaml` 为 `policyd`、`openvpn`、`web`、`retention` 补上
  `TZ: ${TZ:-Asia/Shanghai}`。此前这四个容器使用 UTC，而 MariaDB、`vpn-admin`
  和数据库时间使用本地时区，导致 `podman logs -t` 外层时间与日志内容相差 8 小时。
- 现在 policyd 文件日志、OpenVPN 日志与 status 可读时间、nginx access log、
  retention 环境均为本地时区；OpenVPN status 的 epoch 字段不变。
- 升级时旧的 `vpn-policyd.log` 已轮转为 `vpn-policyd.log.utc`，新日志从本地时间开始。
- 文档补充时区说明；修改 `.env` 的 `TZ` 后需要重建容器（`restart` 不会更新环境变量）。

## [0.3.1] - 2026-11-17

访问审计的计量与策略正确性修复。

### Fixed

- **上行字节严重少计**：`ct state established,related accept` 原本排在 per-user
  策略链之前，TCP/UDP/ICMP 长连接只有首个包会被计入 `flows`。现在 `tun0` 的每个
  包都先经过 `vmap @user_fwd` / `@user_in`，允许规则逐包计数。
- **撤回权限对已建立连接不生效**：同一个顺序问题导致已建立的客户端→目标流量
  不会被新策略 drop；现在撤回 allow 后，客户端发出的包会立即被拒绝并写入
  `deny` 审计（反向在途数据仍可能短暂到达客户端）。
- 客户端隔离（`tun0 -> tun0`）移动到策略链之前，并把尝试记录为 deny。
- 会话清理顺序改为：最终采样 → 删 nft 规则 → 归档 → 清集合/基线；此前 DB
  归档失败时计数器已被清空，重试会永久丢失最后一段流量。
- 采样写入包在单个数据库事务中，避免 access_log 与 flow_state 部分成功导致
  下一轮重复计数。
- `interim_update` 不再依赖 RADIUS accounting：默认关闭 accounting 时也会更新
  `vpn_sessions.bytes_in/out` 与 `last_seen`，reconcile 归档不再丢用量。
- allow/rev 集合超时从 10 分钟改为 24 小时，deny 保持 10 分钟；reconcile 会清理
  不属于在线会话的残留元素。
- policyd 启动时校验审计 schema；升级未执行 `deploy/migrate.sh` 会直接退出并
  提示，而不是半运行。
- 升级时如果检测到旧版本集合（超时不一致），原子重建 `vpn_acl` 并重置
  `vpn_flow_state` 基线。
- `deploy/test-access-audit.sh` 增加 TCP 大流量、精确字节断言、传输中撤回权限
  测试；`test-reliability.sh` 的 reconcile 补建改为轮询，避免固定 sleep 抖动。
- 历史会话没有 `session_id` 时不显示「访问记录」（不再按用户名近似混查）。

## [0.3.0] - 2026-11-17

访问审计：记录每个会话访问了哪些目标、哪些被拒绝，以及上下行字节。

### Added

- nftables 新增三个审计集合 `flows` / `flows_rev` / `flows_deny`，键为
  「客户端隧道 IP . 目标 IP」，元素自带 `counter`，10 分钟无流量自动过期。
  forward/input 的 allow 规则与 drop 规则都会更新对应集合。
- `vpn-policyd` 每 `flow_sample_interval`（默认 30 秒）采样集合计数器，
  按会话累加到 `vpn_access_log`（目标、allow/deny、上下行字节、首次/最后访问）。
- 原始计数器保存在 `vpn_flow_state`，policyd 重启后继续做差；连接时清理该 IP
  的旧元素，断开/reconcile 清理前做最终采样再删除规则与基线。
- 升级时若现有 `vpn_acl` 缺少审计集合，policyd 用单个 `nft -f` 原子重建表并
  恢复所有在线会话。
- 新增 API：`/api/sessions/{id}/access`、`/api/access`（用户/目标 IP/目标网段
  反查/allow-deny/时间范围）、`/api/access/export`。
- Web 新增「访问审计」页面；在线会话、历史会话、用户列表都有「访问记录」入口。
- `vpn_session_history` 新增 `session_id`，历史会话可直接关联访问记录
  （`sql/011_session_history_session_id.sql`）。
- `retention-cleanup` 新增 `--access-days`（默认 180 天），同时清理
  `vpn_access_log` 与 `vpn_flow_state`。
- 新增 `deploy/test-access-audit.sh`：真实客户端验证 allow/deny、上下行字节、
  policyd 重启不丢、断开最终采样与集合清理。

## [0.2.2] - 2026-11-17

运维与测试脚本修复。

### Fixed

- `vpn-admin` 处理 `SIGTERM`/`SIGINT`：容器内 PID 1 默认忽略 SIGTERM，
  之前停止/重启要等 10 秒被 SIGKILL，现在 <0.2 秒优雅退出。
- `retention` 命令加 `trap`，同样避免 PID 1 忽略 TERM。
- `readyz` 的数据库检查失败时限流打印原因（每 30 秒最多一条）。
- 所有脚本的本地健康检查使用 `curl --noproxy '*'`，并在启动时把
  `127.0.0.1/localhost/::1` 加入 `no_proxy`；此前在设置了 `http_proxy`
  的环境里会把本机请求发给代理，导致误判。
- 修复脚本里 `podman ps | grep -q` 在 `pipefail` 下触发 SIGPIPE 的误判。
- `soak-faults` 把 precheck 跳过计入 `skipped`，不再算作失败。

## [0.2.1] - 2026-11-16

并发与会话匹配的正确性修复。

### Fixed

- session marker 改为 `<user>@<ip>@<time_unix>`：同一用户重连时新旧连接各有
  自己的 marker，旧连接的 disconnect 不会读到新连接的 session_id。
- disconnect 在**明确提供** `session_id` 但查不到时不再回退到 IP/用户名，
  避免误杀重连后的新会话；只有未提供 id 的旧客户端才走回退。
- policyd 用全局锁串行化 connect / disconnect / refresh / reconcile，
  避免 orphan 清理与并发连接竞争导致 nft 链被误删。
- reconcile 恢复会话时跳过已删除/禁用的用户，避免反复失败。
- `backup.sh --restore` 不再覆盖 `.env`（备份留作 `.env.restored`），
  并恢复 `deploy/openvpn/server.conf`。
- `migrate.sh` 因缺表跳过的迁移不再记为已应用。

### Added

- `deploy/test-reliability.sh`：重连隔离、并发连接、策略版本轮询、
  reconcile 自愈四项回归。

## [0.2.0] - 2026-11-16

运行时可靠性版本。

### Added

- `vpn-policyd` 主动轮询 `vpn_policy_version`（`policy_check_interval`，默认 5s），
  不再依赖 admin 的 `REFRESH` 推送。
- `client-disconnect` 通过 `<socket 目录>/clients/<user>@<ip>` 精确匹配 `session_id`
  （新增 `libvpncore/session_marker`，带单元测试）。
- `reconcile` 双向：OpenVPN 在线但数据库缺记录时，自动补建会话并恢复 nft 规则
  （`recover_grace` 默认 15s，避免与 connect hook 竞争）。
- `reconcile` / `interim` 移到独立线程；nft 操作在 `NftManager` 内部串行化，
  connect hook 不再被全量刷新阻塞。
- `deploy/migrate.sh` + `schema_migrations`：按文件名顺序执行 `sql/`，记录 checksum，
  重复执行是 no-op。
- `deploy/backup.sh`：数据库 + 配置 + 证书的备份/恢复，支持保留份数与 `--list`。
- compose 新增 `retention` 容器，每天自动执行 `retention-cleanup --apply`。

### Changed

- `install.sh` 改用 `migrate.sh` 应用数据库迁移。
- 升级时用内容指纹判断是否需要重编 C++/前端，并在需要时重建镜像；
  源码变化会清理 `build/` 再编译（避免时钟偏移导致 make 跳过）。
- 策略版本变化会打日志并触发一次全量刷新。

### Fixed

- `Db::affected_rows()` / `last_insert_id()` 不再先 `mysql_ping`（会覆盖上一条语句
  的结果，曾导致 retention 的 `DELETE ... LIMIT` 循环永不退出）。
- `migrate.sh` 在缺少 `radacct` 表时跳过 `006_ensure_indexes.sql`。

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