# 故障排查

先跑一遍自动巡检，多数问题会直接定位：

```bash
sudo ./deploy/verify.sh
```

## 1. 用户连不上 VPN

| 检查 | 命令 |
|---|---|
| 1194/udp 是否放行 | `firewall-cmd --list-all` |
| OpenVPN 是否在跑 | `podman logs --tail 100 vpn-openvpn` |
| 证书是否过期 | `openssl x509 -in /etc/openvpn/server/server.crt -noout -dates` |
| 服务器时间是否准确 | `timedatectl` |
| 认证是否失败 | Web「认证失败」页面 / `vpn_auth_log` |

时钟偏移是最常见的原因，客户端会报 `certificate is not yet valid`。
证书签发后无法补救，只能重签。

认证失败原因只写审计日志，客户端统一收到“用户名或密码错误”（防枚举）。
看具体原因：

```bash
podman exec vpn-mariadb mariadb -uroot -p"$PW" radius \
  -e "SELECT username, remote_ip, success, reason, created_at
      FROM vpn_auth_log ORDER BY id DESC LIMIT 20;"
```

限流规则：同一 `username + IP` 5 次失败/5 分钟，同一 IP 20 次/5 分钟。
被限流时等待窗口结束，或清理 `vpn_auth_log` 中对应时间段的记录。

## 2. 能连上，但访问不了目标

按顺序排查：

1. **客户端路由**：`allow` 是否真的生成了 `push_route`？
   ```bash
   sudo ./build/vpn-policyctl --config /etc/vpn-policy/config show <user>
   ```
2. **网关策略**：用户/组规则是否命中、是否被 deny 覆盖？
   ```bash
   sudo nft list chain inet vpn_acl fwd_<hash>
   sudo nft list map inet vpn_acl user_fwd
   ```
3. **firewalld 转发**：`tun0` 是否在 trusted 区（firewalld 默认 reject 转发）。
4. **回程路由 / masquerade**：目标机器是否知道如何回到隧道网段。
5. **策略版本未刷新**：
   ```bash
   podman exec vpn-mariadb mariadb ... -e "SELECT * FROM vpn_policy_version;"
   grep -E "refresh|policy" /var/log/vpn-policyd/vpn-policyd.log | tail
   ```

`deny` 的语义是「不推送路由 + 网关侧 drop」；如果客户端能通过其他路径直达该网段，
网关无法阻止。

## 3. 审计里没有记录

| 现象 | 原因 / 处理 |
|---|---|
| 完全没有访问记录 | `flow_sample_interval` 未到；或流量没走 tun0（split tunnel） |
| 只有 allow 没有 deny | deny 集合 10 分钟过期，采样间隔内无新包就会消失 |
| 记录里 `up=0` | 下行是 established 流量，服务器主动发起的连接只有下行 |
| 某目标一直不出现 | 审计集合已满（65536），看 policyd 日志的容量告警 |
| 断线后记录缺失 | 断开时先做最终采样；若归档失败，计数会保留重试 |

检查：

```bash
sudo nft list set inet vpn_acl flows
sudo nft list set inet vpn_acl flows_rev
sudo nft list set inet vpn_acl flows_deny
grep -E "near capacity|active targets" /var/log/vpn-policyd/vpn-policyd.log
```

字节是 L3 转发字节，与 OpenVPN 状态页的总量口径不同（后者含封装与 keepalive），
属于审计级近似，不要用于计费。

## 4. `/readyz` 失败

```bash
curl -s --noproxy '*' http://127.0.0.1:8080/readyz
```

| 字段 | 含义 | 排查 |
|---|---|---|
| `database` | 能连库并执行 `SELECT 1` | `podman logs vpn-mariadb`，检查 `.env` 密码 |
| `policyd` | IPC `PING` 有响应 | `podman logs vpn-policyd`，检查 socket 权限 |
| `status_file` | status 文件 30 秒内更新过 | OpenVPN 是否在跑，`status` 指令是否配置 |

## 5. 策略不生效 / 用户被踢后仍在

- `vpn-policyd` 只在 `vpn_policy_version` 变化时做完整 REFRESH；
  直接改数据库必须 `UPDATE vpn_policy_version SET version=version+1`；
- Web/CLI 的写操作会自动 bump 并发送 REFRESH；
- 禁用/改组/改固定 IP 会 `KICK` 在线会话（API 与 CLI 都支持）；
- KICK 失败只告警，可手动：
  ```bash
  podman kill --signal HUP vpn-openvpn   # 或通过管理 socket client-kill
  ```

## 6. Web 打不开 / 证书报错

```bash
podman logs --tail 50 vpn-web
openssl s_client -connect 127.0.0.1:443 -servername localhost </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates
```

- 自签证书需要客户端信任，或换成正式证书后重启 `vpn-web`；
- 浏览器报 CSP 相关错误：确认 `deploy/nginx/nginx.conf` 与 `web/dist` 是同一版本；
- 登录后被重定向到 `/dashboard` 属正常（`redirect` 只接受站内路径）。

## 7. 容器反复重启

```bash
podman ps -a --format '{{.Names}}\t{{.Status}}'
podman logs --tail 100 vpn-policyd
podman logs --tail 100 vpn-admin
```

常见原因：

- `policyd`：schema 缺失（跑 `deploy/migrate.sh`）、nft 权限（缺 `NET_ADMIN`）、
  IPC 目录被删（`/run/vpn-policyd`，由 tmpfiles 保证）；
- `admin`：数据库连不上、`admin.conf` 路径错误；
- `openvpn`：`/dev/net/tun` 缺失、1194 被占用、证书不匹配。

## 8. 磁盘或数据库增长过快

```bash
podman exec vpn-mariadb mariadb -uroot -p"$PW" radius -e "
  SELECT table_name, ROUND(data_length/1024/1024,1) AS mb, table_rows
  FROM information_schema.tables WHERE table_schema='radius'
  ORDER BY data_length DESC LIMIT 10;"
```

- `vpn_access_log` 增长最快：缩短 `--access-days` 或调大 `flow_sample_interval`；
- `vpn_session_history`：调小 `--session-days`；
- 手动清理见 [`operations.md`](operations.md#5-数据留存)。

## 9. 需要更多信息时

```bash
sudo ./deploy/verify.sh
podman ps -a
podman logs --tail 200 vpn-policyd
podman logs --tail 200 vpn-admin
tail -n 200 /var/log/vpn-policyd/vpn-policyd.log
sudo nft list table inet vpn_acl
curl -s --noproxy '*' http://127.0.0.1:8080/readyz
```

提交问题时附上：版本（`curl /readyz` 或页面底部）、上述输出、复现步骤。