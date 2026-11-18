# 升级与回滚

升级会重启 `policyd` / `openvpn`，**在线用户会被断开**。请在维护窗口执行。

## 1. 升级前

```bash
git status                 # 确认工作区状态
sudo ./deploy/upgrade.sh --check
```

输出示例：

```
源码版本    1.0.0
运行版本    0.3.6
待应用迁移  2
应用镜像    <image id>
```

`--check` 在“运行版本落后”或“有未应用迁移”时返回非 0。

升级前请确认：

- 磁盘剩余 > 20%；
- 当前 `readyz` 正常（`sudo ./deploy/verify.sh`）；
- 已了解本次变更（`CHANGELOG.md`）；
- 最近一次备份可用（建议先跑 `sudo ./deploy/test-restore.sh`）。

## 2. 一键升级

```bash
sudo ./deploy/upgrade.sh          # 交互确认
sudo ./deploy/upgrade.sh --yes    # 非交互
```

脚本按顺序执行：

1. 备份数据库与配置到 `/var/backups/vpn-acl/`；
2. 把当前镜像打上 `localhost/vpn-acl-app:rollback`；
3. 编译 C++、跑 `ctest`、构建前端、`stage-app.sh`、构建镜像；
4. 应用 `sql/` 下未执行的迁移；
5. 重建 `admin / policyd / openvpn / retention` 容器，重启 `web`；
6. 等待 `/readyz`，运行 `deploy/verify.sh`。

任一步失败都会中止；第 3 步之后失败可用回滚。

## 3. 手动升级（脚本不适用时）

```bash
sudo ./deploy/backup.sh
sudo podman tag localhost/vpn-acl-app:latest localhost/vpn-acl-app:rollback

cmake -S . -B build -DVPN_WITH_DB=ON -DVPN_WITH_ADMIN=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure

cd vpn-admin/web && npm ci && npm run build && cd ../..
./deploy/stage-app.sh
podman-compose build app

sudo ./deploy/migrate.sh
sudo podman rm -f vpn-admin vpn-policyd vpn-openvpn vpn-retention
sudo podman-compose up -d
sudo podman restart vpn-web
sudo ./deploy/verify.sh
```

## 4. 回滚

```bash
sudo ./deploy/upgrade.sh --rollback
sudo ./deploy/upgrade.sh --rollback --backup /var/backups/vpn-acl/vpn-acl-XXXX.tar.gz
```

流程：恢复最近一次备份（数据库 + 配置 + 证书）→ 把 `:rollback` 镜像切回
`:latest` → 重建应用容器 → 验收。

限制：

- 只回退**一步**（镜像标签只保留一份）；
- 数据库回退到备份时刻，备份之后的写入会丢失；
- 如果升级脚本在“构建”阶段就失败，数据库尚未改动，只需 `podman-compose up -d`。

## 5. 迁移规则

- `sql/*.sql` 按文件名顺序执行，记录在 `schema_migrations`；
- 迁移只做向前兼容的加法（新表/新列），**不要修改已应用的文件内容**，
  否则 checksum 校验会报错；
- `vpn-policyd` 启动时会检查审计相关 schema，缺失会直接退出；
- 因此**必须先 `migrate.sh`，再启动新版本 policyd**（升级脚本已按此顺序）。

## 6. 升级后

```bash
sudo ./deploy/verify.sh
curl -s --noproxy '*' http://127.0.0.1:8080/readyz
```

`readyz` 会返回当前版本：

```json
{"database":true,"policyd":true,"status_file":true,"version":"1.0.0"}
```

Web 侧边栏底部也会显示版本号。

## 7. 常见问题

| 现象 | 处理 |
|---|---|
| `readyz` 一直 503 | `podman logs vpn-admin`，常见是迁移未应用或数据库连不上 |
| policyd 反复重启 | `podman logs vpn-policyd`，schema 检查失败时按提示跑 `migrate.sh` |
| 升级后在线会话丢失 | 正常：重建容器会断开用户，客户端会自动重连 |
| 版本号仍显示旧值 | 容器未重建：`podman rm -f vpn-admin && podman-compose up -d app` |