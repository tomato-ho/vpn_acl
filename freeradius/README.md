# FreeRADIUS 容器（可选，第三方仓库）

## 这不是本项目的必需组件

默认部署**不使用**这个目录：`accounting_enabled=0`，用量写入本库
（`vpn_session_history`）。只有在需要把 Start/Interim/Stop 送到 `radacct`
时才需要 RADIUS。

## 为什么这里用的是第三方仓库

`Containerfile` 通过 `packages.inkbridgenetworks.com` 安装 FreeRADIUS 3.2，
原因是 **EL10 的官方仓库（appstream / EPEL）没有可用的 freeradius 包**。

这意味着：

- 镜像构建依赖一个**第三方公司的软件仓库**，可用性、包内容和签名都不由本项目控制；
- **不随本项目维护**，不作为发布验证的一部分；
- 如果该仓库下线或变更，这个 profile 会直接构建失败。

## 推荐用法：不要用这个容器

把用量发到你**已有的** RADIUS 服务器即可，不需要本目录：

```ini
# policyd.conf
accounting_enabled=1
radius_server=10.0.0.10
radius_port=1813
radius_secret=<与对方 clients.conf 一致>
```

只要对方是标准的 RFC 2866 accounting 接收端（FreeRADIUS、RADIUSdesk、
商业 NAS 网关等）都可以。

## 如果你确实想用这个容器

```bash
podman-compose --profile radius up -d
```

前提：`.env` 里的 `RADIUS_SECRET` 与 FreeRADIUS `clients.conf` 一致，
并且 MariaDB 已导入 FreeRADIUS 的表（`radcheck` / `radacct` / `radpostauth` / `nas` 等）。

## 许可证

FreeRADIUS 本身是 **GPL-2.0**。本仓库只提供构建脚本与配置模板，不包含
FreeRADIUS 源码或二进制。