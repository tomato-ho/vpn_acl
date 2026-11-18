#!/usr/bin/env bash
#
# 升级 / 回滚：备份 → 迁移 → 重新构建 → 滚动重启 → 验收。
#
#   sudo ./deploy/upgrade.sh --check          # 只报告版本与待应用迁移
#   sudo ./deploy/upgrade.sh                  # 交互确认后升级
#   sudo ./deploy/upgrade.sh --yes            # 非交互升级
#   sudo ./deploy/upgrade.sh --rollback       # 恢复最近一次备份 + 回滚镜像
#   sudo ./deploy/upgrade.sh --rollback --backup FILE
#
# 升级会重启 policyd/openvpn，在线用户会被断开。请在维护窗口执行。
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

MODE=upgrade
ASSUME_YES=0
BACKUP_FILE=""
BACKUP_DIR=/var/backups/vpn-acl
APP_IMAGE=localhost/vpn-acl-app:latest
ROLLBACK_TAG=localhost/vpn-acl-app:rollback

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) MODE=check ;;
        --rollback) MODE=rollback ;;
        --yes|-y) ASSUME_YES=1 ;;
        --backup) BACKUP_FILE=${2:?}; shift ;;
        --backup-dir) BACKUP_DIR=${2:?}; shift ;;
        -h|--help) sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "未知参数 $1" ;;
    esac
    shift
done

[[ $(id -u) -eq 0 ]] || die "需要 root（重建容器、读写证书）"
[[ -f .env ]] || die "缺少 .env（请先运行 deploy/install.sh）"
command -v podman >/dev/null || die "缺少 podman"

env_value() {
    { grep -E "^$1=" .env || true; } | tail -1 | cut -d= -f2-
}

source_version() {
    sed -n 's/^project(vpn_acl VERSION \([0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1
}

running_version() {
    local body
    body=$(curl --noproxy '*' -s --max-time 5 \
        http://127.0.0.1:8080/readyz 2>/dev/null || true)
    local version
    version=$(grep -o '"version":"[^"]*"' <<< "$body" | cut -d'"' -f4)
    if [[ -n "$version" ]]; then
        printf '%s' "$version"
        return 0
    fi
    podman exec vpn-admin /usr/local/sbin/vpn-admin --version 2>/dev/null |
        awk '{print $2}' || true
}

pending_migrations() {
    local status
    status=$(./deploy/migrate.sh --status 2>/dev/null || true)
    grep -o '待应用 [0-9]*' <<< "$status" | awk '{print $2}' || echo 0
}

confirm() {
    (( ASSUME_YES )) && return 0
    [[ -t 0 ]] || die "非交互环境请加 --yes"
    local answer
    read -r -p "$1 [y/N] " answer
    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

wait_ready() {
    local _
    for _ in $(seq 1 60); do
        if curl --noproxy '*' -fsS --max-time 3 \
            http://127.0.0.1:8080/readyz >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}

recreate_app_containers() {
    # 顺序很重要：podman-compose 用 --requires 表达 depends_on，
    # 被依赖的容器在还有依赖者时无法删除。先删 web/openvpn，再删 admin/policyd。
    podman rm -f vpn-web vpn-openvpn vpn-admin vpn-policyd vpn-retention \
        >/dev/null 2>&1 || true
    podman-compose up -d >/dev/null

    local ids
    ids=$(for name in vpn-policyd vpn-openvpn vpn-admin vpn-retention; do
        podman inspect -f '{{.Image}}' "$name" 2>/dev/null || echo missing
    done | sort -u | wc -l)
    if [[ "$ids" != "1" ]]; then
        die "重建后应用容器镜像不一致（检查 podman ps -a）"
    fi
}

build_all() {
    log "编译 C++ 组件"
    cmake -S . -B build -DVPN_WITH_DB=ON -DVPN_WITH_ADMIN=ON >/dev/null
    cmake --build build -j"$(nproc)" >/dev/null
    log "运行单元测试"
    ctest --test-dir build --output-on-failure

    log "构建前端"
    if [[ ! -d vpn-admin/web/node_modules ]]; then
        (cd vpn-admin/web && npm ci --no-audit --no-fund >/dev/null)
    fi
    (cd vpn-admin/web && npm run build >/dev/null)

    log "收集镜像上下文"
    ./deploy/stage-app.sh >/dev/null

    log "构建应用镜像"
    podman-compose build app >/dev/null
}

do_check() {
    local src running pending
    src=$(source_version)
    running=$(running_version)
    pending=$(pending_migrations)

    printf '源码版本    %s\n' "${src:-未知}"
    printf '运行版本    %s\n' "${running:-未知}"
    printf '待应用迁移  %s\n' "$pending"

    local image_id
    image_id=$(podman image inspect -f '{{.Id}}' "$APP_IMAGE" 2>/dev/null || echo "缺少 $APP_IMAGE")
    printf '应用镜像    %s\n' "$image_id"

    if [[ -z "$running" ]]; then
        warn "无法读取运行版本（旧镜像或服务未启动），需要升级"
        return 1
    fi
    if [[ -n "$src" && "$src" != "$running" ]]; then
        warn "运行版本与源码不一致，需要升级"
        return 1
    fi
    if [[ "$pending" != "0" ]]; then
        warn "存在未应用的迁移，需要升级"
        return 1
    fi
    log "已是最新版本（$src）"
}

do_upgrade() {
    local src running pending
    src=$(source_version)
    running=$(running_version)
    pending=$(pending_migrations)
    [[ -n "$src" ]] || die "无法从 CMakeLists.txt 解析版本"

    log "升级计划：${running:-未知} -> $src（待应用迁移 $pending）"
    warn "升级会重启 policyd/openvpn，在线用户会被断开"
    confirm "继续升级？" || die "已取消"

    if [[ -n "$(git status --porcelain 2>/dev/null || true)" ]]; then
        warn "工作区有未提交改动，升级会按当前文件构建"
    fi

    log "1/6 备份数据库与配置"
    ./deploy/backup.sh --out "$BACKUP_DIR" --keep 7 | sed 's/^/    /'

    log "2/6 保留当前镜像为 :rollback"
    if podman image exists "$APP_IMAGE"; then
        podman tag "$APP_IMAGE" "$ROLLBACK_TAG"
    else
        warn "找不到 $APP_IMAGE，跳过回滚镜像标记"
    fi

    log "3/6 构建"
    build_all

    log "4/6 应用数据库迁移"
    ./deploy/migrate.sh

    log "5/6 重建应用容器"
    recreate_app_containers

    log "6/6 验收"
    if ! wait_ready; then
        die "readyz 未在 120 秒内恢复：podman logs vpn-admin / vpn-policyd"
    fi
    if ! ./deploy/verify.sh; then
        warn "verify.sh 报告失败项，可用 --rollback 回退"
        exit 1
    fi

    log "升级完成：$src"
    printf '回滚：sudo %s --rollback\n' "$0"
}

do_rollback() {
    local archive=$BACKUP_FILE
    if [[ -z "$archive" ]]; then
        if [[ ! -d "$BACKUP_DIR" ]]; then
            die "备份目录不存在：$BACKUP_DIR（用 --backup FILE 指定备份）"
        fi
        archive=$(find "$BACKUP_DIR" -maxdepth 1 -name 'vpn-acl-*.tar.gz' \
            -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true)
    fi
    [[ -n "$archive" && -f "$archive" ]] || die "找不到可用的备份（--backup FILE）"

    log "回滚计划：恢复 $archive"
    warn "这会用备份覆盖当前数据库与配置"
    confirm "继续回滚？" || die "已取消"

    log "1/3 恢复备份"
    ./deploy/backup.sh --restore "$archive" --yes

    log "2/3 切回上一个镜像"
    if podman image exists "$ROLLBACK_TAG"; then
        podman tag "$ROLLBACK_TAG" "$APP_IMAGE"
        recreate_app_containers
        wait_ready || warn "readyz 未恢复，请查看容器日志"
    else
        warn "没有 $ROLLBACK_TAG，保留当前镜像"
    fi

    log "3/3 验收"
    ./deploy/verify.sh || warn "verify.sh 报告失败项"
    log "回滚完成"
}

case "$MODE" in
    check) do_check ;;
    upgrade) do_upgrade ;;
    rollback) do_rollback ;;
esac