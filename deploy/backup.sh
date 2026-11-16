#!/usr/bin/env bash
#
# 备份/恢复 VPN Access Control（数据库 + 配置 + 证书）。
#
#   ./deploy/backup.sh                    # 备份到 /var/backups/vpn-acl
#   ./deploy/backup.sh --out DIR --keep 14
#   ./deploy/backup.sh --list
#   ./deploy/backup.sh --restore FILE --yes
#
# 备份包含：MariaDB 全库 dump、.env、/etc/vpn-policy、OpenVPN 证书、Web 证书、
# OpenVPN 的 server.conf。文件权限 0600（含私钥与密钥）。
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

OUT_DIR=/var/backups/vpn-acl
CLEANUP_DIR=""
KEEP=7
MODE=backup
RESTORE_FILE=""
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT_DIR=${2:?}; shift ;;
        --keep) KEEP=${2:?}; shift ;;
        --list) MODE=list ;;
        --restore) MODE=restore; RESTORE_FILE=${2:?}; shift ;;
        -y|--yes) ASSUME_YES=1 ;;
        -h|--help) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "未知参数 $1" ;;
    esac
    shift
done

env_value() {
    { grep -E "^$1=" .env || true; } | tail -1 | cut -d= -f2-
}

[[ -f .env ]] || die "缺少 .env"
ROOT_PW=$(env_value MARIADB_ROOT_PASSWORD)
DB_NAME=$(env_value MARIADB_DATABASE); DB_NAME=${DB_NAME:-radius}
CONFIG_DIR=$(env_value VPN_CONFIG_DIR); CONFIG_DIR=${CONFIG_DIR:-/etc/vpn-policy}
OPENVPN_CERTS=$(env_value VPN_OPENVPN_CERTS); OPENVPN_CERTS=${OPENVPN_CERTS:-/etc/openvpn/server}
WEB_CERTS=$(env_value VPN_CERTS_DIR); WEB_CERTS=${WEB_CERTS:-/etc/nginx/ssl}
[[ -n "$ROOT_PW" ]] || die ".env 里没有 MARIADB_ROOT_PASSWORD"

cleanup() {
    [[ -n "$CLEANUP_DIR" ]] && rm -rf "$CLEANUP_DIR"
}
trap cleanup EXIT

mariadb_running() {
    local names
    names=$(podman ps --format '{{.Names}}' 2>/dev/null || true)
    grep -qx 'vpn-mariadb' <<< "$names"
}

wait_for_db() {
    local _
    for _ in $(seq 1 60); do
        if podman exec vpn-mariadb mariadb -uroot -p"$ROOT_PW" \
            -e "SELECT 1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    die "MariaDB 未就绪"
}

do_backup() {
    [[ $(id -u) -eq 0 ]] || die "备份需要 root（读取证书私钥）"
    mariadb_running || die "容器 vpn-mariadb 未运行"
    command -v tar >/dev/null || die "缺少 tar"

    mkdir -p "$OUT_DIR"
    chmod 0700 "$OUT_DIR"

    local stamp tmp
    stamp=$(date +%Y%m%d-%H%M%S)
    tmp=$(mktemp -d)
    CLEANUP_DIR=$tmp
    mkdir -p "$tmp/db" "$tmp/files"

    log "导出数据库 $DB_NAME"
    podman exec vpn-mariadb mariadb-dump \
        --single-transaction --routines --triggers \
        -uroot -p"$ROOT_PW" "$DB_NAME" > "$tmp/db/$DB_NAME.sql"

    cp -a .env "$tmp/files/env" 2>/dev/null || true
    [[ -d "$CONFIG_DIR" ]] && cp -a "$CONFIG_DIR" "$tmp/files/vpn-policy"
    [[ -d "$OPENVPN_CERTS" ]] && cp -a "$OPENVPN_CERTS" "$tmp/files/openvpn-certs"
    [[ -d "$WEB_CERTS" ]] && cp -a "$WEB_CERTS" "$tmp/files/web-certs"
    [[ -f deploy/openvpn/server.conf ]] &&
        cp -a deploy/openvpn/server.conf "$tmp/files/openvpn-server.conf"

    local archive="$OUT_DIR/vpn-acl-$stamp.tar.gz"
    log "打包 $archive"
    tar -czf "$archive" -C "$tmp" .
    chmod 0600 "$archive"

    # 轮转
    find "$OUT_DIR" -maxdepth 1 -name 'vpn-acl-*.tar.gz' -printf '%T@ %p\n' |
        sort -rn | tail -n +$((KEEP + 1)) | cut -d' ' -f2- |
        while IFS= read -r old; do
            [[ -n "$old" ]] || continue
            log "删除旧备份 $old"
            rm -f "$old"
        done

    log "完成：$archive"
}

do_list() {
    [[ -d "$OUT_DIR" ]] || die "目录不存在：$OUT_DIR"
    ls -lh "$OUT_DIR"/vpn-acl-*.tar.gz 2>/dev/null || echo "没有备份"
}

do_restore() {
    [[ $(id -u) -eq 0 ]] || die "恢复需要 root"
    [[ -f "$RESTORE_FILE" ]] || die "备份文件不存在：$RESTORE_FILE"
    if [[ $ASSUME_YES -ne 1 ]]; then
        die "恢复会覆盖当前数据库与证书，确认请加 --yes"
    fi

    local tmp
    tmp=$(mktemp -d)
    CLEANUP_DIR=$tmp
    tar -xzf "$RESTORE_FILE" -C "$tmp"

    [[ -f "$tmp/db/$DB_NAME.sql" ]] || die "备份里没有数据库 dump"

    log "停止容器"
    podman-compose down >/dev/null 2>&1 || true
    log "启动 MariaDB"
    podman-compose up -d mariadb >/dev/null
    wait_for_db

    log "恢复数据库"
    podman exec -i vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB_NAME" \
        < "$tmp/db/$DB_NAME.sql"

    if [[ -d "$tmp/files/vpn-policy" ]]; then
        log "恢复配置到 $CONFIG_DIR"
        mkdir -p "$CONFIG_DIR"
        cp -a "$tmp/files/vpn-policy/." "$CONFIG_DIR/"
    fi
    if [[ -d "$tmp/files/openvpn-certs" ]]; then
        log "恢复 OpenVPN 证书到 $OPENVPN_CERTS"
        mkdir -p "$OPENVPN_CERTS"
        cp -a "$tmp/files/openvpn-certs/." "$OPENVPN_CERTS/"
    fi
    if [[ -d "$tmp/files/web-certs" ]]; then
        log "恢复 Web 证书到 $WEB_CERTS"
        mkdir -p "$WEB_CERTS"
        cp -a "$tmp/files/web-certs/." "$WEB_CERTS/"
    fi
    if [[ -f "$tmp/files/openvpn-server.conf" ]]; then
        log "恢复 deploy/openvpn/server.conf（会覆盖仓库里的同名文件）"
        cp -a "$tmp/files/openvpn-server.conf" deploy/openvpn/server.conf
    fi
    if [[ -f "$tmp/files/env" ]]; then
        # 不覆盖当前 .env：MariaDB 的 root 密码是初始化时写入数据目录的，
        # 直接换 .env 会与新库不匹配。备份里的版本留作参考。
        log "备份中的 .env 保存为 .env.restored（当前 .env 不变）"
        cp -a "$tmp/files/env" .env.restored
        chmod 0600 .env.restored
    fi

    log "启动全部服务"
    podman-compose up -d >/dev/null
    log "恢复完成（请用备份里的管理员密码登录）"
}

case "$MODE" in
    backup) do_backup ;;
    list) do_list ;;
    restore) do_restore ;;
esac