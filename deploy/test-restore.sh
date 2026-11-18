#!/usr/bin/env bash
#
# 备份恢复演练：验证 deploy/backup.sh 的产物确实可以恢复。
#
#   sudo ./deploy/test-restore.sh           # 备份 → 恢复到临时 MariaDB → 比对
#   sudo ./deploy/test-restore.sh --keep    # 保留临时容器便于排查
#
# 恢复到临时容器（vpn-restore-test），不触碰 vpn-mariadb 里的生产数据。
# 真实恢复请用 deploy/backup.sh --restore。
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

KEEP=0
case "${1:-}" in
    --keep) KEEP=1 ;;
    "") ;;
    -h|--help) sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "未知参数 $1" ;;
esac

[[ $(id -u) -eq 0 ]] || die "需要 root（读写证书与数据库）"

env_value() {
    [[ -f .env ]] || return 0
    { grep -E "^$1=" .env || true; } | tail -1 | cut -d= -f2-
}

DB_NAME=$(env_value MARIADB_DATABASE); DB_NAME=${DB_NAME:-radius}
LIVE_NAME=vpn-mariadb
TEST_NAME=vpn-restore-test
TEST_PW=$(openssl rand -hex 16)
IMAGE=$(podman inspect -f '{{.ImageName}}' "$LIVE_NAME" 2>/dev/null || true)
IMAGE=${IMAGE:-docker.io/library/mariadb:10.11}

TMP=$(mktemp -d)
cleanup() {
    if (( KEEP )); then
        warn "保留临时容器 $TEST_NAME 与目录 $TMP"
        return
    fi
    podman rm -f "$TEST_NAME" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

step=0
failures=0
ok() { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
bad() { printf '\033[1;31m[fail]\033[0m %s\n' "$*"; failures=$((failures + 1)); }

# ---------------------------------------------------------------- 1. 备份
step=$((step + 1)); log "$step. 生成备份"
./deploy/backup.sh --out "$TMP/backups" --keep 1 >/dev/null
ARCHIVE=$(find "$TMP/backups" -maxdepth 1 -name 'vpn-acl-*.tar.gz' | head -1)
[[ -n "$ARCHIVE" ]] || die "没有生成备份文件"
ok "备份文件：$(basename "$ARCHIVE") ($(du -h "$ARCHIVE" | cut -f1))"

# ---------------------------------------------------------------- 2. 检查产物
step=$((step + 1)); log "$step. 检查备份内容"
listing=$(tar -tzf "$ARCHIVE")
grep -qx './db/'"$DB_NAME"'.sql' <<< "$listing" || bad "缺少 db/$DB_NAME.sql"
grep -qx './files/env' <<< "$listing" || bad "缺少 files/env"
grep -q './files/vpn-policy/' <<< "$listing" || warn "备份里没有 vpn-policy 配置"
grep -q './files/openvpn-certs/' <<< "$listing" || warn "备份里没有 OpenVPN 证书"
(( failures == 0 )) && ok "备份包含数据库、.env、配置与证书"

# ---------------------------------------------------------------- 3. 临时库
step=$((step + 1)); log "$step. 启动临时 MariaDB（$TEST_NAME）"
podman rm -f "$TEST_NAME" >/dev/null 2>&1 || true
mkdir -p "$TMP/data"
podman run -d --name "$TEST_NAME" \
    -e MARIADB_ROOT_PASSWORD="$TEST_PW" \
    -e MARIADB_DATABASE="$DB_NAME" \
    -v "$TMP/data:/var/lib/mysql" \
    "$IMAGE" >/dev/null

ready=0
for _ in $(seq 1 60); do
    if podman exec "$TEST_NAME" mariadb -uroot -p"$TEST_PW" \
        -e "SELECT 1" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done
(( ready == 1 )) || die "临时 MariaDB 未就绪"
ok "临时实例已就绪"

# ---------------------------------------------------------------- 4. 恢复
step=$((step + 1)); log "$step. 把 dump 导入临时实例"
tar -xzf "$ARCHIVE" -C "$TMP" './db/'"$DB_NAME"'.sql'
podman exec -i "$TEST_NAME" mariadb -uroot -p"$TEST_PW" "$DB_NAME" \
    < "$TMP/db/$DB_NAME.sql"
ok "导入完成"

# ---------------------------------------------------------------- 5. 比对
step=$((step + 1)); log "$step. 比对生产库与恢复库"

live_sql() {
    podman exec "$LIVE_NAME" mariadb -uroot -p"$(env_value MARIADB_ROOT_PASSWORD)" \
        -N -B "$DB_NAME" -e "$1" 2>/dev/null
}
test_sql() {
    podman exec "$TEST_NAME" mariadb -uroot -p"$TEST_PW" -N -B "$DB_NAME" \
        -e "$1" 2>/dev/null
}

compare_hash() {
    local label=$1 query=$2
    local live test
    if ! live=$(live_sql "$query") || ! test=$(test_sql "$query"); then
        bad "$label 查询失败"
        return
    fi
    live=$(printf '%s' "$live" | md5sum | cut -d' ' -f1)
    test=$(printf '%s' "$test" | md5sum | cut -d' ' -f1)
    if [[ "$live" == "$test" ]]; then
        ok "$label 一致（$live）"
    else
        bad "$label 不一致（live=$live restore=$test）"
    fi
}

compare_count() {
    local label=$1 table=$2
    local live test
    if ! live=$(live_sql "SELECT COUNT(*) FROM $table") ||
        ! test=$(test_sql "SELECT COUNT(*) FROM $table"); then
        bad "$label 查询失败"
        return
    fi
    if [[ -n "$live" && "$live" == "$test" ]]; then
        ok "$label 行数一致（$live）"
    else
        bad "$label 行数不一致（live=$live restore=$test）"
    fi
}

compare_hash "vpn_users" \
    "SELECT username, group_id, fixed_ip, enabled, password_hash FROM vpn_users ORDER BY username"
compare_hash "vpn_groups" \
    "SELECT id, name, ip_start, ip_end, description FROM vpn_groups ORDER BY id"
compare_hash "vpn_settings" \
    "SELECT name, value FROM vpn_settings ORDER BY name"
compare_hash "vpn_admins" \
    "SELECT username, enabled, password_hash FROM vpn_admins ORDER BY username"
compare_count "schema_migrations" schema_migrations
compare_count "vpn_session_history" vpn_session_history
compare_count "vpn_access_log" vpn_access_log

# ---------------------------------------------------------------- 6. 结构
step=$((step + 1)); log "$step. 检查恢复库的 auditor schema"
for check in \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='vpn_flow_state'" \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='vpn_session_history' AND column_name='session_id'"; do
    value=$(test_sql "$check")
    if [[ "$value" == "1" ]]; then
        ok "schema 检查通过"
    else
        bad "schema 检查失败：$check"
    fi
done

printf '\n'
if (( failures > 0 )); then
    die "恢复演练失败：$failures 项不通过"
fi
log "恢复演练通过：备份可以完整恢复"