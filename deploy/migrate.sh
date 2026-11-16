#!/usr/bin/env bash
#
# 按文件名顺序应用 sql/ 下的迁移，并记录到 schema_migrations。
#
#   ./deploy/migrate.sh            # 应用未执行的迁移
#   ./deploy/migrate.sh --status   # 只看状态，不改数据库
#
# 重复执行是安全的：已应用且 checksum 一致的文件会跳过。
# 需要 vpn-mariadb 容器正在运行，以及仓库根目录的 .env。
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

env_value() {
    { grep -E "^$1=" .env || true; } | tail -1 | cut -d= -f2-
}

[[ -f .env ]] || die "缺少 .env（请先运行 ./deploy/install.sh）"
ROOT_PW=$(env_value MARIADB_ROOT_PASSWORD)
DB_NAME=$(env_value MARIADB_DATABASE)
DB_NAME=${DB_NAME:-radius}
[[ -n "$ROOT_PW" ]] || die ".env 里没有 MARIADB_ROOT_PASSWORD"

running_names=$(podman ps --format '{{.Names}}' 2>/dev/null || true)
grep -qx 'vpn-mariadb' <<< "$running_names" ||
    die "容器 vpn-mariadb 未运行"

mysql_exec() {
    podman exec -i vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB_NAME" "$@"
}

table_exists() {
    local count
    count=$(mysql_exec -N -e \
        "SELECT COUNT(*) FROM information_schema.tables
          WHERE table_schema='$DB_NAME' AND table_name='$1'")
    [[ "$count" != "0" ]]
}

status_only=0
[[ ${1:-} == "--status" ]] && status_only=1

mysql_exec -e "CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(128) NOT NULL,
  checksum CHAR(64) NOT NULL,
  applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci" >/dev/null

shopt -s nullglob
files=(sql/*.sql)
shopt -u nullglob
(( ${#files[@]} > 0 )) || die "sql/ 下没有迁移文件"

applied=0
skipped=0
pending=0
skipped_missing=0

for file in "${files[@]}"; do
    version=$(basename "$file")
    checksum=$(sha256sum "$file" | awk '{print $1}')
    recorded=$(mysql_exec -N -e \
        "SELECT checksum FROM schema_migrations WHERE version='$version'")

    if [[ -n "$recorded" ]]; then
        if [[ "$recorded" != "$checksum" ]]; then
            warn "$version 已应用，但文件内容已变化（checksum 不一致）"
        fi
        if [[ $status_only -eq 1 ]]; then
            printf '  applied  %s\n' "$version"
        fi
        skipped=$((skipped + 1))
        continue
    fi

    if [[ $status_only -eq 1 ]]; then
        pending=$((pending + 1))
        printf '  pending  %s\n' "$version"
        continue
    fi

    # 与 FreeRADIUS 相关的迁移只在对应表存在时执行
    required_table=""
    case "$version" in
        005_*) required_table=radpostauth ;;
        006_*) required_table=radacct ;;
    esac
    if [[ -n "$required_table" ]] && ! table_exists "$required_table"; then
        # 不记录为已应用：以后补上 FreeRADIUS 表时还应重新尝试。
        log "跳过 $version（没有 $required_table 表）"
        skipped_missing=$((skipped_missing + 1))
        continue
    fi

    log "应用 $version"
    mysql_exec < "$file" >/dev/null
    mysql_exec -e "INSERT INTO schema_migrations (version, checksum)
                   VALUES ('$version', '$checksum')" >/dev/null
    applied=$((applied + 1))
done

if [[ $status_only -eq 1 ]]; then
    printf '\n已应用 %d 个，待应用 %d 个\n' "$skipped" "$pending"
    exit 0
fi

printf '\n迁移完成：新应用 %d 个，已应用 %d 个' "$applied" "$skipped"
if [[ $skipped_missing -gt 0 ]]; then
    printf '，因缺表跳过 %d 个' "$skipped_missing"
fi
printf '\n'
