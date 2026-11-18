#!/usr/bin/env bash
#
# 交付验收 / 日常巡检：不依赖 VPN 客户端，检查运行中的栈是否健康。
#
#   sudo ./deploy/verify.sh                # 人类可读
#   sudo ./deploy/verify.sh --quiet        # 只打印警告/失败与汇总
#   sudo ./deploy/verify.sh --no-color
#
# 可选真实登录检查（默认只验证未登录时返回 401）：
#   VPN_ADMIN_USER=admin VPN_ADMIN_PASSWORD='...' sudo -E ./deploy/verify.sh
#
# 退出码：0 = 全部通过（允许有警告）；1 = 存在失败项。
#
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1

QUIET=0
USE_COLOR=1
for arg in "$@"; do
    case "$arg" in
        --quiet) QUIET=1 ;;
        --no-color) USE_COLOR=0 ;;
        -h|--help) sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "未知参数：$arg" >&2; exit 2 ;;
    esac
done

if (( USE_COLOR )) && [[ -t 1 ]]; then
    C_OK=$'\033[1;32m'; C_WARN=$'\033[1;33m'; C_BAD=$'\033[1;31m'
    C_DIM=$'\033[2m'; C_END=$'\033[0m'
else
    C_OK=''; C_WARN=''; C_BAD=''; C_DIM=''; C_END=''
fi

PASS=0
WARN=0
FAIL=0

pass() { PASS=$((PASS + 1)); (( QUIET )) || printf '%s[ok]%s %s\n' "$C_OK" "$C_END" "$*"; }
warn() { WARN=$((WARN + 1)); printf '%s[warn]%s %s\n' "$C_WARN" "$C_END" "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '%s[fail]%s %s\n' "$C_BAD" "$C_END" "$*"; }
section() { (( QUIET )) || printf '\n%s==>%s %s\n' "$C_DIM" "$C_END" "$*"; }

env_value() {
    [[ -f .env ]] || return 0
    { grep -E "^$1=" .env || true; } | tail -1 | cut -d= -f2-
}

DB_NAME=$(env_value MARIADB_DATABASE); DB_NAME=${DB_NAME:-radius}
ROOT_PW=$(env_value MARIADB_ROOT_PASSWORD)
APP_PW=$(env_value MARIADB_PASSWORD)

sql() {
    # 只读查询；失败返回非 0，由调用方判定。
    podman exec vpn-mariadb mariadb -uroot -p"$ROOT_PW" -N -B "$DB_NAME" \
        -e "$1" 2>/dev/null
}

api() {
    curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null || echo 000
}

api_body() {
    curl --noproxy '*' -s --max-time 5 "$1" 2>/dev/null || true
}

# ---------------------------------------------------------------- 配置
section "配置与凭据"

if [[ -f .env ]]; then
    pass ".env 存在"
else
    fail ".env 缺失（先运行 deploy/install.sh 或恢复备份）"
fi

if [[ -n "$ROOT_PW" && -n "$APP_PW" ]]; then
    if [[ "$ROOT_PW" == "$APP_PW" ]]; then
        fail "数据库 root 与应用账号使用同一密码，必须分开"
    else
        pass "数据库 root / 应用账号密码已分离"
    fi
else
    fail ".env 缺少 MARIADB_ROOT_PASSWORD 或 MARIADB_PASSWORD"
fi

# ---------------------------------------------------------------- 容器
section "容器"

EXPECTED_CONTAINERS=(vpn-mariadb vpn-policyd vpn-openvpn vpn-admin vpn-web vpn-retention)
for name in "${EXPECTED_CONTAINERS[@]}"; do
    status=$(podman inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)
    case "$status" in
        running) pass "容器 $name 运行中" ;;
        missing) fail "容器 $name 不存在" ;;
        *) fail "容器 $name 状态为 $status" ;;
    esac
done

app_ids=$(
    for name in vpn-policyd vpn-openvpn vpn-admin vpn-retention; do
        podman inspect -f '{{.Image}}' "$name" 2>/dev/null || echo missing
    done | sort -u | wc -l
)
if [[ "$app_ids" == "1" ]]; then
    pass "应用容器使用同一镜像"
else
    fail "应用容器镜像不一致（policyd/openvpn/admin/retention 应来自同一次构建）"
fi

latest_id=$(podman image inspect -f '{{.Id}}' localhost/vpn-acl-app:latest 2>/dev/null || true)
running_id=$(podman inspect -f '{{.Image}}' vpn-policyd 2>/dev/null || true)
if [[ -n "$latest_id" && "$latest_id" == "$running_id" ]]; then
    pass "运行中的镜像即 latest"
elif [[ -n "$latest_id" ]]; then
    warn "运行中的镜像不是 latest（升级后尚未重建容器？）"
fi

# ---------------------------------------------------------------- 健康
section "健康检查"

ready_code=$(api http://127.0.0.1:8080/readyz)
ready_body=$(api_body http://127.0.0.1:8080/readyz)
if [[ "$ready_code" == "200" ]]; then
    pass "/readyz 返回 200"
else
    fail "/readyz 返回 $ready_code：$ready_body"
fi

for field in database policyd status_file; do
    if grep -q "\"$field\":true" <<< "$ready_body"; then
        pass "readyz $field = true"
    else
        fail "readyz $field != true"
    fi
done

source_version=$(sed -n 's/^project(vpn_acl VERSION \([0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1)
running_version=$(grep -o '"version":"[^"]*"' <<< "$ready_body" | cut -d'"' -f4)
if [[ -z "$running_version" ]]; then
    warn "readyz 未返回版本（运行的是升级前的镜像？）"
elif [[ "$running_version" == "$source_version" ]]; then
    pass "运行版本 $running_version 与源码一致"
else
    fail "运行版本 $running_version 与源码 $source_version 不一致"
fi

if ./deploy/migrate.sh --status 2>/dev/null | grep -q '待应用 0'; then
    pass "数据库迁移已全部应用"
else
    fail "存在未应用的数据库迁移（运行 deploy/migrate.sh）"
fi

# ---------------------------------------------------------------- 策略
section "策略与审计"

if nft list table inet vpn_acl >/dev/null 2>&1; then
    pass "nftables 表 inet vpn_acl 存在"
else
    fail "nftables 表 inet vpn_acl 不存在（policyd 未下发策略？）"
fi

sets=$(nft list sets inet vpn_acl 2>/dev/null || true)
for set_name in flows flows_rev flows_deny; do
    if grep -q "set $set_name " <<< "$sets"; then
        pass "审计集合 $set_name 存在"
    else
        warn "审计集合 $set_name 不存在（旧镜像或未重建表）"
    fi
done

for table in vpn_access_log vpn_flow_state; do
    count=$(sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='$table'")
    if [[ "$count" == "1" ]]; then
        pass "表 $table 存在"
    else
        fail "表 $table 缺失（迁移未应用）"
    fi
done

has_session_col=$(sql "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='vpn_session_history' AND column_name='session_id'")
if [[ "$has_session_col" == "1" ]]; then
    pass "vpn_session_history.session_id 存在"
else
    fail "vpn_session_history.session_id 缺失（迁移未应用）"
fi

# ---------------------------------------------------------------- Web
section "Web 与安全头"

if command -v openssl >/dev/null 2>&1; then
    end_date=$(openssl s_client -connect 127.0.0.1:443 -servername localhost \
        </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null \
        | cut -d= -f2)
    if [[ -n "$end_date" ]]; then
        end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        days_left=$(( (end_epoch - now_epoch) / 86400 ))
        if (( end_epoch <= now_epoch )); then
            fail "Web 证书已过期（$end_date）"
        elif (( days_left < 30 )); then
            warn "Web 证书将在 ${days_left} 天后过期（$end_date）"
        else
            pass "Web 证书有效期 ${days_left} 天"
        fi
    else
        warn "无法读取 Web 证书（443 未监听？）"
    fi
else
    warn "未安装 openssl，跳过证书检查"
fi

headers=$(curl --noproxy '*' -k -s -D - -o /dev/null --max-time 5 https://127.0.0.1/ 2>/dev/null || true)
for header in content-security-policy strict-transport-security x-frame-options; do
    if grep -qi "^$header:" <<< "$headers"; then
        pass "Web 响应包含 $header"
    else
        fail "Web 响应缺少 $header"
    fi
done

metrics_code=$(api http://127.0.0.1:8080/metrics)
if [[ "$metrics_code" == "200" ]]; then
    pass "/metrics 可访问"
else
    fail "/metrics 返回 $metrics_code"
fi

unauth_code=$(api http://127.0.0.1:8080/api/me)
if [[ "$unauth_code" == "401" ]]; then
    pass "未登录访问 /api/me 返回 401"
else
    warn "未登录访问 /api/me 返回 $unauth_code（预期 401）"
fi

if [[ -n "${VPN_ADMIN_USER:-}" && -n "${VPN_ADMIN_PASSWORD:-}" ]]; then
    login_code=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
        --max-time 5 -H 'Content-Type: application/json' \
        -d "$(printf '{"username":"%s","password":"%s"}' "$VPN_ADMIN_USER" "$VPN_ADMIN_PASSWORD")" \
        http://127.0.0.1:8080/api/login 2>/dev/null || echo 000)
    if [[ "$login_code" == "200" ]]; then
        pass "管理员登录成功"
    else
        fail "管理员登录失败（HTTP $login_code）"
    fi
else
    warn "未提供 VPN_ADMIN_USER/VPN_ADMIN_PASSWORD，跳过真实登录"
fi

# ---------------------------------------------------------------- 环境
section "环境"

host_tz=$(date +%Z)
db_tz=$(podman exec vpn-mariadb date +%Z 2>/dev/null || echo unknown)
if [[ "$host_tz" == "$db_tz" ]]; then
    pass "数据库容器时区与宿主一致（$host_tz）"
else
    warn "数据库容器时区 $db_tz 与宿主 $host_tz 不一致（检查 .env 的 TZ）"
fi

disk=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')
if (( disk >= 90 )); then
    fail "根分区已使用 ${disk}%"
elif (( disk >= 80 )); then
    warn "根分区已使用 ${disk}%"
else
    pass "根分区使用 ${disk}%"
fi

if podman logs --tail 200 vpn-policyd 2>&1 | grep -qE '\bERROR\b'; then
    warn "vpn-policyd 最近日志包含 ERROR（podman logs vpn-policyd）"
else
    pass "vpn-policyd 最近日志无 ERROR"
fi

status_file=$(env_value VPN_OPENVPN_RUN_DIR); status_file=${status_file:-/run/openvpn-server}/status.log
if [[ -f "$status_file" ]]; then
    age=$(( $(date +%s) - $(stat -c %Y "$status_file") ))
    if (( age <= 30 )); then
        pass "OpenVPN status 文件新鲜（${age}s）"
    else
        fail "OpenVPN status 文件已 ${age}s 未更新"
    fi
else
    fail "OpenVPN status 文件不存在：$status_file"
fi

# ---------------------------------------------------------------- 汇总
printf '\n%s汇总%s：通过 %d，警告 %d，失败 %d\n' \
    "$C_DIM" "$C_END" "$PASS" "$WARN" "$FAIL"

if (( FAIL > 0 )); then
    exit 1
fi