#!/usr/bin/env bash
#
# 长时间故障注入，用于验证宿主机上的栈能否在一晚上反复恢复。
#
#   sudo ./deploy/soak-faults.sh --duration 10h --interval 15m
#   sudo ./deploy/soak-faults.sh --dry-run
#   sudo ./deploy/soak-faults.sh --only restart_admin,policy_bump --duration 10m
#
# 每次只注入一个故障，注入前确认当前健康，注入后等待恢复并记录耗时。
# 不会执行 podman-compose down，不会删除数据，只使用一个测试用户 soak-client。
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

# 本机健康检查必须绕过 HTTP 代理（很多环境全局设置了 http_proxy）。
export no_proxy="127.0.0.1,localhost,::1${no_proxy:+,$no_proxy}"
export NO_PROXY="$no_proxy"

LOG_FILE=${SOAK_LOG:-/var/log/vpn-soak-faults.log}
CSV_FILE=${SOAK_CSV:-/var/log/vpn-soak-faults.csv}
POLICYCTL=./build/vpn-policyctl
CONNECT=./build/vpn-client-connect
DISCONNECT=./build/vpn-client-disconnect
CONFIG=/etc/vpn-policy/config

SOAK_USER=soak-client
SOAK_IP=10.9.100.89

DURATION=36000       # 10h
INTERVAL=900         # 15m
TIMEOUT=180          # 单次恢复超时
DRY_RUN=0
SHUFFLE=0
ONLY_CSV=""
SKIP_CSV=""
KEEP_USER=0

log() {
    local line
    line="$(date -Is) $*"
    printf '%s\n' "$line"
    printf '%s\n' "$line" >> "$LOG_FILE"
}

fail() { log "[FAIL] $*"; exit 1; }

parse_duration() {
    local value=$1
    case "$value" in
        *h) echo $(( ${value%h} * 3600 )) ;;
        *m) echo $(( ${value%m} * 60 )) ;;
        *s) echo "${value%s}" ;;
        *) echo "$value" ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION=$(parse_duration "${2:?}"); shift ;;
        --interval) INTERVAL=$(parse_duration "${2:?}"); shift ;;
        --timeout) TIMEOUT=${2:?}; shift ;;
        --only) ONLY_CSV=${2:?}; shift ;;
        --skip) SKIP_CSV=${2:?}; shift ;;
        --shuffle) SHUFFLE=1 ;;
        --keep-user) KEEP_USER=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "未知参数 $1" ;;
    esac
    shift
done

[[ $(id -u) -eq 0 ]] || fail "需要 root"
[[ -f .env ]] || fail "缺少 .env"
[[ -f "$CONFIG/vpn-policy.conf" ]] || fail "缺少 $CONFIG"
[[ -x "$POLICYCTL" ]] || fail "缺少 $POLICYCTL（先 ./configure.sh）"

ROOT_PW=$(grep -E '^MARIADB_ROOT_PASSWORD=' .env | tail -1 | cut -d= -f2-)
DB_NAME=$(grep -E '^MARIADB_DATABASE=' .env | tail -1 | cut -d= -f2-)
DB_NAME=${DB_NAME:-radius}

sql() { podman exec -i vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB_NAME" "$@"; }
sqlq() { podman exec vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB_NAME" -N -e "$1"; }

readyz() {
    curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:8080/readyz >/dev/null 2>&1
}

wait_ready() {
    local limit=$1
    local start
    start=$(date +%s)
    while (( $(date +%s) - start < limit )); do
        readyz && return 0
        sleep 2
    done
    return 1
}

container_running() {
    [[ "$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]
}

wait_container() {
    local name=$1 limit=$2
    local start
    start=$(date +%s)
    while (( $(date +%s) - start < limit )); do
        container_running "$name" && return 0
        sleep 1
    done
    return 1
}

wait_mariadb_healthy() {
    local limit=$1
    local start
    start=$(date +%s)
    while (( $(date +%s) - start < limit )); do
        if podman exec vpn-mariadb healthcheck.sh --connect \
            --innodb_initialized >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}

refresh_total() {
    curl --noproxy '*' -s --max-time 3 http://127.0.0.1:8080/metrics 2>/dev/null |
        awk '/^vpn_policyd_refresh_total /{print $2}' | tail -1
}

container_restarts() {
    local name value total=0
    for name in vpn-policyd vpn-admin vpn-openvpn vpn-web vpn-retention; do
        value=$(podman inspect -f '{{.RestartCount}}' "$name" 2>/dev/null || echo 0)
        total=$((total + ${value:-0}))
    done
    echo "$total"
}

ensure_soak_user() {
    if ! $POLICYCTL --config "$CONFIG" show "$SOAK_USER" >/dev/null 2>&1; then
        log "创建测试用户 $SOAK_USER ($SOAK_IP)"
        $POLICYCTL --config "$CONFIG" user-add "$SOAK_USER" --group staff \
            --fixed-ip "$SOAK_IP" >/dev/null
        $POLICYCTL --config "$CONFIG" password-reset "$SOAK_USER" \
            --password 'SoakTest123!' >/dev/null
    fi
}

cleanup() {
    if [[ $KEEP_USER -eq 1 ]]; then
        log "保留测试用户 $SOAK_USER（--keep-user）"
        return 0
    fi
    log "清理测试用户 $SOAK_USER"
    sql -e "DELETE FROM vpn_sessions WHERE username='$SOAK_USER';
            DELETE FROM vpn_session_history WHERE username='$SOAK_USER';
            DELETE FROM vpn_auth_log WHERE username='$SOAK_USER';
            DELETE FROM vpn_user_rules WHERE username='$SOAK_USER';
            DELETE FROM vpn_users WHERE username='$SOAK_USER';" \
        >/dev/null 2>&1 || true
    sql -e "UPDATE vpn_policy_version SET version=version+1, updated_at=NOW()
             WHERE id=1" >/dev/null 2>&1 || true
    rm -f /tmp/soak-*.conf
}

connect_hook() {
    local user=$1 ip=$2 t=$3 out=$4
    env common_name="$user" username="$user" trusted_ip=127.0.0.1 \
        time_unix="$t" "$CONNECT" "$out" >/dev/null
}

disconnect_hook() {
    local user=$1 ip=$2 t=$3
    env common_name="$user" username="$user" \
        ifconfig_pool_remote_ip="$ip" time_unix="$t" \
        bytes_received=1 bytes_sent=1 time_duration=1 \
        "$DISCONNECT" >/dev/null 2>&1 || true
}

session_of() { sqlq "SELECT session_id FROM vpn_sessions WHERE username='$SOAK_USER' LIMIT 1"; }

# ---------------------------------------------------------------- 场景

scenario_restart_openvpn() {
    podman restart vpn-openvpn >/dev/null
    wait_container vpn-openvpn 60 || return 1
    wait_ready "$TIMEOUT"
}

scenario_restart_mariadb() {
    podman restart vpn-mariadb >/dev/null
    wait_mariadb_healthy "$TIMEOUT" || return 1
    wait_ready "$TIMEOUT"
}

scenario_stop_mariadb() {
    podman stop vpn-mariadb >/dev/null
    sleep 20
    podman start vpn-mariadb >/dev/null
    wait_mariadb_healthy "$TIMEOUT" || return 1
    wait_ready "$TIMEOUT"
}

scenario_restart_policyd() {
    podman restart vpn-policyd >/dev/null
    wait_container vpn-policyd 60 || return 1
    wait_ready "$TIMEOUT"
}

scenario_restart_admin() {
    podman restart vpn-admin >/dev/null
    wait_container vpn-admin 60 || return 1
    wait_ready "$TIMEOUT"
}

scenario_restart_retention() {
    podman restart vpn-retention >/dev/null
    wait_container vpn-retention 60 || return 1
    wait_ready "$TIMEOUT"
}

scenario_network_reload() {
    podman network reload --all >/dev/null 2>&1 || return 1
    sleep 2
    podman exec vpn-admin getent hosts mariadb >/dev/null 2>&1 || return 1
    wait_ready "$TIMEOUT"
}

scenario_policy_bump() {
    local before after
    before=$(refresh_total)
    sql -e "UPDATE vpn_policy_version SET version=version+1, updated_at=NOW()
             WHERE id=1" >/dev/null
    sleep 14 # admin 的 metrics 缓存默认 10s
    after=$(refresh_total)
    [[ -n "$before" && -n "$after" ]] || return 1
    [[ "$after" -gt "$before" ]]
}

scenario_synthetic_reconnect() {
    local t1 t2 sid1 sid2
    t1=$(date +%s)
    connect_hook "$SOAK_USER" "$SOAK_IP" "$t1" /tmp/soak-1.conf || return 1
    sid1=$(session_of)
    [[ -n "$sid1" ]] || return 1
    t2=$((t1 + 3))
    connect_hook "$SOAK_USER" "$SOAK_IP" "$t2" /tmp/soak-2.conf || return 1
    sid2=$(session_of)
    [[ -n "$sid2" && "$sid1" != "$sid2" ]] || return 1
    disconnect_hook "$SOAK_USER" "$SOAK_IP" "$t1"
    sleep 1
    [[ "$(session_of)" == "$sid2" ]] || return 1
    disconnect_hook "$SOAK_USER" "$SOAK_IP" "$t2"
    return 0
}

ALL_SCENARIOS=(
    restart_openvpn
    restart_mariadb
    stop_mariadb
    restart_policyd
    restart_admin
    restart_retention
    network_reload
    policy_bump
    synthetic_reconnect
)

selected=()
for scenario in "${ALL_SCENARIOS[@]}"; do
    if [[ -n "$ONLY_CSV" && ",$ONLY_CSV," != *",$scenario,"* ]]; then
        continue
    fi
    if [[ -n "$SKIP_CSV" && ",$SKIP_CSV," == *",$scenario,"* ]]; then
        continue
    fi
    selected+=("$scenario")
done
(( ${#selected[@]} > 0 )) || fail "没有可运行的场景"

if [[ $SHUFFLE -eq 1 ]]; then
    mapfile -t selected < <(printf '%s\n' "${selected[@]}" | shuf)
fi

if [[ $DRY_RUN -eq 1 ]]; then
    echo "场景（${#selected[@]} 个）：${selected[*]}"
    echo "duration=${DURATION}s interval=${INTERVAL}s timeout=${TIMEOUT}s"
    exit 0
fi

[[ -f "$LOG_FILE" ]] || : > "$LOG_FILE"
if [[ ! -f "$CSV_FILE" ]]; then
    echo "time,scenario,result,recovery_seconds,readyz,restarts" > "$CSV_FILE"
fi

trap cleanup EXIT
trap 'log "收到中断，准备退出"; exit 130' INT TERM

running_names=$(podman ps --format '{{.Names}}' 2>/dev/null || true)
grep -qx vpn-mariadb <<< "$running_names" || fail "vpn-mariadb 未运行"
grep -qx vpn-policyd <<< "$running_names" || fail "vpn-policyd 未运行"
if ! wait_ready 60; then
    log "初始 readyz 不健康，等待恢复（不退出）"
    if ! wait_ready "$TIMEOUT"; then
        log "警告：readyz 仍未恢复，继续运行；precheck 会跳过不健康的轮次"
    fi
fi

if ! $POLICYCTL --config "$CONFIG" group-show staff >/dev/null 2>&1; then
    fail "缺少 staff 组（soak 脚本需要它创建测试用户）"
fi
ensure_soak_user

log "开始故障注入：duration=${DURATION}s interval=${INTERVAL}s"
log "场景：${selected[*]}"

end_at=$(( $(date +%s) + DURATION ))
index=0
total=0
success=0
skipped=0
failure=0
max_recovery=0

while (( $(date +%s) < end_at )); do
    scenario=${selected[$((index % ${#selected[@]}))]}
    index=$((index + 1))
    total=$((total + 1))

    if ! wait_ready 60; then
        log "precheck_failed scenario=$scenario（当前不健康，跳过本轮）"
        printf '%s,%s,precheck_failed,0,false,%s\n' \
            "$(date -Is)" "$scenario" "$(container_restarts)" >> "$CSV_FILE"
        skipped=$((skipped + 1))
    else
        log "注入 scenario=$scenario"
        started=$(date +%s)
        restarts_before=$(container_restarts)
        if "scenario_$scenario"; then
            recovery=$(( $(date +%s) - started ))
            log "恢复 scenario=$scenario recovery=${recovery}s"
            printf '%s,%s,ok,%s,true,%s\n' \
                "$(date -Is)" "$scenario" "$recovery" "$restarts_before" >> "$CSV_FILE"
            success=$((success + 1))
            (( recovery > max_recovery )) && max_recovery=$recovery
        else
            recovery=$(( $(date +%s) - started ))
            log "失败 scenario=$scenario recovery=${recovery}s（超时或检查未通过）"
            printf '%s,%s,failed,%s,false,%s\n' \
                "$(date -Is)" "$scenario" "$recovery" "$(container_restarts)" >> "$CSV_FILE"
            failure=$((failure + 1))
        fi
    fi

    remaining=$(( end_at - $(date +%s) ))
    if (( remaining <= 0 )); then
        break
    fi
    sleep_for=$INTERVAL
    (( sleep_for > remaining )) && sleep_for=$remaining
    sleep "$sleep_for"
done

log "结束：total=$total ok=$success skipped=$skipped failed=$failure max_recovery=${max_recovery}s"
log "日志：$LOG_FILE  CSV：$CSV_FILE"

[[ $failure -eq 0 ]]