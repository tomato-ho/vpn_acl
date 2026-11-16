#!/usr/bin/env bash
#
# 长时间采样，配合 soak-faults.sh 使用。
#
#   sudo ./deploy/soak-monitor.sh --interval 5m --duration 10h
#   sudo ./deploy/soak-monitor.sh --out /var/log/vpn-soak.csv
#
# 每次采样写一行 CSV：就绪状态、policyd 内存/句柄、会话/历史、nft 链、
# 容器重启次数、DB 连接数、刷新/对账计数。
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

OUT=${SOAK_MONITOR_CSV:-/var/log/vpn-soak.csv}
INTERVAL=300
DURATION=0

log() { printf '%s %s\n' "$(date -Is)" "$*"; }
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
        --interval) INTERVAL=$(parse_duration "${2:?}"); shift ;;
        --duration) DURATION=$(parse_duration "${2:?}"); shift ;;
        --out) OUT=${2:?}; shift ;;
        -h|--help) sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "未知参数 $1" ;;
    esac
    shift
done

[[ $(id -u) -eq 0 ]] || fail "需要 root"
[[ -f .env ]] || fail "缺少 .env"

ROOT_PW=$(grep -E '^MARIADB_ROOT_PASSWORD=' .env | tail -1 | cut -d= -f2-)
DB_NAME=$(grep -E '^MARIADB_DATABASE=' .env | tail -1 | cut -d= -f2-)
DB_NAME=${DB_NAME:-radius}

sqlq() { podman exec vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB_NAME" -N -e "$1" 2>/dev/null || echo "-1"; }

mkdir -p "$(dirname "$OUT")"
if [[ ! -f "$OUT" ]]; then
    echo "time,readyz,database,policyd,status_file,rss_kb,fds,sessions,history,chains,restarts,db_conns,refresh_total,reconcile_total,refresh_errors,reconcile_errors" > "$OUT"
fi

end_at=0
if (( DURATION > 0 )); then
    end_at=$(( $(date +%s) + DURATION ))
fi

log "采样开始 interval=${INTERVAL}s duration=${DURATION}s -> $OUT"

while true; do
    ts=$(date -Is)
    ready_body=$(curl -s --max-time 3 http://127.0.0.1:8080/readyz 2>/dev/null || true)
    ready=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
        http://127.0.0.1:8080/readyz 2>/dev/null || true)
    ready=${ready:-000}
    db_flag=$(grep -o '"database":[a-z]*' <<< "$ready_body" | cut -d: -f2)
    policyd_flag=$(grep -o '"policyd":[a-z]*' <<< "$ready_body" | cut -d: -f2)
    status_flag=$(grep -o '"status_file":[a-z]*' <<< "$ready_body" | cut -d: -f2)

    pid=$(pgrep -f 'vpn-policyd --config' | head -1 || true)
    if [[ -n "$pid" ]]; then
        rss=$(ps -o rss= -p "$pid" | awk '{print $1+0}')
        fds=$(find /proc/"$pid"/fd -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    else
        rss=0
        fds=0
    fi

    sessions=$(sqlq "SELECT COUNT(*) FROM vpn_sessions")
    history=$(sqlq "SELECT COUNT(*) FROM vpn_session_history")
    db_conns=$(sqlq "SELECT COUNT(*) FROM information_schema.processlist")

    chains=$(nft list table inet vpn_acl 2>/dev/null | grep -c 'chain uf_' || true)

    restarts=0
    for name in vpn-policyd vpn-admin vpn-openvpn vpn-web vpn-retention; do
        value=$(podman inspect -f '{{.RestartCount}}' "$name" 2>/dev/null || echo 0)
        restarts=$((restarts + ${value:-0}))
    done

    metrics=$(curl -s --max-time 3 http://127.0.0.1:8080/metrics 2>/dev/null || true)
    refresh_total=$(awk '/^vpn_policyd_refresh_total /{print $2}' <<< "$metrics" | tail -1)
    reconcile_total=$(awk '/^vpn_policyd_reconcile_total /{print $2}' <<< "$metrics" | tail -1)
    refresh_errors=$(awk '/^vpn_policyd_refresh_errors_total /{print $2}' <<< "$metrics" | tail -1)
    reconcile_errors=$(awk '/^vpn_policyd_reconcile_errors_total /{print $2}' <<< "$metrics" | tail -1)

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$ts" "$ready" "${db_flag:-}" "${policyd_flag:-}" "${status_flag:-}" \
        "$rss" "$fds" "$sessions" "$history" "$chains" "$restarts" "$db_conns" \
        "${refresh_total:-0}" "${reconcile_total:-0}" \
        "${refresh_errors:-0}" "${reconcile_errors:-0}" >> "$OUT"

    if (( end_at > 0 && $(date +%s) >= end_at )); then
        break
    fi
    sleep "$INTERVAL"
done

log "采样结束：$OUT"