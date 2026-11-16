#!/usr/bin/env bash
#
# 可靠性回归测试（需要已运行的 compose 栈 + root）。
#
#   sudo ./deploy/test-reliability.sh
#
# 覆盖：
#   A. 同一用户重连：旧连接的 disconnect 不能杀掉新会话（marker 按连接时间隔离）
#   B. 并发连接：5 个用户同时 CONNECT，跨一次 reconcile 后会话与 nft 链仍完整
#   C. 版本轮询：直接改 vpn_policy_version，不调 IPC，policyd 应自动刷新
#   D. reconcile 自愈：删除在线会话行后应被补建并恢复 nft
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }
ok() { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

[[ $(id -u) -eq 0 ]] || fail "需要 root"
[[ -x build/vpn-policyctl ]] || fail "缺少 build/vpn-policyctl（先 ./configure.sh）"
[[ -x build/vpn-client-connect ]] || fail "缺少 build/vpn-client-connect"
[[ -x build/vpn-client-disconnect ]] || fail "缺少 build/vpn-client-disconnect"
[[ -f /etc/vpn-policy/config/vpn-policy.conf ]] || fail "缺少 /etc/vpn-policy/config"
[[ -f .env ]] || fail "缺少 .env"

if [[ -n ${OPENVPN_BIN:-} ]]; then
    :
elif command -v openvpn >/dev/null 2>&1; then
    OPENVPN_BIN=$(command -v openvpn)
elif [[ -x /data/app/openvpn-2.7.9/sbin/openvpn ]]; then
    OPENVPN_BIN=/data/app/openvpn-2.7.9/sbin/openvpn
else
    fail "找不到 openvpn 客户端二进制（可用 OPENVPN_BIN 指定）"
fi

POLICYCTL=./build/vpn-policyctl
CONNECT=./build/vpn-client-connect
DISCONNECT=./build/vpn-client-disconnect
CONFIG=/etc/vpn-policy/config
ROOT_PW=$(grep -E '^MARIADB_ROOT_PASSWORD=' .env | tail -1 | cut -d= -f2-)
DB=$(grep -E '^MARIADB_DATABASE=' .env | tail -1 | cut -d= -f2-)
DB=${DB:-radius}
MARKER_DIR=/run/vpn-policyd/clients

sql() { podman exec -i vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB" "$@"; }
sqlq() { podman exec vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB" -N -e "$1"; }

podman ps --format '{{.Names}}' | grep -qx vpn-policyd ||
    fail "vpn-policyd 未运行"
podman ps --format '{{.Names}}' | grep -qx vpn-mariadb ||
    fail "vpn-mariadb 未运行"

if ! $POLICYCTL --config "$CONFIG" group-show staff >/dev/null 2>&1; then
    log "创建测试组 staff"
    $POLICYCTL --config "$CONFIG" group-add staff \
        --ip-start 10.9.100.10 --ip-end 10.9.100.200 >/dev/null
    $POLICYCTL --config "$CONFIG" group-rule-add staff allow 192.168.140.0/24 \
        >/dev/null
fi

cleanup_users=()
D_PID=""
cleanup() {
    if [[ -n "$D_PID" ]]; then
        kill "$D_PID" 2>/dev/null || true
    fi
    pkill -f 'dev tun-rel' 2>/dev/null || true
    local user
    for user in "${cleanup_users[@]:-}"; do
        [[ -n "$user" ]] || continue
        sql -e "DELETE FROM vpn_sessions WHERE username='$user';
                DELETE FROM vpn_session_history WHERE username='$user';
                DELETE FROM vpn_auth_log WHERE username='$user';
                DELETE FROM vpn_user_rules WHERE username='$user';
                DELETE FROM vpn_users WHERE username='$user';" >/dev/null 2>&1
    done
    rm -f /tmp/vpn-rel-*.conf
    sql -e "UPDATE vpn_policy_version SET version=version+1, updated_at=NOW()
             WHERE id=1" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 清理上次失败留下的测试客户端
pkill -f 'dev tun-rel' 2>/dev/null || true

create_user() {
    local user=$1 ip=$2
    sql -e "DELETE FROM vpn_sessions WHERE username='$user';
            DELETE FROM vpn_user_rules WHERE username='$user';
            DELETE FROM vpn_users WHERE username='$user';" >/dev/null
    $POLICYCTL --config "$CONFIG" user-add "$user" --group staff \
        --fixed-ip "$ip" >/dev/null
    $POLICYCTL --config "$CONFIG" password-reset "$user" \
        --password 'RelTest123!' >/dev/null
    cleanup_users+=("$user")
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
        bytes_received=100 bytes_sent=200 time_duration=10 \
        "$DISCONNECT" >/dev/null 2>&1 || true
}

session_id_of() {
    sqlq "SELECT session_id FROM vpn_sessions WHERE username='$1' LIMIT 1"
}

wait_online() {
    local user=$1 tries=${2:-20}
    local _
    for _ in $(seq 1 "$tries"); do
        if [[ -n "$(session_id_of "$user")" ]]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

wait_status_ip() {
    local ip=$1 tries=${2:-30}
    local _
    for _ in $(seq 1 "$tries"); do
        grep -q "$ip" /run/openvpn-server/status.log && return 0
        sleep 0.5
    done
    return 1
}

wait_offline() {
    local user=$1 tries=${2:-20}
    local _
    for _ in $(seq 1 "$tries"); do
        if [[ -z "$(session_id_of "$user")" ]]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

nft_chain_exists() {
    local ip=$2
    local state
    state=$(nft list table inet vpn_acl 2>/dev/null || true)
    grep -q "$ip : jump uf_" <<< "$state"
}

# ---------------------------------------------------------------- A. 重连隔离
log "A. 同一用户重连：旧 disconnect 不应杀掉新会话"
A_USER="t-rel-a"
A_IP=10.9.100.91
create_user "$A_USER" "$A_IP"
T1=$(date +%s)
connect_hook "$A_USER" "$A_IP" "$T1" /tmp/vpn-rel-a1.conf
wait_online "$A_USER" || fail "A: 首次连接未上线"
SID1=$(session_id_of "$A_USER")

sleep 1
T2=$((T1 + 5))
connect_hook "$A_USER" "$A_IP" "$T2" /tmp/vpn-rel-a2.conf
wait_online "$A_USER" || fail "A: 第二次连接未上线"
SID2=$(session_id_of "$A_USER")
[[ "$SID1" != "$SID2" ]] || fail "A: 重连后 session_id 未变化"
[[ -f "$MARKER_DIR/$A_USER@$A_IP@$T1" ]] ||
    fail "A: 旧连接 marker 不存在（应与其他连接隔离）"

# 旧连接的 disconnect（使用旧 time_unix）
disconnect_hook "$A_USER" "$A_IP" "$T1"
sleep 1
[[ "$(session_id_of "$A_USER")" == "$SID2" ]] ||
    fail "A: 旧 disconnect 误杀了新会话"
ok "A: 新会话保持在线"

disconnect_hook "$A_USER" "$A_IP" "$T2"
wait_offline "$A_USER" || fail "A: 新会话未正常下线"
ok "A: 新会话正常归档"

# ---------------------------------------------------------------- B. 并发
log "B. 5 个用户并发连接，跨一次 reconcile"
B_USERS=()
B_IPS=()
i=1
while [[ $i -le 5 ]]; do
    user="t-rel-b$i"
    ip="10.9.100.8$i"
    create_user "$user" "$ip"
    B_USERS+=("$user")
    B_IPS+=("$ip")
    i=$((i + 1))
done

TB=$(date +%s)
i=0
while [[ $i -lt 5 ]]; do
    connect_hook "${B_USERS[$i]}" "${B_IPS[$i]}" "$TB" \
        "/tmp/vpn-rel-b$i.conf" &
    i=$((i + 1))
done
wait

i=0
while [[ $i -lt 5 ]]; do
    wait_online "${B_USERS[$i]}" || fail "B: ${B_USERS[$i]} 未上线"
    i=$((i + 1))
done

log "等待一个 reconcile 周期..."
sleep 35

i=0
while [[ $i -lt 5 ]]; do
    [[ -n "$(session_id_of "${B_USERS[$i]}")" ]] ||
        fail "B: reconcile 后会丢失 ${B_USERS[$i]} 的会话"
    nft_chain_exists "${B_USERS[$i]}" "${B_IPS[$i]}" ||
        fail "B: reconcile 后 ${B_USERS[$i]} 的 nft 链丢失"
    i=$((i + 1))
done
ok "B: 并发会话与 nft 链完整"

i=0
while [[ $i -lt 5 ]]; do
    disconnect_hook "${B_USERS[$i]}" "${B_IPS[$i]}" "$TB"
    i=$((i + 1))
done
i=0
while [[ $i -lt 5 ]]; do
    wait_offline "${B_USERS[$i]}" || fail "B: ${B_USERS[$i]} 未下线"
    i=$((i + 1))
done
ok "B: 全部正常下线"

# ---------------------------------------------------------------- C. 版本轮询
log "C. 直接递增 vpn_policy_version（不调 IPC）"
before=$(curl -s http://127.0.0.1:8080/metrics |
    awk '/^vpn_policyd_refresh_total /{print $2}')
sql -e "UPDATE vpn_policy_version SET version=version+1, updated_at=NOW()
         WHERE id=1" >/dev/null
sleep 14
after=$(curl -s http://127.0.0.1:8080/metrics |
    awk '/^vpn_policyd_refresh_total /{print $2}')
[[ -n "$before" && -n "$after" ]] || fail "C: 读不到 refresh_total"
[[ "$after" -gt "$before" ]] ||
    fail "C: 版本变化后 policyd 没有自动刷新 ($before -> $after)"
ok "C: policyd 自动刷新（$before -> $after）"

# ---------------------------------------------------------------- D. 自愈
log "D. 删除在线会话行，reconcile 应补建（真实客户端）"
D_USER="t-rel-d"
D_IP=10.9.100.86
create_user "$D_USER" "$D_IP"
printf '%s\n%s\n' "$D_USER" 'RelTest123!' > /tmp/vpn-rel-d.cred
chmod 600 /tmp/vpn-rel-d.cred

timeout 120 "$OPENVPN_BIN" --config /etc/vpn-policy/client.ovpn --dev tun-reld \
    --remote 127.0.0.1 1194 --auth-user-pass /tmp/vpn-rel-d.cred \
    --route-noexec --ifconfig-noexec \
    > /tmp/vpn-rel-d.log 2>&1 &
D_PID=$!

wait_online "$D_USER" 40 || fail "D: 真实客户端未上线"
wait_status_ip "$D_IP" 30 || fail "D: 状态文件里没有该客户端"

sql -e "DELETE FROM vpn_sessions WHERE username='$D_USER'" >/dev/null
[[ -z "$(session_id_of "$D_USER")" ]] || fail "D: 删除会话行失败"

log "等待 reconcile 补建..."
sleep 35
[[ -n "$(session_id_of "$D_USER")" ]] || fail "D: reconcile 未补建会话"
nft_chain_exists "$D_USER" "$D_IP" || fail "D: reconcile 未恢复 nft 链"
ok "D: 会话已补建且 nft 已恢复"

kill "$D_PID" 2>/dev/null || true
wait "$D_PID" 2>/dev/null || true
rm -f /tmp/vpn-rel-d.cred

log "全部可靠性用例通过"