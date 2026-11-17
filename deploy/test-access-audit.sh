#!/usr/bin/env bash
#
# 访问审计回归测试（需要已运行的 compose 栈 + root + openvpn 客户端）。
#
#   sudo ./deploy/test-access-audit.sh
#
# 覆盖：
#   A. 允许访问：目标 IP、上行/下行字节被记录
#   B. 拒绝访问：被策略 drop 的目标也会记录
#   C. policyd 重启：采样基线不丢，字节继续累加
#   D. 断开：最终采样落库，nft 集合与采样基线被清理
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

# 本机健康检查必须绕过 HTTP 代理（很多环境全局设置了 http_proxy）。
export no_proxy="127.0.0.1,localhost,::1${no_proxy:+,$no_proxy}"
export NO_PROXY="$no_proxy"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }
ok() { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

[[ $(id -u) -eq 0 ]] || fail "需要 root"
[[ -x build/vpn-policyctl ]] || fail "缺少 build/vpn-policyctl（先 ./configure.sh）"
[[ -f /etc/vpn-policy/config/vpn-policy.conf ]] || fail "缺少 /etc/vpn-policy/config"
[[ -f /etc/vpn-policy/client.ovpn ]] || fail "缺少 /etc/vpn-policy/client.ovpn"
[[ -f .env ]] || fail "缺少 .env"
for tool in ip ping nft; do
    command -v "$tool" >/dev/null 2>&1 || fail "缺少命令：$tool"
done

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
CONFIG=/etc/vpn-policy/config
ROOT_PW=$(grep -E '^MARIADB_ROOT_PASSWORD=' .env | tail -1 | cut -d= -f2-)
DB=$(grep -E '^MARIADB_DATABASE=' .env | tail -1 | cut -d= -f2-)
DB=${DB:-radius}

USER_NAME=flowtest
GROUP_NAME=flowtest
VIRTUAL_IP=10.9.100.90
ALLOW_TARGET=10.99.0.2
DENY_TARGET=10.97.0.1
CLIENT_NS=vpnflow-client
TARGET_NS=vpnflow-target
CLIENT_VETH=vc-out
TARGET_VETH=vt-out
CRED_FILE=/tmp/vpn-flow.cred
CLIENT_LOG=/tmp/vpn-flow-client.log
CLIENT_PID=""
FIREWALLD_ACTIVE=0
TUN0_WAS_TRUSTED=0

sql() { podman exec -i vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB" "$@"; }
sqlq() { podman exec vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB" -N -e "$1"; }

running_names=$(podman ps --format '{{.Names}}' 2>/dev/null || true)
grep -qx vpn-policyd <<< "$running_names" || fail "vpn-policyd 未运行"
grep -qx vpn-mariadb <<< "$running_names" || fail "vpn-mariadb 未运行"

cleanup() {
    if [[ -n "$CLIENT_PID" ]]; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    pkill -f "[o]penvpn.*$CLIENT_NS" 2>/dev/null || true
    if [[ $FIREWALLD_ACTIVE -eq 1 ]]; then
        firewall-cmd --zone=trusted --remove-interface="$TARGET_VETH" \
            >/dev/null 2>&1 || true
        if [[ $TUN0_WAS_TRUSTED -eq 0 ]]; then
            firewall-cmd --zone=trusted --remove-interface=tun0 \
                >/dev/null 2>&1 || true
        fi
    fi
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$TARGET_NS" 2>/dev/null || true
    ip link del "$CLIENT_VETH" 2>/dev/null || true
    ip link del "$TARGET_VETH" 2>/dev/null || true
    rm -f "$CRED_FILE" "$CLIENT_LOG"

    sql -e "DELETE FROM vpn_flow_state WHERE session_id IN
                 (SELECT session_id FROM vpn_sessions WHERE username='$USER_NAME');
            DELETE FROM vpn_access_log WHERE username='$USER_NAME';
            DELETE FROM vpn_sessions WHERE username='$USER_NAME';
            DELETE FROM vpn_session_history WHERE username='$USER_NAME';
            DELETE FROM vpn_auth_log WHERE username='$USER_NAME';
            DELETE FROM vpn_user_rules WHERE username='$USER_NAME';
            DELETE FROM vpn_users WHERE username='$USER_NAME';
            DELETE r FROM vpn_group_rules r
                 JOIN vpn_groups g ON g.id = r.group_id
                 WHERE g.name='$GROUP_NAME';
            DELETE FROM vpn_groups WHERE name='$GROUP_NAME';
            UPDATE vpn_policy_version SET version=version+1, updated_at=NOW()
                 WHERE id=1;" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---------------------------------------------------------------- 准备
log "准备测试组 / 用户"
sql -e "DELETE FROM vpn_sessions WHERE username='$USER_NAME';
        DELETE FROM vpn_user_rules WHERE username='$USER_NAME';
        DELETE FROM vpn_users WHERE username='$USER_NAME';" >/dev/null
if ! $POLICYCTL --config "$CONFIG" group-show "$GROUP_NAME" >/dev/null 2>&1; then
    $POLICYCTL --config "$CONFIG" group-add "$GROUP_NAME" \
        --ip-start 10.9.100.90 --ip-end 10.9.100.99 >/dev/null
    $POLICYCTL --config "$CONFIG" group-rule-add "$GROUP_NAME" allow \
        10.99.0.0/24 >/dev/null
fi
$POLICYCTL --config "$CONFIG" user-add "$USER_NAME" --group "$GROUP_NAME" \
    --fixed-ip "$VIRTUAL_IP" >/dev/null
$POLICYCTL --config "$CONFIG" password-reset "$USER_NAME" \
    --password 'FlowTest123!' >/dev/null

log "建立客户端 / 目标网络命名空间"
ip netns del "$CLIENT_NS" 2>/dev/null || true
ip netns del "$TARGET_NS" 2>/dev/null || true
ip link del "$CLIENT_VETH" 2>/dev/null || true
ip link del "$TARGET_VETH" 2>/dev/null || true

ip netns add "$CLIENT_NS"
ip netns add "$TARGET_NS"

ip link add "$CLIENT_VETH" type veth peer name vc-in
ip link set vc-in netns "$CLIENT_NS"
ip addr add 10.98.0.1/24 dev "$CLIENT_VETH"
ip link set "$CLIENT_VETH" up
ip -n "$CLIENT_NS" addr add 10.98.0.2/24 dev vc-in
ip -n "$CLIENT_NS" link set vc-in up
ip -n "$CLIENT_NS" link set lo up

ip link add "$TARGET_VETH" type veth peer name vt-in
ip link set vt-in netns "$TARGET_NS"
ip addr add 10.99.0.1/24 dev "$TARGET_VETH"
ip link set "$TARGET_VETH" up
ip -n "$TARGET_NS" addr add "$ALLOW_TARGET/24" dev vt-in
ip -n "$TARGET_NS" link set vt-in up
ip -n "$TARGET_NS" link set lo up
ip -n "$TARGET_NS" route add default via 10.99.0.1

# firewalld 默认会拒绝未显式放行的转发流量。测试期间把 tun0/对端 veth
# 临时放进 trusted 区，结束时恢复原状。
if command -v firewall-cmd >/dev/null 2>&1 &&
    firewall-cmd --state >/dev/null 2>&1; then
    FIREWALLD_ACTIVE=1
    if firewall-cmd --zone=trusted --query-interface=tun0 >/dev/null 2>&1; then
        TUN0_WAS_TRUSTED=1
    else
        firewall-cmd --zone=trusted --add-interface=tun0 >/dev/null 2>&1 || true
    fi
    firewall-cmd --zone=trusted --add-interface="$TARGET_VETH" \
        >/dev/null 2>&1 || true
fi

printf '%s\n%s\n' "$USER_NAME" 'FlowTest123!' > "$CRED_FILE"
chmod 600 "$CRED_FILE"

log "启动真实 OpenVPN 客户端（netns 内）"
ip netns exec "$CLIENT_NS" "$OPENVPN_BIN" \
    --config /etc/vpn-policy/client.ovpn \
    --remote 10.98.0.1 1194 \
    --dev tun0 \
    --route-nopull \
    --auth-user-pass "$CRED_FILE" \
    > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

wait_session() {
    for _ in $(seq 1 40); do
        if [[ -n "$(sqlq "SELECT session_id FROM vpn_sessions WHERE username='$USER_NAME' LIMIT 1")" ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}
wait_session || { tail -20 "$CLIENT_LOG" >&2; fail "客户端未上线"; }
SESSION_ID=$(sqlq "SELECT session_id FROM vpn_sessions WHERE username='$USER_NAME' LIMIT 1")
[[ -n "$SESSION_ID" ]] || fail "读不到 session_id"

for _ in $(seq 1 30); do
    if ip -n "$CLIENT_NS" addr show tun0 2>/dev/null | grep -q "$VIRTUAL_IP"; then
        break
    fi
    sleep 1
done
ip -n "$CLIENT_NS" addr show tun0 | grep -q "$VIRTUAL_IP" ||
    fail "客户端 tun0 未获得 $VIRTUAL_IP"
ip -n "$CLIENT_NS" route add 10.99.0.0/24 dev tun0
ip -n "$CLIENT_NS" route add 10.97.0.0/24 dev tun0
ok "客户端已连接（session=$SESSION_ID）"

nft_set_contains() {
    nft list set inet vpn_acl "$1" 2>/dev/null | grep -q "$VIRTUAL_IP"
}

wait_for_log() {
    local dest=$1 action=$2 field=$3 value
    for _ in $(seq 1 40); do
        value=$(sqlq "SELECT $field FROM vpn_access_log
                       WHERE session_id='$SESSION_ID'
                         AND dest_ip='$dest' AND action='$action'")
        if [[ -n "$value" && "$value" != "0" ]]; then
            printf '%s' "$value"
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------- A. allow
log "A. 向允许目标发流量（$ALLOW_TARGET）"
ip netns exec "$CLIENT_NS" ping -c 5 -i 0.2 "$ALLOW_TARGET" >/dev/null ||
    fail "ping 允许目标失败"
UP=$(wait_for_log "$ALLOW_TARGET" allow bytes_up) ||
    fail "没有记录到允许目标的流量"
DOWN=$(sqlq "SELECT bytes_down FROM vpn_access_log
              WHERE session_id='$SESSION_ID'
                AND dest_ip='$ALLOW_TARGET' AND action='allow'")
[[ "$DOWN" -gt 0 ]] || fail "允许目标没有下行字节（bytes_down=$DOWN）"
[[ "$UP" -gt 0 ]] || fail "允许目标没有上行字节"
ok "A: allow 记录 dest=$ALLOW_TARGET up=$UP down=$DOWN"

# 上行来自 flows，下行来自 flows_rev，必须都能在 nft 里看到元素。
nft_set_contains flows || fail "flows 集合没有该客户端元素"
nft_set_contains flows_rev || fail "flows_rev 集合没有该客户端元素"

# ---------------------------------------------------------------- B. deny
log "B. 向未授权目标发流量（$DENY_TARGET）"
ip netns exec "$CLIENT_NS" ping -c 3 -i 0.2 "$DENY_TARGET" >/dev/null 2>&1 || true
DENY_UP=$(wait_for_log "$DENY_TARGET" deny bytes_up) ||
    fail "没有记录到被拒绝的目标"
[[ "$DENY_UP" -gt 0 ]] || fail "deny 记录字节为 0"
nft_set_contains flows_deny || fail "flows_deny 集合没有该客户端元素"
ok "B: deny 记录 dest=$DENY_TARGET up=$DENY_UP"

# ---------------------------------------------------------------- C. 重启
log "C. 重启 policyd，采样基线不应丢失"
BEFORE=$(sqlq "SELECT bytes_up FROM vpn_access_log
                WHERE session_id='$SESSION_ID'
                  AND dest_ip='$ALLOW_TARGET' AND action='allow'")
podman restart vpn-policyd >/dev/null
for _ in $(seq 1 30); do
    if curl --noproxy '*' -fsS --max-time 2 \
        http://127.0.0.1:8080/readyz >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
sleep 3
ip netns exec "$CLIENT_NS" ping -c 5 -i 0.2 "$ALLOW_TARGET" >/dev/null ||
    fail "重启后 ping 允许目标失败"

AFTER=$BEFORE
for _ in $(seq 1 40); do
    AFTER=$(sqlq "SELECT bytes_up FROM vpn_access_log
                   WHERE session_id='$SESSION_ID'
                     AND dest_ip='$ALLOW_TARGET' AND action='allow'")
    if [[ -n "$AFTER" && "$AFTER" -gt "$BEFORE" ]]; then
        break
    fi
    sleep 2
done
[[ -n "$AFTER" && "$AFTER" -gt "$BEFORE" ]] ||
    fail "policyd 重启后字节没有继续累加（$BEFORE -> $AFTER）"
[[ "$(sqlq "SELECT COUNT(*) FROM vpn_sessions WHERE username='$USER_NAME'")" == "1" ]] ||
    fail "重启后会话丢失"
ok "C: 重启后继续累加（$BEFORE -> $AFTER）"

# ---------------------------------------------------------------- D. 断开
log "D. 断开客户端，应做最终采样并清理集合"
ip netns exec "$CLIENT_NS" ping -c 3 -i 0.2 "$ALLOW_TARGET" >/dev/null || true
kill "$CLIENT_PID" 2>/dev/null || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=""

for _ in $(seq 1 40); do
    [[ -z "$(sqlq "SELECT session_id FROM vpn_sessions WHERE username='$USER_NAME'")" ]] &&
        break
    sleep 1
done
[[ -z "$(sqlq "SELECT session_id FROM vpn_sessions WHERE username='$USER_NAME'")" ]] ||
    fail "会话未正常归档"

FINAL=$(sqlq "SELECT bytes_up FROM vpn_access_log
               WHERE session_id='$SESSION_ID'
                 AND dest_ip='$ALLOW_TARGET' AND action='allow'")
[[ -n "$FINAL" && "$FINAL" -ge "$AFTER" ]] ||
    fail "断开时最终采样丢失（$AFTER -> $FINAL）"
[[ "$(sqlq "SELECT COUNT(*) FROM vpn_flow_state WHERE session_id='$SESSION_ID'")" == "0" ]] ||
    fail "断开后采样基线未清理"
if nft_set_contains flows || nft_set_contains flows_rev || nft_set_contains flows_deny; then
    fail "断开后 nft 集合仍残留该客户端元素"
fi
[[ "$(sqlq "SELECT COUNT(*) FROM vpn_access_log WHERE session_id='$SESSION_ID'")" -ge 2 ]] ||
    fail "审计记录不应随会话删除"
ok "D: 最终采样保留（up=$FINAL），集合与基线已清理"

log "全部访问审计用例通过"