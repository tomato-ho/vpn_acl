#!/usr/bin/env bash
#
# 配置边界与认证风控回归测试（需要已运行的栈 + root）。
#
#   sudo ./deploy/test-guards.sh
#
# 覆盖：
#   A. 固定 IP / 组范围拒绝 network/broadcast/gateway
#   B. 规则/服务上限在写入时生效
#   C. VPN 认证失败限流按 username+IP，不会跨 IP 锁死用户
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

export no_proxy="127.0.0.1,localhost,::1${no_proxy:+,$no_proxy}"
export NO_PROXY="$no_proxy"

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }
ok() { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

[[ $(id -u) -eq 0 ]] || fail "需要 root"
POLICYCTL=./build/vpn-policyctl
AUTH_CHECK=./build/vpn-auth-check
CONFIG=/etc/vpn-policy/config
[[ -x "$POLICYCTL" ]] || fail "缺少 build/vpn-policyctl"
[[ -x "$AUTH_CHECK" ]] || fail "缺少 build/vpn-auth-check"
[[ -f "$CONFIG/vpn-policy.conf" ]] || fail "缺少 $CONFIG/vpn-policy.conf"
[[ -f .env ]] || fail "缺少 .env"

ROOT_PW=$(grep -E '^MARIADB_ROOT_PASSWORD=' .env | tail -1 | cut -d= -f2-)
DB=$(grep -E '^MARIADB_DATABASE=' .env | tail -1 | cut -d= -f2-)
DB=${DB:-radius}
GROUP=guard-test
BAD_GROUP=guard-bad
USER=guard-user
AUTH_CRED=/tmp/vpn-guard.cred

sql() { podman exec -i vpn-mariadb mariadb -uroot -p"$ROOT_PW" "$DB" "$@"; }

cleanup() {
    sql -e "DELETE FROM vpn_flow_state WHERE session_id IN
                 (SELECT session_id FROM vpn_sessions WHERE username='$USER');
            DELETE FROM vpn_access_log WHERE username='$USER';
            DELETE FROM vpn_session_history WHERE username='$USER';
            DELETE FROM vpn_sessions WHERE username='$USER';
            DELETE FROM vpn_auth_log WHERE username='$USER';
            DELETE FROM vpn_user_rules WHERE username='$USER';
            DELETE FROM vpn_users WHERE username='$USER';
            DELETE FROM vpn_server_services
             WHERE (scope_type='user' AND scope_id='$USER')
                OR (scope_type='group' AND scope_id='$GROUP')
                OR (scope_type='group' AND scope_id='$BAD_GROUP');
            DELETE r FROM vpn_group_rules r JOIN vpn_groups g
             ON g.id=r.group_id WHERE g.name='$GROUP' OR g.name='$BAD_GROUP';
            DELETE FROM vpn_groups WHERE name='$GROUP' OR name='$BAD_GROUP';
            UPDATE vpn_policy_version SET version=version+1, updated_at=NOW()
             WHERE id=1;" >/dev/null 2>&1 || true
    rm -f "$AUTH_CRED"
}
trap cleanup EXIT
cleanup

# ---------------------------------------------------------------- A. 固定 IP
log "A. 固定 IP / 组范围边界"
$POLICYCTL --config "$CONFIG" group-add "$GROUP" \
    --ip-start 10.9.100.210 --ip-end 10.9.100.240 >/dev/null

for ip in 10.9.100.1 10.9.100.0 10.9.100.255; do
    if $POLICYCTL --config "$CONFIG" user-add "$USER" --group "$GROUP" \
        --fixed-ip "$ip" >/dev/null 2>&1; then
        fail "A: 固定 IP $ip 应被拒绝"
    fi
done
$POLICYCTL --config "$CONFIG" user-add "$USER" --group "$GROUP" \
    --fixed-ip 10.9.100.210 >/dev/null
$POLICYCTL --config "$CONFIG" password-reset "$USER" \
    --password 'GuardTest123!' >/dev/null
if $POLICYCTL --config "$CONFIG" group-add "$BAD_GROUP" \
    --ip-start 10.9.100.1 --ip-end 10.9.100.10 >/dev/null 2>&1; then
    fail "A: 包含网关的组范围应被拒绝"
fi
ok "A: gateway/network/broadcast 均被拒绝"

# ---------------------------------------------------------------- B. 服务上限
log "B. max_services_per_user 写入校验"
port=20001
while [[ $port -le 20016 ]]; do
    $POLICYCTL --config "$CONFIG" service-add user "$USER" \
        "10.9.100.1:${port}/tcp" >/dev/null
    port=$((port + 1))
done
if $POLICYCTL --config "$CONFIG" service-add user "$USER" \
    "10.9.100.1:20017/tcp" >/dev/null 2>&1; then
    fail "B: 第 17 个服务应被拒绝"
fi
ok "B: 服务超限被拒绝"

# ---------------------------------------------------------------- C. 规则上限
log "C. max_rules_per_user 写入校验"
for i in $(seq 0 127); do
    $POLICYCTL --config "$CONFIG" user-rule-add "$USER" allow \
        "10.1.${i}.0/24" >/dev/null
done
if $POLICYCTL --config "$CONFIG" user-rule-add "$USER" allow \
    "10.2.0.0/16" >/dev/null 2>&1; then
    fail "C: 第 129 条用户规则应被拒绝"
fi
if $POLICYCTL --config "$CONFIG" group-rule-add "$GROUP" allow \
    "10.3.0.0/16" >/dev/null 2>&1; then
    fail "C: 会把用户推到 129 条的组规则应被拒绝"
fi
ok "C: 用户/组规则超限被拒绝"

# ---------------------------------------------------------------- D. 认证限流
log "D. VPN 认证限流按 username+IP"
printf '%s\n%s\n' "$USER" 'WrongPass123!' > "$AUTH_CRED"
chmod 600 "$AUTH_CRED"
for _ in $(seq 1 5); do
    if env VPN_AUTH_CONFIG="$CONFIG" trusted_ip=203.0.113.10 \
        "$AUTH_CHECK" "$AUTH_CRED" >/dev/null 2>&1; then
        fail "D: 错误密码不应通过"
    fi
done
printf '%s\n%s\n' "$USER" 'GuardTest123!' > "$AUTH_CRED"
if env VPN_AUTH_CONFIG="$CONFIG" trusted_ip=203.0.113.10 \
    "$AUTH_CHECK" "$AUTH_CRED" >/dev/null 2>&1; then
    fail "D: 同一 IP 连续失败后仍应被限流"
fi
if ! env VPN_AUTH_CONFIG="$CONFIG" trusted_ip=203.0.113.11 \
    "$AUTH_CHECK" "$AUTH_CRED" >/dev/null 2>&1; then
    fail "D: 另一来源 IP 不应被同一 username 的失败锁死"
fi
ok "D: 限流按 username+IP 生效"

log "全部边界/风控用例通过"