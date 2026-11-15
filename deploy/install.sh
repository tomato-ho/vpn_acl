#!/usr/bin/env bash
#
# VPN Access Control 一键安装脚本（podman-compose）
#
#   ./deploy/install.sh             # 完整安装并启动
#   ./deploy/install.sh --check     # 只做环境检查，不修改任何东西
#   ./deploy/install.sh --with-deps # 先安装系统依赖（RHEL/Rocky/Alma 10）
#   ./deploy/install.sh --offline   # 不联网/不编译，使用已有二进制与 deploy/images/*.tar
#   ./deploy/install.sh --demo      # 额外创建演示用组和用户
#   ./deploy/install.sh --uninstall # 停止并移除容器（保留数据）
#   ./deploy/install.sh --purge     # 连同数据目录一起删除（危险）
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

CONFIG_DIR=${VPN_CONFIG_DIR:-/etc/vpn-policy}
RUN_DIR=${VPN_RUN_DIR:-/run/vpn-policyd}
OPENVPN_RUN_DIR=${VPN_OPENVPN_RUN_DIR:-/run/openvpn-server}
LOG_DIR=${VPN_LOG_DIR:-/var/log/vpn-policyd}

MODE=install
OFFLINE=0
DEMO=0
WITH_DEPS=0
ASSUME_YES=0
PROXY_URL=""
NEED_IMAGE_REBUILD=0

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
VPN Access Control 一键安装脚本（podman-compose）

  ./deploy/install.sh                完整安装并启动
  ./deploy/install.sh --check        只做环境检查，不修改任何东西
  ./deploy/install.sh --with-deps    先安装系统依赖（RHEL/Rocky/Alma 10）
  ./deploy/install.sh --proxy URL    所有下载走 HTTP 代理（如 http://192.168.1.1:10809）
  ./deploy/install.sh --offline      不联网/不编译，使用已有二进制与 deploy/images/*.tar
  ./deploy/install.sh --demo         额外创建演示用组和用户
  ./deploy/install.sh --uninstall    停止并移除容器（保留数据）
  ./deploy/install.sh --purge        连同数据目录一起删除（危险）
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) MODE=check ;;
        --offline) OFFLINE=1 ;;
        --demo) DEMO=1 ;;
        --with-deps) WITH_DEPS=1 ;;
        --proxy)
            [[ -n ${2:-} ]] || die "--proxy 需要一个 URL 参数"
            PROXY_URL=$2
            shift
            ;;
        --uninstall) MODE=uninstall ;;
        --purge) MODE=purge ;;
        -y|--yes) ASSUME_YES=1 ;;
        -h|--help) usage ;;
        *) echo "install: 未知参数 $1" >&2; exit 2 ;;
    esac
    shift
done

apply_proxy() {
    [[ -n "$PROXY_URL" ]] || return 0
    export http_proxy=$PROXY_URL https_proxy=$PROXY_URL
    export HTTP_PROXY=$PROXY_URL HTTPS_PROXY=$PROXY_URL
    export no_proxy=${no_proxy:-localhost,127.0.0.1,::1,192.168.152.0/24,10.9.100.0/24}
    export NO_PROXY=$no_proxy
    log "使用代理 $PROXY_URL"
}

random_password() {
    # 注意：不要用 `tr </dev/urandom | head -c`，在 pipefail 下 head 关闭管道会让
    # tr 收到 SIGPIPE（退出码 141）从而中断安装。
    local len=${1:-20}
    local raw
    raw=$(head -c $((len * 4)) /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
    printf '%s' "${raw:0:len}"
}

compose() {
    if command -v podman-compose >/dev/null 2>&1; then
        podman-compose "$@"
    else
        podman compose "$@"
    fi
}

# ---------------------------------------------------------------- 系统依赖

# 返回缺失的系统包（空格分隔）。命令型依赖用 command -v 判断，
# 避免 rpm -q npm 这类虚拟包名误报（npm 实际由 nodejs-npm 提供）。
openvpn_bin_path() {
    if [[ -n ${VPN_OPENVPN_BIN:-} && -x ${VPN_OPENVPN_BIN} ]]; then
        printf '%s' "$VPN_OPENVPN_BIN"
        return 0
    fi
    if command -v openvpn >/dev/null 2>&1; then
        command -v openvpn
        return 0
    fi
    if [[ -x /data/app/openvpn-2.7.9/sbin/openvpn ]]; then
        printf '%s' /data/app/openvpn-2.7.9/sbin/openvpn
        return 0
    fi
    return 1
}

missing_deps() {
    local missing=()
    command -v podman >/dev/null 2>&1 || missing+=(podman)
    command -v podman-compose >/dev/null 2>&1 || missing+=(podman-compose)
    command -v nft >/dev/null 2>&1 || missing+=(nftables)
    openvpn_bin_path >/dev/null 2>&1 || missing+=(openvpn)
    command -v openssl >/dev/null 2>&1 || missing+=(openssl)
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    command -v ss >/dev/null 2>&1 || missing+=(iproute)
    command -v tar >/dev/null 2>&1 || missing+=(tar)
    command -v gzip >/dev/null 2>&1 || missing+=(gzip)
    command -v gcc >/dev/null 2>&1 || missing+=(gcc)
    command -v g++ >/dev/null 2>&1 || missing+=(gcc-c++)
    command -v make >/dev/null 2>&1 || missing+=(make)
    command -v cmake >/dev/null 2>&1 || missing+=(cmake)
    command -v pkg-config >/dev/null 2>&1 || missing+=(pkgconf-pkg-config)
    command -v node >/dev/null 2>&1 || missing+=(nodejs)
    command -v npm >/dev/null 2>&1 || missing+=(nodejs-npm)
    rpm -q openssl-devel >/dev/null 2>&1 || missing+=(openssl-devel)
    rpm -q mariadb-connector-c-devel >/dev/null 2>&1 \
        || missing+=(mariadb-connector-c-devel)
    rpm -q spdlog-devel >/dev/null 2>&1 || missing+=(spdlog-devel)
    rpm -q epel-release >/dev/null 2>&1 || missing+=(epel-release)
    printf '%s' "${missing[*]:-}"
}

install_deps() {
    [[ $WITH_DEPS -eq 1 ]] || return 0
    [[ $OFFLINE -eq 1 ]] && die "--offline 与 --with-deps 不能同时使用"

    [[ -r /etc/os-release ]] || die "无法识别发行版（缺少 /etc/os-release）"
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
        rocky|rhel|almalinux|centos|ol) ;;
        *) die "--with-deps 只支持 RHEL 系发行版（当前：${PRETTY_NAME:-unknown}）" ;;
    esac
    command -v dnf >/dev/null 2>&1 || die "未找到 dnf"

    local major="${VERSION_ID%%.*}"
    if [[ "$major" != "10" ]]; then
        warn "建议在 EL10 上构建（当前 ${PRETTY_NAME:-unknown}），"
        warn "其它版本编译出的二进制可能与镜像基线不兼容"
    fi

    local missing
    missing=$(missing_deps)
    if [[ -z "$missing" ]]; then
        log "系统依赖已齐全"
    else
        # 1) 先装 EPEL（spdlog-devel / fmt-devel 来自 EPEL）
        if ! rpm -q epel-release >/dev/null 2>&1; then
            log "安装 EPEL 仓库（提供 spdlog/fmt）"
            dnf -y install epel-release
        fi
        # 2) 重新计算，再装其余；如果存在 crb 仓库就一并启用
        missing=$(missing_deps)
        if [[ -n "$missing" ]]; then
            log "安装系统依赖：$missing"
            local repo_args=()
            if dnf repolist --all 2>/dev/null |
                grep -qE '^crb[[:space:]]'; then
                repo_args=(--enablerepo=crb)
            fi
            # shellcheck disable=SC2086
            dnf -y install "${repo_args[@]}" $missing
        fi
    fi

    modprobe tun 2>/dev/null || true
    modprobe nf_tables 2>/dev/null || true

    local still
    still=$(missing_deps)
    [[ -z "$still" ]] || die "依赖安装后仍缺失：$still"

    if command -v getenforce >/dev/null 2>&1 &&
        [[ "$(getenforce)" == "Enforcing" ]]; then
        warn "SELinux 为 Enforcing：host netns + nft 可能被拒绝。"
        warn "如遇权限问题，可给 policyd/openvpn 加 --security-opt label=disable"
    fi
}

# ---------------------------------------------------------------- 环境检查

check_prereqs() {
    [[ $(id -u) -eq 0 ]] || die "需要 root 权限（nft、tun、绑定 80/443）"

    local missing
    missing=$(missing_deps)
    if [[ -n "$missing" ]]; then
        warn "缺少系统依赖：$missing"
        die "请运行：./deploy/install.sh --with-deps"
    fi

    command -v podman >/dev/null || die "未找到 podman"
    if command -v podman-compose >/dev/null 2>&1; then
        podman-compose --version >/dev/null 2>&1 || die "podman-compose 不可用"
    elif ! podman compose version >/dev/null 2>&1; then
        die "未找到 podman-compose（或 podman compose）"
    fi

    [[ -e /dev/net/tun ]] || die "/dev/net/tun 不存在，请确认内核支持 tun"
    local modules
    modules=$(lsmod 2>/dev/null || true)
    if ! grep -qw tun <<< "$modules"; then
        modprobe tun 2>/dev/null || true
        modules=$(lsmod 2>/dev/null || true)
        grep -qw tun <<< "$modules" ||
            warn "tun 模块未加载，OpenVPN 可能启动失败"
    fi
    command -v nft >/dev/null || die "未找到 nft（policyd 需要）"
    command -v openssl >/dev/null || die "未找到 openssl"
    command -v curl >/dev/null || die "未找到 curl（健康检查需要）"

    local port
    local names
    names=$(podman ps --format '{{.Names}}' 2>/dev/null || true)
    if grep -qE '^vpn-(openvpn|web|admin|mariadb|policyd|retention)$' <<< "$names"; then
        log "检测到本项目容器已在运行，跳过端口占用检查"
    elif command -v ss >/dev/null 2>&1; then
        local listeners
        listeners=$(ss -lntu 2>/dev/null || true)
        for port in 80 443 8080 1194 3306; do
            if grep -qE "[:.]${port}\b" <<< "$listeners"; then
                case "$port" in
                    1194|8080) warn "端口 $port 已被占用（旧服务未停？）" ;;
                    *) warn "端口 $port 已被占用" ;;
                esac
            fi
        done
    else
        warn "未找到 ss，跳过端口检查"
    fi

    if command -v systemctl >/dev/null 2>&1; then
        local unit
        for unit in openvpn-server@server nginx vpn-admin vpn-policyd; do
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                warn "检测到宿主旧服务 $unit 仍在运行，将停止并禁用"
            fi
        done
    fi

    log "环境检查通过"
}

stop_legacy_services() {
    command -v systemctl >/dev/null 2>&1 || return 0
    local unit
    for unit in openvpn-server@server nginx vpn-admin vpn-policyd; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            log "停止宿主服务 $unit"
            systemctl stop "$unit" || true
        fi
        if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            log "禁用宿主服务 $unit（改用容器）"
            systemctl disable "$unit" >/dev/null 2>&1 || true
        fi
    done
}

# ---------------------------------------------------------------- 配置与密钥

ensure_env() {
    if [[ -f .env ]]; then
        log ".env 已存在，保持不变"
        return
    fi
    log "生成 .env（随机密码）"
    local root_pw db_pw radius_pw
    root_pw=$(random_password 24)
    db_pw=$(random_password 24)
    radius_pw=$(random_password 24)
    cat > .env <<EOF
COMPOSE_PROJECT_NAME=vpn-acl

TZ=Asia/Shanghai

MARIADB_ROOT_PASSWORD=$root_pw
MARIADB_DATABASE=radius
MARIADB_USER=radius
MARIADB_PASSWORD=$db_pw
MARIADB_BIND=127.0.0.1
MARIADB_HOST_PORT=3306

# 可选：仅当启用 RADIUS accounting profile 时需要
RADIUS_SECRET=$radius_pw

# 路径（可覆盖 compose 里的默认值）
VPN_CONFIG_DIR=$CONFIG_DIR
VPN_RUN_DIR=$RUN_DIR
VPN_OPENVPN_RUN_DIR=$OPENVPN_RUN_DIR
VPN_LOG_DIR=$LOG_DIR
VPN_CERTS_DIR=/etc/nginx/ssl
VPN_OPENVPN_CERTS=/etc/openvpn/server
VPN_OPENVPN_CONF=$ROOT/deploy/openvpn/server.conf
VPN_WEB_ROOT=$ROOT/vpn-admin/web/dist
EOF
    chmod 600 .env
}

env_value() {
    local key=$1
    grep -E "^${key}=" .env | tail -1 | cut -d= -f2-
}

# 优先取环境变量，其次 .env，最后用默认值（与 compose 的取值顺序一致）
file_env() {
    local key=$1 fallback=$2 value=${!1:-}
    if [[ -z "$value" && -f .env ]]; then
        value=$(env_value "$key" || true)
    fi
    [[ -n "$value" ]] || value=$fallback
    printf '%s' "$value"
}

ensure_configs() {
    local db_pw nas_ip
    db_pw=$(env_value MARIADB_PASSWORD)
    nas_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -n "$nas_ip" ]] || nas_ip=127.0.0.1

    install -d -m 0750 "$CONFIG_DIR" "$CONFIG_DIR/config"
    install -d -m 0750 "$LOG_DIR" "$RUN_DIR" "$OPENVPN_RUN_DIR"

    if [[ ! -f "$CONFIG_DIR/config/vpn-policy.conf" ]]; then
        log "生成 $CONFIG_DIR/config/vpn-policy.conf"
        sed "s|replace-with-radius-db-password|$db_pw|" \
            config/vpn-policy.conf.example > "$CONFIG_DIR/config/vpn-policy.conf"
        chmod 0640 "$CONFIG_DIR/config/vpn-policy.conf"
    fi

    if [[ ! -f "$CONFIG_DIR/policyd.conf" ]]; then
        log "生成 $CONFIG_DIR/policyd.conf"
        sed -e "s|replace-with-radius-db-password|$db_pw|" \
            -e "s|^nas_ip=.*|nas_ip=$nas_ip|" \
            config/vpn-policyd.conf.example > "$CONFIG_DIR/policyd.conf"
        chmod 0640 "$CONFIG_DIR/policyd.conf"
    fi

    if [[ ! -f "$CONFIG_DIR/admin.conf" ]]; then
        log "生成 $CONFIG_DIR/admin.conf"
        sed -e "s|replace-with-radius-db-password|$db_pw|" \
            -e "s|^trust_proxy=.*|trust_proxy=1|" \
            config/vpn-admin.conf.example > "$CONFIG_DIR/admin.conf"
        chmod 0640 "$CONFIG_DIR/admin.conf"
    fi

    install -m 0644 deploy/vpn-policy.tmpfiles /etc/tmpfiles.d/vpn-policy.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/vpn-policy.conf 2>/dev/null || true
}

gen_web_certs() {
    local dir
    dir=$(file_env VPN_CERTS_DIR /etc/nginx/ssl)
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -n "$host_ip" ]] || host_ip=127.0.0.1
    if [[ -f "$dir/vpn-admin.crt" && -f "$dir/vpn-admin.key" ]]; then
        log "Web 证书已存在，保持不变"
        return
    fi
    log "生成 Web 自签证书（$dir）"
    install -d -m 0750 "$dir"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
        -keyout "$dir/vpn-admin.key" -out "$dir/vpn-admin.crt" \
        -subj "/CN=vpn-admin" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$host_ip" >/dev/null 2>&1
    chmod 0600 "$dir/vpn-admin.key"
}

gen_openvpn_pki() {
    local dir
    dir=$(file_env VPN_OPENVPN_CERTS /etc/openvpn/server)
    if [[ -f "$dir/ca.crt" && -f "$dir/server.crt" && -f "$dir/ta.key" ]]; then
        log "OpenVPN 证书已存在，保持不变"
        return
    fi
    log "生成 OpenVPN CA / 服务端证书 / ta.key（$dir）"
    install -d -m 0750 "$dir"
    pushd "$dir" >/dev/null
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout ca.key -out ca.crt -subj "/CN=VPN Access CA" >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -sha256 -nodes \
        -keyout server.key -out server.csr -subj "/CN=vpn-server" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        -addext "subjectAltName=DNS:vpn-server" >/dev/null 2>&1
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out server.crt -days 3650 -sha256 -copy_extensions copy >/dev/null 2>&1
    # tls-auth 静态密钥：必须由 OpenVPN 生成（新格式带 BEGIN/END 头）。
    # 直接用 openssl rand 写 256 字节会被 OpenVPN 2.7 拒绝。
    if command -v openvpn >/dev/null 2>&1; then
        openvpn --genkey secret ta.key >/dev/null 2>&1
    else
        podman run --rm -v "$dir:/certs" localhost/vpn-acl-app:latest \
            /usr/local/sbin/openvpn --genkey secret /certs/ta.key >/dev/null 2>&1
    fi
    rm -f server.csr ca.srl
    chmod 0600 ca.key server.key ta.key
    popd >/dev/null
}

# 给管理员留一份可直接导入的客户端模板（无客户端证书，仅账号密码）
write_client_template() {
    local dir
    dir=$(file_env VPN_OPENVPN_CERTS /etc/openvpn/server)
    local out=$CONFIG_DIR/client.ovpn
    [[ -f "$out" ]] && return
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -n "$host_ip" ]] || host_ip=127.0.0.1
    log "生成客户端模板 $out"
    {
        echo "client"
        echo "dev tun"
        echo "proto udp"
        echo "remote $host_ip 1194"
        echo "resolv-retry infinite"
        echo "nobind"
        echo "persist-key"
        echo "persist-tun"
        echo "auth-user-pass"
        echo "remote-cert-tls server"
        echo "verb 3"
        echo "<ca>"
        cat "$dir/ca.crt"
        echo "</ca>"
        echo "<tls-auth>"
        cat "$dir/ta.key"
        echo "</tls-auth>"
        echo "key-direction 1"
    } > "$out"
    chmod 0644 "$out"
}

# ---------------------------------------------------------------- 构建与数据库

SOURCE_STAMP=build/.source-stamp
WEB_STAMP=vpn-admin/web/dist/.source-stamp

# 用内容指纹而不是 mtime：容器/虚拟机时钟偏移会让 -newer 判断失真。
source_fingerprint() {
    find libvpncore libvpnservice vpn-admin vpn-policyd vpn-policyctl \
         vpn-client-connect vpn-client-disconnect vpn-auth-check CMakeLists.txt \
         -type f \( -name '*.cpp' -o -name '*.h' -o -name 'CMakeLists.txt' \) \
         -not -path 'vpn-admin/web/*' -print0 |
        sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
}

web_fingerprint() {
    find vpn-admin/web/src vpn-admin/web/public vpn-admin/web/index.html \
         vpn-admin/web/package.json vpn-admin/web/package-lock.json \
         vpn-admin/web/vite.config.ts vpn-admin/web/tsconfig.json \
         -type f -print0 |
        sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
}

binaries_stale() {
    [[ -x build/vpn-admin && -x build/vpn-policyd &&
        -x build/vpn-auth-check ]] || return 0
    [[ -f $SOURCE_STAMP ]] || return 0
    [[ "$(cat "$SOURCE_STAMP")" != "$(source_fingerprint)" ]]
}

web_dist_stale() {
    [[ -f vpn-admin/web/dist/index.html && -f $WEB_STAMP ]] || return 0
    [[ "$(cat "$WEB_STAMP")" != "$(web_fingerprint)" ]]
}

ensure_binaries() {
    if ! binaries_stale; then
        log "C++ 产物已是最新"
        return
    fi
    # 编译不需要网络，离线模式也允许（依赖已由 --with-deps 或镜像提供）
    log "编译 C++ 组件（源码有更新）"
    # 时钟偏移会让 make 误以为目标文件比源码新；直接清掉构建目录保证确定性。
    rm -rf build
    ./configure.sh >/dev/null
    source_fingerprint > "$SOURCE_STAMP"
    NEED_IMAGE_REBUILD=1
}

ensure_web_dist() {
    if ! web_dist_stale; then
        log "前端产物已是最新"
        return
    fi
    if command -v npm >/dev/null 2>&1; then
        if [[ ! -d vpn-admin/web/node_modules ]]; then
            [[ $OFFLINE -eq 1 ]] &&
                die "前端需要重建，但缺少 node_modules 且处于 --offline"
            log "安装前端依赖（npm ci）"
            (cd vpn-admin/web && npm ci --no-audit --no-fund)
        fi
        log "构建前端（npm run build）"
        (cd vpn-admin/web && npm run build)
        web_fingerprint > "$WEB_STAMP"
        NEED_IMAGE_REBUILD=1
        return
    fi
    [[ $OFFLINE -eq 1 ]] &&
        die "前端需要重建，但未安装 npm；请使用包含 dist 的离线包"
    die "缺少 npm：请先安装 nodejs/npm 或使用已构建的 dist"
}

build_image() {
    local required=(docker.io/library/mariadb:10.11
                    docker.io/library/nginx:1.29-alpine)
    if [[ $OFFLINE -eq 1 ]]; then
        local img missing=()
        for img in "${required[@]}"; do
            podman image exists "$img" || missing+=("$img")
        done
        if ((${#missing[@]})); then
            local tar
            for tar in deploy/images/*.tar; do
                [[ -f "$tar" ]] || continue
                log "加载离线镜像 $tar"
                podman load -i "$tar" >/dev/null
            done
            missing=()
            for img in "${required[@]}"; do
                podman image exists "$img" || missing+=("$img")
            done
        fi
        if ((${#missing[@]})); then
            die "缺少镜像：${missing[*]}；请在联网机器运行 ./deploy/save-images.sh，把 deploy/images/*.tar 拷过来"
        fi
    fi

    if [[ $OFFLINE -eq 1 && $NEED_IMAGE_REBUILD -eq 0 ]] &&
        podman image exists localhost/vpn-acl-app:latest; then
        log "使用已有应用镜像"
        return
    fi

    if ! podman image exists quay.io/rockylinux/rockylinux:10; then
        [[ $OFFLINE -eq 1 ]] &&
            die "缺少基础镜像 quay.io/rockylinux/rockylinux:10；请把应用镜像一起离线导出"
        log "拉取基础镜像 quay.io/rockylinux/rockylinux:10"
    fi

    log "收集二进制并构建镜像"
    ./deploy/stage-app.sh >/dev/null
    compose build app
}

wait_for_db() {
    local pw
    pw=$(env_value MARIADB_ROOT_PASSWORD)
    for _ in $(seq 1 60); do
        if podman exec vpn-mariadb mariadb -uroot -p"$pw" -e "SELECT 1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    die "MariaDB 未在 120 秒内就绪"
}


apply_sql() {
    log "应用数据库 schema"
    ./deploy/migrate.sh
}

create_admin() {
    local pw db exists
    pw=$(env_value MARIADB_ROOT_PASSWORD)
    db=$(grep -E '^MARIADB_DATABASE=' .env | cut -d= -f2-)
    exists=$(podman exec vpn-mariadb mariadb -uroot -p"$pw" -N -e \
        "SELECT COUNT(*) FROM $db.vpn_admins" 2>/dev/null || echo 0)
    if [[ "$exists" != "0" ]]; then
        log "已存在管理员账号，跳过创建"
        return
    fi

    local admin_pw
    admin_pw=$(random_password 16)
    log "创建管理员账号 admin（密码见下方输出）"
    build/vpn-policyctl --config "$CONFIG_DIR/config" \
        admin-create admin --password "$admin_pw" >/dev/null
    ADMIN_PASSWORD=$admin_pw
}

seed_demo() {
    local pw db exists
    pw=$(env_value MARIADB_ROOT_PASSWORD)
    db=$(grep -E '^MARIADB_DATABASE=' .env | cut -d= -f2-)
    exists=$(podman exec vpn-mariadb mariadb -uroot -p"$pw" -N -e \
        "SELECT COUNT(*) FROM $db.vpn_groups WHERE name='staff'" 2>/dev/null || echo 0)
    if [[ "$exists" != "0" ]]; then
        log "演示数据已存在，跳过"
        return
    fi
    log "创建演示数据"
    build/vpn-policyctl --config "$CONFIG_DIR/config" \
        group-add staff --ip-start 10.9.100.10 --ip-end 10.9.100.200 >/dev/null
    build/vpn-policyctl --config "$CONFIG_DIR/config" \
        group-rule-add staff allow 192.168.140.0/24 >/dev/null
    build/vpn-policyctl --config "$CONFIG_DIR/config" \
        user-add demo --group staff --fixed-ip 10.9.100.10 >/dev/null
    build/vpn-policyctl --config "$CONFIG_DIR/config" \
        password-reset demo --password 'DemoPass123!' >/dev/null
    DEMO_PASSWORD='DemoPass123!'
}

wait_ready() {
    local reloads=0
    for _ in $(seq 1 60); do
        if curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1; then
            return 0
        fi
        # 容器 DNS 抖动会导致 admin 连不上 mariadb；刷新一次 podman 网络再试
        if ((reloads < 3)) &&
            podman ps --format '{{.Names}}' 2>/dev/null |
                grep -q '^vpn-admin$'; then
            if ! podman exec vpn-admin getent hosts mariadb >/dev/null 2>&1; then
                reloads=$((reloads + 1))
                warn "容器内解析不到 mariadb，刷新 podman 网络（$reloads/3）"
                podman network reload --all >/dev/null 2>&1 || true
            fi
        fi
        sleep 2
    done
    warn "readyz 未在 120 秒内通过，请查看：podman logs vpn-admin"
}

# 让容器在宿主重启后自动拉起（restart: unless-stopped 依赖这个 unit）
enable_boot_start() {
    command -v systemctl >/dev/null 2>&1 || return 0
    if systemctl list-unit-files podman-restart.service >/dev/null 2>&1; then
        if systemctl enable --now podman-restart.service >/dev/null 2>&1; then
            log "已启用 podman-restart.service（开机自动启动容器）"
        else
            warn "启用 podman-restart.service 失败，重启后容器不会自动拉起"
        fi
    else
        warn "系统没有 podman-restart.service，重启后需手工 podman-compose up -d"
    fi
}

print_summary() {
    local host_ip
    host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -n "$host_ip" ]] || host_ip=127.0.0.1
    echo
    echo "------------------------------------------------------------"
    echo " 管理后台   https://$host_ip/"
    echo " 管理员     admin"
    if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
        echo " 初始密码   $ADMIN_PASSWORD   （只显示这一次，请立即修改）"
    else
        echo " 初始密码   （已存在管理员，未修改）"
    fi
    if [[ -n "${DEMO_PASSWORD:-}" ]]; then
        echo " 演示用户   demo / $DEMO_PASSWORD"
    fi
    echo
    echo " 客户端模板 $CONFIG_DIR/client.ovpn"
    echo " 配置目录   $CONFIG_DIR"
    echo " 数据目录   $ROOT/mariadb/data"
    echo
    echo " 常用命令："
    echo "   podman-compose ps"
    echo "   podman logs -f vpn-openvpn"
    echo "   ./deploy/install.sh --uninstall"
    echo "------------------------------------------------------------"
}

# ---------------------------------------------------------------- 主流程

uninstall() {
    compose down || true
    log "容器已停止（数据保留）。彻底删除请用 --purge"
}

purge() {
    compose down || true
    rm -f "$RUN_DIR/policyd.sock" "$OPENVPN_RUN_DIR"/*.sock
    if [[ $ASSUME_YES -eq 1 ]]; then
        rm -rf mariadb/data
        log "已删除 mariadb/data"
    else
        warn "保留 mariadb/data；确认要删除请加 --yes"
    fi
}

cmd_install() {
    apply_proxy
    install_deps
    check_prereqs
    [[ $MODE == check ]] && { log "--check 完成，未做任何修改"; exit 0; }

    ensure_env
    # 以 .env 为准解析路径（与 compose 的变量替换保持一致）
    CONFIG_DIR=$(file_env VPN_CONFIG_DIR /etc/vpn-policy)
    RUN_DIR=$(file_env VPN_RUN_DIR /run/vpn-policyd)
    OPENVPN_RUN_DIR=$(file_env VPN_OPENVPN_RUN_DIR /run/openvpn-server)
    LOG_DIR=$(file_env VPN_LOG_DIR /var/log/vpn-policyd)
    stop_legacy_services
    ensure_configs
    ensure_binaries
    ensure_web_dist
    build_image
    gen_web_certs
    gen_openvpn_pki
    write_client_template

    log "启动数据库"
    if podman ps -a --format '{{.Names}}' 2>/dev/null | grep -qx 'vpn-mariadb'; then
        podman start vpn-mariadb >/dev/null 2>&1 || true
    else
        compose up -d mariadb
    fi
    wait_for_db
    apply_sql
    create_admin
    [[ $DEMO -eq 1 ]] && seed_demo

    log "启动全部服务"
    # podman-compose 在配置变化时对已存在的容器名比较挑剔，
    # 先 down 再 up 更确定（数据在 bind mount 里，不受影响）。
    compose down >/dev/null 2>&1 || true
    compose up -d
    enable_boot_start
    wait_ready
    print_summary
}

case "$MODE" in
    check)     check_prereqs; log "--check 完成，未做任何修改" ;;
    install)   cmd_install ;;
    uninstall) uninstall ;;
    purge)     purge ;;
esac