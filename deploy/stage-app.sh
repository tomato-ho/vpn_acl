#!/usr/bin/env bash
# 把已编译好的 C++ 二进制、宿主上的 nft，以及它们依赖的「非基础库」，
# 收集到 deploy/build-context/。
#
# 这样镜像不需要联网装包，也不需要编译工具链 —— 适合离线/内网交付。
# 产物被 .gitignore 忽略，每次构建前重新生成。
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin_dir=${1:-$root/build}
out=$root/deploy/build-context

binaries=(vpn-admin vpn-policyd vpn-policyctl vpn-client-connect vpn-client-disconnect vpn-auth-check)

# OpenVPN 二进制：优先 VPN_OPENVPN_BIN，其次 PATH 里的 openvpn，
# 最后兼容本机自编译的默认路径。
openvpn_bin=${VPN_OPENVPN_BIN:-}
if [[ -z "$openvpn_bin" ]]; then
    openvpn_bin=$(command -v openvpn || true)
fi
if [[ -z "$openvpn_bin" && -x /data/app/openvpn-2.7.9/sbin/openvpn ]]; then
    openvpn_bin=/data/app/openvpn-2.7.9/sbin/openvpn
fi

# 基础镜像（rockylinux:10）里已经有的库，不需要重复带
base_lib_re='^(linux-vdso|ld-linux|libc\.so|libm\.so|libdl\.so|libpthread\.so|librt\.so|libutil\.so|libresolv\.so|libstdc\+\+|libgcc_s|libz\.so|libssl\.so|libcrypto\.so|libcurl\.so|libreadline|libjansson|libgmp|libtinfo)'

rm -rf "$out"
mkdir -p "$out/bin" "$out/sbin" "$out/lib"

collect_deps() {
    local target=$1
    local lib base
    while IFS= read -r lib; do
        [[ -n "$lib" && -f "$lib" ]] || continue
        base=$(basename "$lib")
        if [[ $base =~ $base_lib_re ]]; then
            continue
        fi
        cp -Lf "$lib" "$out/lib/$base"
    done < <(ldd "$target" 2>/dev/null | awk '/=> \//{ print $3 }')
}

for name in "${binaries[@]}"; do
    if [[ ! -x "$bin_dir/$name" ]]; then
        echo "stage-app: 缺少可执行文件 $bin_dir/$name，请先运行 ./configure.sh" >&2
        exit 1
    fi
    install -m 0755 "$bin_dir/$name" "$out/bin/$name"
    collect_deps "$bin_dir/$name"
done

# policyd 通过 shell 调用 nft 下发规则，容器里也要有一份
if [[ ! -x /usr/sbin/nft ]]; then
    echo "stage-app: 找不到 /usr/sbin/nft（请安装 nftables）" >&2
    exit 1
fi
install -m 0755 /usr/sbin/nft "$out/sbin/nft"
collect_deps /usr/sbin/nft

# OpenVPN 服务端（容器里不用再装 PAM 插件）
if [[ ! -x "$openvpn_bin" ]]; then
    echo "stage-app: 找不到 OpenVPN 可执行文件" >&2
    echo "           请安装 openvpn（dnf install openvpn），" >&2
    echo "           或用 VPN_OPENVPN_BIN=/path/to/openvpn 指定" >&2
    exit 1
fi
install -m 0755 "$openvpn_bin" "$out/bin/openvpn"
collect_deps "$openvpn_bin"

echo "stage-app: 已生成 $out"
echo "  bin:  $(find "$out/bin" -maxdepth 1 -type f -printf '%f ')"
echo "  sbin: $(find "$out/sbin" -maxdepth 1 -type f -printf '%f ')"
echo "  lib:  $(find "$out/lib" -maxdepth 1 -type f -printf '%f ')"