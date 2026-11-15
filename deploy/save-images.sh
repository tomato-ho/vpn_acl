#!/usr/bin/env bash
#
# 导出/加载离线镜像（用于内网、无法访问 Docker Hub 的机器）。
#
#   ./deploy/save-images.sh          # 导出到 deploy/images/*.tar
#   ./deploy/save-images.sh --load   # 从 deploy/images/*.tar 加载
#
# 导出后把 deploy/images/ 整个目录拷到目标机器，执行：
#   ./deploy/install.sh --offline
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=$ROOT/deploy/images
IMAGES=(
    docker.io/library/mariadb:10.11
    docker.io/library/nginx:1.29-alpine
    localhost/vpn-acl-app:latest
)

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

mode=${1:---save}
command -v podman >/dev/null || die "未找到 podman"

case "$mode" in
--save)
    mkdir -p "$OUT"
    for img in "${IMAGES[@]}"; do
        if ! podman image exists "$img"; then
            warn "跳过（本地没有该镜像）：$img"
            continue
        fi
        name=$(printf '%s' "$img" | tr '/:' '__')
        log "导出 $img -> $OUT/$name.tar"
        podman save -o "$OUT/$name.tar" "$img"
    done
    log "完成。把 $OUT 目录拷到目标机器后运行：./deploy/install.sh --offline"
    ;;
--load)
    [[ -d "$OUT" ]] || die "目录不存在：$OUT"
    found=0
    for tar in "$OUT"/*.tar; do
        [[ -f "$tar" ]] || continue
        found=1
        log "加载 $tar"
        podman load -i "$tar"
    done
    [[ $found -eq 1 ]] || die "$OUT 下没有 .tar 文件"
    ;;
*)
    echo "usage: $0 [--save|--load]" >&2
    exit 2
    ;;
esac