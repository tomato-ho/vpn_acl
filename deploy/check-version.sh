#!/usr/bin/env bash
#
# 校验版本号在各处是否一致。
#
#   ./deploy/check-version.sh          # 只检查
#   ./deploy/check-version.sh --show   # 打印各处版本
#
# 版本号唯一来源是 CMakeLists.txt 的 project(VERSION ...)；
# package.json、README、CHANGELOG 必须与它一致，CI 会跑这个脚本。
#
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

SHOW=0
case "${1:-}" in
    --show) SHOW=1 ;;
    "") ;;
    *) echo "用法: $0 [--show]" >&2; exit 2 ;;
esac

fail=0

cmake_version=$(sed -n 's/^project(vpn_acl VERSION \([0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1)
pkg_version=$(sed -n 's/.*"version": "\([0-9][0-9.]*\)".*/\1/p' vpn-admin/web/package.json | head -1)
readme_version=$(sed -n 's/^当前版本：\*\*\([0-9][0-9.]*\)\*\*.*/\1/p' README.md | head -1)
changelog_version=$(sed -n 's/^## \[\([0-9][0-9.]*\)\].*/\1/p' CHANGELOG.md | head -1)

[[ -n "$cmake_version" ]] || { echo "无法从 CMakeLists.txt 解析版本" >&2; fail=1; }
[[ -n "$pkg_version" ]] || { echo "无法从 vpn-admin/web/package.json 解析版本" >&2; fail=1; }
[[ -n "$readme_version" ]] || { echo "无法从 README.md 解析版本（需要“当前版本：**x.y.z**”）" >&2; fail=1; }
[[ -n "$changelog_version" ]] || { echo "无法从 CHANGELOG.md 解析版本" >&2; fail=1; }

if (( SHOW )); then
    printf '%-12s %s\n' CMakeLists "$cmake_version"
    printf '%-12s %s\n' package.json "$pkg_version"
    printf '%-12s %s\n' README "$readme_version"
    printf '%-12s %s\n' CHANGELOG "$changelog_version"
fi

for item in "package.json:$pkg_version" "README:$readme_version" "CHANGELOG:$changelog_version"; do
    name=${item%%:*}
    value=${item#*:}
    if [[ "$value" != "$cmake_version" ]]; then
        echo "版本不一致：CMakeLists=$cmake_version $name=$value" >&2
        fail=1
    fi
done

if (( fail )); then
    exit 1
fi

echo "版本一致：$cmake_version"