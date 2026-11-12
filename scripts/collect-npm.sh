#!/usr/bin/env bash
# 把 CI 产物（dist/*.tar.gz）里的二进制放进 npm 平台包目录
# 用法：先把 4 个平台产物放到 dist/release/，再运行
set -euo pipefail
cd "$(dirname "$0")/.."

REL="${1:-dist/release}"
[[ -d "$REL" ]] || { echo "缺少目录 $REL（放 CI 下载的 4 个产物）"; exit 1; }

extract() { # $1=产物名 $2=npm 目录 $3=二进制名
  local name="$1" dir="$2" bin="$3"
  local tgz="$REL/${name}.tar.gz"
  local zipf="$REL/${name}.zip"
  tmp="$(mktemp -d)"
  if [[ -f "$tgz" ]]; then
    tar -xzf "$tgz" -C "$tmp"
  elif [[ -f "$zipf" ]]; then
    unzip -qo "$zipf" -d "$tmp"
  else
    echo "⚠ 缺 ${name}.tar.gz / .zip"; rm -rf "$tmp"; return 1
  fi
  mv "$tmp/${bin}" "packaging/npm/platforms/${dir}/${bin}"
  cp LICENSE THIRD_PARTY_NOTICES.md "packaging/npm/platforms/${dir}/" 2>/dev/null || true
  chmod +x "packaging/npm/platforms/${dir}/${bin}"
  rm -rf "$tmp"
  echo "✓ ${dir}"
}

extract aunzip-aarch64-apple-darwin          darwin-arm64 aunzip || true
extract aunzip-x86_64-unknown-linux-gnu      linux-x64    aunzip || true
extract aunzip-x86_64-pc-windows-msvc        win32-x64    aunzip.exe || true

echo
echo "现在可以逐个发布："
for d in darwin-arm64 linux-x64 win32-x64; do
  echo "  cd packaging/npm/platforms/${d} && npm publish --access public"
done
echo "  cd packaging/npm && npm publish --access public"
