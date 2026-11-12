#!/usr/bin/env bash
# tag 推上去之后算 Homebrew 所需的 sha256，并写回 formula
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:-$(git describe --tags --abbrev=0)}"
REPO="Oh-Agent-AI/agent-unzip"
URL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"

echo "▸ 下载 ${TAG} 源码包…"
SHA="$(curl -fsSL "$URL" | shasum -a 256 | awk '{print $1}')"
[[ -n "$SHA" ]] || { echo "下载失败，tag 是否已推送？"; exit 1; }

echo "  sha256 = ${SHA}"
sed -i '' "s/sha256 \".*\"/sha256 \"${SHA}\"/" packaging/homebrew/agent-unzip.rb
sed -i '' "s|v[0-9]*\.[0-9]*\.[0-9]*\.tar\.gz|${TAG}.tar.gz|" packaging/homebrew/agent-unzip.rb

echo "▸ 已写回 packaging/homebrew/agent-unzip.rb："
grep -E "url|sha256" packaging/homebrew/agent-unzip.rb | head -3
