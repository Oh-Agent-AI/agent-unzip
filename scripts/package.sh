#!/usr/bin/env bash
# 打一个可分发产物：二进制 + 许可 + 校验和
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)"
TARGET="$(rustc -vV | awk '/host:/{print $2}')"
NAME="pak-${TARGET}"
OUT="dist/${NAME}"

echo "▸ 构建 pak ${VERSION} (${TARGET})"
cargo build --release

rm -rf "${OUT}" && mkdir -p "${OUT}"
cp target/release/pak "${OUT}/"
cp LICENSE THIRD_PARTY_NOTICES.md README.md "${OUT}/"

tar -C "${OUT}" -czf "dist/${NAME}.tar.gz" .
if command -v shasum >/dev/null; then
  shasum -a 256 "dist/${NAME}.tar.gz" > "dist/${NAME}.tar.gz.sha256"
else
  sha256sum "dist/${NAME}.tar.gz" > "dist/${NAME}.tar.gz.sha256"
fi

echo "▸ 产物："
ls -lh "dist/${NAME}.tar.gz"
cat "dist/${NAME}.tar.gz.sha256"
echo
echo "内容："
tar -tzf "dist/${NAME}.tar.gz"
