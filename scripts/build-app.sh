#!/usr/bin/env bash
# 构建桌面版并签名。
# 必须签名：Tauri bundler 产出的 .app 没有 _CodeSignature 目录，
# 未签名的包 `codesign -v` 会失败，分发出去也可能被 Gatekeeper 拒。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "▸ 构建 App"
(cd src-tauri && CARGO_HOME="$PWD/../.cargo" CARGO_TARGET_DIR="$PWD/../target" cargo tauri build --bundles app)

APP="target/release/bundle/macos/安全解压缩.app"
[[ -d "$APP" ]] || { echo "构建产物不存在"; exit 1; }

# 注意：必须「浅签名」。用 codesign --deep 会让 WebKit 子进程起不来，
# 表现为进程存在但窗口永远不出现。
echo "▸ 签名（ad-hoc，表面签名）"
codesign --force --sign - "$APP"
codesign -v "$APP" && echo "  ✓ 签名校验通过"

echo "▸ 安装到本地目录"
DEST_DIR="${1:-/Applications}"
rm -rf "${DEST_DIR}/安全解压缩.app"
cp -R "$APP" "${DEST_DIR}/"
codesign --force --sign - "${DEST_DIR}/安全解压缩.app"
codesign -v "${DEST_DIR}/安全解压缩.app" && echo "  ✓ 已安装到 ${DEST_DIR}"
