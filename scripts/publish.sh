#!/usr/bin/env bash
# 发布前的检查清单（不代替你按回车）
set -euo pipefail
cd "$(dirname "$0")/.."

echo "▸ 1/5 测试"
cargo test --quiet

echo "▸ 2/5 本地打包"
./scripts/package.sh >/dev/null && echo "  ✓ dist/"

echo "▸ 3/5 契约自检"
./target/release/pak --schema | head -c 120; echo " …"

echo "▸ 4/5 npm 主包 dry-run"
(cd packaging/npm && npm pack --dry-run --cache /tmp/npmc --logs-dir /tmp/npml 2>&1 | tail -3)

echo "▸ 5/5 还需要你手动做："
cat <<'TXT'
  git remote add origin git@github.com:OWNER/pak.git
  git push -u origin main --tags        # 触发 CI 出 4 个平台产物
  下载产物到 dist/release/ 然后：
  ./scripts/collect-npm.sh
TXT
