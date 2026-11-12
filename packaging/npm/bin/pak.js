#!/usr/bin/env node
// 平台二进制的解析器（esbuild / swc 同款策略）：
// 每个平台一个 optionalDependency 包，装不上就报清楚的错。
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

const platforms = {
  "darwin arm64": "@pak/cli-darwin-arm64",
  "darwin x64": "@pak/cli-darwin-x64",
  "linux x64": "@pak/cli-linux-x64",
  "win32 x64": "@pak/cli-win32-x64",
};

const key = `${process.platform} ${process.arch}`;
const pkg = platforms[key];

if (!pkg) {
  console.error(
    `\npak 暂不支持 ${key}。\n` +
      `可选安装方式：\n` +
      `  • 从 GitHub Releases 下载对应平台的二进制\n` +
      `  • macOS: brew tap <user>/pak && brew install pak\n`
  );
  process.exit(13);
}

let binPath;
try {
  const pkgJson = require.resolve(`${pkg}/package.json`);
  const dir = path.dirname(pkgJson);
  binPath = path.join(dir, process.platform === "win32" ? "pak.exe" : "pak");
} catch {
  console.error(
    `\npak: 缺少平台包 ${pkg}。\n` +
      `如果你用 npm 的 --no-optional / --omit=optional 安装，请去掉该参数重装。\n` +
      `或直接从 GitHub Releases 下载二进制。\n`
  );
  process.exit(13);
}

if (!fs.existsSync(binPath)) {
  console.error(`pak: 平台包存在但二进制缺失：${binPath}\n请重新安装或反馈 issue。`);
  process.exit(13);
}

const r = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
process.exit(r.status === null ? 13 : r.status);
