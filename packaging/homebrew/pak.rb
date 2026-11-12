# Homebrew formula 模板 —— 放到自己的 tap 里用：
#   brew tap <你的用户名>/pak https://github.com/<你的用户名>/homebrew-pak
#   brew install <你的用户名>/pak/pak
#
# 为什么不投 homebrew-core：
#   本 formula 内嵌 UnRAR（非 OSI 许可），core 通常不接受这类依赖。
#   自家 tap 没有这个限制；同时 LICENSE 仍是 MIT，UnRAR 条款见 THIRD_PARTY_NOTICES.md。
class Pak < Formula
  desc "Untrusted-archive gate: inspect first, extract only if safe"
  homepage "https://github.com/OWNER/pak"
  url "https://github.com/OWNER/pak/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256"
  license "MIT"
  head "https://github.com/OWNER/pak.git", branch: "main"

  depends_on "rust" => :build

  def install
    # 只装 CLI。桌面壳在 src-tauri/，homebrew 不涉及。
    system "cargo", "install", *std_cargo_args(path: ".")
    # 许可见证：必须随二进制一起分发
    (share/"pak").install "LICENSE", "THIRD_PARTY_NOTICES.md"
  end

  def caveats
    <<~EOS
      pak 内置 UnRAR，仅用于解压 RAR（不提供 RAR 压缩）。
      条款全文：#{opt_share}/pak/THIRD_PARTY_NOTICES.md

      给 Agent 用的时候，建议直接读 JSON 契约：
        pak --schema
        pak inspect 某个包.rar
    EOS
  end

  test do
    assert_match "pak", shell_output("#{bin}/pak --version")
    # 契约自检：必须输出合法 JSON
    (testpath/"x.txt").write "hi"
    system "zip", "-q", "a.zip", "x.txt"
    assert_match '"schema":"pak/1"', shell_output("#{bin}/pak inspect a.zip")
  end
end
