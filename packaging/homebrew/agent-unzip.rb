# Homebrew formula 模板 —— 放到自己的 tap 里用：
#   brew tap <你的用户名>/aunzip https://github.com/<你的用户名>/homebrew-aunzip
#   brew install <你的用户名>/aunzip/aunzip
#
# 为什么不投 homebrew-core：
#   本 formula 内嵌 UnRAR（非 OSI 许可），core 通常不接受这类依赖。
#   自家 tap 没有这个限制；同时 LICENSE 仍是 MIT，UnRAR 条款见 THIRD_PARTY_NOTICES.md。
class AgentUnzip < Formula
  desc "Agent-friendly unzipper: JSON out, never blocks, refuses risky archives"
  homepage "https://github.com/Oh-Agent-AI/agent-unzip"
  url "https://github.com/Oh-Agent-AI/agent-unzip/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "41c3237a731415853182892ed320e4847826a99977aa09cb69a6e552f857200d"
  license "MIT"
  head "https://github.com/Oh-Agent-AI/agent-unzip.git", branch: "main"

  depends_on "rust" => :build

  def install
    # 只装 CLI。桌面壳在 src-tauri/，homebrew 不涉及。
    system "cargo", "install", *std_cargo_args(path: ".")
    # 许可见证：必须随二进制一起分发
    (share/"aunzip").install "LICENSE", "THIRD_PARTY_NOTICES.md"
  end

  def caveats
    <<~EOS
      aunzip 内置 UnRAR，仅用于解压 RAR（不提供 RAR 压缩）。
      条款全文：#{opt_share}/aunzip/THIRD_PARTY_NOTICES.md

      给 Agent 用的时候，建议直接读 JSON 契约：
        aunzip --schema
        aunzip inspect 某个包.rar
    EOS
  end

  test do
    assert_match "aunzip", shell_output("#{bin}/aunzip --version")
    # 契约自检：必须输出合法 JSON
    (testpath/"x.txt").write "hi"
    system "zip", "-q", "a.zip", "x.txt"
    assert_match '"schema":"aunzip/1"', shell_output("#{bin}/aunzip inspect a.zip")
  end
end
