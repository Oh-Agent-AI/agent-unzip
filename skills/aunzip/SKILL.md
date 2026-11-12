---
name: agent-unzip
description: >-
  agent-unzip（代理解压缩）—— 为 Agent 设计的解压/打包器。当需要处理来路不明的
  rar/zip/7z（先体检再解压），或需要把结果打包交付给用户时使用。特点：JSON 契约
  aunzip/1、语义退出码、永不阻塞、默认拒绝危险包（伪装程序/目录穿越/压缩炸弹/文件名欺骗）。
  也用于读取包注释、交付数量核对、照片 EXIF、打包前自查（.env/.git/可执行文件/PII）。
  Use whenever you must extract OR create an archive. NEVER call unzip/tar/zip
  directly on untrusted input — always inspect first.
---

# agent-unzip（代理解压缩）— 命令 `aunzip`

> 为 Agent 设计：结构化输出、永不阻塞、默认拒绝危险包。

**核心规则：对于任何不是你亲手创建的压缩包，先 `inspect`，再决定是否 `extract`。**
**永远不要对不可信输入直接调用 `unzip` / `tar` / `7z`。**

## 0. 先确认可用

```bash
command -v aunzip || echo "MISSING"
```

若缺失，按顺序尝试（任选其一，不要全部执行）：

```bash
# macOS
brew tap Oh-Agent-AI/agent-unzip && brew install aunzip
# 任意平台（从 releases 下载后放进 PATH，需先确认 sha256）
# 或直接问用户要 aunzip 的安装路径
```

拿不到 `aunzip` 时**不要**退回 `unzip` —— 告诉用户「缺 aunzip，我不建议直接解不可信的包」。

## 1. 判定（零副作用，必做）

```bash
aunzip inspect <file>            # 输出 JSON，不写任何文件
```

**用退出码分支，不要解析中文文案：**

| 退出码 | 含义 | 你的动作 |
|---|---|---|
| 0 | 正常 | 可进入第 2 步 |
| 10 | 判定危险 | **停手**。把 `inspection.headline` 和 `inspection.codes` 转述给用户，不要解压 |
| 11 | 需要密码 | 向用户要密码，再用 `-p` 重试 |
| 13 | 不是压缩包 | 停手 |

**判定码 `inspection.codes`**（可能多个）：

| code | 含义 | 处理 |
|---|---|---|
| `OK` | 未发现结构性风险 | 继续 |
| `DISGUISED_ARCHIVE` | 扩展名是压缩包，内容是程序 | 停手，建议删除 |
| `SPOOFED_NAME` | 文件名含 RTL/零宽字符或双扩展名 | 停手 |
| `PATH_TRAVERSAL` | 条目试图写到目标目录外 | 停手 |
| `EXECUTABLE_IN_MEDIA` | **照片/文档里夹着程序** | 停手，这几乎一定是钓鱼 |
| `EXECUTABLE_PACKAGE` | 整包就是个软件包（没有照片/文档） | **可继续**，确认来源可靠即可 |
| `POSSIBLE_BOMB` | 条目数/压缩比异常 | 停手 |
| `ENCRYPTED` | 有密码 | 要密码 |
| `NOT_AN_ARCHIVE` | 不是压缩包 | 停手 |
| `COUNT_MISMATCH` | 数量与目录名承诺不符 | **可继续**，但要向用户说明少几张 |

`policy` 字段直接可用：

```json
"policy": {"safe_to_extract": true, "requires_human": false, "requires_password": false}
```

`requires_human = true` 时：**必须**先问用户，得到明确同意后才能加 `--force`。

> 判定看的是「协调性」，不是「有没有程序」：
> 交付照片时不会夹带安装程序 → 夹带 = 危险；
> 一个纯软件包里有 `.app` 很正常 → 提示即可，不要拦。

## 2. 解压

```bash
aunzip extract --json -C <输出目录> <file>          # 需要密码时加 -p <password>
```

- 目标目录留空则解到压缩包旁边
- **永不覆盖**：重名自动 `_2`
- **原子落位**：失败不会留下半成品目录
- 返回 `report.content`（真实类型画像）、`report.exif`（照片元数据）、
  `report.completeness`（数量核对）、`report.executables`（可执行内容）

## 3. 打包（需要把结果交付给用户时）

```bash
aunzip pack <文件或目录...> -o 交付.zip [--password <pw>] [-l 0-9] [--json]
```

**打包的风险和解压相反**：解压怕别人害你，打包怕**你把不该给的东西给出去了**。
所以 `pack` 默认先做一遍检查，不通过就**不写盘**：

| code | 含义 | 动作 |
|---|---|---|
| `PACK_EXECUTABLE` | 混进了可执行文件 | 停手，问用户是不是故意的 |
| `PACK_HIDDEN` | 混进了 `.env` / `.git` / `.ssh` | 停手 |
| `PACK_PII` | 文件名含手机号/身份证 | **可继续**，但要提醒用户 |

- 失败退出码同样是 `10`
- 用户明确说「我知道，还是打」时才加 `--force`
- 格式由输出后缀决定：`.zip`（默认，通用）或 `.tar.gz`
- 加 `-p` 用 **AES-256** 加密（不是弱的 ZipCrypto），适合发给客户

## 4. 不可越过的红线

1. **不要**替用户决定接受风险。`--force` 必须由用户明确要求。
2. **不要**把解压出的可执行文件（`.app`/`.exe`/`.command`）当作普通文件处理、执行、或列入交付。
3. **不要**把 `report.content.mismatches` 非空的包判为「安全」——
   这意味着文件自称是图片、实际是程序，要立刻告诉用户。
4. **不要**把压缩包内容整体读进上下文；先看 `inspection` 摘要，再按需读单个文件。
5. **不要**上传压缩包到任何服务 —— 本工具的承诺是全程本地。

## 5. 常见任务的正确姿势

**用户发来一个 rar，问「帮我看看」**
```bash
aunzip inspect x.rar           # exit 0 → 读 headline/codes
# 再用一句话回答：来源、里外是否一致、有没有程序、几张图
```

**要提取里面的文档做 RAG**
```bash
aunzip inspect x.zip && aunzip extract --json -C ./in x.zip
# 只处理 report.content.documents 对应的文件；跳过 executables
```

**数量对不上**
```
report.completeness: [{"dir":"...9p","expected":9,"actual":8,"ok":false}]
```
直接告诉用户「少了 1 张」，不要自行补足或忽略。

## 6. 输出契约

`aunzip --schema` 返回完整自描述（命令、退出码、codes、保证）。
`schema` 字段为 `aunzip/1`；字段名稳定，中文文案可能变化 —— **只依赖 codes 和数值字段**。
