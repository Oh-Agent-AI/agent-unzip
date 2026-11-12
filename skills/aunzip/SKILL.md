---
name: aunzip-archive-gate
description: >-
  用 aunzip 处理「来路不明的压缩包」：先体检再解压。当需要解压用户上传/客户发来的
  rar、zip、7z，或需要在解压前判断包是否安全（伪装的可执行文件、目录穿越、压缩炸弹、
  文件名欺骗）时使用。也用于读取压缩包注释、交付完整性核对、照片 EXIF 摘要。
  Use when you must extract an untrusted archive, or must decide whether it is safe
  to extract at all. NEVER call unzip/tar directly on untrusted input.
---

# aunzip — 不可信压缩包的闸门

**核心规则：对于任何不是你亲手创建的压缩包，先 `inspect`，再决定是否 `extract`。**
**永远不要对不可信输入直接调用 `unzip` / `tar` / `7z`。**

## 0. 先确认可用

```bash
command -v aunzip || echo "MISSING"
```

若缺失，按顺序尝试（任选其一，不要全部执行）：

```bash
# macOS
brew tap OWNER/aunzip && brew install aunzip
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
| `EXECUTABLE_ENTRY` | 包内有可执行内容 | 停手，除非用户明确说「我知道，继续」 |
| `POSSIBLE_BOMB` | 条目数/压缩比异常 | 停手 |
| `ENCRYPTED` | 有密码 | 要密码 |
| `NOT_AN_ARCHIVE` | 不是压缩包 | 停手 |
| `COUNT_MISMATCH` | 数量与目录名承诺不符 | **可继续**，但要向用户说明少几张 |

`policy` 字段直接可用：

```json
"policy": {"safe_to_extract": true, "requires_human": false, "requires_password": false}
```

`requires_human = true` 时：**必须**先问用户，得到明确同意后才能加 `--force`。

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
