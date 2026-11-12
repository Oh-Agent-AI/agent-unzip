# 第三方许可 / Third-Party Notices

本产品包含 UnRAR 源码（经 `unrar_sys` crate 编译）。**UnRAR 不适用 MIT 许可**，
其条款如下，任何二进制分发都必须附带本文件。

---

## UnRAR (RARLAB) — 仅用于解压

```
 ******    *****   ******   UnRAR - free utility for RAR archives
 **   **  **   **  **   **  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ******   *******  ******    License for use and distribution of
 **   **  **   **  **   **   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 **   **  **   **  **   **         FREE portable version
                                   ~~~~~~~~~~~~~~~~~~~~~

      The source code of UnRAR utility is freeware. This means:

   1. All copyrights to RAR and the utility UnRAR are exclusively
      owned by the author - Alexander Roshal.

   2. UnRAR source code may be used in any software to handle
      RAR archives without limitations free of charge, but cannot be
      used to develop RAR (WinRAR) compatible archiver and to
      re-create RAR compression algorithm, which is proprietary.
      Distribution of modified UnRAR source code in separate form
      or as a part of other software is permitted, provided that
      full text of this paragraph, starting from "UnRAR source code"
      words, is included in license, or in documentation if license
      is not available, and in source code comments of resulting package.

   3. The UnRAR utility may be freely distributed. It is allowed
      to distribute UnRAR inside of other software packages.

   4. THE RAR ARCHIVER AND THE UnRAR UTILITY ARE DISTRIBUTED "AS IS".
      NO WARRANTY OF ANY KIND IS EXPRESSED OR IMPLIED.  YOU USE AT
      YOUR OWN RISK. THE AUTHOR WILL NOT BE LIABLE FOR DATA LOSS,
      DAMAGES, LOSS OF PROFITS OR ANY OTHER KIND OF LOSS WHILE USING
      OR MISUSING THIS SOFTWARE.
```

### 对本项目的约束（重要）

- ✅ 允许：在 `pak` 中内嵌 UnRAR 用于**解压** RAR，并免费分发
- ✅ 必须：在任何分发形式中附带上述第 2 段全文（本文件即为此用途）
- ❌ 禁止：用 UnRAR 源码开发 **RAR 兼容的压缩器**，或重建 RAR 压缩算法

因此 `pak` **只解不压 RAR**，这不是功能缺失，是合规前提。

---

## 其他依赖

| crate | 许可 |
|---|---|
| zip / tar / flate2 / bzip2-rs / lzma-rs / sevenz-rust2 | MIT / Apache-2.0 |
| kamadak-exif | BSD-2-Clause |
| encoding_rs | Apache-2.0 / MIT |
| tauri | MIT / Apache-2.0 |
