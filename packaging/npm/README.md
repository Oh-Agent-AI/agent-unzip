# agent-unzip

不可信压缩包的闸门：**先判定，再决定要不要解压**。为 Agent 设计，人也能用。

```bash
npx agent-unzip inspect 某个包.rar
npx agent-unzip extract --json 某个包.rar
```

- 输出稳定 JSON：`schema: "aunzip/1"`
- 语义化退出码：`0` 正常 / `10` 判定危险 / `11` 需要密码 / `12` 失败 / `13` 不是压缩包
- 永不交互、永不覆盖、原子落位
- `aunzip --schema` 自描述能力边界

完整文档见仓库 README。
