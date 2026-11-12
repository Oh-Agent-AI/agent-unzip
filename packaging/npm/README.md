# agent-unzip

**agent-unzip（代理解压缩）** —— 为 Agent 设计的解压器。

只做三件事：**先判定、再解压、打包前自查**。人也能用，但优先服务 Agent。

```bash
npx agent-unzip inspect 某个包.rar
npx agent-unzip extract --json 某个包.rar
```

- 输出稳定 JSON：`schema: "aunzip/1"`
- 语义化退出码：`0` 正常 / `10` 判定危险 / `11` 需要密码 / `12` 失败 / `13` 不是压缩包
- 永不交互、永不覆盖、原子落位
- `aunzip --schema` 自描述能力边界

完整文档见仓库 README。
