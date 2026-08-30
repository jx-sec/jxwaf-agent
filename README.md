# JXWAF Agent

通过 AI Agent 运维 JXWAF：Go 命令行工具 + 文档体系，让 AI 在 IDE（Claude Code / Trae / Cursor 等）中用自然语言完成 WAF 防护配置的生成、验证与下发。

支持 JXWAF 三个版本：**标准版 / 专业版 / 云WAF**。版本差异（认证、端点命名、租户参数）由 CLI 内部适配层自动处理，对使用者与 AI 是统一命令面。

## 快速开始

```bash
# 构建（或下载 Release 二进制）
go build -o jxwaf-cli ./cmd/cli

# 初始化官方沙盒（官方免费云测试环境，独立命令组，与自有环境隔离）
./jxwaf-cli sandbox init

# 查看配置（凭据脱敏）与连通性
./jxwaf-cli config show
./jxwaf-cli config validate
```

自有环境接入（标准版/专业版/自建云）：

```bash
./jxwaf-cli config set --name prod --version professional \
  --base-url https://your-console --waf-auth <token> --group-name <域名组>
```

## 典型闭环

```bash
# 1. 生成配置（语义参数 → 规范请求体；拦截类默认 watch 观察）
./jxwaf-cli generate web-rule --params /tmp/rule.json --output /tmp/rule_cfg.json

# 2. 官方沙盒一键验证（清空基线→部署→打流量→查日志→报告→清理，环境回到空态）
./jxwaf-cli sandbox verify /tmp/rule_cfg.json

# 3. 沙盒手动清理与查询
./jxwaf-cli sandbox reset
./jxwaf-cli rule web list --params '{"page":1}' --env sandbox
./jxwaf-cli soc log query --params '{"from_time":"...","to_time":"...","page":1,"sql_rules":[...]}' --env sandbox
```

## 输出契约

- stdout 仅 JSON；stderr 为 `{"result":false,"error":"..."}`；退出码 0=成功 / 1=失败
- 写操作默认 **dry-run**（仅预览请求），显式 `--apply` 才落地

## 文档

| 文档 | 内容 |
|---|---|
| [docs/requirements.md](docs/requirements.md) | 需求基线（范围、架构、安全模型、验收标准） |
| [docs/cli.md](docs/cli.md) | 完整命令参考 |
| [docs/rule_dev.md](docs/rule_dev.md) | 规则与白名单开发规范（rule_matchs 结构等） |
| [docs/module_dev.md](docs/module_dev.md) | 名单 / 组件 / 网站接入规范 |
| [docs/verify.md](docs/verify.md) | 验证方法与 SOC 日志分析 |
| [docs/sop.md](docs/sop.md) | 安全工作规范（两步审核 / 红线 / SOP） |
| [docs/versions.md](docs/versions.md) | 三版本差异与能力矩阵 |

## AI IDE 接入

- [CLAUDE.md](CLAUDE.md) — Claude Code 接入说明
- [AGENTS.md](AGENTS.md) — Cursor / Copilot 等通用接入说明
- `.trae/rules/` — Trae 工作规则

多 IDE 通用：仅凭本仓库文档与 CLI，任何 AI IDE 均可完成运维闭环。

## 开发

```bash
go test ./...   # 单元 + 集成（含完整闭环 E2E 模拟测试）
go vet ./...
```

依赖：Go 1.25+、cobra、golang.org/x/term。