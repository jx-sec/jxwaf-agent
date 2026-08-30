# AGENTS.md

通用 AI 编码助手接入说明（适用于 Cursor / Copilot / 各类 agentic 工具；Claude Code 见 CLAUDE.md）。

## 项目是什么

JXWAF Agent：一个 Go 编写的命令行工具 `jxwaf-cli` + 文档体系，让 AI 在 IDE 中用自然语言运维 JXWAF（标准版 / 专业版 / 云WAF 三版本）。AI 负责编排，CLI 是确定执行层，版本差异（认证/端点命名/租户参数）由 CLI 内部 adapter 处理。

## 必须遵守

1. CLI 输出契约：stdout 仅 JSON，stderr 为 `{"result":false,"error":"..."}`，退出码 0/1。必须解析 JSON 后再继续，不得臆造输出。
2. 两步审核：写入操作默认 dry-run，用户确认后才加 `--apply` 执行；未确认不得下发生产环境。
3. 观察优先：拦截类规则先 watch，验证无误报再 block。
4. 删除需用户二次确认（"确认删除"话术），展示影响范围。
5. 凭据安全：waf_auth 等凭据严禁明文出现在对话或文件中（`config show` 已脱敏）。

## 标准工作流

需求分析 → 信息澄清 → 查 docs/ 文档 → generate 生成 → **官方沙盒 `sandbox verify` 一键闭环验证**（sandbox 命令组与自有环境隔离）→ 用户确认 → 生产 dry-run → --apply。

- 官方沙盒初始化：`jxwaf-cli sandbox init`；沙盒操作统一走 `sandbox` 命令组（verify/cleanup/reset），默认环境 sandbox，与 active 无关
- 自有环境验证用通用 `verify --url`：只发流量出报告，绝不自动部署/清空配置

## 文档索引

- `docs/requirements.md`：需求基线（范围、架构、安全模型、验收标准）
- `docs/`：命令参考与模块规范（逐步补充）

## 开发约定

- 输出文本简洁，数据细节引导用户看命令输出，不重复粘贴 JSON。
- 参数 JSON 临时文件放 `/tmp` 或 `output/`（已 gitignore）。