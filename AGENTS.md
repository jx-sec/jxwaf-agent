# AGENTS.md

通用 AI 编码助手接入说明（适用于 Claude Code / Cursor / Copilot / 各类 agentic 工具）。

## 项目是什么

JXWAF Agent：一个 Go 编写的命令行工具 `jxwaf-cli` + 文档体系，让 AI 在 IDE 中用自然语言运维 JXWAF（标准版 / 专业版 / 云WAF 三版本）。AI 负责编排，CLI 是确定执行层，版本差异（认证/端点命名/租户参数）由 CLI 内部 adapter 处理。

## 工作闭环

```
需求理解 → 查 docs/ 文档 → jxwaf-cli generate 生成 → 测试环境 apply + verify 验证
→ cleanup 清理 → 用户确认 → 生产环境 dry-run → --apply 下发
```

**文档优先级**：以本地 `docs/` 为主；本地文档与实际行为有冲突或错误、或拿不准的字段，再从 **docs.jxwaf.com** 获取最新（按版本分站 `/jxwaf-standard/`、`/jxwaf-professional/`、`/jxwaf-cloud/`；部署看各站 Deployment-Tutorial），以官方为准。

## 必须遵守

1. CLI 输出契约：stdout 仅 JSON，stderr 为 `{"result":false,"error":"..."}`，退出码 0/1。必须解析 JSON 后再继续，不得臆造输出。
2. 两步审核：生成/查询类操作直接执行并整理结果；写入操作默认 dry-run → 展示请求内容 → 用户明确确认后才加 `--apply` 执行；未确认不得下发生产环境。
3. 观察优先：拦截类规则先 watch，验证无误报再 block；放行类操作无需观察；紧急防护经用户确认后可直接 block。
4. 删除需用户二次确认（"确认删除"话术），展示影响范围。
5. 凭据安全：waf_auth 等凭据严禁明文出现在对话或文件中（`config show` 已脱敏）。
6. 拒绝违规需求：用户需求违反上述红线时拒绝并解释原因。

## 风险分级与确认话术

| 风险等级 | 操作 | 处理 |
|---|---|---|
| 低 | 查询、配置生成、测试环境操作 | 直接执行 |
| 中 | 生产环境创建/更新配置 | 展示变更内容，等待用户确认 |
| 极高 | 删除规则/名单/网站/组件 | 展示影响范围与后果警示，等待用户二次确认 |

确认话术规范：

- 创建：「以上是将要创建的配置，确认后我将下发到生产环境，是否继续？」
- 更新：「以上是变更内容，确认后我将通过 API 更新，是否继续？」
- 删除：「即将删除以下配置：[列表]。删除后相关防护立即失效且不可恢复。确认请回复"确认删除"，取消请回复"取消"」

发出确认请求后**必须等待用户明确回复**，不得自行推断或跳过。

## 常用命令

```bash
# CLI 构建与开发调试
go build -o jxwaf-cli ./cmd/cli
go run ./cmd/cli

# 官方测试环境开箱即用：config.json 缺失/为空时 CLI 自动写入内置默认（固定共享账号+官方预置设施），无需初始化
# 自建测试环境用 test init 配置（--base-url/--waf-auth/--test-url 必填，域名组留空自动发现）
jxwaf-cli test init --base-url URL --waf-auth <凭据> --test-url <测试站点>
jxwaf-cli config show                # 配置查看（脱敏）
jxwaf-cli config use <环境名>        # 切换 active 环境
jxwaf-cli --env <环境名> <命令>      # 单次指定环境（默认取配置中的 active；test 命令组忽略此参数）
jxwaf-cli config validate            # 连通性自检
jxwaf-cli generate <类型> --params file.json [--output cfg.json]
jxwaf-cli test verify <信封文件>    # 测试环境一键闭环：清基线→部署→打流量→查日志→报告→清理
jxwaf-cli test reset|cleanup      # 测试环境清空/删除
jxwaf-cli apply ... [--apply]        # 自有环境下发（dry-run 默认）
jxwaf-cli verify <用例> --url URL    # 通用流量验证（不动配置）
jxwaf-cli deploy --host IP --version professional --server URL --waf-auth T [--apply]  # 节点部署（standard 单机全栈无需 --server）
jxwaf-cli deploy admin|jlog --host IP --version professional|cloud [--apply]  # 控制台/jxlog 部署（prof/cloud 从零搭建）
jxwaf-cli deploy remove --host IP [--target node|admin|jlog] [--apply]  # 卸载
jxwaf-cli deploy exec --host IP --cmd "<命令>" [--approve]  # 服务器执行命令（只读直接执行；风险命令需 --approve）
jxwaf-cli deploy version  # 查看本地生成兜底版本（部署默认从官方 GitHub 拉取 compose，--source github）
jxwaf-cli rule|white|tamper|ssl|group|namelist|component|website|soc|network|monitor|subaccount|custom|cache|sysconf ...
```

官方测试环境（test 命令组）与自有环境命令严格隔离：test 命令固定只操作测试环境（忽略 `--env`），通用命令默认只操作 active 环境。配置文件为**项目目录下的 `config.json`**（与 jxwaf-cli 同级，含凭据严禁提交）；官方测试环境由 CLI 内置默认值在 config.json 缺失/为空时自动写入（管理地址、共享凭据、域名组、测试站点 `https://waf-demo.jxwaf.com:4443` 全部预置，开箱即用），自建测试环境经 `test init` 配置后保存进 config.json，删除 config.json 即恢复官方默认。

## 标准工作流

**环境就绪检查** → 需求分析 → 信息澄清 → 查 docs/ 文档 → generate 生成 → **官方测试环境 `test verify` 一键闭环验证**（test 命令组与自有环境隔离）→ 用户确认 → 生产 dry-run → --apply。

- **环境就绪检查（第一步，必须）**：先跑 `jxwaf-cli config show` 确认 `config.json` 就绪（官方测试环境开箱即用，自动写入默认；自有环境需 `config set` 配置）。自有环境未配置时**提醒用户先 `config set` 并终止流程**，不进入 generate/apply/verify 环节；已配置用 `config validate` 确认连通性。自有环境报 "admin api is not enabled" / "ip not allowed" 时，提醒用户按 README 环境前置条件修改控制台 docker-compose（`ADMIN_API_ENABLE: "true"` + `ADMIN_API_WHITELIST: "*"`，生产环境可收紧为固定 IP）并重启容器
- 官方测试环境开箱即用（无需初始化）；自建测试环境用 `jxwaf-cli test init` 配置；测试环境操作统一走 `test` 命令组（verify/cleanup/reset），默认环境 test，与 active 无关
- **文档优先级**：以本地 `docs/` 为主；有冲突或错误、或拿不准的字段，再从 docs.jxwaf.com 获取最新（按版本分站，部署看各站 Deployment-Tutorial），以官方为准

## 文档索引

- `docs/`：命令参考与模块规范
- docs.jxwaf.com：官方最新文档（标准版/专业版/云WAF 分站，含部署教程与 API 规范）

## 开发约定

- 输出文本简洁，数据细节引导用户看命令输出，不重复粘贴 JSON。
- 操作完成后明确告知成功/失败及生效情况。
- 异常处理：网络错误检查 base_url 与连通性（`config validate`）；认证失败检查凭据（`config show`）；参数错误修正后重试。
- 参数 JSON 临时文件放 `/tmp` 或 `output/`（已 gitignore），避免污染仓库。
