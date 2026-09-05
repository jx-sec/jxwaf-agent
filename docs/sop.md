# 安全工作规范（SOP 与红线）

## 两步审核机制

1. **生成/查询/测试环境操作**：直接执行，将结果整理后展示
2. **生产环境下发**：先 dry-run（默认行为）→ 展示请求内容 → 用户明确确认 → `--apply` 执行

所有写入命令（`apply`、资源 `create/edit/delete/status`、`cleanup`）默认 dry-run，仅输出请求预览；显式 `--apply` 才实际执行。

## 风险分级

| 风险 | 操作 | 处理 |
|---|---|---|
| 低 | 查询、generate、测试环境 apply/verify/cleanup | 直接执行 |
| 中 | 生产环境创建/更新配置 | 展示变更内容，等待用户确认 |
| 极高 | 删除规则/名单/网站/组件 | 展示影响范围与后果警示，等待用户二次确认 |

确认话术：
- 创建：「以上是将要创建的配置，确认后我将下发到生产环境，是否继续？」
- 更新：「以上是变更内容（变更前 → 变更后），确认后我将通过 API 更新，是否继续？」
- 删除：「即将删除以下配置：[...]。删除后相关防护立即失效且不可恢复。确认请回复"确认删除"，取消请回复"取消"」

发出确认请求后必须等待用户明确回复，不得自行推断或跳过。用户拒绝时终止操作并询问是否调整方案。

## 核心红线

1. **观察优先**：测试环境验证拦截类规则直接用 `block`（测试环境无真实业务，watch 不拦截无法直观验证）；生产环境首发建议 `watch` 观察无误报后转 `block`；放行类（白名单/bypass）无需观察；紧急防护经用户确认后可直接 block
2. **LuaJIT 兼容**（组件）：禁止 Lua 5.2+ 语法；`code` 由 generate 自动 Base64；组件内禁止 pcall
3. **网站接入**：回源地址必填；HTTPS 证书与域名必须匹配
4. **JSON 字符串字段**：`rule_matchs`、`entity`、`name_list_rule`、`source_ip` 等复杂字段统一由 generate 转换为 JSON 字符串（agent 只给语义数组），不要手拼字符串
5. **凭据安全**：`config show` 已脱敏；严禁将明文 waf_auth 写入对话回复或任何文件
6. **拒绝违规需求**：用户需求违反红线时拒绝并解释原因

## 模块选择决策树

| 需求特征 | 选用模块 | 说明 |
|---|---|---|
| 基于频率统计的防护（限速/CC） | `flow-rule` | 时间窗口计数，超阈值处罚（见 rule_dev.md entity 结构） |
| 自定义检测逻辑（正则无法覆盖） | `component` | 可独立执行动作（unify_action），或设 `ngx.ctx` 变量由规则 `ctx_args` 引用联动处置 |
| IP/域名/UA 等键值黑白名单 | `name-list` | 直接封禁/放行用 block/bypass 动作；需规则决定处置则 action=watch + 规则引用 `global_name_list_result` |
| 单次请求特征匹配拦截 | `web-rule` | 即时匹配，不支持频率统计 |
| 放行特定流量 | `web-white` / `flow-white` | 命中即跳过对应侧防护 |

## 标准工作流（SOP）

```
需求分析 → 信息澄清 → 读 docs 对应规范 → generate 生成（含用例，--output 落盘信封）
→ 测试环境：test verify 一键闭环（清基线→部署→打流量→查日志→报告→清理，环境回到空态）
→ 误报/漏报调整（≤3 次迭代，调试用 --no-fresh/--keep）
→ 展示验证报告与最终配置 → 用户确认 → 生产 dry-run → --apply → 结果反馈
```

测试环境用独立命令组 `test`（verify/cleanup/reset），与自有环境命令隔离（无内置默认值，使用前需 `test init` 配置）；自有环境验证用通用 `verify --url`（只发流量不动配置）。兜底每日 `test reset --apply`。

**文档优先级**：以本地 `docs/` 为主。当本地文档与线上行为有冲突或错误、或拿不准的字段时，再到 **docs.jxwaf.com** 获取最新（按版本分站：`/jxwaf-standard/`、`/jxwaf-professional/`、`/jxwaf-cloud/`；部署类看各站 `Deployment-Tutorial`），以官方为准。

## 异常处理

| 现象 | 处置 |
|---|---|
| 网络错误/超时 | `config validate` 检查连通性；检查 base_url |
| `waf_auth fail` / `invalid jxwaf_waf_auth` | 凭据无效：`config show` 核对，重跑 `config set`（自建测试环境用 `test init`） |
| `ip not allowed` | 调用方 IP 不在管理 API 白名单（联系环境管理员加白） |
| `param is null` / 参数错误 | 核对 params 字段（cli.md / rule_dev.md / module_dev.md），修正重试 |
| `rule_name is exist` 等重名 | 改 `--update`（apply）或换名；判定为已存在配置时先查询再决策 |
| `can not decode component_data` | 检查 Lua 5.2+ 语法 / Base64 / 括号匹配 |
| 专业版 `group_name` 缺失 | 加 `--group` 或 `config set --group-name` |
| 云WAF admin `sub_user_name` 缺失 | 加 `--sub-user` |