# jxwaf-cli 命令参考

所有命令输出契约：**stdout 为 JSON**，**stderr 为错误 `{"result":false,"error":"..."}`**，退出码 0=成功 / 1=失败。不确定参数含义时以本文档为准。

## 全局参数

| 参数 | 说明 |
|---|---|
| `--env <name>` | 目标环境名称，默认取配置中的 active（见 `config show`） |
| `--group <name>` | 专业版域名组（防护类操作必填，或配置 `--group-name`） |
| `--sub-user <name>` | 云WAF 主账号操作的目标子账号名（防护类操作必填） |

## 初始化与配置

### `jxwaf-cli sandbox init`

保存官方**测试沙盒**凭据（`~/.jxwaf/config.json`，权限 0600）。官方沙盒为**专业版**共享环境：固定账号 + 固定节点/测试域名，所有人共用；使用独立的 `sandbox` 命令组操作，与自有环境彻底隔离。

```
jxwaf-cli sandbox init [--base-url URL] [--name ENV] [--group-name G]
```

- 无注册流程：直接写入内置的官方环境地址与共享凭据，环境名默认 `sandbox`
- **不会修改 active 配置**：通用命令（rule/namelist/apply 等）默认不会命中沙盒
- 专业版防护操作必须指定域名组：`--group-name` 显式指定，或留空自动发现环境里的第一个域名组
- 可用环境变量 `JXWAF_OFFICIAL_BASE_URL` / `JXWAF_OFFICIAL_MASTER_AUTH` 覆盖；官方测试域名（verify 用）见 `JXWAF_OFFICIAL_TEST_URL`

### `jxwaf-cli config`

```
jxwaf-cli config show                     # 查看配置（凭据脱敏，仅保留前 4 位）
jxwaf-cli config set --name N --version standard|professional|cloud \
                     --base-url URL --waf-auth T [--sub-waf-auth T] [--sub-user-name N] [--group-name G]
jxwaf-cli config validate [--env E]       # 连通性自检（可达到性，非业务校验）
```

- 自有环境（标准版/专业版/自建云）用 `config set` 手动添加：标准版/专业版 waf_auth 来自部署环境（标准版为环境变量 `WAF_AUTH`，专业版为控制台注册账号生成的 waf_auth）
- 自建云主账号模式：`--waf-auth` 自己的主账号 token + `--sub-user-name` 默认子账号名（防护操作自动注入）；云WAF 用户（子账号）模式：额外 `--sub-waf-auth`

## 配置生成（AI 辅助核心）

### `jxwaf-cli generate <类型> --params <file|->`

类型：`web-rule` / `web-white` / `flow-rule` / `name-list` / `component` / `domain`

```
jxwaf-cli generate web-rule --params /tmp/p.json [--output /tmp/cfg.json]
```

- `--params`：JSON 文件路径、`-`（stdin）或内联 JSON，含 `config` 与可选 `test_cases` 两节
- 输出：`type`、`op`、`config`（规范化请求体）、`preview`（语义摘要，用于向用户展示）、`test_cases`
- `--output`：落盘信封 `{type, op, config, test_cases}`（供 `apply`/`verify` 使用）
- 未指定 `rule_action` 时默认 `watch`（观察优先红线）

字段与校验规范见 [rule_dev.md](rule_dev.md)、[module_dev.md](module_dev.md)。

## 下发

### `jxwaf-cli apply <配置文件> [--update] [--apply]`

下发 `generate --output` 生成的配置到目标环境。

- 默认 dry-run：仅输出 `{dry_run, path, body}` 预览，不发请求
- `--apply` 实际执行；`--update` 按编辑接口更新（否则按创建）
- 业务失败（如重名 `rule_name is exist`）走 stderr 错误

### 资源写入子命令（统一 dry-run/apply 机制）

```
jxwaf-cli rule web|flow create|edit|delete|status --params '{...}' [--apply]
jxwaf-cli namelist create|edit|delete|status|item-add|item-del --params '{...}' [--apply]
jxwaf-cli component create|edit|delete|status --params '{...}' [--apply]
jxwaf-cli website create|edit|delete --params '{...}' [--apply]
jxwaf-cli website access create|edit|delete --params '{...}' [--apply]   # 仅云WAF
```

- `--params` 即 API 请求体（JSON 文件/`-`/内联），租户参数自动注入，无需手写
- **默认 dry-run**，`--apply` 才落地；删除类操作务必先 dry-run 展示影响

## 查询

```
jxwaf-cli rule web|flow list|get --params '{...}'
jxwaf-cli namelist list|get|item-list --params '{...}'
jxwaf-cli component list|get --params '{...}'
jxwaf-cli website list|get --params '{...}'
jxwaf-cli website access list|get --params '{...}'       # 仅云WAF
jxwaf-cli soc log query --params '{...}'
```

常见参数：

- 分页列表：`{"page": 1}`
- 单条查询：规则 `{"rule_name": "x"}`；名单 `{"name_list_name": "x"}`；组件 `{"name": "x"}`；域名 `{"domain": "x"}`（云WAF admin 另需 `--sub-user`）
- 攻击日志：`{"from_time":"2026-08-30 10:00:00","to_time":"2026-08-30 11:00:00","page":1,"sql_rules":[{"field":"host","operation":"equals","value":"www.example.com"}]}`；sql_rules.field 白名单：`host, uri, request_uri, method, query_string, src_ip, user_agent, cookie, status, waf_module, waf_policy, waf_action, ...`；operation: `contains/prefix/suffix/equals/not_equals`

## 测试环境验证闭环

### 官方沙盒（sandbox 命令组，与自有环境隔离）

```
jxwaf-cli sandbox verify <用例文件> [--url https://...] [--wait 5] [--keep] [--no-fresh]
jxwaf-cli sandbox cleanup --type web-rule|flow-rule|name-list|component|website --names a,b [--apply]
jxwaf-cli sandbox reset [--apply]
```

- `sandbox verify` 为**一键沙盒闭环**：清空基线 → 部署信封配置 → 打测试流量 → 查 SOC 日志 → 报告 → 清理本次配置（环境回到空态）。判定：`expect=block` 且状态码 403/444 → `blocked`；`expect=pass` 且非 403/444 → `passed`；否则 `unexpected`。watch 类规则返回 200，需结合 `soc_logs` 中 `waf_action` 判读（见 [verify.md](verify.md)）
  - `--no-fresh`：不清基线（连续调试）；`--keep`：验证后保留配置
  - `--url` 省略时取官方测试域名（环境变量 `JXWAF_OFFICIAL_TEST_URL` 可覆盖）
- `sandbox cleanup`：沙盒按名称批量删除配置，默认 dry-run，`--apply` 执行（**删除不可恢复**）
- `sandbox reset`：沙盒全量清空规则/白名单/名单/组件（**不删域名**），默认 dry-run；官方兜底"每日空环境"可挂定时 `jxwaf-cli sandbox reset --apply`

### 通用验证（自有环境，只发流量不动配置）

```
jxwaf-cli verify <用例文件> --url https://example.com [--wait 5]
```

通用 `verify` 仅发送测试流量 + 查 SOC 日志出报告，**不会部署或清空任何配置**。

## 典型工作流

```
需求分析 → generate 生成 → apply 到测试环境(--apply) → verify 验证
→ 误报/漏报则改参数重试(≤3次) → cleanup 清理 → 用户确认 → 生产 --apply
```

安全规范与红线见 [sop.md](sop.md)；三版本能力差异见 [versions.md](versions.md)。