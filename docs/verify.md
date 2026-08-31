# 测试环境验证

验证闭环：部署配置 → 打测试流量 → 查 SOC 日志 → 出报告 → 判断误报/漏报 → 调整或放行。

## 用例设计

每个配置至少 1 攻击 + 1 正常用例。用例字段：`name`、`method`（默认 GET）、`path`、`query`、`body`、`header`（可选）、`expect`（`block`/`pass`）。

- **攻击用例**：携带要拦截的特征载荷（如 `?id=1 union select 1`），`expect=block`
- **正常用例**：同路径正常参数，`expect=pass`，用于暴露误报

用例随 `generate` 参数传入（params 中 `test_cases` 数组），`generate --output` 会落盘到信封文件。

## 执行

```bash
# 一键闭环（官方沙盒专用命令组，与自有环境隔离）：
# 清空基线 → 部署 → 打流量 → 查日志 → 报告 → 清理本次配置（环境回到空态）
jxwaf-cli generate web-rule --params /tmp/rule.json --output /tmp/rule_cfg.json
jxwaf-cli sandbox verify /tmp/rule_cfg.json [--url https://test.example.com] [--wait 5]
```

官方沙盒验证（`sandbox verify`）自动完成全流程，结束时环境回到空态。自有环境（标准版/专业版/自建云）使用通用 `verify --url`，只发流量出报告，**不会部署或清空任何配置**；需要分批手动时用 `apply` 下发 → `verify --no-fresh`…（注：通用 verify 无 --no-fresh/--keep 参数，手动流程为 `apply --apply` → `verify` → `cleanup --apply`）。

调试开关（仅 sandbox verify）：

- `--no-fresh`：不清空基线，连续调试同一份配置时使用
- `--keep`：验证后保留本次部署的配置（如需后续手工检查）

## 判定标准

| 场景 | 期望 | 通过条件 |
|---|---|---|
| 攻击用例 | block | HTTP 状态码 403 / 444（`blocked`） |
| 正常用例 | pass | 非 403/444（`passed`） |
| watch 动作规则 | 攻击用例 | 状态码通常 200，**结合 soc_logs 判读**：`waf_action` 出现 watch 记录即命中生效 |

## 误报/漏报处理策略（≤3 次迭代）

1. **漏报**（攻击用例 `unexpected`，仍放行）：
   - 检查 rule_matchs 参数取值与实际请求不符（路径/参数名/大小写）
   - 确认规则已下发生效（`rule web list` 查状态与优先级）
   - 收紧匹配条件后重试
2. **误报**（正常用例 `unexpected`，被拦截）：
   - 优先**加具体规则放行特定场景**而非放宽原规则（如对已知正常参数加 web-white）
   - 或缩小原规则匹配范围（限定 path 前缀、参数名）
3. 三次迭代未收敛：停下向用户报告现象与已排除的原因，不盲目继续

## SOC 日志分析

```
jxwaf-cli soc log query --params '{"from_time":"...","to_time":"...","page":1,"sql_rules":[...]}'
```

- 时间格式 `YYYY-MM-DD HH:MM:SS`，pageSize 固定 20，注意分页
- 常用过滤：`host` equals 域名、`waf_action` equals `block/watch`、`src_ip` equals 攻击源
- 关键字段：`waf_module`（命中模块）、`waf_policy`（命中规则名）、`waf_action`（实际动作）、`waf_extra`（细节）

### waf_module 对照（定位拦截/放行来源）

| waf_module | 模块 |
|---|---|
| `base_component` | 防护组件 |
| `name_list` | 名单防护 |
| `flow_white_rule` / `web_white_rule` | 流量/Web 白名单 |
| `flow_ip_region_block` | IP 区域封禁 |
| `flow_rule_protection` / `web_rule_protection` | 流量/Web 防护规则 |
| `flow_engine_protection` / `web_engine_protection` | 流量/Web 引擎防护 |
| `web_page_tamper_proof` | 网页防篡改 |

### waf_action 对照

| waf_action | 含义 |
|---|---|
| `block` | 被拦截（403） |
| `reject_response` | 连接被关闭（444） |
| `bot_check` | 人机识别质询 |
| `network_block` | 网络层封禁 |
| `watch` | 观察记录 |
| `pass` | 放行 |
| `web_bypass` / `flow_bypass` / `all_bypass` | 白名单/名单放行 |

## 用例设计分模块要点

- **Web 规则**：攻击载荷放 path/headers/body；正常用例同路径相似参数（暴露误报）；补编码变体（URL/Unicode/Hex）与大小写变体
- **流量规则**：每条用例仅发送 1 次请求，触发限速需把攻击用例在 `test_cases` 数组中**重复多次**（重复条数 > exceed_count，或验证时临时调低阈值如 exceed_count=3 配 4 条重复用例）；正常用例低频
- **组件**：攻击用例带触发特征；组件设 ctx 变量由规则处置时，同时验证规则引用是否生效
- **名单**：条目内特征请求应 block，条目外应 pass；临时名单验证过期自动放行

误报/漏报的排查决策树与调优见 [playbook.md](playbook.md)。

## 通过标准

攻击用例全部 `blocked`（或 watch 场景 soc 有对应命中）、正常用例全部 `passed`，且无异常 → 可向用户提交验证报告（report 数据）并申请生产下发。