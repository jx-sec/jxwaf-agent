# 规则与白名单开发规范

适用：Web 防护规则（`web-rule`）、Web 白名单（`web-white`）、流量防护规则（`flow-rule`）。

## 字段总览

| 字段 | 类型 | 说明 |
|---|---|---|
| `rule_name` | string | 规则名（唯一） |
| `rule_detail` | string | 描述 |
| `rule_matchs` | string | 匹配条件（JSON 字符串，结构见下） |
| `rule_action` | string | `block` 拦截 / `watch` 观察 / `bot_check` 人机验证 |
| `action_value` | string | 仅 `bot_check` 需要：`auto`/`slipper`/`puzzle`/`words`；其他为空字符串 |
| `filter`* | string | `"true"`/`"false"`：是否启用匹配条件（仅 flow-rule） |
| `entity`* | string | 统计实体（JSON 字符串，仅 flow-rule，如 `["src_ip"]`） |
| `stat_time`* | string | 统计时间窗（秒，仅 flow-rule） |
| `exceed_count`* | string | 超阈值次数（仅 flow-rule） |
| `block_time`* | string | 封禁时长（秒，仅 flow-rule） |

\* 标记项仅流量规则存在。`generate` 会自动完成数值→字符串、数组→JSON 字符串的转换，agent 写语义参数即可。

## rule_matchs 结构（核心）

JSON 字符串，数组为 OR 关系，每项结构：

```json
[
  {
    "match_args": [{"key": "http_args", "value": "query_string"}],
    "args_prepocess": ["none"],
    "match_operator": "rx",
    "match_value": "union.*select"
  }
]
```

### match_args.key（参数大类）

| key | value 取值 |
|---|---|
| `http_args` | `path`/`query_string`/`method`/`src_ip`/`raw_body`/`version`/`scheme`/`raw_header` |
| `header_args` | `host`/`cookie`/`referer`/`user_agent`/`default`（自定义头名） |
| `cookie_args` / `uri_args` / `post_args` / `json_post_args` / `ctx_args` | `default`（自定义参数名） |
| `global_name_list_result` | 名单名，名单结果联动（`status_check` + `exist`） |

同一 `match_args` 内多参数为 AND。

### args_prepocess

`none` / `lowerCase` / `base64Decode` / `length` / `uriDecode` / `uniDecode` / `hexDecode`

### match_operator

| 类别 | 取值 |
|---|---|
| 字符串 | `rx` 正则 / `str_prefix` 前缀 / `str_suffix` 后缀 / `str_contain` 包含 / `str_ncontain` 不包含 / `str_eq` 等于 / `str_neq` 不等于 |
| 数字 | `gt` / `lt` / `eq` / `neq` |
| 存在性 | `status_check`（`match_value` 为 `exist`/`no_exist`） |

## 典型场景

### 拦截 SQL 注入（观察优先版）

```json
{
  "config": {
    "rule_name": "watch_sql_injection",
    "rule_detail": "观察SQL注入攻击",
    "rule_matchs": [
      {
        "match_args": [{"key": "http_args", "value": "query_string"}],
        "args_prepocess": ["none"],
        "match_operator": "rx",
        "match_value": "union.*select|insert.*into|sleep\\("
      }
    ],
    "rule_action": "watch",
    "action_value": ""
  }
}
```

### 名单联动封禁（名单命中则拦截）

`name-list` 需先存在同名名单（action 见 module_dev.md）：

```json
{
  "rule_matchs": [
    {
      "match_args": [{"key": "global_name_list_result", "value": "malicious_ip"}],
      "args_prepocess": ["none"],
      "match_operator": "status_check",
      "match_value": "exist"
    }
  ],
  "rule_action": "block"
}
```

### 流量限速（60 秒内单 IP 超 100 次封 600 秒）

```json
{
  "config": {
    "rule_name": "flow_rate_limit",
    "rule_detail": "每IP限速",
    "rule_matchs": [{"match_args": [{"key": "http_args", "value": "method"}], "args_prepocess": ["none"], "match_operator": "eq", "match_value": "1"}],
    "rule_action": "block",
    "action_value": "",
    "filter": "false",
    "entity": ["src_ip"],
    "stat_time": 60,
    "exceed_count": 100,
    "block_time": 600
  },
  "test_cases": [
    {"name": "正常请求", "method": "GET", "path": "/", "expect": "pass"},
    {"name": "高频请求", "method": "GET", "path": "/", "expect": "block"}
  ]
}
```

## 设计红线

1. **观察优先**：新增拦截类规则默认 `watch`；测试环境验证无误报（`verify` 报告正常用例全过）后再改 `block`
2. 每个规则的匹配条件要**具体**：优先针对确定的攻击载荷/POC 设计，避免宽泛正则导致误报
3. 正则用 `rx`；字符串精确比对用 `str_eq`/`str_contain`，性能更好
4. 名单联动时先创建名单、再建规则；名单删除会级联删除条目，依赖它的规则会失效（先处理规则）