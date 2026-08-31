# 规则与白名单开发规范

适用：Web 防护规则（`web-rule`）、Web 白名单（`web-white`）、流量防护规则（`flow-rule`）、流量白名单（`flow-white`）。

> 字段与枚举已对齐 jxwaf_admin_server 控制台源码与 jxwaf_node 节点引擎（三版本引擎一致）。**控制台服务端对 rule_action 不做枚举校验（任意值透传入库），错误动作值会被静默入库但节点不执行**——`generate` 按本文档枚举做客户端校验，以 CLI 报错为准。

## 字段总览

| 字段 | 类型 | 说明 |
|---|---|---|
| `rule_name` | string | 规则名（唯一） |
| `rule_detail` | string | 描述 |
| `rule_matchs` | string | 匹配条件（JSON 字符串，结构见下） |
| `rule_action` | string | 执行动作（按类型枚举，见下表） |
| `action_value` | string | 动作值：`bot_check` 时为人机识别方式；`network_block` 时为封禁秒数（正整数）；其余动作为空字符串 |
| `filter`* | string | `"true"`/`"false"`：是否启用匹配条件（仅 flow-rule） |
| `entity`* | string | 统计实体（JSON 字符串，仅 flow-rule，结构见下） |
| `stat_time`* | string | 统计时间窗（秒，正整数，仅 flow-rule） |
| `exceed_count`* | string | 超阈值次数（正整数，仅 flow-rule） |
| `block_time`* | string | 封禁时长（秒，正整数，仅 flow-rule） |

\* 标记项仅流量规则存在。`generate` 会自动完成数值→字符串、数组→JSON 字符串的转换，agent 写语义参数即可。

## rule_action 按类型枚举（对齐节点引擎 waf.lua 分支）

| 类型 | 合法动作 | 说明 |
|---|---|---|
| `web-rule` | `block` / `watch` / `reject_response` | **不支持 bot_check**（节点 web 规则无该分支，静默不生效）；`reject_response` 在 web 规则上与 `block` 行为一致（均返回拦截页 403，非 444） |
| `web-white` | `watch` / `web_bypass` | **放行动作是 `web_bypass`**（Web 安全防护加白），不接受 block |
| `flow-rule` | `block` / `reject_response` / `watch` / `bot_check` / `network_block` | `reject_response` 拒绝响应（444）；`network_block` 网络封禁（action_value=秒数） |
| `flow-white` | `watch` / `flow_bypass` | **放行动作是 `flow_bypass`**（流量安全防护加白） |

未指定 `rule_action` 时 generate 默认 `watch`（观察优先红线）。

`bot_check` 的 `action_value`：`auto`（无交互验证）/ `slipper`（滑块）/ `puzzle`（拼图）/ `words`（选字），对齐节点 `unify_action.bot_check_ip`。

## rule_matchs 结构（核心）

JSON 字符串，数组元素结构：

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

### 多条件逻辑（引擎逐条短路，勿写反）

- **数组内多个 rule_match = AND**：每条都必须命中，任一条未命中则整体不匹配（引擎 break）
- **单条 rule_match 内多个 match_args = OR**：任一参数命中即该条命中（引擎 break）
- 同一条 rule_match 只有一组 `args_prepocess` / `match_operator` / `match_value`，对该条内所有 match_args 的取值依次生效

要表达「参数 A **且** 参数 B」必须拆成两个 rule_match（数组两个元素）；写在同一条的 match_args 里是「或」关系。

### match_args 的 key 与 value 语义（对齐引擎 request.get_args，顶层 11 个 key）

| key | value 语义 |
|---|---|
| `http_args` | **固定枚举 15 个**，见下表 |
| `header_args` | 任意头名（大小写不敏感，取第一个，上限 200 个）：预设 `host`/`cookie`/`referer`/`user_agent` 或自定义头名 |
| `cookie_args` / `uri_args` / `post_args` | 指定 Cookie/查询字符串/表单参数的**值**（上限 200 个） |
| `json_post_args` | JSON 请求体顶层字段值（**仅顶层字段，不支持 a.b.c 嵌套**；非 string 类型自动 cjson.encode） |
| `ctx_args` | 防护组件写入的 `ngx.ctx` 变量名 |
| `global_name_list_result` | **名单名**（与 name_list_name 一致；配合 `status_check` + `exist` 实现名单联动） |
| `string` | 常量值（引擎返回 `tostring(value)`，用于常量比较/全站统计维度） |
| `web_rule_protection_result` / `web_engine_protection_result` | 已执行的 Web 规则/引擎规则名（规则链联动，按执行顺序引用前面的规则结果） |

### http_args 的 value（15 个）

| value | 引擎返回 |
|---|---|
| `path` | `ngx.var.uri`（请求路径，不含 query string） |
| `query_string` | 完整查询字符串 |
| `method` | 请求方法 |
| `src_ip` | `ngx.ctx.src_ip`（组件可能已改写）或 `remote_addr` |
| `raw_body` | 内存中的请求体（**不触发 read_body**；文件型 body 返回 nil → 匹配不执行） |
| `version` / `scheme` | HTTP 版本 / http(s) |
| `raw_header` | 全部 header 排序后 JSON 编码（有缓存） |
| `raw_header_no_referer` | 同上但移除 referer 头（溯源检测场景） |
| `request_uri` | `ngx.var.request_uri`（含 query string 的完整 URI） |
| `host` / `user_agent` / `referer` / `cookie` | 对应请求头（cookie 为原始字符串） |
| `high_risk_header` | 仅 11 个高风险头的 JSON 编码：user-agent / x-forwarded-for / forwarded / cookie / referer / content-type / accept-language / authorization / x-real-ip / client-ip / true-client-ip |

### args_prepocess（数组按顺序执行，前一个输出是后一个输入）

`none` / `lowerCase` / `base64Decode`（失败返回原值）/ `length`（返回长度字符串）/ `uriDecode` / `uniDecode`（仅 `\u00NN` 0-255）/ `hexDecode`（仅 `\xNN`）/ `type`（返回值类型字符串）

未识别的预处理 key 返回 **nil**，会导致后续运算符收到 nil。

### match_operator（14 个）

| 类别 | 取值 |
|---|---|
| 字符串 | `str_contain`（plain 子串，非正则）/ `str_ncontain` / `str_eq`（tostring 全等）/ `str_neq` / `str_prefix` / `str_suffix` |
| 正则 | `rx`（`ngx.re.match`，选项 **oij**：编译缓存+**忽略大小写**+JIT） |
| 数字 | `gt` / `lt` / `eq` / `neq`（tonumber 转换，非数字不匹配） |
| 存在性 | `status_check`（match_value 为 `exist`/`no_exist`；**唯一允许参数为 nil 时执行的运算符**） |
| IP | `ip_in_cidr`（单个 CIDR，仅 IPv4）/ `ip_in_cidrs`（逗号分隔多 CIDR，仅 IPv4） |

**nil 传播规则**：参数取值为 nil 时运算符直接不执行（引擎跳过），该 match_arg 不命中——**漏报排查时优先怀疑这里**（如 raw_body 为 nil、预处理返回 nil、参数名写错）。

## 正则编写规范（rx 运算符）

WAF 规则每次请求都执行正则匹配，正则质量直接影响性能与稳定性（WAF 是业务关键路径）。编写 match_value 时必须遵守：

1. **能用字符串运算符就不用 rx**：str_contain/str_prefix/str_eq/str_suffix 比 regex 快 10-100 倍
2. **禁止嵌套量词（防 ReDoS）**：`(a+)+`、`(a*)*`、`(a|b)*` 会导致指数级回溯，攻击者可构造恶意输入打满 CPU
3. **避免 `.*` 滥用**：`.*foo` 会从每个位置尝试匹配。用具体字符类限定边界：`[^&]*foo`（参数内）、`[^\s]*foo`（单行内）
4. **非贪婪优先**：必须用通配时 `.*?` 优于 `.*`，更优的是具体字符类 `[^"]*`、`[^&]*`
5. **锚定范围**：用 `^` 锚定开头、`\b` 锚定单词边界，减少匹配尝试位置
6. **rx 已忽略大小写**（引擎选项含 i）：无需为大小写变体写 `[aA]` 字符类；`str_*` 运算符则大小写敏感，需要时加 `lowerCase` 预处理并把 match_value 写小写

| 避免 | 推荐 | 原因 |
|---|---|---|
| `.*admin.*` | `^/admin/[a-z]+$` | 贪婪+双 `.*`，高回溯+误报 |
| `union.*select` | `union[\s/\*]+select` | 限定分隔符，避免跨参数匹配 |
| `.+` | `[a-zA-Z0-9]+` | 明确字符集 |
| `(a\|b)*` | `[ab]*` | 字符类比交替快 |

## entity 结构（仅 flow-rule）

JSON 字符串，**扁平 `[{key, value}]` 数组**（引擎逐项取值后**无分隔符拼接**为统计键）：

```json
[{"key": "http_args", "value": "src_ip"}]
```

- key 取值同 match_args（`http_args` 固定枚举 / `header_args` 头名 / `string` 常量等）；`string` 常量用于全站维度统计
- 统计键结构：`"flow_rule_stat" + 各字段取值拼接`，存共享字典 `jxwaf_inner`，TTL=stat_time
- 处罚键结构：`"flow_rule_block" + src_ip`，TTL=block_time
- `exceed_count` 为**严格大于**（100 表示第 101 次请求触发）
- `filter="false"` 时对所有请求统计；`"true"` 时仅统计命中 rule_matchs 的请求

## 动作行为详解

| 动作 | 行为 |
|---|---|
| `block` | 设置 request_uuid 响应头，返回拦截页（默认 403，控制台可自定义） |
| `reject_response` | 流量规则/名单：`ngx.exit(444)` 直接关闭连接无响应；**Web 规则：与 block 一致（拦截页）** |
| `watch` | 仅记录日志不拦截 |
| `bot_check` | 人机识别（auto=无交互/slipper=滑块/puzzle=拼图/words=选字），通过后设 Cookie 86400 秒 |
| `network_block` | 网络层封禁 IP（POST 控制台 /network_block + 本地字典缓存），返回 444 |
| `web_bypass` / `flow_bypass` / `all_bypass` | 置跳过标志，跳过对应侧防护（名单/白名单动作） |

## 执行顺序（access 阶段，引擎实际链路）

```
access_init → base_component(组件) → global_name_list(名单) → domain_check → bot_commit_auth
→ flow_white_rule → flow_ip_region_block → flow_rule_protection → flow_engine_protection
→ web_white_rule → web_rule_protection → web_engine_protection → web_page_tamper_proof
→ custom_*（专业版自定义头/回源） → init_jxwaf_devid
```

- 每个子模块 pcall 包裹，失败仅记 ERR 日志不中断
- **组件最先执行**（可设 ngx.ctx 供后续规则 ctx_args 引用）；**名单先于所有规则**；**流量防护整体先于 Web 防护**；**白名单先于规则检测**
- 规则按 `rule_order_time` 升序执行（值越小越先执行，控制台置顶=当前最小值-1）
- 规则匹配后立即执行动作并终止（ngx.exit）

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
        "match_value": "union[\\s/\\*]+select|insert[\\s/\\*]+into|sleep\\("
      }
    ],
    "rule_action": "watch",
    "action_value": ""
  }
}
```

### 多条件 AND（路径前缀 且 参数包含）

```json
{
  "rule_matchs": [
    {"match_args": [{"key": "http_args", "value": "path"}], "args_prepocess": ["none"], "match_operator": "str_prefix", "match_value": "/api/"},
    {"match_args": [{"key": "uri_args", "value": "id"}, {"key": "post_args", "value": "id"}], "args_prepocess": ["none"], "match_operator": "str_contain", "match_value": "union"}
  ]
}
```

（第一条=路径前缀；第二条=GET 或 POST 参数包含 union；两条 AND）

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
    "entity": [{"key": "http_args", "value": "src_ip"}],
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

### Web 白名单（命中即放行 Web 防护）

```json
{
  "config": {
    "rule_name": "white_api_scanner",
    "rule_detail": "内部扫描器放行",
    "rule_matchs": [
      {
        "match_args": [{"key": "header_args", "value": "user_agent"}],
        "args_prepocess": ["none"],
        "match_operator": "str_prefix",
        "match_value": "InternalScanner/"
      }
    ],
    "rule_action": "web_bypass",
    "action_value": ""
  }
}
```

## 设计红线

1. **观察优先**：新增拦截类规则默认 `watch`；测试环境验证无误报（`verify` 报告正常用例全过）后再改 `block`
2. 每个规则的匹配条件要**具体**：优先针对确定的攻击载荷/POC 设计，避免宽泛正则导致误报
3. 正则遵守上文「正则编写规范」（禁嵌套量词、限字符类）；字符串精确比对用 `str_eq`/`str_contain`，性能更好
4. 名单联动时先创建名单、再建规则；名单删除会级联删除条目，依赖它的规则会失效（先处理规则）
5. 白名单类型的放行动作是 `web_bypass`/`flow_bypass`（不是 allow/pass）
6. 误报/漏报排查与调优见 [playbook.md](playbook.md)；实战案例见 [profiles.md](profiles.md)
