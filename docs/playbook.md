# 运维 Playbook（误报/漏报排查与调优）

> 配置下发后的排查调优手册。验证执行流程见 [verify.md](verify.md)，字段规范见 [rule_dev.md](rule_dev.md) / [module_dev.md](module_dev.md)，组件开发与排查见 [component_dev.md](component_dev.md)。

## 误报处理

### 第一步：定位拦截来源（SOC 日志 waf_module 字段）

| waf_module | 来源 | 排查方向 |
|---|---|---|
| `web_rule_protection` | Web 防护规则 | 查 waf_policy 中的规则名 → rule_matchs |
| `flow_rule_protection` | 流量防护规则 | 阈值/统计窗口/entity 维度 |
| `flow_engine_protection` | 流量引擎防护 | ip_access_limit / ip_count_limit / domain_access_limit / ssl_fingerprint / emergency |
| `web_engine_protection` | Web 引擎防护（AI+语义分析） | 看 waf_extra 中的 token_hash |
| `base_component` | 防护组件 | 组件 conf 阈值与检测逻辑 |
| `name_list` | 名单误封 | 条目来源与过期时间 |

查询命令：

```
jxwaf-cli soc log query --params '{"from_time":"...","to_time":"...","page":1,
  "sql_rules":[{"field":"waf_policy","operation":"contains","value":"<规则名>"}]}'
```

### 第二步：处置（按影响程度）

```
确认误报（waf_module 定位）
  ├── 紧急止血 → rule_action 改 watch 或 status=false（影响所有 IP）
  ├── 误报面小 → 加白名单放行特定流量（web-white / flow-white，仅放行该范围）
  └── 根因修复（见下）
```

### Web 规则误报 SOP

```
waf_module=web_rule_protection
  ├── match_value 过宽？ → 收窄（str_contain 改 str_eq / 加锚定 ^ / 限定 path）
  ├── 大小写问题？ → rx 已忽略大小写；str_* 加 lowerCase 预处理 + match_value 小写
  ├── 编码变体误命中？ → 检查 args_prepocess 是否该去掉（过度解码）
  └── 修复后 verify 复现确认放行
```

### 流量规则误报 SOP

```
waf_module=flow_rule_protection
  ├── exceed_count 过低？ → 提高阈值（不低于峰值 QPS × 2）
  ├── stat_time 过短？ → 延长窗口
  ├── block_time 过长？ → 缩短处罚
  ├── entity 维度不当？ → 增加 path 维度（src_ip + path 双维度，避免不同接口互相影响）
  └── 特定 IP 放行 → flow-white（rule_action=flow_bypass）
```

### Web 引擎误报 SOP

```
waf_module=web_engine_protection
  ├── 紧急 → 切换 protection_mode 为 business_priority（业务优先）
  ├── 语义分析误判 → learn 模式学习
  ├── AI 模型误判 → 等待模型蒸馏自动修正
  └── 特定接口放行 → web-white
```

### 组件误报 SOP

看 waf_extra 中组件记录的触发变量（path/count/src_ip）→ 调整组件 conf 阈值（如 ip_request_threshold）→ 重新下发。

## 漏报排查

```
确认漏报（攻击流量 waf_action=pass）
  ├── 请求经过 WAF？ → SOC 日志有记录（无记录=流量未走节点，查 DNS/回源）
  ├── 被白名单 bypass？ → waf_action 含 bypass，检查 web_bypass/flow_bypass 标志
  ├── 被名单 bypass？ → all_bypass/web_bypass/flow_bypass 名单
  ├── 规则启用？ → status="true"（jxwaf-cli rule web list 查）
  └── 匹配条件未命中（最常见）：
        ├── match_args key/value 取错（参数名/路径/大小写）
        ├── 取值为 nil → 运算符直接跳过（raw_body 文件型返回 nil；预处理 key 拼错返回 nil）
        ├── 编码未解码 → 加 uriDecode/base64Decode/uniDecode/hexDecode
        ├── json_post_args 只支持顶层字段（不支持 a.b.c 嵌套）
        ├── rx 已忽略大小写（不需要大小写变体）
        └── 流量规则：filter 配置错误或未达阈值（严格大于 exceed_count）
```

## 规则调优原则

### Web 防护规则

1. 精确匹配优先：str_eq > str_contain，str_prefix > rx（正则慢 10-100 倍）
2. 字符串运算符大小写敏感：关键字匹配加 `lowerCase` 预处理，match_value 统一小写
3. 多层解码按需叠加：uriDecode / base64Decode / uniDecode / hexDecode（攻击载荷常见混淆）
4. 观察先行：新规则先 watch，SOC 日志观察无误报后改 block
5. raw_body 限制：仅返回内存中 body，大 body（文件上传）可能为 nil → 用 post_args/json_post_args 替代

### 流量防护规则

1. entity 维度选择：

| 场景 | entity | 说明 |
|---|---|---|
| 全局限速 | src_ip 单维度 | 所有接口合并计数 |
| 接口限速 | src_ip + path 双维度 | 避免不同接口互相影响 |
| 会话限速 | cookie_args:session_id | 按会话而非 IP |

2. 阈值：`exceed_count` = 峰值 QPS × 2-3（严格大于才触发）
3. `stat_time` 建议 10-60 秒
4. 处罚方式选择：

| 场景 | 动作 | 理由 |
|---|---|---|
| 一般 CC | `bot_check`（auto） | 人机识别对正常用户无感，仅拦自动化工具 |
| 恶意攻击 | `block` 或 `network_block` | 直接阻断/网络层封禁 |
| 紧急防护 | `reject_response` | 444 关闭连接，节省带宽 |

### 日 PV 级别与限速建议（单 IP 请求/60s 起点）

| 日 PV | 单 IP 请求/60s | 独立 IP 数/60s | 域名总请求/60s | 阻断时长 |
|---|---|---|---|---|
| ~1 万 | 50~100 | 50~100 | 1,000~3,000 | 600s |
| ~10 万 | 200~500 | 200~500 | 5,000~10,000 | 600s |
| ~100 万 | 600~1,500 | 1,500~3,000 | 30,000~60,000 | 300~600s |
| ~1000 万 | 2,000~5,000 | 10,000~20,000 | 200,000~400,000 | 120~300s |

（以此为起点，按业务实际峰值微调；共用出口 IP 的企业用户需放宽单 IP 阈值）

### 流量引擎预案参考值（专业版，web 引擎侧）

| 预案 | IP访问限制 | IP数量限制 | 域名访问限制 | SSL指纹 | 紧急防护 |
|---|---|---|---|---|---|
| daily_observe（日常观察） | 1000/60s, watch | 1000/60s, watch | 100000/60s, watch | 关 | 关 |
| daily_protect（日常防护） | 1000/60s, bot_check(auto) | 1000/60s, bot_check | 100000/60s, bot_check | 关 | 关 |
| attack_protect（攻击防护） | 500/60s, bot_check(slipper) | 500/60s, bot_check | 50000/60s, bot_check | 开 | 关 |
| emergency_protect（紧急防护） | 100/60s, bot_check(words) | 100/60s, bot_check | 10000/60s, bot_check | 开 | 开 |

## 组件加载失败排查

现象：组件下发后节点报 `can not decode component_data`，组件未执行。

根因：code 不是合法 base64、或解码后含 LuaJIT 不支持的 Lua 5.2+ 语法，loadstring 编译失败。

排查顺序（对齐引擎源码 `decode_base64 → loadstring → 执行返回 table` 链路）：

1. code 是否 base64 编码（`generate` 已自动处理；手拼 API 时易漏）
2. Lua 5.2+ 语法（完整对照表见 component_dev.md：`& | ~ >> << // goto` 等）
3. 括号/引号匹配、loadstring 语法错误
4. 组件必须 `return _M` 且含 `check` 函数（loadstring 执行后返回 table 才会被注册）

常见报错 → 替代：

| 错误现象 | 原因 | 替代 |
|---|---|---|
| unexpected symbol near '&' | 按位与 | `bit.band(a, b)` |
| unexpected symbol near '\|' | 按位或 | `bit.bor(a, b)` |
| unexpected symbol near '~' | 异或/非 | `bit.bxor` / `bit.bnot` |
| unexpected symbol near '>' | 右移 >> | `bit.rshift(a, n)` |
| unexpected symbol near '<' | 左移 << | `bit.lshift(a, n)` |
| '// ' expected | 整数除法 | `math.floor(a / b)` |
| no visible label | goto | 重构为循环 |

## 防护能力边界

- **覆盖良好**（检出率 95%+）：SQL 注入、XSS、文件包含、目录遍历、文件上传、SSTI、XXE、SSI、XPath、XSLT、反序列化（Java/PHP/.NET/Python/NodeJS/Ruby）、WAF 绕过变体
- **薄弱点**：GraphQL 注入（检出率低）。涉及 GraphQL 场景需定制：自定义防护组件检测查询结构 + Web 规则匹配 `json_post_args:query` 中的恶意 payload

## 紧急解封（按封禁层次）

| 封禁层次 | 解封方式 | 影响面 |
|---|---|---|
| 规则误拦 | 临时 status="false" 或 rule_action=watch | 所有 IP |
| 名单误封 | 删除名单条目，或加 flow_bypass 名单放行该 IP | 仅该 IP |
| 网络层封禁 | SOC → 网络封禁 IP 名单中删除或加白 | 仅该 IP |
| 流量处罚缓存 | 等待 block_time 过期自动解封 | 仅该 IP |

处置顺序：先确认误报根因（waf_module），止血（bypass 该 IP）→ 根因修复（收窄规则/调阈值）→ 恢复。

## 性能参考（单节点 4 核 8G）

| 防护状态 | HTTP | HTTPS |
|---|---|---|
| 纯转发 | 48K QPS | 30K QPS |
| Web 防护引擎开启 | 31K（↓35%） | 21K（↓30%） |
| 全防护开启 | 18K（↓62%） | 13K（↓56%） |

- 配置同步间隔 3 秒（下发后等约 3-5 秒再验证）
- 节点心跳异常阈值 10 分钟
- 自定义组件叠加会进一步损耗（组件每请求执行，遵守 [component_dev.md](component_dev.md) 性能红线）
