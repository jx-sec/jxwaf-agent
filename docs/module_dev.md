# 名单 / 组件 / 网站接入规范

> 字段与枚举已对齐 jxwaf_admin_server 控制台源码与 jxwaf_node 节点引擎（三版本引擎一致）。

## 一、名单防护（name-list）

### 字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `name_list_name` | string | 名单名（唯一） |
| `name_list_detail` | string | 描述 |
| `name_list_rule` | string | 名单规则（JSON 字符串，**扁平 `[{key, value}]` 数组**，结构见下） |
| `name_list_action` | string | 命中处置动作（枚举见下表） |
| `action_value` | string | 动作值：`bot_check` 时为人机识别方式；`network_block` 时为封禁秒数；其余为空 |
| `name_list_expire` | string | 条目是否自动过期 `"true"`/`"false"` |
| `name_list_expire_time` | string | 过期秒数（expire=true 时必填，正整数） |

### name_list_rule 结构（与 rule_matchs 不同！）

**扁平 `[{key, value}]` 数组**——引擎逐项取值后**无分隔符拼接**为条目查找键（如 `src_ip` + `host` 拼成 `1.1.1.1www.test.com`），在条目哈希表中做**纯等值查找**（无前缀/正则/范围匹配）：

```json
[{"key": "http_args", "value": "src_ip"}]
```

| key | value 语义 |
|---|---|
| `http_args` | 固定枚举（同 rule_dev.md 的 15 个：`path`/`query_string`/`method`/`src_ip`/`host`/`user_agent`/`cookie`/`referer`/`raw_header`/`high_risk_header` 等） |
| `header_args` | 任意头名（`host`/`cookie`/`referer`/`user_agent`/自定义） |
| `cookie_args` / `uri_args` / `post_args` / `json_post_args` / `ctx_args` | 自定义参数名 |

例：IP 名单用 `[{"key":"http_args","value":"src_ip"}]`，条目为 IP 值；UA 名单用 `[{"key":"header_args","value":"user_agent"}]`。

**拼接限制**：任一项取值为 nil/table 则放弃本次查找（仅接受 string/number/boolean）；多字段拼接时注意歧义（`1.1.1.1` + `www.a.com` 与 `1.1.1.1www.a.com` 其他拆分组合可能碰撞）。

### name_list_action 枚举

| 动作 | 说明 |
|---|---|
| `block` | 阻断请求 |
| `reject_response` | 拒绝响应（444 关闭连接） |
| `watch` | 观察模式（仅记录日志） |
| `bot_check` | 人机识别（action_value：`auto`/`slipper`/`puzzle`/`words`） |
| `network_block` | 网络封禁（action_value=封禁秒数） |
| `all_bypass` | **放行**：Web+流量安全防护全加白 |
| `web_bypass` | **放行**：仅 Web 安全防护加白 |
| `flow_bypass` | **放行**：仅流量安全防护加白 |

条目操作（无需 generate，直接写入命令）：

```
jxwaf-cli namelist item-add --params '{"name_list_name":"malicious_ip","name_list_item":"1.2.3.4"}' --apply
jxwaf-cli namelist item-del --params '{"name_list_name":"malicious_ip","name_list_item":"1.2.3.4"}' --apply
```

- 条目已存在时 item-add 仅刷新过期时间（幂等）；条目过期时间从父名单的 expire/expire_time 继承计算
- 删除名单级联删除其所有条目

### 使用模式

- **直接封禁/放行**：名单 action 直接处置，无需规则（执行先于所有规则，纯哈希查找，性能最好）
- **标记+规则处置**：名单 action=watch，规则用 `global_name_list_result` 引用名单名（`status_check exist`）决定最终动作（见 rule_dev.md 名单联动示例）
- 临时封禁场景必须 `name_list_expire="true"` + 过期时间，避免条目永久残留

## 二、防护组件（component）

组件 = 自定义 Lua 检测代码，在 access 阶段**最先执行**（先于名单与所有规则），可独立完成检测与处置，也可设 `ngx.ctx` 变量与规则联动（规则用 `ctx_args` 引用）。

> **运行定位**：WAF 是业务流量关键基础设施，组件对**每个请求**执行，性能与稳定性直接影响业务可用性。组件卡顿/崩溃会阻断正常流量，必须遵守本节性能与稳定性红线。

### 字段与生成方式

```
jxwaf-cli generate component --params '{"config":{"name":"...","detail":"...","code":"<Lua源码>","conf":"{}"}}'
```

| 字段 | 说明 |
|---|---|
| `name` | 组件名（唯一） |
| `detail` | 描述 |
| `code` | Lua 源码（generate 自动 base64 编码）或 `code_base64`（已编码，二选一） |
| `conf` | 组件配置（JSON 字符串，按组件协议约定） |

**编码链路（已对齐源码）**：控制台服务端 create/edit 会校验 code 必须是合法 base64 且解码后可 loadstring；DB 中存 base64；节点 `/waf_update` 拿到后 `decode_base64 + loadstring` 编译执行。因此 **code 必须由调用方编码**（generate 已自动处理），明文直传会被服务端拒绝。

### 代码模板

```lua
local request = require "resty.jxwaf.request"
local unify_action = require "resty.jxwaf.unify_action"

local _M = {}

function _M.check(conf_data)
    if conf_data == nil then
        return
    end
    -- 检测逻辑
    -- 独立完成：调用 unify_action 执行动作
    -- 联合判断：ngx.ctx.<var> = <value>（后续规则用 ctx_args 引用）
    -- 放行流量：ngx.ctx.web_bypass = true 或 ngx.ctx.flow_bypass = true
    return
end

return _M
```

### check 函数签名（引擎调用方式）

- 节点调用：`pcall(_waf_component_code[name].check, component_conf)`，**每请求执行一次**
- **唯一参数**：`conf_data`（conf 字段 JSON 解码结果，table）；不传入 request 等对象，需自行 require
- 返回值引擎不使用（专业版/云版忽略；不要依赖返回值传递结果，用 `ngx.ctx`）
- 节点对每个组件单独 pcall，异常仅记 ERR 日志，不影响其他组件与后续链路（fail-safe）

### 配置读取最佳实践

conf_data 从 JSON 解码而来，数值字段可能是 string 或 number，读取时必须 tonumber 转换并带默认值：

```lua
local stat_time = 60  -- 默认值
if conf_data then
    stat_time = tonumber(conf_data["stat_time"]) or stat_time
end
```

- 不要直接 `conf_data.stat_time or 60`（JSON 解码后 "60" 可能是 string，无法用于数值比较）
- 字符串字段需 type 校验：`if type(conf_data["bot_check_type"]) == "string" then ...`

### LuaJIT 兼容（最高频踩坑点）

运行环境：OpenResty 1.29.2.3 + LuaJIT 2.1（基于 Lua 5.1），不支持 Lua 5.2+ 语法。使用不兼容语法会导致组件加载失败，节点报 `can not decode component_data`。**generate 会做静态校验拦截，以 CLI 报错为准。**

| 禁止（Lua 5.2+） | 替代（LuaJIT 兼容） |
|---|---|
| `a & b` / `a \| b` / `a ~ b` / `~a` | `bit.band` / `bit.bor` / `bit.bxor` / `bit.bnot`（需 `local bit = require "bit"`） |
| `a >> n` / `a << n` | `bit.rshift(a, n)` / `bit.lshift(a, n)` |
| `a // b` | `math.floor(a / b)` |
| `goto label` / `::label::` | 重构为循环/函数 |
| `continue`（for 内跳过） | `do break end`… 或 if/else 包裹 |
| `1LL`/`1ULL` 64位整数字面量 | 直接用 number |
| `string.pack`/`string.unpack` | 手动拼接字节 |
| `table.move` | for 循环复制 |
| `math.tointeger` | `type(x)=="number" and x==math.floor(x)` |
| `utf8.char`/`utf8.codepoint` | Lua 5.3+ 库，不可用 |

注意：`~=`（不等比较）是合法 LuaJIT 语法，不会被误杀。

### 共享字典 ngx.shared.jxwaf_user

组件专用的共享字典（所有组件共用，引擎自身零占用），用于跨请求状态共享（计数/缓存/标记）。**禁止使用 `jxwaf_inner`**（WAF 内部字典：流量统计/处罚/网络封禁/AI 分析，组件写入会污染引擎内部状态）；**禁止写入 `waf_conf_data`**（配置缓存）。

**key 命名规范**：`<project>_<purpose>|<key>`（前缀必须拼项目名，避免与其他组件冲突；各段建议用 `|` 分隔避免拼接歧义）。

| 方法 | 说明 |
|---|---|
| `get(key)` / `set(key, value, ttl)` | 读 / 写（ttl 秒，0 永不过期） |
| `add(key, value, ttl)` | **原子写：仅 key 不存在时写入**。返回 true=首次写入，false=已存在。「每 IP/窗口仅触发一次」场景必须用它判断返回值，**不要 get+set（有竞态）** |
| `incr(key, value, init, ttl)` | 原子递增（**ttl 仅首次创建生效，后续 incr 不刷新 → 天然固定窗口**） |
| `expire(key, ttl)` / `delete(key)` | 设过期 / 删除 |

**统计/计数必须用固定窗口**：`incr` 的 init+ttl 已实现固定窗口语义（窗口到期自动归零）。**禁止对统计 key 额外调用 `expire` 刷新 TTL**——否则退化为滑动窗口，TTL 被不断刷新导致累积周期远超设定窗口，合法用户短暂突发会逐步累积到阈值造成误拦截。需要滑动窗口语义时自行记录时间戳实现。

其他约束：所有写入必须带 TTL（防内存无限增长 worker OOM）；value 只能 string/number/boolean（table 需 cjson.encode）。

### 可用 API

- **JXWAF 专用**：`resty.jxwaf.request`（请求参数 get_args）、`resty.jxwaf.unify_action`（动作执行）、`resty.jxwaf.iputils`（`ip_in_cidr`/`ip_in_cidrs`，**IP/CIDR 判断禁止自行实现**）
- **OpenResty**：`ngx.req.get_headers/get_uri_args/get_post_args`、`ngx.req.get_body_data/read_body`、`ngx.req.get_method/http_version`、`ngx.var.*`、`ngx.ctx`、`ngx.header.*`、`ngx.exit/ngx.say/ngx.log`、`ngx.shared.*`、`ngx.timer.at/every`
- **正则与编码**：`ngx.re.match/find/gsub/sub`（options 建议 `"oij"`）、`ngx.md5/hmac_sha1`、`ngx.encode_base64/decode_base64`、`cjson.safe.*`
- **Lua 标准库**：`string`/`table`/`math`/`os`、`require "bit"`

### 执行防护动作（统一走 unify_action）

**已对齐引擎源码**：组件内执行动作的正确方式是**直接 require `resty.jxwaf.unify_action` 调用**（与引擎内置模块同款模式）。~~ngx.ctx.jxwaf_protection~~ 变量在引擎中**不存在**，不要使用。

```lua
local unify_action = require "resty.jxwaf.unify_action"

-- 阻断（page_conf 可选：{code=403, html="<html>...{{request_uuid}}...</html>"}，缺省用默认拦截页）
unify_action.block({code = 403, html = "<html>blocked</html>"})

-- 拒绝响应（444 关闭连接）
unify_action.reject_response()

-- 人机识别（必须先提交认证上下文，否则静默失效）
unify_action.bot_commit_auth()
unify_action.bot_check_ip("slipper")   -- auto/slipper/puzzle/words

-- 网络封禁（expire_time 秒数，缺省/<=0 直接不执行）
unify_action.network_block(config_info, src_ip, expire_time)
```

注意事项：

- `block()` 内部 `ngx.exit` 终结请求；check 被 pcall 包裹，ngx.exit 会被 pcall 捕获产生一条 ERR 日志（`component_protection error ... lua exited`）属**正常现象**，请求仍按该状态码终结
- `bot_check_ip` 前必须先调 `bot_commit_auth()`，否则人机识别上下文缺失，防护静默失效
- 正常路径不要 ngx.exit（fail-safe：组件出错/未命中应放行）

### waf_log 日志规范

组件执行动作时，应在调用 unify_action **之前**设置 `ngx.ctx.waf_log`，便于 SOC 审计追溯：

```lua
ngx.ctx.waf_log = {
    waf_module = "base_component",
    waf_policy = "防护组件-<组件名>",
    waf_action = "block",  -- block/reject_response/bot_check/network_block
    waf_extra = "cc_attack_triggered path=" .. path .. " count=" .. tostring(count),
}
```

waf_extra 记录触发关键变量（path/count/src_ip 等），误报排查时直接看这里。

### 开发风格与性能红线（必须遵守）

1. **简洁优先**：一个组件只解决一个问题；辅助函数内联在组件文件内，不抽公共库
2. **require 置顶**：所有 require 放模块顶层（`local _M = {}` 之前），**禁止放 check 函数内**——顶层 per-worker 只执行一次，函数内每次请求都有调用开销
3. **禁止外部 IO**：禁止 cosocket 外部 HTTP 调用、禁止文件 IO、禁止长循环阻塞。组件每请求执行，任何阻塞随 QPS 放大千倍直接拖垮业务
4. **轻量计算**：正则用 ngx.re + "oij"（编译缓存）；避免每请求大字符串拼接、深层 table 遍历
5. **原子操作优先**：统计/标记用 add/incr，不要 get+set（竞态+两次字典访问）
6. **fail-safe**：只在确定拦截时才调 unify_action；组件出错放行（pcall 兜底，异常仅记日志）
7. **最小依赖**：只用必要模块；WAF 内置库（resty.jxwaf.*）优先，禁止重造轮子
8. 组件内**无需 pcall**（节点已包裹）；无需读配置缓存（conf_data 由引擎传入）

### 加载失败排查

节点 error.log 出现 `can not decode component_data` 时按序排查：
1. code 是否 base64（generate 已处理；手拼 API 时易漏）
2. Lua 5.2+ 语法（`& | ~ >> << // goto` 等，见上表）
3. 括号/引号匹配、loadstring 语法错误

## 三、网站接入（website / domain）

### 域名创建字段（generate domain）

| 字段 | 说明 |
|---|---|
| `domain` | 域名 |
| `detail` | 域名描述（必填） |
| `http` / `https` | `"true"`/`"false"`（不能同时为 false） |
| `ssl_domain` | 关联 SSL 证书域名（HTTPS 时必填非空，需先在证书管理创建证书；http-only 时输出空串占位） |
| `source_ip` | 回源地址数组（必填；IP 或域名，域名自动 DNS 解析） |
| `source_http_port` / `source_https_port` | 回源端口（正整数，默认 80/443；https 未显式指定时 **443**，不允许留空） |
| `origin_protocol` | `http`/`https`/`follow` |
| `balance_type` | `round_robin`/`ip_hash` |
| `pre_proxy` | 前置代理 `"true"`/`"false"` |
| `real_ip_conf` | 真实 IP 头：`XRI`（X-Real-IP）/`XFF` |
| `connect_timeout` / `send_timeout` / `read_timeout` | 超时（秒，正整数） |

租户参数自动注入：专业版自动带 `group_name`，云WAF 主账号自动带 `sub_user_name`（域名类虽路径无中缀但 body 必带），无需手写。

### 接入流程（云WAF）

1. 查询网站接入配置：`jxwaf-cli website access list`（admin）或直接创建域名
2. `generate domain` 生成 → `apply --apply` 创建；创建后控制台/DNS 平台配置 CNAME 指向返回的 `cname`
3. 证书与域名必须匹配（HTTPS 时）

### 安全的删除顺序

删除域名前先处理依赖：规则/白名单关联该域名会失效。测试环境闭环：防护配置 → verify → cleanup 清理测试规则 → 域名如需清理最后删。

## 四、网页防篡改（tamper）

走 `jxwaf-cli tamper create --params '{...}'` 直接下发（字段与服务端 check_param 一致）：

| 字段 | 说明 |
|---|---|
| `rule_name` | 规则名（唯一，删除/启停/查询的主键） |
| `rule_detail` | 规则描述 |
| `rule_matchs` | 匹配条件数组（结构同 Web 规则 rule_matchs） |
| `cache_page_url` | 被防护页面的 URL |
| `cache_page_content` | 页面缓存内容（防篡改基线） |
| `cache_content_type` | 内容类型 |

启停：`{"rule_name":"x","status":"true"|"false"}`。命中动作固定为 `page_tamper_proof`（返回缓存基线页面）。

## 五、SSL 证书（ssl）

走 `jxwaf-cli ssl create --params '{...}'`（标准版/专业版为全局模块，云WAF 归属子账号自动注入 `sub_user_name`）：

| 字段 | 说明 |
|---|---|
| `ssl_domain` | 证书域名（唯一，查询/删除主键） |
| `detail` | 描述（必填） |
| `private_key` | PEM 私钥内容 |
| `public_key` | PEM 证书内容 |

注意：私钥属于敏感材料，params 文件放 `/tmp` 或 `output/`（已 gitignore），勿提交仓库；域名 HTTPS 接入前需先创建匹配的证书。泛域名证书自动签发（request_wildcard_cert）为控制台/异步任务流，CLI 暂不覆盖。

## 六、域名组（group，仅专业版）

| 字段 | 说明 |
|---|---|
| `group_name` | 组名（唯一；创建组会自动初始化该组的引擎防护/区域封禁配置） |
| `group_detail` | 组描述（edit 仅可改此字段） |

删除域名组会**级联删除组下所有域名与防护配置**，务必先确认影响范围。专业版创建域名前必须先建域名组（CLI `--group` / 环境默认 `group_name` 引用）。

## 七、自定义配置（custom；标准版不支持）

四类模块同构（`custom request-header|response-header|response-content|upstream`），租户参数自动注入：

| 模块 | create/edit 必填字段 |
|---|---|
| request-header | `rule_name` / `rule_detail` / `rule_matchs` / `filter` / `header_name` / `header_value` |
| response-header | 同 request-header |
| response-content | `rule_name` / `rule_detail` / `rule_matchs` / `filter` / `content_type` / `return_code` / `return_content` |
| upstream | `rule_name` / `rule_detail` / `rule_matchs` / `filter` / `source_ip` / `source_http_port` / `source_https_port` |

`filter` 为生效范围（如 `web`），`rule_matchs` 结构同 Web 规则。专业版归域名组、云WAF归子账号。

## 八、缓存管理（cache；仅云WAF）

| 模块 | create 必填字段 |
|---|---|
| policy（缓存策略） | `rule_name` / `rule_detail` / `rule_matchs` / `cache_key` |
| no-cache（不缓存） | `rule_name` / `rule_detail` / `rule_matchs` |
| bypass（缓存绕过） | `rule_name` / `rule_detail` / `rule_matchs` |

缓存任务（warmup/refresh）：create/list/detail/delete；CDN 预热/刷新与缓存开关仅子账号模式（`cache cdn preheat|refresh --params '{"urls":"..."}'`，最多 100 个 URL）。

## 九、运维模块

### 网络封禁（network，三版本）
- 封禁：`network create --params '{"ip":"1.2.3.4","status":"1","expire_time":3600}'`（status：1 封禁 / 2 解封；expire_time 单位秒）
- 解封：`edit` 改 status=2；总开关：`status`（查询）/ `status-set`（block|closed）
- 应急场景：确认攻击 IP 后可直接 block（经用户确认）

### 子账号（subaccount，仅云WAF主账号）
- create：`{"sub_user_name":"x","user_password":"...","sub_otp_auth":"true|false","website_access_conf":"接入配置名"}`（自动初始化防护配置）
- `waf-auth` 重置子账号凭据（旧值立即失效）；`otp-reset` 重置 OTP（返回新密钥）
- delete 级联删除 17 张关联表并清理云 DNS A 记录

### 系统配置（sysconf，标准版不支持）
- `log`：日志远程/调试开关与日志服务器地址
- `report`：ClickHouse 连接配置（SOC 统计的数据源前置）；`report test` 验证连通性
- `page`：自定义拦截页/404 页（HTML 内容）
- `backup`/`load`：整库备份/恢复（load 高危：先清空后覆盖，务必 dry-run 确认）

### SOC 查询（soc，三版本）
- 统计/事件/用量类参数：`from_time`/`to_time`（YYYY-MM-DD HH:MM:SS 必填），可选 `domain`（`*.` 前缀通配）
- 误报处理闭环：`soc model list` 查 AI 判定记录 → `soc model result` 标记误报 → `soc model white-add` 加 Token 白名单
