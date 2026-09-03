# 防护组件开发规范（component）

> 与节点引擎行为对齐（三版本引擎一致）。名单/网站接入等其余模块规范见 [module_dev.md](module_dev.md)，规则编写与名单联动见 [rule_dev.md](rule_dev.md)。

组件 = 自定义 Lua 检测代码，在 access 阶段**最先执行**（先于名单与所有规则），可独立完成检测与处置，也可设 `ngx.ctx` 变量与规则联动（规则用 `ctx_args` 引用）。

> **运行定位**：WAF 是业务流量关键基础设施，组件对**每个请求**执行，性能与稳定性直接影响业务可用性。组件卡顿/崩溃会阻断正常流量，必须遵守本文性能与稳定性红线。

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

**编码链路**：控制台服务端 create/edit 会校验 code 必须是合法 base64 且解码后可 loadstring；DB 中存 base64；节点 `/waf_update` 拿到后 `decode_base64 + loadstring` 编译执行。因此 **code 必须由调用方编码**（generate 已自动处理），明文直传会被服务端拒绝。

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
- **唯一参数**：`conf_data`（conf 字段 JSON 解码结果，table；由控制台 `/waf_update` 下发时预先解码，节点直接传入）；不传入 request 等对象，需自行 require
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

- **JXWAF 专用**：`resty.jxwaf.request`（取参，语义见下）、`resty.jxwaf.unify_action`（动作执行，见下节）、`resty.jxwaf.iputils`（IP/CIDR 判断，**禁止自行实现**，签名见下）
- **OpenResty**：`ngx.req.get_headers/get_uri_args/get_post_args`、`ngx.req.get_body_data/read_body`、`ngx.req.get_method/http_version`、`ngx.var.*`、`ngx.ctx`、`ngx.header.*`、`ngx.exit/ngx.say/ngx.log`、`ngx.shared.*`、`ngx.timer.at/every`
- **正则与编码**：`ngx.re.match/find/gsub/sub`（options 建议 `"oij"`）、`ngx.md5/hmac_sha1`、`ngx.encode_base64/decode_base64`、`cjson.safe.*`
- **Lua 标准库**：`string`/`table`/`math`/`os`、`require "bit"`

### resty.jxwaf.request 取参语义

组件内取请求参数统一用 `request.get_args(key, value)`，key/value 与规则 match_args 完全同一张表（完整枚举见 rule_dev.md）：

```lua
local request = require "resty.jxwaf.request"
local src_ip = request.get_args("http_args", "src_ip")
local id = request.get_args("uri_args", "id")
```

返回类型细节：

- 多值参数（同名 header/参数多次出现）只取**第一个**；不存在返回 nil
- `http_args:high_risk_header` 返回 **table**（11 个高风险头键值对），仅供组件内遍历，不要当字符串用
- `http_args:raw_body` 不触发 read_body，文件型 body 返回 nil
- `http_args:raw_header` / `raw_header_no_referer` 返回排序后的 JSON 编码字符串（引擎有缓存，可重复调用）

### resty.jxwaf.iputils 精确签名

```lua
local iputils = require "resty.jxwaf.iputils"

-- 输入 CIDR 字符串数组 → {{lower, upper}, ...}；纯 IP 自动按 /32 处理；
-- 无效条目跳过并记 ERR 日志（不中断）
local cidrs = iputils.parse_cidrs({"8.134.210.0/24", "61.174.128.69"})

-- ip 命中任一网段返回 true；未命中 false；ip 非法返回 nil
iputils.ip_in_cidrs(src_ip, cidrs)
```

**易错点（高危）**：`ip_in_cidrs` 第二参数**必须传 `parse_cidrs` 的返回值（table）**，传逗号分隔字符串会在 ipairs 处抛错，被引擎 pcall 捕获后**组件静默失效（每次请求报错放行）**。

规则运算符 `ip_in_cidr` / `ip_in_cidrs`（match_operator）由引擎内部实现（自带 split + parse），与组件侧 API 不同名不同参，不要混淆。

### ngx.ctx 引擎变量（组件可交互）

| 变量 | 读/写 | 说明 |
|---|---|---|
| `request_uuid` | 读 | 本次请求唯一 ID（拦截页 `{{request_uuid}}` 占位符同源），可用于日志关联 |
| `src_ip` | 读/写 | 当前源 IP；组件覆盖后，后续所有模块（规则/名单/统计/日志）取到新值（CDN 真实 IP 场景） |
| `iso_code` | 读 | GeoIP 国家码 |
| `group_name` | 读 | 当前域名所属分组（专业版） |
| `web_bypass` / `flow_bypass` | 写 | 置 true 跳过对应侧防护（等价白名单动作） |
| `waf_log` | 写 | SOC 日志上下文，调用 unify_action 前设置（见 waf_log 日志规范） |

### 执行防护动作（统一走 unify_action）

组件内执行动作的正确方式是**直接 require `resty.jxwaf.unify_action` 调用**（与引擎内置模块同款模式）。~~ngx.ctx.jxwaf_protection~~ 变量在引擎中**不存在**，不要使用。

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
- `bot_check` 通过后签发 Cookie `jxwaf_bot_check`（86400 秒），密钥绑定 waf_auth + UA + SSL 指纹：更换 UA 或 SSL 指纹需重新完成质询；持有有效 Cookie 的请求 `bot_check_ip` 直接放行（不再出质询页）
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