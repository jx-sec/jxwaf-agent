---
name: component_dev
description: 防护组件开发规范 - LuaJIT 兼容性、check 函数签名、共享字典使用、unify_action 调用方式
---

# 防护组件开发规范

## 代码模板
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
    -- 联合判断：ngx.ctx.<var> = <value>
    -- 放行流量：ngx.ctx.web_bypass = true 或 ngx.ctx.flow_bypass = true
    return
end

return _M
```

## check 函数签名
- 节点调用：`pcall(_waf_component_code[name].check, component_conf)`
- **唯一参数**：conf_data（conf 字段 JSON 解码结果）
- **不传入** request/operator/preprocess/ctx 等对象，需自行 require
- **不传入** ngx.ctx，但可直接访问 ngx.ctx
- 返回值无要求（节点不使用返回值）

## 配置读取最佳实践
conf_data 从 JSON 解码而来，数值字段可能是 string 或 number，读取时必须 tonumber 转换并带默认值：
```lua
local stat_time = 60  -- 默认值
if conf_data then
    stat_time = tonumber(conf_data["stat_time"]) or stat_time
end
```
- 不要直接 `conf_data.stat_time or 60`（JSON 解码后 "60" 可能是 string，无法用于数值比较）
- 字符串字段需 type 校验：`if type(conf_data["bot_check_type"]) == "string" then ...`

## LuaJIT 兼容性（最高频踩坑点）
运行环境：OpenResty 1.29.2.3 + LuaJIT 2.1（基于 Lua 5.1），不支持 Lua 5.2+ 语法。
使用不兼容语法会导致组件加载失败，节点报 "can not decode component_data"。

### 位运算符（禁止 → 替代）
| 禁止（Lua 5.2+） | 替代（LuaJIT 兼容） |
|------------------|---------------------|
| a & b | bit.band(a, b) |
| a \| b | bit.bor(a, b) |
| a ~ b | bit.bxor(a, b) |
| ~a | bit.bnot(a) |
| a >> n | bit.rshift(a, n) |
| a << n | bit.lshift(a, n) |
| a &= b | a = bit.band(a, b) |
| a // b | math.floor(a / b) |

使用前需声明：`local bit = require "bit"`

### 控制流语法
| 禁止 | 替代 |
|------|------|
| goto label | 重构为循环/函数 |
| ::label:: | 同上 |
| continue | do break end（在 for 循环内） |

### 其他禁止
- 整数除法 //（用 math.floor(a/b)）
- 64位整数字面量 1LL/1ULL（直接用 number）
- string.pack / string.unpack（手动拼接字节）
- table.move（手动 for 循环复制）
- math.tointeger（用 type(x)=="number" and x==math.floor(x)）
- utf8.char / utf8.codepoint（Lua 5.3+ 的 utf8 库）
- 复合赋值 <<= >>= |= &=

## 共享字典 ngx.shared.jxwaf_user
组件专用的共享字典（所有组件共用），用于跨请求状态共享（如计数、缓存、标记）。

> **重要**：组件必须使用 `jxwaf_user`，**禁止使用 `jxwaf_inner`**（后者是 WAF 内部字典，用于流量统计/处罚/网络封禁，组件写入会与 WAF 内部 key 冲突）。
> WAF 内部 jxwaf_inner 使用的 key 前缀：`flow_rule_stat`、`flow_rule_block`、`network_block`、`ai_analysis`

### key 命名规范
```
<project_name>_<purpose>|<key>
```
示例：`"cc_attack_defense_freq|" .. path .. "|" .. src_ip`、`"api_test_count_" .. src_ip`

> 建议 key 各部分用 `|` 分隔（而非 `_`），避免拼接歧义（如 src_ip 含 `_` 时与分隔符混淆）。

### 常用 API
| 方法 | 说明 |
|------|------|
| get(key) | 读取值 |
| set(key, value, ttl) | 写入值（ttl 秒，0 为永不过期） |
| **add(key, value, ttl)** | **原子写入：仅当 key 不存在时写入，返回 true 表示首次写入成功，false 表示已存在。用于"首次标记"场景避免竞态** |
| incr(key, value, init, ttl) | 原子递增（init 为初始值，**ttl 仅在 key 首次创建时生效，后续 incr 不刷新 ttl → 天然固定窗口**） |
| expire(key, ttl) | 设置过期时间 |
| delete(key) | 删除 |

### 注意事项
1. key 前缀必须拼接项目名，避免与其他组件冲突
2. 必须 set TTL，避免内存无限增长
3. value 只能是 string/number/boolean，存储 table 需 cjson.encode
4. 禁止写入 waf_conf_data（配置缓存字典）
5. 禁止使用 jxwaf_inner（WAF 内部字典）
6. "每 IP/每窗口仅触发一次"场景，必须用 `add` 原子操作判断返回值，不要用 `get`+`set`（有竞态条件）
7. **统计/计数场景用固定窗口，禁止 expire 刷新**：`incr` 的 init+ttl 已实现固定窗口语义（窗口到期自动归零重置）。**禁止对统计 key 额外调用 `expire` 刷新 TTL**，否则固定窗口退化为滑动窗口——TTL 被不断刷新导致累积周期远超设定窗口，合法流量（如不同用户短暂突发）会逐步累积到阈值误拦截。需要滑动窗口语义时应自行记录时间戳列表实现，不要用 expire 凑

## 可用 API 完整列表
组件在 OpenResty 环境运行，可用 API 包括：

### JXWAF 专用模块
- `require "resty.jxwaf.request"`：请求参数获取（get_args(key, value)）
- `require "resty.jxwaf.unify_action"`：统一动作执行

### OpenResty 标准 API
- `ngx.req.get_headers(limit)` / `ngx.req.get_uri_args(limit)` / `ngx.req.get_post_args(limit)`
- `ngx.req.get_body_data()` / `ngx.req.read_body()`
- `ngx.req.get_method()` / `ngx.req.http_version()`
- `ngx.var.*`（如 ngx.var.uri, ngx.var.remote_addr, ngx.var.http_host）
- `ngx.ctx`（上下文变量，可跨阶段共享）
- `ngx.header.*`（响应头设置）
- `ngx.exit(code)` / `ngx.say(str)` / `ngx.log(level, msg)`
- `ngx.shared.*`（共享字典）
- `ngx.timer.at(delay, callback)` / `ngx.timer.every(interval, callback)`

### 正则与编码
- `ngx.re.match(subject, pattern, options)` / `ngx.re.find` / `ngx.re.gsub` / `ngx.re.sub`
  - options 建议 "oij"（o=编译缓存, i=忽略大小写, j=PCRE JIT）
- `ngx.md5(str)` / `ngx.hmac_sha1(key, str)`
- `ngx.encode_base64(str)` / `ngx.decode_base64(str)`
- `cjson.safe.encode(obj)` / `cjson.safe.decode(str)`

### Lua 标准库
- `string` / `table` / `math` / `io`(仅 init 阶段) / `os`
- `require "bit"`（位运算）

## unify_action 调用方式
```lua
local unify_action = require "resty.jxwaf.unify_action"

-- 阻断请求（返回 403 拦截页面）
unify_action.block({code = 403, html = "<html>...</html>"})
-- html 可选，不传则用默认拦截页面
-- html 中可用 {{request_uuid}} 占位符

-- 拒绝响应（444 关闭连接）
unify_action.reject_response()

-- 人机识别（调用前必须先调用 bot_commit_auth 提交认证上下文）
unify_action.bot_commit_auth()
unify_action.bot_check_ip("slipper")  -- auto/slipper/puzzle/words

-- 网络封禁（需 expire_time 秒数）
unify_action.network_block(config_info, src_ip, expire_time)
```

> **重要**：调用 `bot_check_ip` 前必须先调用 `bot_commit_auth()`，否则人机识别上下文缺失，可能导致防护静默失效。

## waf_log 日志规范
组件执行动作时，应在调用 unify_action **之前**设置 `ngx.ctx.waf_log` 记录日志上下文，便于审计追溯：
```lua
ngx.ctx.waf_log = {
    waf_module = "component",
    waf_policy = "防护组件-<组件名>",
    waf_action = "bot_check",  -- block/bot_check/network_block/reject_response
    waf_extra = "cc_attack_triggered path=" .. path .. " count=" .. tostring(count),
}
```
- waf_extra 记录触发关键变量，便于排查（如 path、count、src_ip 等）

## 开发风格（必须遵守）
1. 简洁优先：每个组件独立运行，一个组件只解决一个问题
2. 内联实现：辅助函数直接写在组件文件内，不抽取公共库
3. 扁平结构：头部注释 → 顶层 require → 辅助函数 → check 函数 → return _M
4. 最小依赖：只 require 必要模块，不引入第三方库
5. 直白逻辑：优先 if/else 和 for 循环，不用元表、闭包工厂、高阶函数
6. 注释克制：只在「为什么这么做」需要解释时加注释
7. **require 置顶**：所有 require 必须放在模块顶层（`local _M = {}` 之前），**禁止放在 check 函数内**。模块顶层代码 per-worker 只执行一次；函数内 require 每次请求都调用，虽有 package.loaded 缓存但仍有函数调用开销，影响性能

## 性能与稳定性（必须遵守）
WAF 处于业务流量关键路径，防护组件在 access 阶段对每个请求执行，性能和稳定性直接影响业务可用性。以下为硬性要求：

1. **require 置顶**：require 放模块顶层，per-worker 只执行一次（见开发风格 7）
2. **禁止外部 IO**：**禁止 cosocket 外部 HTTP 调用、禁止文件 IO、禁止长循环阻塞**。组件每次请求都执行，任何阻塞会随 QPS 放大千倍，直接拖垮业务
3. **共享字典必设 TTL**：所有 set/add/incr 必须带 TTL，避免内存无限增长导致 worker OOM
4. **fail-safe 原则**：组件出错应放行（return），不能阻断正常流量。节点已 pcall 包裹，异常自动记 ERR 日志。只在确定要拦截时才调 unify_action，正常路径不要 ngx.exit
5. **轻量计算**：正则用 ngx.re + "oij" 选项（编译缓存）；避免每次请求大字符串拼接、深层 table 遍历
6. **原子操作优先**：统计/标记场景用 add/incr 原子操作，不要 get+set（竞态 + 两次字典访问）

## 错误处理
节点 base_component 已用 pcall 包裹 check 调用，组件内无需再包 pcall。
异常自动记录 ERR 日志，不影响后续组件和规则执行。
组件内若需主动终止请求，调用 unify_action（会 ngx.exit）。

## code 字段编码
- 组件 code 字段存**明文 Lua 源码**，控制台 create/load 接口直接存储，不做 Base64 编码
- 节点端加载时自动 Base64 解码后 loadstring 编译
- 生成配置时直接在 code 字段写入 Lua 源码即可
