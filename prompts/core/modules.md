# JXWAF 四大模块速查

## 匹配参数（request.get_args key + value）

### 顶层 key 列表（11 个）
| key | value 取值 | 说明 |
|-----|-----------|------|
| http_args | 见下表 | HTTP 请求元信息 |
| header_args | <header_name> | 指定 Header 值，取第一个（大小写不敏感，上限 200 个） |
| cookie_args | <cookie_name> | 指定 Cookie 值，取第一个 |
| uri_args | <param_name> | 查询字符串参数值（上限 200 个） |
| post_args | <param_name> | 表单请求体参数值（上限 200 个） |
| json_post_args | <param_name> | JSON 请求体字段值（**仅顶层字段**，不支持 a.b.c 嵌套；非 string 类型自动 cjson.encode） |
| ctx_args | <ctx_key> | 防护组件中自定义的 ngx.ctx 变量 |
| global_name_list_result | <list_name> | 名单防护的匹配结果 |
| string | <常量值> | 返回 tostring(value)，用于常量匹配 |
| web_rule_protection_result | <rule_name> | Web 规则匹配结果 |
| web_engine_protection_result | <rule_name> | Web 引擎匹配结果 |

### http_args 支持的 value（15 个）
| value | 返回 |
|-------|------|
| path | ngx.var.uri（请求路径，不含 query string） |
| query_string | ngx.var.query_string |
| method | ngx.req.get_method() |
| src_ip | ngx.ctx.src_ip or ngx.var.remote_addr |
| raw_body | ngx.req.get_body_data()（**不调用 read_body**，仅返回内存中 body，文件 body 返回 nil） |
| version | ngx.req.http_version() |
| scheme | ngx.var.scheme |
| raw_header | 所有 header 排序后 cjson.encode（缓存到 ngx.ctx） |
| raw_header_no_referer | 同上但移除 referer 头 |
| request_uri | ngx.var.request_uri（含 query string 的完整 URI） |
| host | ngx.var.http_host or ngx.var.host |
| user_agent | ngx.var.http_user_agent |
| referer | ngx.var.http_referer |
| cookie | ngx.var.http_cookie（原始 cookie 字符串） |
| high_risk_header | 高风险 header 表 cjson.encode（user-agent/x-forwarded-for/forwarded/cookie/referer/content-type/accept-language/authorization/x-real-ip/client-ip/true-client-ip） |

## 参数预处理（args_prepocess，数组按顺序执行，前一个输出为后一个输入）
| key | 说明 |
|-----|------|
| none | 不处理 |
| lowerCase | 转小写（注意大小写：camelCase） |
| base64Decode | BASE64 解码（失败返回原值） |
| length | 返回字符串长度（字符串形式） |
| uriDecode | URL 解码（ngx.unescape_uri） |
| uniDecode | UNICODE 解码（仅处理 \u00NN，0-255 范围） |
| hexDecode | 十六进制解码（仅处理 \xNN） |
| type | 返回值类型字符串（"number"/"string"/"nil"/"table"/"boolean"） |

> 未识别的 key 返回 nil，会导致后续运算符收到 nil（status_check 除外）

## 匹配运算符（match_operator，共 13 个，大小写敏感）
| 运算符 | 说明 |
|--------|------|
| str_contain | 包括（plain 子串查找，非正则） |
| str_ncontain | 不包括 |
| str_eq | 等于（tostring 全等） |
| str_neq | 不等于 |
| str_prefix | 前缀匹配（from==1） |
| str_suffix | 后缀匹配（从尾部反向查找） |
| gt | 数字大于（tonumber 转换，非数字不匹配） |
| lt | 数字小于 |
| eq | 数字等于 |
| neq | 数字不等于 |
| status_check | 参数存在判断（exist / no_exist，**唯一允许 arg 为 nil 时执行**） |
| rx | 正则匹配（ngx.re.match，选项 oij：编译缓存+忽略大小写+JIT） |
| ip_in_cidr | IP 在网段（单个 CIDR，仅 IPv4） |
| ip_in_cidrs | IP 在多网段（逗号分隔 CIDR，仅 IPv4） |

## 多条件逻辑
- 同一规则内多个 rule_match = AND（全部命中才触发）
- 单个 rule_match 内多个 match_args = OR（任一命中即可）

## rule_matchs 数据结构
```json
[
  {
    "match_args": [{"key": "http_args", "value": "path"}],
    "args_prepocess": ["none"],
    "match_operator": "str_contain",
    "match_value": "/admin"
  }
]
```

## Web 防护规则
- 功能：单次请求即时匹配
- 字段：rule_name, rule_detail, rule_matchs, rule_action, action_value, group_name(专业版)
- 动作：block（阻断，返回 403）/ watch（观察）/ reject_response（返回 444 关闭连接）
- 不支持频率统计与网络封禁

## 流量防护规则
- 功能：基于频率统计的防护
- 额外字段：filter, entity, stat_time, exceed_count, block_time
- filter："true"（启用匹配条件）/ "false"（对所有请求生效）
- entity：统计对象数组，如 [{"key":"http_args","value":"src_ip"}]，多字段值**无分隔符拼接**为统计 key
- stat_time：统计时间窗口（秒）
- exceed_count：触发阈值（请求次数**严格大于**此值）
- block_time：处罚持续时间（秒）
- 动作：block / reject_response / bot_check / network_block / watch
- action_value：bot_check 类型（auto/slipper/puzzle/words）/ network_block 秒数
- 统计 key 结构：`"flow_rule_stat" + table.concat(entity 各字段值)`，存入 jxwaf_inner，TTL=stat_time
- 封禁 key 结构：`"flow_rule_block" + src_ip`，存入 jxwaf_inner，TTL=block_time

## 防护组件
- 功能：自定义 Lua 代码检测，access 阶段最先执行（base_component）
- 字段：name, detail, code（Lua 源码，节点端 Base64 解码后 loadstring）, conf（JSON 配置字符串）
- check(conf_data) 入口函数，conf_data 为 conf 字段 JSON 解码结果（**唯一参数**）
- 可用 API：
  - require "resty.jxwaf.request"：获取请求参数（get_args）
  - require "resty.jxwaf.unify_action"：执行动作（block/reject_response/bot_check/network_block）
  - ngx.ctx：设置上下文变量供后续模块引用
  - ngx.shared.jxwaf_inner：共享字典（**注意 key 前缀避免冲突**）
  - ngx.re.match / ngx.re.find / ngx.re.gsub：PCRE 正则
  - cjson.safe：JSON 处理
  - ngx.md5 / ngx.hmac_sha1 / ngx.encode_base64 / ngx.decode_base64
  - require "bit"：位运算（LuaJIT 兼容）
  - ngx.req.get_headers() / ngx.req.get_uri_args() 等标准 OpenResty API

## 名单防护
- 功能：基于键值哈希查找的快速匹配，先于所有规则检测执行
- 字段：name_list_name, name_list_detail, name_list_rule, name_list_action, action_value, name_list_expire, name_list_expire_time
- name_list_rule：JSON 数组，定义查找 key 的构造方式（按顺序取值后**无分隔符拼接**）
  ```json
  [{"key": "http_args", "value": "src_ip"}, {"key": "header_args", "value": "host"}]
  ```
  拼接结果如 `1.1.1.1www.test.com`，在条目哈希表中查找
- **任一字段为 nil/table 则放弃查找**（仅接受 string/number/boolean）
- 查找为纯哈希匹配，无前缀/正则/范围匹配
- 动作：block / reject_response / bot_check / network_block / watch / all_bypass / web_bypass / flow_bypass
- name_list_expire："true"（临时，需设 expire_time）/ "false"（永久）
- 条目通过 create_global_name_list_item 或外部 API 单独添加

## 白名单规则
- Web 白名单：rule_action 固定为 web_bypass，命中设 ngx.ctx.web_bypass=true，跳过 Web 防护规则/引擎/防篡改
- 流量白名单：rule_action 固定为 flow_bypass，命中设 ngx.ctx.flow_bypass=true，跳过流量防护规则/引擎/IP区域封禁
- 字段同 Web/流量规则（rule_name, rule_detail, rule_matchs, rule_action, action_value）

## 动作行为详解
| 动作 | 行为 |
|------|------|
| block | 设置 request_uuid 响应头，返回拦截页面（默认 403，可自定义） |
| reject_response | ngx.exit(444)，Nginx 直接关闭连接无响应 |
| watch | 仅记录日志不拦截 |
| bot_check | 人机识别（auto=5秒盾/slipper=滑块/puzzle=拼图/words=选字），通过后设 Cookie 86400 秒 |
| network_block | 网络层封禁 IP，POST 到 jxwaf_server/network_block，设 jxwaf_inner TTL，返回 444 |
| all_bypass | 同时设置 web_bypass=true 和 flow_bypass=true |
| web_bypass | 设置 web_bypass=true |
| flow_bypass | 设置 flow_bypass=true |
