# JXWAF 四大模块速查

## 匹配参数（match_args.key + match_args.value）
| key | value 取值 |
|-----|-----------|
| http_args | path / query_string / method / src_ip / raw_body / version / scheme / raw_header / request_uri / host / user_agent / referer / cookie |
| header_args | <header_name>（指定 Header 值，取第一个） |
| cookie_args | <cookie_name>（指定 Cookie 值，取第一个） |
| uri_args | <param_name>（查询字符串参数值） |
| post_args | <param_name>（表单请求体参数值） |
| json_post_args | <param_name>（JSON 请求体字段值） |
| ctx_args | <ctx_key>（防护组件中自定义的 ngx.ctx 变量） |
| global_name_list_result | <list_name>（名单防护的匹配结果） |

## 参数预处理（args_prepocess，数组按顺序执行）
- none：不处理
- lowerCase：转小写
- base64Decode：BASE64 解码（失败返回原值）
- length：返回字符串长度
- uriDecode：URL 解码（ngx.unescape_uri）
- uniDecode：UNICODE 解码（\u00XX）
- hexDecode：十六进制解码（\xNN）

## 匹配运算符（match_operator）
| 运算符 | 说明 |
|--------|------|
| str_contain | 包括（子串查找） |
| str_ncontain | 不包括 |
| str_eq | 等于（字符串全等） |
| str_neq | 不等于 |
| str_suffix | 后缀匹配 |
| str_prefix | 前缀匹配 |
| gt / lt / eq / neq | 数字大于/小于/等于/不等于 |
| status_check | 参数存在判断（exist / no_exist） |
| rx | 正则匹配（ngx.re.match，选项 oij，PCRE 忽略大小写+JIT） |
| ip_in_cidr | IP 在网段（单个 CIDR） |
| ip_in_cidrs | IP 在多网段（逗号分隔） |

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
- 字段：rule_name, rule_detail, rule_matchs, rule_action, action_value, group_name
- 动作：block（阻断）/ watch（观察）
- 不支持频率统计与网络封禁

## 流量防护规则
- 功能：基于频率统计的防护
- 额外字段：filter, entity, stat_time, exceed_count, block_time
- filter：true（启用匹配条件）/ false（对所有请求生效）
- entity：统计对象数组，如 [{"key":"http_args","value":"src_ip"}]，多字段拼接为统计 key
- stat_time：统计时间窗口（秒）
- exceed_count：触发阈值（请求次数超过此值）
- block_time：处罚持续时间（秒）
- 动作：block / reject_response / bot_check / network_block / watch
- action_value：bot_check 类型（auto/slipper/puzzle/words）/ network_block 秒数

## 防护组件
- 功能：自定义 Lua 代码检测，access 阶段最先执行
- 字段：name, detail, code（Base64 编码）, conf（JSON 配置）
- check(conf_data) 入口函数，conf_data 为 conf 字段 JSON 解码结果
- 可用 API：
  - require "resty.jxwaf.request"：获取请求参数
  - require "resty.jxwaf.unify_action"：执行动作（block/reject_response/bot_check 等）
  - ngx.ctx：设置上下文变量供后续模块引用
  - ngx.shared.jxwaf_user：组件专用共享字典（所有组件共用）
  - ngx.re.*：正则匹配
  - cjson.safe：JSON 处理
  - require "bit"：位运算（LuaJIT 兼容）

## 名单防护
- 功能：基于键值查找的快速匹配，先于所有规则检测执行
- 字段：name_list_name, name_list_detail, name_list_rule, name_list_action, action_value, name_list_expire, name_list_expire_time
- name_list_rule：JSON 数组，定义查找 key 的构造方式（按顺序拼接字段值）
- 动作：block / reject_response / bot_check / network_block / watch / all_bypass / web_bypass / flow_bypass

## 白名单规则
- Web 白名单：命中设 web_bypass=true，跳过 Web 防护规则/引擎/防篡改
- 流量白名单：命中设 flow_bypass=true，跳过流量防护规则/引擎/IP区域封禁
- 字段同 Web/流量规则，rule_action 固定为 web_bypass / flow_bypass

## 执行顺序（access 阶段）
```
base_component → global_name_list → domain_check → bot_commit_auth
→ flow_white_rule → flow_ip_region_block → flow_rule_protection → flow_engine_protection
→ web_white_rule → web_rule_protection → web_engine_protection → web_page_tamper_proof
```
- 防护组件最先执行，可设 ngx.ctx 供后续引用
- 名单防护先于所有规则检测
- 流量防护整体先于 Web 防护
- 白名单先于规则检测
- 规则按 rule_order_time 升序执行（值越小越先执行）
- 规则匹配后立即执行动作并终止（ngx.exit）
