# JxWAF 配置说明

本文档整理自 JxWAF 专业版/标准版节点源码与控制台代码，聚焦 **Web 防护规则** 与 **流量防护规则** 两大模块的配置字段、匹配引擎、执行动作与节点检测逻辑。

---

## 一、规则引擎（通用匹配机制）

Web 防护规则、流量防护规则、网页防篡改、白名单规则、名单防护、高级配置等功能模块，均基于同一套规则引擎定义触发条件。

### 1.1 请求处理流程

```
请求到达
  │
  ├── access_init        初始化域名配置、真实 IP、GeoIP
  ├── base_component     执行自定义防护组件
  ├── global_name_list   全局名单匹配
  ├── domain_check       域名有效性检查
  ├── bot_commit_auth    人机识别前置
  │
  ├── flow_white_rule    流量白名单（命中则 flow_bypass=true）
  ├── flow_ip_region_block  IP 区域封禁
  ├── flow_rule_protection  流量防护规则 ★
  ├── flow_engine_protection 流量防护引擎（IP访问限制/IP数量限制/域名访问限制/SSL指纹/紧急防护）
  │
  ├── web_white_rule     Web 白名单（命中则 web_bypass=true）
  ├── web_rule_protection   Web 防护规则 ★
  ├── web_engine_protection Web 防护引擎（AI 模型 + 语义分析）
  ├── web_page_tamper_proof 网页防篡改
  │
  ├── custom_request_header / custom_response_header / custom_response_content / custom_upstream_address
  └── init_jxwaf_devid    设备指纹初始化
```

> 标 ★ 的为本手册重点覆盖模块。检测顺序：流量防护先于 Web 防护；白名单先于规则检测，命中白名单后对应模块跳过。

### 1.2 匹配参数（match_args.key + match_args.value）

| key（参数类别）       | value（字段名）   | 取值说明                                       |
|-----------------------|-------------------|------------------------------------------------|
| `http_args`           | `path`            | URL 路径，如 `/waf/waf_get_domain_list`        |
| `http_args`           | `query_string`    | 原始查询串，如 `test=a&test2=b`                |
| `http_args`           | `method`          | 请求方法，如 `POST`                            |
| `http_args`           | `src_ip`          | 客户端来源 IP（已处理代理透传）                |
| `http_args`           | `raw_body`        | 原始请求体                                     |
| `http_args`           | `version`         | HTTP 版本，如 `1.1`                            |
| `http_args`           | `scheme`          | 协议，`http` / `https`                         |
| `http_args`           | `raw_header`      | 原始 Header（JSON 序列化，按 key 排序）        |
| `http_args`           | `request_uri`     | 含查询参数的完整 URI                           |
| `http_args`           | `host`            | Host 头                                        |
| `http_args`           | `user_agent`      | User-Agent                                     |
| `http_args`           | `referer`         | Referer                                        |
| `http_args`           | `cookie`          | 原始 Cookie 串                                 |
| `header_args`         | `<header_name>`   | 指定 Header 值（取第一个）                     |
| `cookie_args`         | `<cookie_name>`   | 指定 Cookie 值（取第一个）                     |
| `uri_args`            | `<param_name>`    | 查询字符串参数值（取第一个）                   |
| `post_args`           | `<param_name>`    | 表单请求体参数值（取第一个）                   |
| `json_post_args`      | `<param_name>`    | JSON 请求体字段值（非字符串则 JSON 编码）      |
| `ctx_args`            | `<ctx_key>`       | 防护组件中自定义的 ngx.ctx 变量                |
| `global_name_list_result` | `<list_name>` | 名单防护的匹配结果                             |

### 1.3 参数处理（args_prepocess，数组按顺序执行）

| 处理选项      | 标识             | 说明                                              |
|---------------|------------------|---------------------------------------------------|
| 不处理        | `none`           | 原值返回                                          |
| 小写处理      | `lowerCase`      | 转小写                                            |
| BASE64 解码   | `base64Decode`   | 解码失败返回原值                                  |
| 长度计算      | `length`         | 返回字符串长度（转字符串）                        |
| URL 解码      | `uriDecode`      | `ngx.unescape_uri`                                |
| UNICODE 解码  | `uniDecode`      | 解码 `\u00XX` 形式                                |
| 十六进制解码  | `hexDecode`      | 解码 `\xNN` 形式                                  |

### 1.4 匹配方式（match_operator）

| 匹配方式     | 标识            | 说明                                                     |
|--------------|-----------------|----------------------------------------------------------|
| 包括         | `str_contain`   | 原始子串查找（`string.find`，非模式）                    |
| 不包括       | `str_ncontain`  | 不包含则命中                                             |
| 等于         | `str_eq`        | 字符串全等                                               |
| 不等于       | `str_neq`       | 字符串不等                                               |
| 后缀匹配     | `str_suffix`    | 末尾匹配                                                 |
| 前缀匹配     | `str_prefix`    | 开头匹配（from==1）                                      |
| 数字大于     | `gt`            | 双方 tonumber 后比较，非数字则不命中                     |
| 数字小于     | `lt`            | 同上                                                     |
| 数字等于     | `eq`            | 同上                                                     |
| 数字不等于   | `neq`           | 同上                                                     |
| 参数存在判断 | `status_check`  | `exist`（存在命中）/ `no_exist`（不存在命中）            |
| 正则匹配     | `rx`            | `ngx.re.match`，选项 `oij`（PCRE，忽略大小写+JIT）       |
| IP 在网段    | `ip_in_cidr`    | 单个 CIDR，如 `192.168.1.0/24`                          |
| IP 在多网段  | `ip_in_cidrs`   | 逗号分隔多个 CIDR                                        |

> **多条件逻辑**：同一规则内多个 `rule_match` 为 **AND** 关系（全部命中才触发）；单个 `rule_match` 内多个 `match_args` 为 **OR** 关系（任一命中即可）。

### 1.5 rule_matchs 数据结构

```json
[
  {
    "match_args": [
      {"key": "http_args", "value": "path"}
    ],
    "args_prepocess": ["none"],
    "match_operator": "str_contain",
    "match_value": "/admin"
  }
]
```

---

## 二、执行动作

### 2.1 通用动作

| 动作         | 标识               | 适用模块                         | 说明                                   |
|--------------|--------------------|----------------------------------|----------------------------------------|
| 阻断请求     | `block`            | Web 规则/流量规则/引擎/名单/IP区域 | 返回拦截页面（可自定义）               |
| 拒绝响应     | `reject_response`  | 流量规则/引擎/名单/IP区域        | 不返回任何数据，适合 CC 防护           |
| 观察模式     | `watch`            | Web 规则/白名单                  | 仅记录日志不拦截                       |
| 人机识别     | `bot_check`        | 流量规则/引擎/名单/IP区域        | 无交互/滑块/拼图/选字认证              |
| 网络封禁     | `network_block`    | 流量规则/引擎/名单               | 网络层封禁 IP，需设置持续时间          |
| 安全防护全加白 | `all_bypass`      | 名单                             | 跳过 Web + 流量所有安全防护            |
| Web 防护加白 | `web_bypass`       | Web 白名单/名单                  | 仅跳过 Web 安全防护                    |
| 流量防护加白 | `flow_bypass`      | 流量白名单/名单                  | 仅跳过流量安全防护                     |

### 2.2 action_value（动作附加参数）

- `bot_check`：人机识别类型，取值必须为 `auto`（无交互自动检测）/ `slipper`（滑块）/ `puzzle`（滑块拼图）/ `words`（文字点击）之一。其他值会导致人机识别页面不显示（防护静默失效）
- `network_block`：封禁持续时间（秒），如 `3600`
- 其他动作通常为空串

> 取值依据：节点 `resty.jxwaf.unify_action` 模块的 `bot_check_ip(bot_check_mode)` 函数仅识别上述 4 种 mode，传入 `slide`/`select`/空串等无效值时 `bot_check_key` 为空表，验证页面不会返回。

---

## 三、Web 防护规则

### 3.1 功能定位

通过自定义规则匹配请求，对特定 URL、参数、请求头进行精准防护。属于 **单次请求** 的即时检测（非频率统计）。

### 3.2 数据库表与字段

专业版表名：`jxwaf_waf_group_web_rule_protection`
标准版表名：`jxwaf_waf_web_rule_protection`

| 字段             | 类型   | 说明                                         |
|------------------|--------|----------------------------------------------|
| `rule_name`      | string | 规则唯一标识（同分组内不可重复）             |
| `rule_detail`    | string | 规则描述                                     |
| `rule_matchs`    | string | 匹配条件（JSON 字符串，结构见 1.5）          |
| `rule_action`    | string | 执行动作：`block` / `watch`                  |
| `action_value`   | string | 动作附加参数（Web 规则通常为空）             |
| `rule_order_time`| int    | 优先级排序时间戳（越小越先执行）             |
| `status`         | string | 启用状态：`true` / `false`                   |
| `group_name`     | string | 所属分组（专业版）                           |
| `user_name`      | string | 所属用户                                     |

> Web 防护规则仅支持 `block`（阻断）与 `watch`（观察）两种动作，不支持频率统计与网络封禁。

### 3.3 节点检测逻辑（waf.web_rule_protection）

```lua
-- 伪代码，源自 waf.lua
function web_rule_protection()
  if web_bypass then return end           -- Web 白名单已命中，跳过
  for _, rule in ipairs(web_rule_protection_data) do
    local matchs_result = true
    for _, rule_match in ipairs(rule.rule_matchs) do
      local operator_result = false
      for _, match_arg in ipairs(rule_match.match_args) do
        local arg = request.get_args(match_arg.key, match_arg.value)
        for _, preprocess in ipairs(rule_match.args_prepocess) do
          arg = preprocess.process_args(preprocess, arg)
        end
        if arg or match_operator == 'status_check' then
          if operator.match(match_operator, arg, match_value) then
            operator_result = true
            break  -- OR：单个 match_arg 命中即可
          end
        end
      end
      if not operator_result then
        matchs_result = false
        break  -- AND：单个 rule_match 不命中则整条规则不命中
      end
    end
    if matchs_result then
      -- 记录日志 waf_module=web_rule_protection
      if rule_action == "block" or rule_action == "reject_response" then
        unify_action.block(page_conf)  -- 返回拦截页面
      end
      -- watch 仅记录日志
    end
  end
end
```

### 3.4 配置示例

**示例 1：禁止访问 /admin 目录**

```json
{
  "rule_name": "block_admin",
  "rule_detail": "禁止访问后台目录",
  "rule_matchs": "[{\"match_args\":[{\"key\":\"http_args\",\"value\":\"path\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"str_contain\",\"match_value\":\"/admin\"}]",
  "rule_action": "block",
  "action_value": ""
}
```

**示例 2：观察模式监控 SQL 注入特征参数**

```json
{
  "rule_name": "watch_sqli",
  "rule_detail": "监控可能 SQL 注入参数",
  "rule_matchs": "[{\"match_args\":[{\"key\":\"uri_args\",\"value\":\"id\"}],\"args_prepocess\":[\"lowerCase\"],\"match_operator\":\"str_contain\",\"match_value\":\"union select\"}]",
  "rule_action": "watch",
  "action_value": ""
}
```

---

## 四、流量防护规则

### 4.1 功能定位

自定义流量防护规则，支持通过匹配条件筛选请求，并按 **统计实体** 进行 **频率控制**。与 Web 防护规则的核心区别：流量防护规则包含频率统计与处罚机制。

### 4.2 数据库表与字段

专业版表名：`jxwaf_waf_group_flow_rule_protection`
标准版表名：`jxwaf_waf_flow_rule_protection`

| 字段             | 类型   | 说明                                                 |
|------------------|--------|------------------------------------------------------|
| `rule_name`      | string | 规则唯一标识                                         |
| `rule_detail`    | string | 规则描述                                             |
| `rule_matchs`    | string | 匹配条件（JSON 字符串，结构同 1.5）                  |
| `rule_action`    | string | 执行动作：`block`/`reject_response`/`bot_check`/`network_block`/`watch` |
| `action_value`   | string | 动作附加参数（bot_check 类型 / network_block 秒数）  |
| `filter`         | string | 是否启用匹配条件：`true`（启用）/ `false`（对所有请求生效） |
| `entity`         | string | 统计对象（JSON 数组），如 `[{"key":"http_args","value":"src_ip"}]` |
| `stat_time`      | int    | 统计时间窗口（秒）                                   |
| `exceed_count`   | int    | 触发阈值（请求次数超过此值）                         |
| `block_time`     | int    | 处罚持续时间（秒）                                   |
| `rule_order_time`| int    | 优先级排序时间戳                                     |
| `status`         | string | 启用状态                                             |
| `group_name`     | string | 所属分组（专业版）                                   |
| `user_name`      | string | 所属用户                                             |

### 4.3 entity（统计对象）说明

`entity` 是一个 JSON 数组，每个元素结构与 `match_args` 相同，支持多个字段拼接为统计 key。

```json
[
  {"key": "http_args", "value": "src_ip"},
  {"key": "http_args", "value": "path"}
]
```

上述配置表示：按 `src_ip + path` 拼接作为统计 key。同一 IP 访问不同路径分别计数；同一 IP 访问同一路径累计计数。

> 若 `entity` 中任一字段取值为 nil（非 string/非 table），则该请求不参与统计（`nil_exist=true` 跳过）。

### 4.4 节点检测逻辑（waf.flow_rule_protection）

```lua
-- 伪代码，源自 waf.lua
function flow_rule_protection()
  if flow_bypass then return end          -- 流量白名单已命中，跳过

  -- 1. 先检查 src_ip 是否已被本规则处罚（缓存命中直接处置）
  local block_result = jxwaf_inner:get("flow_rule_block" .. src_ip)
  if block_result then
    -- 解析处罚动作并执行（block/reject_response/network_block/bot_check）
    return
  end

  -- 2. 遍历规则
  for _, rule in ipairs(flow_rule_protection_data) do
    local matchs_result = true

    -- 2.1 匹配条件过滤（filter=false 时跳过匹配，对所有请求生效）
    if rule.filter == "true" then
      matchs_result = match_rule(rule.rule_matchs)  -- 同 Web 规则匹配逻辑
    end

    -- 2.2 频率统计
    if matchs_result then
      local stat_key = "flow_rule_stat"
      for _, entity_item in ipairs(rule.entity) do
        stat_key = stat_key .. request.get_args(entity_item.key, entity_item.value)
      end
      -- ngx.shared.jxwaf_inner:incr(key, 1, 0, stat_time)
      local count = jxwaf_inner:incr(stat_key, 1, 0, rule.stat_time)
      if count > rule.exceed_count then
        -- 2.3 触发处罚
        if rule_action == "network_block" then
          unify_action.network_block(config_info, src_ip, action_value)  -- 立即网络封禁
        end
        -- 写入处罚缓存，后续请求直接命中
        jxwaf_inner:set("flow_rule_block" .. src_ip, cjson.encode(block_action), rule.block_time)
      end
    end
  end
end
```

**关键实现细节：**

1. **统计存储**：使用 `ngx.shared.jxwaf_inner`（共享内存字典），`incr(key, 1, 0, stat_time)` 第四个参数为 TTL，到期自动清零。
2. **处罚缓存**：触发阈值后，将处罚动作写入 `flow_rule_block<src_ip>`，TTL 为 `block_time`。后续该 IP 的请求在步骤 1 即被拦截，无需重复统计。
3. **network_block 特殊处理**：网络封禁动作立即执行（调用 nftables 网络层封禁），不依赖缓存。
4. **统计 key 构造**：`"flow_rule_stat" + entity各字段值拼接`，确保不同规则的统计互不干扰（但同规则不同 entity 值会分别计数）。

### 4.5 配置示例

**示例 1：限制单 IP 单路径访问频率**

```json
{
  "rule_name": "limit_ip_path",
  "rule_detail": "限制同一IP对同一路径的访问频率",
  "rule_matchs": "[]",
  "rule_action": "block",
  "action_value": "",
  "filter": "false",
  "entity": "[{\"key\":\"http_args\",\"value\":\"src_ip\"},{\"key\":\"http_args\",\"value\":\"path\"}]",
  "stat_time": 60,
  "exceed_count": 100,
  "block_time": 3600
}
```

效果：同一 IP 针对同一 URI，60 秒内超过 100 次请求后阻断 3600 秒。访问不同 URI 不累计。

**示例 2：限制特定接口的 CC 攻击（带匹配条件）**

```json
{
  "rule_name": "cc_protect_api",
  "rule_detail": "保护 /api/login 接口，限制单 IP 频率",
  "rule_matchs": "[{\"match_args\":[{\"key\":\"http_args\",\"value\":\"path\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"str_contain\",\"match_value\":\"/api/login\"}]",
  "rule_action": "bot_check",
  "action_value": "slipper",
  "filter": "true",
  "entity": "[{\"key\":\"http_args\",\"value\":\"src_ip\"}]",
  "stat_time": 10,
  "exceed_count": 20,
  "block_time": 600
}
```

效果：仅对 `/api/login` 路径生效，同一 IP 10 秒内超过 20 次请求触发滑块人机识别，持续 600 秒。

**示例 3：网络封禁高频攻击 IP**

```json
{
  "rule_name": "network_block_attack",
  "rule_detail": "高频请求直接网络层封禁",
  "rule_matchs": "[]",
  "rule_action": "network_block",
  "action_value": "86400",
  "filter": "false",
  "entity": "[{\"key\":\"http_args\",\"value\":\"src_ip\"}]",
  "stat_time": 30,
  "exceed_count": 500,
  "block_time": 86400
}
```

效果：同一 IP 30 秒内超过 500 次请求，网络层封禁 86400 秒（1 天）。

---

## 五、控制台 API（规则管理）

### 5.1 Web 防护规则 API

| 操作         | 接口路径（专业版前缀）                              | 关键参数                                                              |
|--------------|-----------------------------------------------------|-----------------------------------------------------------------------|
| 列表查询     | `/waf/get_group_web_rule_protection_list`           | `page`, `group_name`                                                  |
| 全量查询     | `/waf/api_get_group_web_rule_protection_list`       | `group_name`                                                          |
| 查询单条     | `/waf/get_group_web_rule_protection`                | `group_name`, `rule_name`                                             |
| 创建规则     | `/waf/create_group_web_rule_protection`             | `group_name`, `rule_name`, `rule_detail`, `rule_matchs`, `rule_action`, `action_value` |
| 编辑规则     | `/waf/edit_group_web_rule_protection`               | 同创建 + `rule_name`（定位）                                          |
| 删除规则     | `/waf/delete_group_web_rule_protection`             | `group_name`, `rule_name`                                             |
| 切换状态     | `/waf/edit_group_web_rule_protection_status`        | `group_name`, `rule_name`, `status`                                   |
| 调整优先级   | `/waf/exchange_group_web_rule_protection_priority`  | `group_name`, `rule_name`, `type`(top/exchange), `exchange_rule_name` |
| 备份导出     | `/waf/backup_group_web_rule_protection`             | `group_name`, `rule_name_list`                                        |
| 恢复导入     | `/waf/load_group_web_rule_protection`               | `group_name`, `rules`                                                 |

### 5.2 流量防护规则 API

| 操作         | 接口路径（专业版前缀）                              | 关键参数                                                              |
|--------------|-----------------------------------------------------|-----------------------------------------------------------------------|
| 列表查询     | `/waf/get_group_flow_rule_protection_list`          | `page`, `group_name`                                                  |
| 查询单条     | `/waf/get_group_flow_rule_protection`               | `group_name`, `rule_name`                                             |
| 创建规则     | `/waf/create_group_flow_rule_protection`            | `group_name`, `rule_name`, `rule_detail`, `rule_matchs`, `rule_action`, `action_value`, `filter`, `entity`, `stat_time`, `exceed_count`, `block_time` |
| 编辑规则     | `/waf/edit_group_flow_rule_protection`              | 同创建 + `rule_name`（定位）                                          |
| 删除规则     | `/waf/delete_group_flow_rule_protection`            | `group_name`, `rule_name`                                             |
| 切换状态     | `/waf/edit_group_flow_rule_protection_status`       | `group_name`, `rule_name`, `status`                                   |
| 调整优先级   | `/waf/exchange_group_flow_rule_protection_priority` | `group_name`, `rule_name`, `type`, `exchange_rule_name`               |
| 备份导出     | `/waf/backup_group_flow_rule_protection`            | `group_name`, `rule_name_list`                                        |
| 恢复导入     | `/waf/load_group_flow_rule_protection`              | `group_name`, `rules`                                                 |

> 标准版接口路径去掉 `group_` 前缀，且不需要 `group_name` 参数。

### 5.3 名单管理 API（规则联动用）

| 操作         | 接口路径                          | 关键参数                                    |
|--------------|-----------------------------------|---------------------------------------------|
| 获取名单条目 | `/api_get_name_list_item_list_list` | `page`, `name_list_name`, `waf_auth`        |
| 创建名单条目 | `/api/create_global_name_list_item` | `name_list_name`, `name_list_item`, `waf_auth` |
| 删除名单条目 | `/api/delete_global_name_list_item` | `name_list_name`, `name_list_item`, `waf_auth` |
| 搜索名单条目 | `/api/search_global_name_list_item` | `page`, `name_list_name`, `search_value`, `waf_auth` |

---

## 六、正则引擎说明

### 6.1 引擎实现

节点使用 `ngx.re.match`（OpenResty PCRE），匹配选项为 `oij`：

- `o`：编译缓存（同一 pattern 复用）
- `i`：忽略大小写
- `j`：启用 JIT 编译（性能优化）

### 6.2 注意事项

1. **正则错误处理**：`ngx.re.match` 返回 `err` 时，节点会 `ngx.exit(500)`，需确保正则语法正确。
2. **性能**：JIT 模式下性能较好，但复杂正则仍可能成为瓶颈，建议配合 `args_prepocess`（如 `lowerCase`）简化匹配。
3. **特殊字符**：`match_value` 中的正则需遵循 PCRE 语法，非正则匹配方式（`str_contain` 等）使用 Lua 原生 `string.find`（plain 模式，非模式匹配）。

### 6.3 正则匹配示例

| 场景             | match_operator | match_value 示例                          |
|------------------|----------------|-------------------------------------------|
| SQL 注入特征     | `rx`           | `union\s+select|information_schema`       |
| XSS 特征         | `rx`           | `<script|onerror=|javascript:`            |
| 路径穿越         | `rx`           | `\.\./\|\.\.\\`                            |
| 命令注入         | `rx`           | `;\s*(cat|ls|id|whoami)\s`                |
| 敏感文件访问     | `rx`           | `/etc/passwd|/proc/self/environ`          |

---

## 七、优先级与执行顺序

### 7.1 模块间执行顺序（access 阶段）

```
base_component → global_name_list → domain_check → bot_commit_auth
→ flow_white_rule → flow_ip_region_block → flow_rule_protection → flow_engine_protection
→ web_white_rule → web_rule_protection → web_engine_protection → web_page_tamper_proof
→ custom_* → init_jxwaf_devid
```

- **防护组件**（base_component）最先执行，可设置 `ngx.ctx` 变量供后续规则引用
- **名单防护**（global_name_list）先于所有规则检测，可设置 bypass 跳过后续模块
- 流量防护整体先于 Web 防护
- 白名单先于规则检测
- 命中 `flow_bypass` 后，后续所有流量模块跳过
- 命中 `web_bypass` 后，后续所有 Web 模块跳过

### 7.2 规则间优先级

- 同一模块内多条规则按 `rule_order_time` **升序** 执行（值越小越先执行）
- `exchange_priority` 接口支持 `top`（置顶）和 `exchange`（交换两条规则顺序）
- 规则匹配后 **立即执行动作并终止**（`unify_action.block` 会 `ngx.exit`），不会继续匹配后续规则

### 7.3 处罚缓存机制（流量规则特有）

```
请求到达
  │
  ├── 检查 flow_rule_block<src_ip> 缓存
  │     ├── 命中 → 直接执行缓存中的处罚动作（不再统计）
  │     └── 未命中 → 进入规则遍历
  │
  └── 规则遍历
        ├── 匹配条件过滤
        ├── 频率统计 incr(flow_rule_stat + entity, 1, 0, stat_time)
        ├── 超过 exceed_count
        │     ├── network_block → 立即网络封禁
        │     └── 其他动作 → 写入 flow_rule_block<src_ip> 缓存（TTL=block_time）
        └── 后续请求在缓存命中阶段即被拦截
```

---

## 八、防护组件

### 8.1 功能定位

防护组件是自定义检测模块，支持编写 Lua 代码实现规则引擎无法覆盖的复杂检测逻辑。组件在 access 阶段 **最先执行**（base_component），先于名单防护和所有规则检测。

**核心能力：**
- 独立实现检测逻辑并直接执行动作（阻断/放行等）
- 设置 `ngx.ctx` 变量，供后续 Web/流量规则通过 `ctx_args` 引用，实现 **组件 + 规则联合判断**
- 读取组件配置（`conf` 字段，JSON 格式）实现参数化检测

### 8.2 数据库表与字段

表名：`jxwaf_waf_component`

| 字段             | 类型   | 说明                                                         |
|------------------|--------|--------------------------------------------------------------|
| `name`           | string | 组件唯一标识（不可重复）                                     |
| `detail`         | string | 组件描述                                                     |
| `code`           | string | Lua 代码（**Base64 编码**后存储），节点侧 `loadstring` 加载  |
| `conf`           | string | 组件配置（JSON 字符串），运行时作为 `conf_data` 传入 `check` |
| `rule_order_time`| int    | 优先级排序时间戳（越小越先执行）                             |
| `status`         | string | 启用状态：`true` / `false`                                   |
| `user_name`      | string | 所属用户                                                     |

### 8.3 组件代码模板与开发规范

```lua
local _M = {}

--[[
  组件检测入口函数
  conf_data: 组件配置（conf 字段 JSON 解码后的 Lua table）
  返回值无强制要求，通过 ngx.ctx / unify_action 产生副作用
]]
function _M.check(conf_data)
  if conf_data == nil then
    return
  end

  -- 示例：读取请求参数
  local request = require "resty.jxwaf.request"
  local src_ip = request.get_args("http_args", "src_ip")
  local path = request.get_args("http_args", "path")

  -- 示例：读取组件配置
  local block_paths = conf_data['block_paths'] or {}

  -- 示例：独立实现检测并执行动作
  for _, block_path in ipairs(block_paths) do
    if path == block_path then
      local unify_action = require "resty.jxwaf.unify_action"
      unify_action.block({code = "403", html = "blocked by component"})
      return
    end
  end

  -- 示例：设置 ctx 变量，供后续规则引用（联合判断）
  ngx.ctx.custom_risk_level = "high"

  return
end

return _M
```

**开发规范：**

1. **模块结构**：必须返回一个包含 `check(conf_data)` 函数的 table
2. **conf_data**：来自 `conf` 字段的 JSON 解码结果，可为 nil（需防御性检查）
3. **可用 API**：
   - `require "resty.jxwaf.request"`：获取请求参数（同规则引擎的 `request.get_args`）
   - `require "resty.jxwaf.unify_action"`：执行动作（block/reject_response/bot_check 等）
   - `ngx.ctx`：设置上下文变量供后续模块引用
   - `ngx.shared.jxwaf_user`：组件专用共享字典（所有组件共用），用于组件间数据共享、计数、缓存等。**key 必须拼接项目名称前缀**避免冲突，如 `"api_test_count_" .. src_ip`
   - `ngx.shared.jxwaf_inner`：WAF 内部共享字典（流量统计/处罚缓存），组件不应直接写入
   - `ngx.re.*`：正则匹配
   - `cjson.safe`：JSON 处理
   - `require "bit"`：位运算（LuaJIT 兼容，见下方 LuaJIT 兼容性要求）
4. **Base64 编码**：代码需 Base64 编码后存入 `code` 字段
5. **错误处理**：节点 `base_component` 已用 `pcall` 包裹 `check` 调用，**组件内无需再包 pcall**。异常自动记录 ERR 日志（`component error: <name>, <err>`），不影响后续组件和规则执行。组件内若需主动终止请求，调用 `unify_action`（会 `ngx.exit`）。
6. **性能**：组件在每次请求时执行，避免耗时操作（如外部 HTTP 调用）

**LuaJIT 兼容性要求（重要）：**

运行环境：OpenResty **1.29.2.3** + LuaJIT 2.1（基于 **Lua 5.1**）。**不支持** Lua 5.2+ 引入的语法和运算符。使用不兼容的语法会导致组件加载失败，节点报 `can not decode component_data` 错误。

#### 8.3.1 位运算符（最高频踩坑点）

| 禁止使用（Lua 5.2+） | 替代方案（LuaJIT 兼容） | 说明 |
|----------------------|-------------------------|------|
| `a & b`              | `bit.band(a, b)`        | 按位与 |
| `a \| b`             | `bit.bor(a, b)`         | 按位或 |
| `a ~ b`              | `bit.bxor(a, b)`        | 按位异或 |
| `~a`                 | `bit.bnot(a)`           | 按位非 |
| `a >> n`             | `bit.rshift(a, n)`      | 逻辑右移（无符号） |
| `a << n`             | `bit.lshift(a, n)`      | 左移 |
| `a &= b`             | `a = bit.band(a, b)`    | 复合赋值（Lua 5.3+） |
| `a \|= b`            | `a = bit.bor(a, b)`     | 复合赋值（Lua 5.3+） |
| `a <<= n`            | `a = bit.lshift(a, n)`  | 复合赋值（Lua 5.3+） |
| `a >>= n`            | `a = bit.rshift(a, n)`  | 复合赋值（Lua 5.3+） |

使用前需在文件顶部声明：
```lua
local bit = require "bit"
```

**bit 模块注意事项：**
- 操作数和返回值是 32 位有符号整数（范围 -2147483648 ~ 2147483647）
- 对于 IP 地址等无符号 32 位数，> 127.255.255.255 的值会表示为负数，但不影响 `bit.band` 比较的正确性
- `bit.lshift` / `bit.rshift` 的移位量会被掩码到 5 位（0-31），移位 ≥ 32 时需特殊处理（如 `prefix == 0` 时 mask 应直接设为 0）

#### 8.3.2 控制流语法

| 禁止使用（Lua 5.2+） | 替代方案 | 说明 |
|----------------------|----------|------|
| `goto label`         | 重构为循环/函数/`do break end` | goto 语句 |
| `::label::`          | 同上     | 标签定义 |
| `continue`（伪关键字） | `do break end`（在 for 循环内）或封装为函数提前 return | Lua 无 continue 关键字，LuaJIT 也不支持 |

**循环内 continue 的替代写法：**
```lua
-- 错误：Lua 没有 continue
for i, v in ipairs(t) do
    if cond then continue end  -- 语法错误
    -- ...
end

-- 正确写法 1：do break end（最简洁）
for i, v in ipairs(t) do
    if cond then do break end end  -- 跳过本次循环
    -- ...
end

-- 正确写法 2：if/else 包裹（逻辑清晰）
for i, v in ipairs(t) do
    if not cond then
        -- ...
    end
end
```

#### 8.3.3 数值类型与运算

| 禁止使用（Lua 5.3+） | 替代方案 | 说明 |
|----------------------|----------|------|
| `a // b`             | `math.floor(a / b)`     | 整数除法 |
| `a //= b`            | `a = math.floor(a / b)` | 整数除法复合赋值 |
| `1LL` / `1ULL`       | 直接用 number（double） | 64 位整数字面量 |
| `math.tointeger(x)`  | `type(x) == "number" and x == math.floor(x)` | 整数判断 |
| `0x1p4`（十六进制浮点） | `16.0` 或 `2^4`         | 十六进制浮点字面量 |

**数值类型说明：**
- LuaJIT 只有 `number` 一种数值类型（双精度浮点 double），**没有** Lua 5.3+ 的 64 位整数子类型
- 整数运算在 ±2^53 范围内精确，超出会丢失精度
- 需要精确 64 位整数运算时，用 `ffi`（LuaJIT 扩展，但组件中慎用）

#### 8.3.4 字符串与 table 操作

| 禁止使用（Lua 5.3+） | 替代方案 | 说明 |
|----------------------|----------|------|
| `string.pack` / `string.unpack` | 手动拼接字节或用 `ffi` | 二进制打包 |
| `string.packsize`    | 手动计算                | 打包大小 |
| `utf8.char` / `utf8.codepoint` | `string.char` + 手动编码 | UTF-8 操作（Lua 5.3+ 的 utf8 库） |
| `table.move(a, f, e, t, d)` | 手动 for 循环复制       | table 区间移动（Lua 5.3+） |

**字符串拼接：**
- 用 `..`（Lua 5.1 语法）
- **不要用** Lua 5.4 的 `..=` 复合赋值
- 大量拼接用 `table.concat(t)` 避免性能问题

#### 8.3.5 元方法与运算符重载

Lua 5.2+ 新增的元方法在 LuaJIT 中**不触发**：

| 禁止依赖的元方法 | 触发场景 | 说明 |
|------------------|----------|------|
| `__band` / `__bor` / `__bxor` / `__bnot` | `a & b` 等 | 位运算元方法（Lua 5.3+） |
| `__shl` / `__shr` | `a << n` / `a >> n` | 移位元方法（Lua 5.3+） |
| `__idiv` | `a // b` | 整数除法元方法（Lua 5.3+） |
| `__unm`（行为差异） | `-a` | LuaJIT 支持，但语义略有不同 |

组件代码中**不应依赖元方法实现运算符重载**，直接调用函数（如 `bit.band(a, b)`）更明确。

#### 8.3.6 其他不兼容特性

| 特性 | 版本 | 替代方案 |
|------|------|----------|
| `xpcall(f, handler, arg1, ...)` 传参 | Lua 5.2+ | 用闭包包装：`xpcall(function() f(arg1) end, handler)` |
| `pcall` 返回值的 `nil` 处理差异 | Lua 5.2+ | LuaJIT 的 pcall 行为与 5.1 一致，注意错误对象可能是字符串而非 table |
| `os.execute` 返回值（exit code） | Lua 5.2+ | LuaJIT 返回 exit code（number），不返回 true/false |
| `load` 函数（替代 `loadstring`） | Lua 5.2+ | 用 `loadstring`（LuaJIT 兼容） |
| `__pairs` / `__ipairs` 元方法 | Lua 5.2+ | 不支持自定义迭代器，直接用 `pairs` / `ipairs` |

#### 8.3.7 LuaJIT 扩展（可用但慎用）

以下 LuaJIT 扩展在组件中**可用**，但需谨慎：

| 扩展 | 用途 | 慎用原因 |
|------|------|----------|
| `ffi` | 调用 C 函数 | 组件每次请求执行，ffi 误用易导致内存泄漏或 segfault |
| `ffi.new` / `ffi.C.*` | 分配 C 内存 | 同上，且组件代码由 `loadstring` 加载，ffi 绑定需在文件顶部 |
| `table.new(n, n)` | 预分配 table | 性能优化，非必要不使用 |
| `table.clear(t)` | 清空 table | 同上 |
| `jit.on` / `jit.off` | 控制 JIT | 组件中不要调用，可能影响整体性能 |
| `ngx.re.*` | PCRE 正则 | 可用，但复杂正则有性能风险 |

#### 8.3.8 组件开发风格

1. **简洁优先**：每个组件独立运行，不为复用增加复杂度。一个组件只解决一个问题。
2. **内联实现**：辅助函数直接写在组件文件内，不抽取公共库。复制优于依赖。
3. **扁平结构**：代码结构为「头部注释 → 辅助函数 → check 函数 → return _M」。
4. **最小依赖**：只 `require` 必要模块，不引入第三方库。
5. **直白逻辑**：优先 `if/else` 和 `for` 循环，不用元表、闭包工厂、高阶函数。
6. **注释克制**：只在「为什么这么做」需要解释时加注释（如 LuaJIT 兼容性、安全考量）。

#### 8.3.9 共享字典 jxwaf_user 使用规范

`ngx.shared.jxwaf_user` 是所有防护组件**共用的**共享字典，用于组件间数据共享、请求计数、状态缓存等。由于所有组件共用同一个字典空间，**写入时 key 必须拼接项目名称前缀**，避免不同组件的 key 冲突。

**key 命名规范：**

```
<project_name>_<purpose>_<key>
```

| 组成 | 说明 | 示例 |
|------|------|------|
| `project_name` | 项目目录名（`generated/<project_name>/`），小写下划线 | `api_test`、`cdn_src` |
| `purpose` | 用途标识，简短语义化 | `count`、`block`、`cache` |
| `key` | 业务 key（IP/用户ID/URL 等） | `src_ip`、`user_id` |

**示例：**
```lua
local jxwaf_user = ngx.shared.jxwaf_user

-- 项目 api_test_id_validate 的请求计数
local count_key = "api_test_count_" .. src_ip
local count = jxwaf_user:incr(count_key, 1, 0, 60)  -- 60 秒 TTL

-- 项目 cdn_src_ip_extract 的缓存
local cache_key = "cdn_src_cache_" .. cdn_ip
jxwaf_user:set(cache_key, "trusted", 3600)  -- 1 小时 TTL
```

**常用 API：**

| 方法 | 说明 | 示例 |
|------|------|------|
| `get(key)` | 读取值 | `local v = jxwaf_user:get(key)` |
| `set(key, value, ttl)` | 写入值（ttl 秒，0 为永不过期） | `jxwaf_user:set(key, "1", 60)` |
| `incr(key, value, init, ttl)` | 原子递增（init 为不存在时的初始值，ttl 为过期时间） | `jxwaf_user:incr(key, 1, 0, 60)` |
| `expire(key, ttl)` | 设置过期时间 | `jxwaf_user:expire(key, 300)` |
| `delete(key)` | 删除 | `jxwaf_user:delete(key)` |

**注意事项：**
1. **key 前缀必须拼接项目名**：如 `"api_test_count_" .. src_ip`，禁止裸用 `"count_" .. src_ip`
2. **必须设置 TTL**：`set`/`incr` 时务必指定过期时间，避免内存无限增长
3. **禁止写入 jxwaf_inner**：`ngx.shared.jxwaf_inner` 是 WAF 内部字典（流量统计/处罚缓存），组件不应直接写入
4. **内存有限**：共享字典内存有限（由 `lua_shared_dict jxwaf_user` 配置），避免存储大对象
5. **value 类型**：`set` 的 value 只能是 string/number/boolean，存储 table 需先用 `cjson.encode` 序列化

### 8.4 节点执行逻辑（waf.base_component）

```lua
-- 伪代码，源自 waf.lua
function base_component()
  for _, component_conf in ipairs(waf_component_data) do
    local conf = component_conf['conf']        -- JSON 字符串，需在节点侧解码
    local name = component_conf['name']
    if waf_component_code[name] then           -- 已 loadstring 加载的模块
      local ok, err = pcall(waf_component_code[name].check, conf)
      if not ok then
        ngx.log(ngx.ERR, "component error: " .. name .. ", " .. err)
      end
    end
  end
end
```

**关键点：**
- 组件按 `rule_order_time` 升序执行
- `pcall` 包裹确保单个组件异常不影响其他组件和后续模块
- 组件内调用 `unify_action.block()` 会 `ngx.exit`，直接终止请求
- 组件设置 `ngx.ctx` 变量后，后续规则可通过 `ctx_args:<key>` 引用

### 8.5 组件与规则联合判断

**机制：组件设置 ctx 变量 → 规则通过 `ctx_args` 匹配**

```
组件执行                          规则匹配
┌─────────────────┐              ┌─────────────────────────┐
│ check(conf_data)│              │ rule_matchs:            │
│                 │              │  match_args:            │
│ ngx.ctx.xxx = y │──ctx 传递──▶ │    key=ctx_args         │
│                 │              │    value=xxx             │
└─────────────────┘              │  match_operator: str_eq │
                                 │  match_value: y          │
                                 └─────────────────────────┘
```

**示例：组件标记高风险请求 → Web 规则拦截**

组件代码：
```lua
function _M.check(conf_data)
  local request = require "resty.jxwaf.request"
  local ua = request.get_args("http_args", "user_agent") or ""
  -- 检测恶意爬虫 UA 特征
  if ngx.re.find(ua, "sqlmap|nikto|nmap", "ijo") then
    ngx.ctx.risk_type = "malicious_scanner"
  end
  return
end
```

Web 防护规则匹配条件：
```json
[{
  "match_args": [{"key": "ctx_args", "value": "risk_type"}],
  "args_prepocess": ["none"],
  "match_operator": "str_eq",
  "match_value": "malicious_scanner"
}]
```

### 8.6 组件配置示例

**conf 字段（JSON）：**
```json
{
  "block_paths": ["/admin", "/phpmyadmin", "/.env"],
  "max_body_length": 1048576,
  "sensitive_headers": ["authorization", "x-api-key"]
}
```

### 8.7 防护组件控制台 API

| 操作         | 接口路径                           | 关键参数                                    |
|--------------|------------------------------------|---------------------------------------------|
| 列表查询     | `/waf/get_component_list`          | `page`                                      |
| 查询单条     | `/waf/get_component`               | `name`                                      |
| 创建组件     | `/waf/create_component`            | `name`, `detail`, `code`, `conf`            |
| 编辑组件     | `/waf/edit_component`              | `name`, `detail`, `code`, `conf`            |
| 删除组件     | `/waf/delete_component`            | `name`                                      |
| 切换状态     | `/waf/edit_component_status`       | `name`, `status`                            |
| 调整优先级   | `/waf/exchange_component_priority` | `name`, `type`(top/exchange), `exchange_name` |
| 备份导出     | `/waf/backup_component`            | `name_list`                                 |
| 恢复导入     | `/waf/load_component`              | `rules`                                     |

---

## 九、名单防护

### 9.1 功能定位

名单防护是基于 **键值查找** 的快速匹配机制，支持 IP、域名、Cookie 等多维度组合。在 access 阶段先于所有规则检测执行（global_name_list）。

**核心能力：**
- 独立实现访问控制（封禁/加白/人机识别等）
- 通过 `global_name_list_result` 将匹配结果传递给后续规则，实现 **名单 + 规则联合判断**
- 通过 `all_bypass`/`web_bypass`/`flow_bypass` 动作跳过后续防护模块
- 支持外部 API 动态增删条目（自动化联动）

### 9.2 数据库表与字段

#### 名单配置表：`jxwaf_waf_global_name_list`

| 字段                     | 类型   | 说明                                                         |
|--------------------------|--------|--------------------------------------------------------------|
| `name_list_name`         | string | 名单唯一标识                                                 |
| `name_list_detail`       | string | 名单描述                                                     |
| `name_list_rule`         | string | 匹配规则（JSON 数组），定义查找 key 的构造方式               |
| `name_list_action`       | string | 执行动作（见 9.3）                                           |
| `action_value`           | string | 动作附加参数（bot_check 类型 / network_block 秒数）          |
| `name_list_expire`       | string | 条目过期配置：`false`（永久）/ 数字（秒）                    |
| `name_list_expire_time`  | string | 过期时间数值（`name_list_expire` 为 `false` 时忽略）         |
| `rule_order_time`        | int    | 优先级排序时间戳                                             |
| `status`                 | string | 启用状态                                                     |
| `user_name`              | string | 所属用户                                                     |

#### 名单条目表：`jxwaf_waf_global_name_list_item`

| 字段                          | 类型   | 说明                                         |
|-------------------------------|--------|----------------------------------------------|
| `name_list_name`              | string | 所属名单名称                                 |
| `name_list_item`              | string | 条目内容（查找 key 的值，如 IP 地址）        |
| `name_list_expire`            | string | 过期配置（继承自名单配置）                   |
| `name_list_item_expire_time`  | int    | 条目过期时间戳（Unix 时间戳，0 表示永久）    |
| `user_name`                   | string | 所属用户                                     |

### 9.3 name_list_rule 结构

`name_list_rule` 是 JSON 数组，定义如何从请求中提取字段并拼接为查找 key：

```json
[
  {"key": "http_args", "value": "src_ip"},
  {"key": "header_args", "value": "host"}
]
```

**查找 key 构造逻辑：**
1. 按数组顺序调用 `request.get_args(key, value)` 获取各字段值
2. 将所有字段值 **顺序拼接** 为一个字符串
3. 用拼接后的字符串在条目表中查找

**示例：**
- `name_list_rule`: `[{"key":"http_args","value":"src_ip"},{"key":"header_args","value":"host"}]`
- 请求：src_ip=`1.1.1.1`，host=`www.test.com`
- 查找 key：`1.1.1.1www.test.com`
- 条目表中需存在 `name_list_item = "1.1.1.1www.test.com"` 才能命中

> 若任一字段值为 nil（非 string/number/boolean），则该请求不参与匹配（`nil_exist=true` 跳过）。

### 9.4 执行动作

名单防护支持最丰富的动作集：

| 动作             | 标识             | 说明                                   |
|------------------|------------------|----------------------------------------|
| 阻断请求         | `block`          | 返回拦截页面                           |
| 拒绝响应         | `reject_response`| 不返回数据                             |
| 人机识别         | `bot_check`      | 人机验证                               |
| 网络封禁         | `network_block`  | 网络层封禁 IP                          |
| 观察模式         | `watch`          | 仅记录日志                             |
| 安全防护全加白   | `all_bypass`     | 跳过 Web + 流量所有安全防护            |
| Web 防护加白     | `web_bypass`     | 仅跳过 Web 安全防护                    |
| 流量防护加白     | `flow_bypass`    | 仅跳过流量安全防护                     |

### 9.5 节点执行逻辑（waf.global_name_list）

```lua
-- 伪代码，源自 waf.lua
function global_name_list()
  for _, name_list_conf in ipairs(waf_global_name_list_data) do
    local name_list_name = name_list_conf['name_list_name']
    local name_list_rule = name_list_conf['name_list_rule']  -- JSON 数组
    local name_list_action = name_list_conf['name_list_action']
    local action_value = name_list_conf['action_value']

    -- 获取该名单的所有条目（Lua table，key 为 name_list_item）
    local name_list_item_data = waf_global_name_list_item_data[name_list_name]
    if name_list_item_data then
      -- 构造查找 key
      local item_value_table = {}
      local nil_exist = false
      for _, rule in ipairs(name_list_rule) do
        local return_value = request.get_args(rule['key'], rule['value'])
        if type(return_value) == "string" or type(return_value) == "number"
           or type(return_value) == "boolean" then
          table.insert(item_value_table, return_value)
        else
          nil_exist = true
          break  -- 任一字段为空，跳过
        end
      end

      if not nil_exist then
        local item_value = table.concat(item_value_table)
        -- 在条目表中查找
        if name_list_item_data[item_value] then
          -- 命中！记录日志并执行动作
          ngx.ctx.waf_log = {
            waf_module = "name_list",
            waf_policy = "名单防护-" .. name_list_name,
            waf_action = name_list_action,
            waf_extra = item_value,
          }
          -- 执行动作（watch 仅记录日志，不执行拦截）
          if name_list_action == "block" then
            unify_action.block(page_conf)
          elseif name_list_action == "reject_response" then
            unify_action.reject_response()
          elseif name_list_action == "network_block" then
            local src_ip = request.get_args("http_args", "src_ip")
            unify_action.network_block(config_info, src_ip, action_value)
          elseif name_list_action == "bot_check" then
            unify_action.bot_commit_auth()
            unify_action.bot_check_ip(action_value)
          elseif name_list_action == "all_bypass" then
            ngx.ctx.web_bypass = true
            ngx.ctx.flow_bypass = true
          elseif name_list_action == "web_bypass" then
            ngx.ctx.web_bypass = true
          elseif name_list_action == "flow_bypass" then
            ngx.ctx.flow_bypass = true
          end
        end
      end
    end
  end
end
```

### 9.6 名单与规则联合判断

**机制一：bypass 动作跳过规则模块**

名单命中后设置 bypass 标志，后续规则模块检测到 bypass 后直接跳过：

```
名单命中 → name_list_action = "web_bypass"
  → ngx.ctx.web_bypass = true
  → web_rule_protection 检测到 web_bypass，直接 return（跳过所有 Web 规则）
```

**机制二：global_name_list_result 传递匹配结果**

> 注意：当前节点源码中 `global_name_list_result` 的写入逻辑在 `request.lua` 中预留了读取接口（`get_global_name_list_result`），实际写入需在组件或自定义逻辑中实现。规则可通过 `global_name_list_result:<list_name>` 引用名单匹配结果。

规则匹配条件示例：
```json
[{
  "match_args": [{"key": "global_name_list_result", "value": "blacklist"}],
  "args_prepocess": ["none"],
  "match_operator": "status_check",
  "match_value": "exist"
}]
```

### 9.7 名单配置示例

**示例 1：IP 黑名单（永久封禁）**

```json
{
  "name_list_name": "ip_blacklist",
  "name_list_detail": "IP 黑名单，永久封禁",
  "name_list_rule": "[{\"key\":\"http_args\",\"value\":\"src_ip\"}]",
  "name_list_action": "block",
  "action_value": "",
  "name_list_expire": "false",
  "name_list_expire_time": "0"
}
```

条目添加：`name_list_item = "1.2.3.4"`

**示例 2：IP + 域名组合白名单（跳过 Web 防护）**

```json
{
  "name_list_name": "web_whitelist",
  "name_list_detail": "内网 IP 访问特定域名跳过 Web 防护",
  "name_list_rule": "[{\"key\":\"http_args\",\"value\":\"src_ip\"},{\"key\":\"header_args\",\"value\":\"host\"}]",
  "name_list_action": "web_bypass",
  "action_value": "",
  "name_list_expire": "false",
  "name_list_expire_time": "0"
}
```

条目添加：`name_list_item = "192.168.1.100www.test.com"`

**示例 3：临时封禁（1 小时）**

```json
{
  "name_list_name": "temp_block",
  "name_list_detail": "临时封禁名单",
  "name_list_rule": "[{\"key\":\"http_args\",\"value\":\"src_ip\"}]",
  "name_list_action": "network_block",
  "action_value": "3600",
  "name_list_expire": "true",
  "name_list_expire_time": "3600"
}
```

### 9.8 名单管理 API

#### 控制台 API（需登录态）

| 操作         | 接口路径                                    | 关键参数                                              |
|--------------|---------------------------------------------|-------------------------------------------------------|
| 名单列表     | `/waf/get_global_name_list_list`            | `page`                                                |
| 名单全量     | `/waf/api_get_global_name_list_list`        | 无                                                    |
| 查询单个名单 | `/waf/get_global_name_list`                 | `name_list_name`                                      |
| 创建名单     | `/waf/create_global_name_list`              | `name_list_name`, `name_list_detail`, `name_list_rule`, `name_list_action`, `action_value`, `name_list_expire`, `name_list_expire_time` |
| 编辑名单     | `/waf/edit_global_name_list`                | 同创建 + `name_list_name`（定位）                     |
| 删除名单     | `/waf/delete_global_name_list`              | `name_list_name`（同时删除所有条目）                  |
| 切换状态     | `/waf/edit_global_name_list_status`         | `name_list_name`, `status`                            |
| 调整优先级   | `/waf/exchange_global_name_list_priority`   | `name_list_name`, `type`, `exchange_name_list_name`   |

#### 条目管理 API（控制台）

| 操作         | 接口路径                                    | 关键参数                                              |
|--------------|---------------------------------------------|-------------------------------------------------------|
| 条目列表     | `/waf/get_name_list_item_list_list`         | `page`, `name_list_name`                              |
| 创建条目     | `/waf/create_global_name_list_item`         | `name_list_name`, `name_list_item`                    |
| 删除条目     | `/waf/delete_global_name_list_item`         | `name_list_name`, `name_list_item`                    |
| 搜索条目     | `/waf/search_global_name_list_item`         | `page`, `name_list_name`, `search_value`              |

#### 外部 API（waf_auth 鉴权，无需登录态）

| 操作         | 接口路径                                        | 关键参数                                              |
|--------------|-------------------------------------------------|-------------------------------------------------------|
| 获取条目     | `/api_get_name_list_item_list_list`             | `page`, `name_list_name`, `waf_auth`                  |
| 创建条目     | `/api/create_global_name_list_item`             | `name_list_name`, `name_list_item`, `waf_auth`        |
| 删除条目     | `/api/delete_global_name_list_item`             | `name_list_name`, `name_list_item`, `waf_auth`        |
| 搜索条目     | `/api/search_global_name_list_item`             | `page`, `name_list_name`, `search_value`, `waf_auth`  |

> 外部 API 适合自动化系统联动：SIEM 检测到攻击 → 调用 API 将攻击 IP 加入黑名单。

---

## 十、联合判断机制总览

### 10.1 四大模块的协作关系

```
请求到达
  │
  ├── 1. 防护组件（base_component）
  │     ├── 独立检测 → 直接执行动作（block 等）
  │     └── 设置 ngx.ctx.xxx → 供规则引用（ctx_args）
  │
  ├── 2. 名单防护（global_name_list）
  │     ├── 独立检测 → 直接执行动作（block/bypass 等）
  │     ├── 设置 bypass → 跳过后续规则模块
  │     └── 匹配结果 → 供规则引用（global_name_list_result）
  │
  ├── 3. 流量防护规则（flow_rule_protection）
  │     ├── 引用组件变量 → ctx_args:xxx
  │     ├── 引用名单结果 → global_name_list_result:xxx
  │     └── 频率统计 → 独立处置
  │
  └── 4. Web 防护规则（web_rule_protection）
        ├── 引用组件变量 → ctx_args:xxx
        ├── 引用名单结果 → global_name_list_result:xxx
        └── 即时匹配 → 独立处置
```

### 10.2 数据传递通道

| 来源模块       | 传递方式                          | 引用方式（规则 match_args）              |
|----------------|-----------------------------------|------------------------------------------|
| 防护组件       | `ngx.ctx.<key> = <value>`        | `{"key": "ctx_args", "value": "<key>"}` |
| 名单防护       | `ngx.ctx.global_name_list_result` | `{"key": "global_name_list_result", "value": "<list_name>"}` |
| 名单防护(bypass)| `ngx.ctx.web_bypass = true`      | 规则模块自动检测，无需配置               |
| 名单防护(bypass)| `ngx.ctx.flow_bypass = true`     | 规则模块自动检测，无需配置               |

### 10.3 典型联合判断场景

**场景 1：组件检测 + 规则拦截**

```
组件：检测到请求体含敏感数据 → ngx.ctx.sensitive_data = true
规则：match_args = ctx_args:sensitive_data, operator = status_check, value = exist
动作：block
```

**场景 2：名单加白 + 规则跳过**

```
名单：内网 IP 白名单 → name_list_action = web_bypass → ngx.ctx.web_bypass = true
规则：web_rule_protection 检测到 web_bypass → 直接 return（跳过所有 Web 规则）
```

**场景 3：名单标记 + 规则差异化处置**

```
名单：高危 IP 标记名单 → name_list_action = watch（仅记录，不拦截）
规则：match_args = global_name_list_result:high_risk, operator = status_check, value = exist
动作：bot_check（对名单命中的 IP 触发人机识别）
```

**场景 4：组件 + 名单 + 规则三级联动**

```
组件：分析请求特征 → ngx.ctx.risk_score = 85
名单：高风险 IP 名单 → 命中后 ngx.ctx.flow_bypass = false（不跳过）
规则：match_args = ctx_args:risk_score, operator = gt, value = 80
      AND match_args = global_name_list_result:high_risk_ip, operator = status_check, value = exist
动作：network_block（组件评分高 + 名单命中 → 网络封禁）
```

---

## 十一、白名单规则

### 11.1 功能定位

白名单规则是与 Web/流量防护规则配套的 **放行机制**。白名单先于规则检测执行，命中后设置 bypass 标志，跳过后续对应模块的所有规则检测。

**与规则的关系：**
- Web 白名单命中 → `ngx.ctx.web_bypass = true` → 跳过 Web 防护规则、Web 防护引擎、网页防篡改
- 流量白名单命中 → `ngx.ctx.flow_bypass = true` → 跳过流量防护规则、流量防护引擎、IP 区域封禁

**与名单防护的区别：**
- 名单防护（global_name_list）：基于键值查找，支持 bypass/block/bot_check 等多种动作，在规则之前执行
- 白名单规则（white_rule）：基于规则引擎匹配（同 Web/流量规则），仅支持放行动作，在对应规则模块之前执行

### 11.2 数据库表与字段

#### Web 白名单规则

专业版表名：`jxwaf_waf_group_web_white_rule`
标准版表名：`jxwaf_waf_web_white_rule`

| 字段             | 类型   | 说明                                         |
|------------------|--------|----------------------------------------------|
| `rule_name`      | string | 规则唯一标识                                 |
| `rule_detail`    | string | 规则描述                                     |
| `rule_matchs`    | string | 匹配条件（JSON 字符串，结构同 1.5）          |
| `rule_action`    | string | 执行动作：`web_bypass`（固定）               |
| `action_value`   | string | 动作附加参数（通常为空）                     |
| `rule_order_time`| int    | 优先级排序时间戳                             |
| `status`         | string | 启用状态                                     |
| `group_name`     | string | 所属分组（专业版）                           |
| `user_name`      | string | 所属用户                                     |

#### 流量白名单规则

专业版表名：`jxwaf_waf_group_flow_white_rule`
标准版表名：`jxwaf_waf_flow_white_rule`

| 字段             | 类型   | 说明                                         |
|------------------|--------|----------------------------------------------|
| `rule_name`      | string | 规则唯一标识                                 |
| `rule_detail`    | string | 规则描述                                     |
| `rule_matchs`    | string | 匹配条件（JSON 字符串，结构同 1.5）          |
| `rule_action`    | string | 执行动作：`flow_bypass`（固定）              |
| `action_value`   | string | 动作附加参数（通常为空）                     |
| `rule_order_time`| int    | 优先级排序时间戳                             |
| `status`         | string | 启用状态                                     |
| `group_name`     | string | 所属分组（专业版）                           |
| `user_name`      | string | 所属用户                                     |

> 白名单规则的 `rule_matchs` 结构与 Web/流量防护规则完全相同（见 1.5），使用同一套规则引擎匹配。

### 11.3 节点检测逻辑

```lua
-- 伪代码，源自 waf.lua

-- Web 白名单检测（在 web_rule_protection 之前执行）
function web_white_rule()
  for _, rule_conf in ipairs(web_white_rule_data) do
    if match_rules(rule_conf['rule_matchs']) then
      -- 记录日志
      ngx.ctx.waf_log = {
        waf_module = "web_white_rule",
        waf_policy = "Web白名单-" .. rule_conf['rule_name'],
        waf_action = "web_bypass",
      }
      -- 设置 bypass，后续 Web 规则模块自动跳过
      ngx.ctx.web_bypass = true
      return  -- 命中即终止，不再匹配后续白名单
    end
  end
end

-- 流量白名单检测（在 flow_rule_protection 之前执行）
function flow_white_rule()
  for _, rule_conf in ipairs(flow_white_rule_data) do
    if match_rules(rule_conf['rule_matchs']) then
      ngx.ctx.waf_log = {
        waf_module = "flow_white_rule",
        waf_policy = "流量白名单-" .. rule_conf['rule_name'],
        waf_action = "flow_bypass",
      }
      ngx.ctx.flow_bypass = true
      return
    end
  end
end
```

**关键点：**
- 白名单使用与防护规则相同的 `match_rules` 函数（见 waf_node_src/access_rule.lua）
- 命中后设置 bypass 标志并 **立即返回**（不再匹配后续白名单规则）
- bypass 标志在后续规则模块入口处被检测（`if web_bypass then return end`）
- 白名单不执行拦截动作，仅放行

### 11.4 白名单与防护规则的执行顺序

```
请求到达
  │
  ├── base_component          防护组件
  ├── global_name_list        名单防护（可设 bypass）
  │
  ├── flow_white_rule         流量白名单 ★ → 命中则 flow_bypass=true
  ├── flow_ip_region_block    IP区域封禁（检测 flow_bypass）
  ├── flow_rule_protection    流量防护规则（检测 flow_bypass）
  ├── flow_engine_protection  流量防护引擎（检测 flow_bypass）
  │
  ├── web_white_rule          Web白名单 ★ → 命中则 web_bypass=true
  ├── web_rule_protection     Web防护规则（检测 web_bypass）
  ├── web_engine_protection   Web防护引擎（检测 web_bypass）
  └── web_page_tamper_proof   网页防篡改（检测 web_bypass）
```

### 11.5 配置示例

**示例 1：Web 白名单 - 放行特定 IP 访问后台**

```json
{
  "rule_name": "allow_admin_ip",
  "rule_detail": "允许内网IP访问后台",
  "rule_matchs": "[{\"match_args\":[{\"key\":\"http_args\",\"value\":\"src_ip\"},{\"key\":\"http_args\",\"value\":\"path\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"ip_in_cidr\",\"match_value\":\"192.168.1.0/24\"}]",
  "rule_action": "web_bypass",
  "action_value": ""
}
```

> 注意：此示例中 match_args 有两个元素（src_ip 和 path），为 OR 关系。如需同时匹配 IP 和路径（AND），需拆为两个 rule_match。

**示例 2：Web 白名单 - 同时匹配 IP 和路径（AND）**

```json
{
  "rule_name": "allow_internal_admin",
  "rule_detail": "内网IP访问/admin路径放行",
  "rule_matchs": "[{\"match_args\":[{\"key\":\"http_args\",\"value\":\"src_ip\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"ip_in_cidr\",\"match_value\":\"192.168.1.0/24\"},{\"match_args\":[{\"key\":\"http_args\",\"value\":\"path\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"str_prefix\",\"match_value\":\"/admin\"}]",
  "rule_action": "web_bypass",
  "action_value": ""
}
```

**示例 3：流量白名单 - 放行健康检查请求**

```json
{
  "rule_name": "allow_health_check",
  "rule_detail": "放行负载均衡健康检查请求",
  "rule_matchs": "[{\"match_args\":[{\"key\":\"header_args\",\"value\":\"User-Agent\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"str_contain\",\"match_value\":\"HealthCheck\"}]",
  "rule_action": "flow_bypass",
  "action_value": ""
}
```

**示例 4：流量白名单 - 放行特定 API 的高频请求**

```json
{
  "rule_name": "allow_api_high_freq",
  "rule_detail": "放行内部系统API的高频请求",
  "rule_matchs": "[{\"match_args\":[{\"key\":\"http_args\",\"value\":\"path\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"str_prefix\",\"match_value\":\"/internal/api/\"},{\"match_args\":[{\"key\":\"header_args\",\"value\":\"X-Internal-Token\"}],\"args_prepocess\":[\"none\"],\"match_operator\":\"str_eq\",\"match_value\":\"secret_token_123\"}]",
  "rule_action": "flow_bypass",
  "action_value": ""
}
```

### 11.6 白名单控制台 API

#### Web 白名单 API（专业版）

| 操作         | 接口路径                                    | 关键参数                                                              |
|--------------|---------------------------------------------|-----------------------------------------------------------------------|
| 列表查询     | `/waf/get_group_web_white_rule_list`        | `page`, `group_name`                                                  |
| 查询单条     | `/waf/get_group_web_white_rule`             | `group_name`, `rule_name`                                             |
| 创建规则     | `/waf/create_group_web_white_rule`          | `group_name`, `rule_name`, `rule_detail`, `rule_matchs`, `rule_action`, `action_value` |
| 编辑规则     | `/waf/edit_group_web_white_rule`            | 同创建 + `rule_name`（定位）                                          |
| 删除规则     | `/waf/delete_group_web_white_rule`          | `group_name`, `rule_name`                                             |
| 切换状态     | `/waf/edit_group_web_white_rule_status`     | `group_name`, `rule_name`, `status`                                   |
| 调整优先级   | `/waf/exchange_group_web_white_rule_priority` | `group_name`, `rule_name`, `type`(top/exchange), `exchange_rule_name` |
| 备份导出     | `/waf/backup_group_web_white_rule`          | `group_name`, `rule_name_list`                                        |
| 恢复导入     | `/waf/load_group_web_white_rule`            | `group_name`, `rules`                                                 |

#### 流量白名单 API（专业版）

| 操作         | 接口路径                                    | 关键参数                                                              |
|--------------|---------------------------------------------|-----------------------------------------------------------------------|
| 列表查询     | `/waf/get_group_flow_white_rule_list`       | `page`, `group_name`                                                  |
| 查询单条     | `/waf/get_group_flow_white_rule`            | `group_name`, `rule_name`                                             |
| 创建规则     | `/waf/create_group_flow_white_rule`         | `group_name`, `rule_name`, `rule_detail`, `rule_matchs`, `rule_action`, `action_value` |
| 编辑规则     | `/waf/edit_group_flow_white_rule`           | 同创建 + `rule_name`（定位）                                          |
| 删除规则     | `/waf/delete_group_flow_white_rule`         | `group_name`, `rule_name`                                             |
| 切换状态     | `/waf/edit_group_flow_white_rule_status`    | `group_name`, `rule_name`, `status`                                   |
| 调整优先级   | `/waf/exchange_group_flow_white_rule_priority` | `group_name`, `rule_name`, `type`, `exchange_rule_name`               |
| 备份导出     | `/waf/backup_group_flow_white_rule`         | `group_name`, `rule_name_list`                                        |
| 恢复导入     | `/waf/load_group_flow_white_rule`           | `group_name`, `rules`                                                 |

> 标准版接口路径去掉 `group_` 前缀，且不需要 `group_name` 参数。
