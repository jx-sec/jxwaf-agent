# JxWAF 运维 SOP

本手册覆盖 Web 防护规则与流量防护规则的常见运维场景：误报处理、漏报排查、规则调优、频率限速调整。

---

## 一、误报处理

### 1.1 现象

正常业务请求被 WAF 拦截，返回拦截页面（默认 403）或触发人机识别。

### 1.2 排查步骤

**步骤 1：定位拦截来源**

在「运营中心 → 日志查询」中按被拦截的 URL/IP/时间筛选，查看日志详情中的字段：

| 字段        | 判断依据                                              |
|-------------|-------------------------------------------------------|
| `waf_module`| `web_rule_protection` → Web 防护规则误报              |
|             | `flow_rule_protection` → 流量防护规则误报             |
|             | `web_engine_protection` → AI/语义引擎误报             |
|             | `flow_engine_protection` → 流量引擎（IP限制等）误报   |
| `waf_policy`| 具体规则名称，如 `Web防护规则-block_admin`            |
| `waf_action`| `block` / `reject_response` / `bot_check`             |

**步骤 2：确认匹配条件**

根据 `waf_policy` 中的规则名，在控制台查看该规则的 `rule_matchs` 配置，对照请求日志中的实际参数值，确认是哪个匹配条件误命中。

**步骤 3：处置（按影响程度选择）**

| 方案               | 适用场景                         | 操作                                                         |
|--------------------|----------------------------------|--------------------------------------------------------------|
| 临时切换观察模式   | 需保留规则但暂停拦截             | 编辑规则，`rule_action` 改为 `watch`                         |
| 调整匹配条件       | 匹配范围过宽                     | 修改 `rule_matchs`，缩小匹配范围（如改 `str_contain` 为 `str_eq`） |
| 添加白名单         | 特定 IP/参数需放行               | 新增 Web 白名单规则或流量白名单规则                           |
| 加入名单加白       | 需跳过整个防护模块               | 通过名单 API 添加 `web_bypass` / `flow_bypass` 条目          |
| 禁用规则           | 紧急情况                         | 编辑规则状态 `status=false`                                  |

### 1.3 误报处理 SOP（Web 防护规则）

```
确认误报（日志 waf_module=web_rule_protection）
  │
  ├── 紧急 → 规则状态改为 false（或 action 改为 watch）
  │
  ├── 分析匹配条件
  │     ├── match_value 过宽？ → 收窄（如 /admin 改为 /admin/login）
  │     ├── args_prepocess 缺失？ → 添加 lowerCase 统一小写
  │     └── match_operator 不当？ → str_contain 改为 str_eq
  │
  └── 验证 → 用 verify.py 复现请求确认放行
```

### 1.4 误报处理 SOP（流量防护规则）

```
确认误报（日志 waf_module=flow_rule_protection）
  │
  ├── 紧急 → 规则状态改为 false
  │
  ├── 分析触发原因
  │     ├── exceed_count 过低？ → 提高阈值
  │     ├── stat_time 过短？ → 延长统计窗口
  │     ├── block_time 过长？ → 缩短处罚时间
  │     └── entity 范围不当？ → 增加 path 维度避免全局计数
  │
  ├── 特定 IP 放行 → 添加流量白名单规则（ip_in_cidr 匹配）
  │
  └── 验证 → 用 verify.py 发送正常频率请求确认不触发
```

---

## 二、漏报排查

### 2.1 现象

已知攻击请求未被拦截，`waf_action=pass`。

### 2.2 排查步骤

**步骤 1：确认请求是否经过 WAF**

检查日志中是否存在该请求记录。若无记录，检查域名接入配置、回源地址、WAF 前代理设置。

**步骤 2：确认是否被白名单跳过**

查看日志 `waf_module` 是否为 `web_white_rule` / `flow_white_rule` / `name_list`，且 `waf_action` 为 `web_bypass` / `flow_bypass` / `all_bypass`。

**步骤 3：确认规则是否启用**

- 规则 `status` 是否为 `true`
- 规则优先级 `rule_order_time` 是否在生效规则之前被其他规则匹配（规则匹配后立即终止）

**步骤 4：分析匹配条件未命中原因**

| 可能原因                 | 排查方法                                                     |
|--------------------------|--------------------------------------------------------------|
| 匹配参数取错             | 对照 `match_args.key/value` 与实际请求，确认取值正确         |
| 参数处理缺失             | 攻击 payload 经编码（URL/Base64/Unicode/Hex），需添加对应 `args_prepocess` |
| 匹配方式不当             | 正则 `rx` 未覆盖变体；`str_contain` 大小写敏感需配合 `lowerCase` |
| 流量规则 filter 配置错误 | `filter=true` 但匹配条件未命中，导致不进入统计               |
| 流量规则未达阈值         | `exceed_count` 过高或 `stat_time` 内请求数不足               |

### 2.3 漏报修复 SOP

```
确认漏报（日志 waf_action=pass 且应为攻击）
  │
  ├── 检查白名单 → 是否被 bypass 跳过
  │
  ├── 检查规则状态 → status 是否 true
  │
  ├── 复现请求 → 用 verify.py 发送攻击 payload
  │     ├── 被拦截 → 问题已解决（可能是偶发）
  │     └── 未拦截 → 进入匹配条件分析
  │
  ├── 匹配条件分析
  │     ├── 打印 request.get_args 实际取值
  │     ├── 确认 args_prepocess 是否解码充分
  │     └── 确认 match_operator 是否覆盖变体
  │
  └── 修复 → 调整 rule_matchs / 新增规则 → 验证
```

---

## 三、规则调优

### 3.1 Web 防护规则调优原则

1. **精确匹配优先**：能用 `str_eq` 不用 `str_contain`，能用 `str_prefix` 不用 `rx`
2. **小写化处理**：涉及关键字匹配时，`args_prepocess` 添加 `lowerCase`，`match_value` 统一小写
3. **多层解码**：攻击载荷常使用 URL/Base64/Unicode/Hex 编码，按需叠加 `uriDecode`/`base64Decode`/`uniDecode`/`hexDecode`
4. **观察先行**：新规则先设 `rule_action=watch`，观察日志无误报后再改 `block`

### 3.2 流量防护规则调优原则

1. **entity 维度选择**：
   - 全局限速：`src_ip` 单维度
   - 接口限速：`src_ip + path` 双维度（避免不同接口互相影响）
   - 会话限速：`cookie_args:session_id` 或 `src_ip + path`
2. **阈值设置**：
   - 参考正常业务峰值 QPS，`exceed_count` 设为峰值的 2-3 倍
   - `stat_time` 建议为 10-60 秒，过短易抖动，过长反应慢
3. **处罚方式选择**：
   - 一般 CC：`bot_check`（人机识别，对业务影响小）
   - 恶意攻击：`block` 或 `network_block`
   - 紧急防护：`reject_response`（不消耗出口带宽）

### 3.3 优先级调整

- 高优先级规则（精确匹配、紧急封禁）`rule_order_time` 设小
- 低优先级规则（宽泛匹配、观察模式）`rule_order_time` 设大
- 使用 `exchange_priority` 接口的 `top` 操作快速置顶

---

## 四、频率限速调整

### 4.1 调整流程

```
1. 评估当前限速效果
   ├── 日志查询 waf_module=flow_rule_protection，统计触发次数
   └── 业务侧反馈是否有正常用户被限

2. 调整参数
   ├── 误限正常用户 → 提高 exceed_count 或延长 stat_time
   ├── 攻击未拦截 → 降低 exceed_count 或缩短 stat_time
   └── 处罚过重 → block_time 缩短或改 bot_check

3. 验证
   ├── verify.py --mode flow --count 150 --interval 0.1  模拟高频
   └── 确认触发阈值与处罚动作符合预期
```

### 4.2 紧急解封

若 IP 被流量规则处罚（缓存命中），可通过以下方式紧急解封：

1. **规则层面**：临时将规则 `status` 改为 `false`（影响所有 IP）
2. **名单层面**：将该 IP 加入 `flow_bypass` 名单（仅放行该 IP）
3. **缓存层面**：需等待 `block_time` 过期自动解封（节点侧无直接清除共享内存的 API）

---

## 五、常用排查命令

### 5.1 日志查询字段对照

| 排查目标         | 日志过滤条件                                              |
|------------------|-----------------------------------------------------------|
| Web 规则拦截     | `waf_module=web_rule_protection`                           |
| 流量规则拦截     | `waf_module=flow_rule_protection`                          |
| 被白名单跳过     | `waf_action` 含 `bypass`                                  |
| 特定 IP 行为     | `src_ip=x.x.x.x`                                          |
| 特定接口         | `request_uri` 模糊匹配                                    |

### 5.2 verify.py 验证命令

```bash
# 验证 Web 规则（单次请求）
python tools/verify.py --url https://demo.jxwaf.com/admin --expect block

# 验证 Web 规则（带攻击 payload）
python tools/verify.py --url "https://demo.jxwaf.com/?id=1' OR 1=1--" --expect block

# 验证流量规则（高频请求）
python tools/verify.py --url https://demo.jxwaf.com/api/login --mode flow --count 150 --interval 0.1 --expect block

# 验证白名单放行
python tools/verify.py --url https://demo.jxwaf.com/admin --header "X-Real-IP: 192.168.1.100" --expect pass
```

### 5.3 waf_cli.py 管理命令

```bash
# 查询 Web 防护规则列表
python tools/waf_cli.py web-rule list --group default

# 创建 Web 防护规则
python tools/waf_cli.py web-rule create --group default --name block_admin \
  --matchs '[{"match_args":[{"key":"http_args","value":"path"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"/admin"}]' \
  --action block

# 查询流量防护规则列表
python tools/waf_cli.py flow-rule list --group default

# 临时禁用规则
python tools/waf_cli.py web-rule status --group default --name block_admin --status false

# 紧急加白名单
python tools/waf_cli.py name-list add-item --name whitelist --item 1.2.3.4
```

---

## 六、防护组件运维 SOP

### 6.1 组件开发流程

```
1. 需求分析
   ├── 规则引擎能否覆盖？ → 是 → 用 Web/流量规则
   └── 否 → 需要自定义逻辑 → 防护组件

2. 编写组件代码
   ├── 定义 check(conf_data) 函数
   ├── 防御性检查 conf_data 是否 nil
   ├── 节点 base_component 已用 pcall 包裹 check 调用，组件内无需再包 pcall
   ├── 独立完成？ → 直接调用 unify_action
   └── 需与规则配合？ → 设置 ngx.ctx.xxx

3. LuaJIT 兼容性检查（重要！）
   ├── 确认未使用 Lua 5.2+ 运算符（& | ~ >> << //）
   ├── 位运算改用 bit 模块（bit.band/bit.bor/bit.lshift/bit.rshift）
   ├── 确认未使用 goto/标签/整数除法等 5.2+ 语法
   └── 详见 waf_manual.md 8.3 节 LuaJIT 兼容性要求

4. 测试组件代码
   ├── 本地 Lua 环境验证语法（推荐用 luajit -bl 检查）
   └── Base64 编码后上传

5. 上线流程
   ├── 创建组件（status=true）
   ├── 观察日志 waf_module=base_component
   ├── 验证检测效果（verify.py）
   └── 如有联合规则，同步创建并验证
```

### 6.2 组件加载失败排查（can not decode component_data）

**现象：** 组件上传后节点报 `can not decode component_data`，组件未执行。

**根本原因：** 组件代码使用了 LuaJIT 不支持的 Lua 5.2+ 语法，`loadstring` 编译失败。

**运行环境：** OpenResty 1.29.2.3 + LuaJIT 2.1（基于 Lua 5.1），详见 `waf_manual.md` 8.3 节。

**排查步骤：**

```
1. 检查节点 error.log
   ├── 搜索 "can not decode component_data" 或 "loadstring"
   └── 确认具体语法错误信息（行号/错误类型）

2. 按下表逐项排查不兼容语法
   ├── 8.3.1 位运算符（& | ~ >> << 及复合赋值）
   ├── 8.3.2 控制流（goto / ::label:: / continue）
   ├── 8.3.3 数值类型（// 整数除法 / 1LL 64位整数字面量）
   ├── 8.3.4 字符串与 table（string.pack / table.move / utf8.*）
   ├── 8.3.5 元方法（__band / __bor / __shl 等不触发）
   └── 8.3.6 其他（xpcall 传参 / load vs loadstring / __pairs）

3. 替换为 LuaJIT 兼容写法（见下方速查表）

4. 重新 Base64 编码上传
   ├── python3 -c "import base64; ..." > code.base64
   └── 通过 waf_cli.py component edit 更新
```

**LuaJIT 兼容性速查表（完整版见 waf_manual.md 8.3 节）：**

| 错误现象 | 原因 | 替代方案 |
|----------|------|----------|
| `unexpected symbol near '&'` | 按位与 | `bit.band(a, b)` |
| `unexpected symbol near '\|'` | 按位或 | `bit.bor(a, b)` |
| `unexpected symbol near '~'` | 按位异或/非 | `bit.bxor(a, b)` / `bit.bnot(a)` |
| `unexpected symbol near '>'` | 右移 `>>` | `bit.rshift(a, n)` |
| `unexpected symbol near '<'` | 左移 `<<` | `bit.lshift(a, n)` |
| `'//' expected near ...` | 整数除法 | `math.floor(a / b)` |
| `no visible label 'xxx'` | goto 语句 | 重构为循环/函数/`do break end` |
| `attempt to call field 'pack' (a nil value)` | string.pack | 手动拼接字节 |
| `attempt to call field 'move' (a nil value)` | table.move | 手动 for 循环复制 |
| `attempt to call field 'tointeger' (a nil value)` | math.tointeger | `type(x)=="number" and x==math.floor(x)` |
| `malformed number near '1LL'` | 64位整数字面量 | 直接用 number |
| `'continue' expected near ...` | continue 关键字 | `do break end` 或 `if not cond then ... end` |

**快速验证脚本（检查 LuaJIT 兼容性）：**
```bash
# 检查是否包含 Lua 5.2+ 不兼容语法（排除注释行）
grep -nE '^[^--]*[&|~]|>>|<<|//|goto |::|continue|\.\.=|LL|ULL|string\.pack|table\.move|math\.tointeger|utf8\.' generated/components/<name>/code.lua || echo "未发现不兼容语法"
```

**本地预检（推荐，上传前必做）：**
```bash
# 若本地有 luajit，可直接检查语法
luajit -bl generated/components/<name>/code.lua > /dev/null && echo "语法 OK" || echo "语法错误"
```

### 6.3 组件误报处理

```
组件误报（日志 waf_module=base_component）
  │
  ├── 紧急 → 组件 status 改为 false
  │
  ├── 分析误报原因
  │     ├── 检测条件过宽？ → 修改 code 中的匹配逻辑
  │     ├── conf 配置不当？ → 调整 conf 参数
  │     └── ctx 变量被规则误用？ → 检查引用该 ctx 的规则
  │
  └── 修复 → 重新 Base64 编码上传 → 验证
```

### 6.4 组件性能排查

组件在每次请求时执行，若出现性能问题：

1. **检查日志**：搜索 `component error` 确认是否有异常
2. **检查耗时操作**：组件内是否有 `ngx.re.match`（复杂正则）、`string.find`（大字符串）等
3. **优化建议**：
   - 简化正则表达式
   - 避免在组件中读取完整请求体（`raw_body`）
   - 短路返回：条件不满足时尽早 return

### 6.5 共享字典 key 冲突排查

**现象：** 组件间数据互相覆盖，计数/缓存异常。

**根本原因：** `ngx.shared.jxwaf_user` 是所有组件共用的共享字典，key 未拼接项目名称前缀导致冲突。

**排查步骤：**

```
1. 检查组件代码中的 key 构造
   ├── grep -n 'jxwaf_user' generated/<project>/components/*/code.lua
   └── 确认每个 key 都以项目名开头

2. 验证 key 命名规范
   ├── 格式: <project_name>_<purpose>_<key>
   ├── 正确: "api_test_count_" .. src_ip
   └── 错误: "count_" .. src_ip  (缺少项目前缀)

3. 检查 TTL 设置
   ├── set/incr 时是否指定了过期时间
   └── 未设置 TTL 会导致内存无限增长
```

**修复示例：**
```lua
-- 错误：key 无项目前缀，易与其他组件冲突
local count = jxwaf_user:incr("count_" .. src_ip, 1, 0, 60)

-- 正确：拼接项目名前缀
local count = jxwaf_user:incr("api_test_count_" .. src_ip, 1, 0, 60)
```

**查看共享字典状态（运维排查）：**
```bash
# 查看共享字典使用情况（需在节点服务器执行）
curl http://127.0.0.1/nginx_status | grep jxwaf_user
# 或通过 resty 命令
resty -e 'local s = ngx.shared.jxwaf_user; print(s:capacity(), s:free_space())'
```

---

## 七、名单防护运维 SOP

### 7.1 名单创建流程

```
1. 确定名单类型
   ├── 黑名单（封禁） → action=block / network_block
   ├── 白名单（放行） → action=all_bypass / web_bypass / flow_bypass
   └── 标记名单（联合规则） → action=watch

2. 确定 name_list_rule（查找 key 构造方式）
   ├── 仅 IP → [{"key":"http_args","value":"src_ip"}]
   ├── IP + 域名 → [{"key":"http_args","value":"src_ip"},{"key":"header_args","value":"host"}]
   └── Cookie + 路径 → [{"key":"cookie_args","value":"session_id"},{"key":"http_args","value":"path"}]

3. 确定过期策略
   ├── 永久名单 → name_list_expire=false
   └── 临时名单 → name_list_expire=true, name_list_expire_time=3600（秒）

4. 创建名单 → 添加条目 → 验证
```

### 7.2 名单条目管理

**添加条目：**
```bash
# 控制台 API
python tools/waf_cli.py name-list add-item --name ip_blacklist --item 1.2.3.4

# 外部 API（自动化联动，需 waf_auth）
python tools/waf_cli.py name-list add-item --name ip_blacklist --item 1.2.3.4 --use-api
```

**批量添加（脚本示例）：**
```bash
# 从文件批量添加
while IFS= read -r ip; do
  python tools/waf_cli.py name-list add-item --name ip_blacklist --item "$ip" --use-api
done < ip_list.txt
```

**搜索条目：**
```bash
python tools/waf_cli.py name-list search-item --name ip_blacklist --search "192.168"
```

### 7.3 名单误报处理

```
名单误封正常 IP
  │
  ├── 紧急解封
  │     ├── 删除条目 → waf_cli.py name-list del-item --name xxx --item 1.2.3.4
  │     └── 或临时禁用名单 → waf_cli.py name-list status --name xxx --status false
  │
  ├── 分析原因
  │     ├── name_list_rule 拼接逻辑有误？ → 检查查找 key 构造
  │     ├── 条目值格式不对？ → 如 IP+域名组合需完整拼接
  │     └── 过期时间设置不当？ → 临时名单过期后条目失效
  │
  └── 修复 → 验证
```

### 7.4 名单与规则联合排查

**bypass 不生效：**
1. 确认名单 `status=true`
2. 确认名单 `name_list_action` 为 `all_bypass`/`web_bypass`/`flow_bypass`
3. 确认条目存在且未过期（`name_list_item_expire_time`）
4. 确认 `name_list_rule` 构造的查找 key 与请求实际值匹配
5. 查看日志 `waf_module=name_list`，确认是否命中

**联合规则不生效：**
1. 确认名单命中（日志有 `waf_module=name_list` 记录）
2. 确认规则匹配条件中 `global_name_list_result:<list_name>` 的 list_name 与名单名一致
3. 确认规则的 `match_operator` 为 `status_check`，`match_value` 为 `exist`

---

## 八、联合判断排查 SOP

### 8.1 组件 + 规则联合不生效

```
1. 确认组件已执行
   ├── 日志 waf_module=base_component 有记录？
   │     ├── 无 → 组件 status=false 或 code 加载失败
   │     └── 有 → 继续
   │
2. 确认 ctx 变量已设置
   ├── 在组件代码中添加 ngx.log(ngx.ERR, "ctx xxx = " .. tostring(ngx.ctx.xxx))
   ├── 查看节点 error.log 确认变量值
   │
3. 确认规则匹配条件正确
   ├── match_args.key = "ctx_args"
   ├── match_args.value = 组件中设置的变量名
   ├── match_operator 与变量值类型匹配（字符串用 str_eq，数字用 gt/lt）
   └── match_value 与组件设置的值一致
```

### 8.2 名单 + 规则联合不生效

```
1. 确认名单命中
   ├── 日志 waf_module=name_list 有记录？
   │     ├── 无 → 名单未命中，检查 name_list_rule 和条目
   │     └── 有 → 确认 waf_action 是否为预期动作
   │
2. bypass 模式
   ├── 名单 action = web_bypass/flow_bypass？
   ├── 规则模块日志是否显示 bypass？
   └── 若规则仍执行 → 检查 ngx.ctx.web_bypass/flow_bypass 是否被后续模块重置
   │
3. 标记模式
   ├── 名单 action = watch（仅记录）？
   ├── 规则引用 global_name_list_result:<list_name>？
   └── 规则 match_operator = status_check, match_value = exist？
```

---

## 九、白名单规则运维 SOP

### 9.1 白名单适用场景

白名单规则与防护规则配套使用，命中后设置 `ngx.ctx.web_bypass` / `ngx.ctx.flow_bypass = true`，后续对应规则模块自动跳过。常见场景：

| 场景                     | 模块           | 匹配条件示例                                                       |
|--------------------------|----------------|--------------------------------------------------------------------|
| 内网 IP 放行后台         | Web 白名单     | `src_ip` ip_in_cidr `192.168.0.0/16`                              |
| 健康检查请求放行         | 流量白名单     | `User-Agent` str_contain `HealthCheck`                            |
| 内部系统高频 API         | 流量白名单     | `path` str_prefix `/internal/api/` AND `X-Internal-Token` str_eq  |
| 合作伙伴回调接口         | Web 白名单     | `path` str_eq `/api/callback` AND `src_ip` ip_in_cidr `1.2.3.0/24`|
| 扫描器误报放行           | Web 白名单     | `User-Agent` str_contain `Nessus`                                 |

### 9.2 白名单 vs 名单 bypass 选择

| 维度         | 白名单规则                                  | 名单 bypass                                |
|--------------|---------------------------------------------|--------------------------------------------|
| 匹配方式     | 规则引擎（match_args + operator + value）   | 键值查找（name_list_rule 构造 key）        |
| 灵活度       | 高（支持 AND/OR、正则、CIDR、Header 等）    | 低（仅精确匹配拼接 key）                   |
| 条目管理     | 无条目概念，规则即配置                      | 支持条目增删改查、过期时间                 |
| 动态更新     | 需编辑规则                                  | 通过 API 增删条目，实时生效                |
| 适用场景     | 复杂匹配条件（多字段 AND、CIDR、正则）      | 大量 IP/域名精确放行，需频繁增删           |

**选择建议：**
- 单条复杂匹配条件 → 白名单规则
- 大量 IP 需要批量放行 → 名单 bypass
- 两者可共存，先匹配名单（global_name_list），再匹配白名单（white_rule）

### 9.3 白名单创建流程

```
1. 确定放行范围
   ├── Web 模块放行 → web-white-rule
   └── 流量模块放行 → flow-white-rule

2. 构造匹配条件
   ├── 单条件放行（如仅 IP） → 单个 rule_match
   ├── 多条件 AND（如 IP + 路径） → 多个 rule_match
   └── 多字段 OR（如 src_ip 或 X-Forwarded-For） → 单个 rule_match 多个 match_args

3. 创建白名单规则
   ├── rule_action 自动设置为 web_bypass / flow_bypass
   └── status 默认 true

4. 验证
   ├── 用 verify.py 发送匹配请求 → 确认日志 waf_action=bypass
   └── 用 verify.py 发送不匹配请求 → 确认规则正常执行
```

### 9.4 白名单误放行排查

**现象：** 攻击请求被放行，日志显示 `waf_module=web_white_rule` / `flow_white_rule`，`waf_action=web_bypass` / `flow_bypass`。

```
排查步骤：
  │
  ├── 1. 定位误放行的白名单规则
  │     └── 日志 waf_policy 字段含规则名（如 "Web白名单-allow_admin_ip"）
  │
  ├── 2. 分析匹配条件
  │     ├── 匹配范围过宽？ → 如 ip_in_cidr 0.0.0.0/0
  │     ├── match_value 错误？ → 如 CIDR 写错
  │     └── args_prepocess 缺失？ → 大小写不一致导致意外命中
  │
  ├── 3. 处置
  │     ├── 紧急 → status 改为 false
  │     ├── 收窄匹配条件 → 添加 AND 约束（如增加 path 匹配）
  │     └── 删除规则 → 若不再需要
  │
  └── 4. 验证 → verify.py 确认攻击请求恢复拦截
```

### 9.5 白名单常用命令

```bash
# 查询 Web 白名单列表
python tools/waf_cli.py web-white-rule list --group default

# 创建 Web 白名单（内网 IP 放行后台）
python tools/waf_cli.py web-white-rule create --group default \
  --name allow_admin_ip \
  --detail "内网IP放行后台" \
  --matchs '[{"match_args":[{"key":"http_args","value":"src_ip"}],"args_prepocess":["none"],"match_operator":"ip_in_cidr","match_value":"192.168.1.0/24"},{"match_args":[{"key":"http_args","value":"path"}],"args_prepocess":["none"],"match_operator":"str_prefix","match_value":"/admin"}]'

# 创建流量白名单（健康检查放行）
python tools/waf_cli.py flow-white-rule create --group default \
  --name allow_health_check \
  --detail "放行健康检查请求" \
  --matchs '[{"match_args":[{"key":"header_args","value":"User-Agent"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"HealthCheck"}]'

# 临时禁用白名单
python tools/waf_cli.py web-white-rule status --group default --name allow_admin_ip --status false

# 调整白名单优先级（置顶）
python tools/waf_cli.py web-white-rule priority --group default --name allow_admin_ip --type top

# 删除白名单
python tools/waf_cli.py web-white-rule delete --group default --name allow_admin_ip
```

### 9.6 白名单与名单 bypass 共存排查

当同时配置了名单 bypass 和白名单规则时，执行顺序为：

```
global_name_list（名单 bypass） → white_rule（白名单） → rule_protection（防护规则）
```

**bypass 不生效排查：**
1. 检查名单是否命中（日志 `waf_module=name_list`，`waf_action` 含 bypass）
2. 若名单未命中，检查白名单是否命中（日志 `waf_module=web_white_rule`/`flow_white_rule`）
3. 若两者都未命中，检查规则模块是否正常执行
4. 注意：名单 bypass 设置 `ngx.ctx.web_bypass` 后，白名单仍会执行（但不会再设置 bypass，因已为 true）

