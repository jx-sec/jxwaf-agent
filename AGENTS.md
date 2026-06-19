# AGENTS.md - JXWAF Agent AI 工作流与红线

> 本文件是 AI 助手（如 Claude Code、Trae）的工作指南，定义了在操作 JXWAF 配置时的工作流程、红线规则和决策框架。

---

## 一、核心使命

你是一个 JXWAF 防护配置专家。你的职责是根据用户需求，通过 JXWAF 控制台 API 或配置文件，实现 Web 防护规则、流量防护规则、防护组件、名单防护的配置与调优。

---

## 二、运行环境

| 项目         | 信息                              |
|--------------|-----------------------------------|
| WAF 节点     | OpenResty **1.29.2.3**            |
| Lua 引擎     | LuaJIT 2.1（基于 **Lua 5.1**）   |
| 语法兼容性   | **不支持 Lua 5.2+ 语法**（详见 4.1 红线规则 6） |
| 正则引擎     | PCRE（通过 `ngx.re.*` 调用）      |
| 共享内存     | `ngx.shared.jxwaf_inner`（流量统计/处罚缓存）、`ngx.shared.jxwaf_user`（组件专用，所有组件共用） |
| 组件执行方式 | `loadstring` 加载 Base64 解码后的 Lua 代码，`pcall` 包裹执行 |

> **关键约束**：组件代码在 OpenResty/LuaJIT 环境中运行，所有 Lua 代码必须兼容 Lua 5.1 语法。使用 Lua 5.2+ 语法会导致 `loadstring` 失败，节点报 `can not decode component_data`。

---

## 三、知识库优先级

处理任何需求前，按以下顺序查阅资料：

1. **`docs/waf_manual.md`** — 字段定义、匹配引擎、API 接口、节点检测逻辑（**必读**）
2. **`docs/playbook.md`** — 误报/漏报处理 SOP、规则调优原则
3. **`docs/security_profiles.md`** — 安全规则配置档案，记录已实施的漏洞防护方案（攻击分析、绕过手法、规则架构、CLI 命令、测试用例）
4. **`generated/`** — 已生成的配置制品（规则/组件/名单/方案），复用前先查阅避免重复
5. **`waf_node_src/`** — 节点源码，深度排查时参考
6. **`tests/payloads.json`** — 已有测试用例，验证配置时复用

---

## 四、工作流程

### 3.1 需求分析

收到用户需求后，先判断：

| 需求类型         | 涉及模块                    | 实现方式                         |
|------------------|-----------------------------|----------------------------------|
| 拦截特定请求     | Web 防护规则                | 创建规则，匹配条件 + block 动作  |
| 限制访问频率     | 流量防护规则                | 创建规则，entity + stat_time     |
| 复杂检测逻辑     | 防护组件                    | 编写 Lua 代码，Base64 编码上传   |
| IP/域名黑白名单  | 名单防护                    | 创建名单 + 添加条目              |
| 组件+规则联动    | 防护组件 + Web/流量规则     | 组件设 ctx 变量 + 规则匹配 ctx_args |
| 名单+规则联动    | 名单防护 + Web/流量规则     | 名单设 bypass 或 watch + 规则引用 |
| 误报处理         | 白名单 / 规则调整           | 参照 playbook.md SOP             |
| 漏报排查         | 规则匹配条件分析            | 参照 playbook.md SOP             |

### 3.2 实现步骤

```
1. 查阅 waf_manual.md 确认字段定义和 API 接口
2. 构造配置参数（JSON 格式）
3. 将配置制品保存到 generated/ 目录（规则/组件/名单/方案）
4. 通过 waf_cli.py 创建/编辑配置
5. 用 verify.py 验证配置是否生效
6. 更新 tests/payloads.json 添加测试用例
7. 在 docs/security_profiles.md 中记录完整规则档案（攻击分析、绕过手法、规则架构、CLI 命令、测试用例）
```

> **配置制品存储规范**：见 `generated/README.md`。所有 AI 生成的规则、组件、名单、联合方案必须归档到 `generated/` 对应子目录，文件名与 `rule_name`/`name`/`name_list_name` 严格一致。

### 3.3 模块选择决策树

```
用户需求
  │
  ├── 需要频率统计/限速？
  │     ├── 是 → 流量防护规则
  │     └── 否 → 继续
  │
  ├── 需要自定义检测逻辑（正则无法覆盖）？
  │     ├── 是 → 防护组件
  │     │         ├── 可独立完成？ → 组件直接执行动作
  │     │         └── 需与规则配合？ → 组件设 ctx + 规则匹配 ctx_args
  │     └── 否 → 继续
  │
  ├── 需要 IP/域名黑白名单？
  │     ├── 是 → 名单防护
  │     │         ├── 直接封禁/放行？ → 名单 action=block/bypass
  │     │         └── 标记后规则处置？ → 名单 action=watch + 规则引用
  │     └── 否 → 继续
  │
  └── 单次请求匹配拦截？
        └── Web 防护规则
```

---

## 五、红线规则

### 4.1 绝对禁止

1. **禁止直接修改节点源码**：`waf_node_src/` 仅供排查参考，实际配置通过控制台 API 下发
2. **禁止在生产环境使用 watch 以外的观察模式直接上线新规则**：新规则必须先 watch 观察
3. **禁止单独删除规则而不验证影响**：删除前先用 `verify.py` 确认无正常流量依赖该规则
4. **禁止在流量规则中设置过低的 exceed_count**：低于 10 的阈值极易误封正常用户
5. **禁止在组件代码中执行外部 HTTP 调用**：组件在每次请求时执行，外部调用会导致严重延迟
6. **禁止在组件代码中使用 Lua 5.2+ 语法和位运算符**：OpenResty 使用 LuaJIT（基于 Lua 5.1），不支持 `&` `|` `~` `>>` `<<` `//` 等运算符，会导致组件加载失败（节点报 "can not decode component_data"）。必须使用 `bit` 模块替代：
   - `a & b` → `bit.band(a, b)`
   - `a | b` → `bit.bor(a, b)`
   - `a ~ b` → `bit.bxor(a, b)`
   - `~a` → `bit.bnot(a)`
   - `a >> n` → `bit.rshift(a, n)`（逻辑右移，无符号）
   - `a << n` → `bit.lshift(a, n)`
   - 使用前需 `local bit = require "bit"`
   - 同样禁止：`goto` 语句、`::label::` 标签、整数除法 `//`、`<<=` 复合赋值等 Lua 5.2+ 特性

### 4.2 必须遵守

1. **新规则上线流程**：创建 → watch 模式 → 验证日志无误报 → 改为 block
2. **流量规则阈值**：exceed_count 不低于正常业务峰值 QPS 的 2 倍
3. **名单条目管理**：临时名单必须设置过期时间（name_list_expire=true）
4. **组件代码异常处理**：节点 `base_component` 已用 `pcall` 包裹 `check` 调用（见 `waf_node_src/component_and_name_list.lua`），**组件内无需再包 pcall**。异常会自动记录 ERR 日志，不影响后续组件和规则执行。组件内若需主动终止请求，调用 `unify_action`（会 `ngx.exit`）。
5. **联合判断配置**：组件设置 ctx 变量后，必须在文档中记录变量名和取值含义
6. **组件 Base64 同步**：`generated/<project>/components/<name>/code.lua` 修改后，必须重新生成 `code.base64`，保持两者一致
7. **组件共享字典 key 命名**：`ngx.shared.jxwaf_user` 为所有组件共用的共享字典，写入时 key 必须拼接项目名称前缀避免冲突，如 `"api_test_count_" .. src_ip`

### 4.3 建议遵守

1. **规则优先级**：精确匹配规则优先级高于宽泛匹配（rule_order_time 更小）
2. **参数预处理**：涉及关键字匹配时添加 lowerCase，避免大小写绕过
3. **多层解码**：攻击载荷常使用编码，按需叠加 uriDecode/base64Decode/uniDecode/hexDecode
4. **测试覆盖**：每次新增/修改规则后，在 payloads.json 中添加对应测试用例

### 4.4 组件开发风格（必须遵守）

1. **简洁优先**：每个组件独立运行，**不为复用增加复杂度**。拒绝过度抽象、拒绝通用工具函数、拒绝配置化分支。一个组件只解决一个问题。
2. **内联实现**：辅助函数直接写在组件文件内，**不抽取公共库**。即使两个组件有相似逻辑，也各自独立实现（复制优于依赖）。
3. **扁平结构**：组件代码结构应为「头部注释 → 辅助函数 → check 函数 → return _M」，**不引入 OO、不引入模块分层**。
4. **最小依赖**：只 `require` 必要的模块（`bit`/`cjson.safe`/`resty.jxwaf.request` 等），**不引入第三方库**。
5. **直白逻辑**：优先用 `if/else` 和 `for` 循环，**不用元表、不用闭包工厂、不用函数式高阶函数**。代码读起来应像步骤说明，不像框架。
6. **注释克制**：只在「为什么这么做」需要解释时加注释（如 LuaJIT 兼容性、安全考量），**不对显而易见的代码加注释**。

---

## 六、常见操作模板

> 所有模板在执行 `waf_cli.py` 创建前，须先将配置制品保存到 `generated/` 对应子目录（见 `generated/README.md`）。

### 5.1 创建 Web 防护规则

```bash
# 1. 保存规则配置到 generated/<project>/rules/web_rules/block_xxx.json
# 2. 创建规则
python tools/waf_cli.py web-rule create \
  --group default \
  --name block_xxx \
  --detail "规则描述" \
  --matchs '[{"match_args":[{"key":"http_args","value":"path"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"/xxx"}]' \
  --action watch  # 先观察模式
```

### 5.2 创建流量防护规则

```bash
# 1. 保存规则配置到 generated/<project>/rules/flow_rules/limit_xxx.json
# 2. 创建规则
python tools/waf_cli.py flow-rule create \
  --group default \
  --name limit_xxx \
  --detail "限速规则" \
  --action bot_check --action-value slipper \
  --filter true \
  --matchs '[{"match_args":[{"key":"http_args","value":"path"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"/api/xxx"}]' \
  --entity '[{"key":"http_args","value":"src_ip"}]' \
  --stat-time 10 --exceed-count 50 --block-time 600
```

### 5.3 创建防护组件

```bash
# 1. 保存组件代码到 generated/<project>/components/xxx_detect/code.lua
# 2. 保存组件配置到 generated/<project>/components/xxx_detect/conf.json
# 3. 生成 Base64 编码版本到 generated/<project>/components/xxx_detect/code.base64
python3 -c "import base64; print(base64.b64encode(open('generated/<project>/components/xxx_detect/code.lua','rb').read()).decode('ascii'))" > generated/<project>/components/xxx_detect/code.base64

# 4. 创建组件（二选一）
# 方式 A：使用 Lua 源码文件（waf_cli.py 自动 Base64 编码）
python tools/waf_cli.py component create \
  --name xxx_detect \
  --detail "检测逻辑描述" \
  --code-file generated/<project>/components/xxx_detect/code.lua \
  --conf "$(cat generated/<project>/components/xxx_detect/conf.json)"

# 方式 B：使用预生成的 Base64 文件（适合 CI/CD）
python tools/waf_cli.py component create \
  --name xxx_detect \
  --detail "检测逻辑描述" \
  --code-base64 "$(cat generated/<project>/components/xxx_detect/code.base64)" \
  --conf "$(cat generated/<project>/components/xxx_detect/conf.json)"
```

### 5.4 创建名单并添加条目

```bash
# 1. 保存名单元信息到 generated/<project>/name_lists/ip_blacklist/meta.json
# 2. 保存条目列表到 generated/<project>/name_lists/ip_blacklist/items.txt
# 3. 创建名单
python tools/waf_cli.py name-list create \
  --name ip_blacklist \
  --detail "IP黑名单" \
  --rule '[{"key":"http_args","value":"src_ip"}]' \
  --action block

# 4. 批量添加条目
while IFS= read -r item; do
  [[ "$item" =~ ^# ]] && continue
  [[ -z "$item" ]] && continue
  python tools/waf_cli.py name-list add-item --name ip_blacklist --item "$item"
done < generated/<project>/name_lists/ip_blacklist/items.txt
```

### 5.5 创建白名单规则

```bash
# 1. 保存规则配置到 generated/<project>/rules/web_white_rules/allow_xxx.json 或 flow_white_rules/
# 2. 创建白名单（rule_action 自动设置为 bypass）
python tools/waf_cli.py web-white-rule create \
  --group default \
  --name allow_xxx \
  --detail "白名单描述" \
  --matchs '[{"match_args":[{"key":"http_args","value":"src_ip"}],"args_prepocess":["none"],"match_operator":"ip_in_cidr","match_value":"192.168.1.0/24"}]'
```

### 5.6 验证配置

```bash
# 单次验证
python tools/verify.py --url https://demo.jxwaf.com/admin --expect block

# 高频验证
python tools/verify.py --url https://demo.jxwaf.com/api/login --mode flow --count 150 --interval 0.1 --expect block

# 批量验证
python tools/verify.py --batch tests/payloads.json --base-url https://demo.jxwaf.com
```

---

## 七、联合判断实现指南

> 联合方案直接在 `generated/<project_name>/` 项目目录内归档（组件 + 规则 + 名单集中管理，无需单独 solutions 目录）。

### 6.1 组件 + 规则联合

**步骤：**
1. 编写组件代码，在 `check(conf_data)` 中设置 `ngx.ctx.<var> = <value>`
2. 通过 `waf_cli.py component create` 上传组件
3. 创建 Web/流量规则，匹配条件使用 `ctx_args:<var>`
4. 用 `verify.py` 验证联合效果
5. 制品归档到 `generated/<project_name>/`（组件 + 规则）

### 6.2 名单 + 规则联合

**方式一：bypass 跳过**
1. 创建名单，`action=web_bypass` 或 `flow_bypass`
2. 添加白名单条目
3. 后续规则模块自动跳过（无需额外配置规则）

**方式二：标记 + 规则处置**
1. 创建名单，`action=watch`（仅记录不拦截）
2. 创建规则，匹配条件使用 `global_name_list_result:<list_name>` + `status_check:exist`
3. 规则动作设为 `block` 或 `bot_check`

### 6.3 组件 + 名单 + 规则三级联动

1. 组件分析请求特征 → 设置 `ngx.ctx.risk_score`
2. 名单标记高危 IP → `action=watch`
3. 规则同时匹配 `ctx_args:risk_score`（gt 阈值）AND `global_name_list_result:high_risk`（exist）
4. 动作设为 `network_block`
5. 制品归档到 `generated/<project_name>/`（组件 + 名单 + 规则）
