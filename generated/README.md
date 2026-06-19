# generated/ — AI 生成的配置存放目录

> 本目录存放 AI（Claude Code / Trae 等）根据用户需求生成的 JXWAF 配置制品，包括规则、组件、名单及联合方案。
>
> 所有配置以可被 `waf_cli.py` 直接消费的格式存储，便于版本管理、复用和回滚。

---

## 目录结构

按 **需求/项目** 组织：每个需求一个独立目录，内部按制品类型细分。一个需求涉及的组件、规则、名单集中管理，便于复用、回滚和版本追踪。

```
generated/
├── <project_name>/              # 每个需求/项目一个目录（小写下划线，如 api_test_id_validate）
│   ├── components/              # 该项目涉及的防护组件
│   │   └── <component_name>/
│   │       ├── code.lua         # 组件 Lua 源码
│   │       ├── code.base64      # Base64 编码版本（直接用于 API 上传）
│   │       └── conf.json        # 组件配置（conf 参数）
│   ├── rules/                   # 该项目涉及的防护规则
│   │   ├── web_rules/           # Web 防护规则（.json）
│   │   ├── flow_rules/          # 流量防护规则（.json）
│   │   ├── web_white_rules/     # Web 白名单规则（.json）
│   │   └── flow_white_rules/    # 流量白名单规则（.json）
│   └── name_lists/              # 该项目涉及的名单
│       └── <list_name>/
│           ├── meta.json        # 名单元信息（rule/action/expire）
│           └── items.txt        # 条目列表（每行一个）
└── README.md
```

> **项目命名**：小写下划线，反映需求本质（如 `api_test_id_validate`、`log4j_protection`、`cc_attack_defense`）。  
> **按需创建子目录**：项目内只创建实际用到的子目录（如纯组件需求无需建 `rules/`）。

---

## 文件命名规范

所有制品路径统一前缀：`generated/<project_name>/`，`<project_name>` 即需求项目名（小写下划线）。

### 规则文件

```
generated/<project_name>/rules/<module>/<rule_name>.json
```

| 模块               | 路径（项目内）                       |
|--------------------|--------------------------------------|
| Web 防护规则       | `rules/web_rules/`                   |
| 流量防护规则       | `rules/flow_rules/`                  |
| Web 白名单规则     | `rules/web_white_rules/`             |
| 流量白名单规则     | `rules/flow_white_rules/`            |

**文件名** = `rule_name`（去掉 `.json` 后缀即为规则名），如 `block_log4j_jndi_injection.json`。

### 组件目录

```
generated/<project_name>/components/<component_name>/
├── code.lua      # Lua 源码（人类可读，便于审查和修改）
├── code.base64   # Lua 源码的 Base64 编码版本（直接用于 API 上传，每次修改 code.lua 后须重新生成）
└── conf.json     # 组件配置 JSON
```

**目录名** = 组件名（`name` 参数）。

**Base64 生成命令**（跨平台，使用 Python）：
```bash
python3 -c "import base64; print(base64.b64encode(open('generated/<project_name>/components/<name>/code.lua','rb').read()).decode('ascii'))" > generated/<project_name>/components/<name>/code.base64
```

### 名单目录

```
generated/<project_name>/name_lists/<list_name>/
├── meta.json     # 名单定义（rule/action/expire 等）
└── items.txt     # 条目列表，每行一个（便于批量 add-item）
```

**目录名** = 名单名（`name_list_name` 参数）。

---

## 文件内容格式

### 规则 JSON 文件

存储创建规则所需的完整参数，可直接用于 `waf_cli.py` 创建：

```json
{
  "rule_name": "block_log4j_jndi_injection",
  "rule_detail": "防护Log4j JNDI注入漏洞攻击(CVE-2021-44228)",
  "rule_matchs": [
    {
      "match_args": [
        {"key": "http_args", "value": "request_uri"},
        {"key": "http_args", "value": "raw_header"}
      ],
      "args_prepocess": ["uriDecode"],
      "match_operator": "rx",
      "match_value": "\\$\\{[^}]*jndi:|jndi:(ldap|rmi|dns)://"
    }
  ],
  "rule_action": "watch",
  "action_value": "",
  "group_name": "default"
}
```

> 流量规则额外包含 `filter`、`entity`、`stat_time`、`exceed_count`、`block_time` 字段。
> 白名单规则的 `rule_action` 固定为 `web_bypass` / `flow_bypass`，无需在文件中指定。

### 组件 code.lua

标准 Lua 源码，遵循 AGENTS.md 中的组件开发规范（节点已 pcall 包裹 check 调用，组件内无需再包 pcall）：

```lua
local _M = {}

function _M.check(conf_data)
    if conf_data == nil then
        return
    end
    -- 检测逻辑
    -- 需与规则联合时：ngx.ctx.<var> = <value>
    return
end

return _M
```

### 组件 conf.json

```json
{
  "param1": "value1",
  "patterns": ["sqlmap", "nikto"]
}
```

### 名单 meta.json

```json
{
  "name_list_name": "ip_blacklist",
  "name_list_detail": "IP黑名单",
  "name_list_rule": [{"key": "http_args", "value": "src_ip"}],
  "name_list_action": "block",
  "action_value": "",
  "name_list_expire": "false",
  "name_list_expire_time": "0"
}
```

### 名单 items.txt

每行一个条目，`#` 开头为注释：

```
# IP 黑名单条目
1.2.3.4
5.6.7.8
10.0.0.1
```

---

## 部署流程

以下命令中 `<project>` 为项目目录名，`<component_name>` / `<rule_name>` / `<list_name>` 为对应制品名。

### 1. 部署单个规则

```bash
# 读取 JSON 文件并创建规则
python3 tools/waf_cli.py web-rule create \
  --group default \
  --name $(jq -r .rule_name generated/<project>/rules/web_rules/<rule_name>.json) \
  --detail "$(jq -r .rule_detail generated/<project>/rules/web_rules/<rule_name>.json)" \
  --matchs "$(jq -c .rule_matchs generated/<project>/rules/web_rules/<rule_name>.json)" \
  --action $(jq -r .rule_action generated/<project>/rules/web_rules/<rule_name>.json)
```

### 2. 部署组件

**方式一：使用 Lua 源码文件（推荐，自动 Base64 编码）**
```bash
python3 tools/waf_cli.py component create \
  --name <component_name> \
  --detail "组件描述" \
  --code-file generated/<project>/components/<component_name>/code.lua \
  --conf "$(cat generated/<project>/components/<component_name>/conf.json)"
```

**方式二：使用预生成的 Base64 文件（适合 CI/CD 或离线上传）**
```bash
python3 tools/waf_cli.py component create \
  --name <component_name> \
  --detail "组件描述" \
  --code-base64 "$(cat generated/<project>/components/<component_name>/code.base64)" \
  --conf "$(cat generated/<project>/components/<component_name>/conf.json)"
```

### 3. 部署名单

```bash
# 创建名单
python3 tools/waf_cli.py name-list create \
  --name $(jq -r .name_list_name generated/<project>/name_lists/<list_name>/meta.json) \
  --detail "$(jq -r .name_list_detail generated/<project>/name_lists/<list_name>/meta.json)" \
  --rule "$(jq -c .name_list_rule generated/<project>/name_lists/<list_name>/meta.json)" \
  --action $(jq -r .name_list_action generated/<project>/name_lists/<list_name>/meta.json)

# 批量添加条目
while IFS= read -r item; do
  [[ "$item" =~ ^# ]] && continue
  [[ -z "$item" ]] && continue
  python3 tools/waf_cli.py name-list add-item --name <list_name> --item "$item"
done < generated/<project>/name_lists/<list_name>/items.txt
```

### 4. 部署完整项目（联合方案）

项目目录本身即为联合方案的归档。按组件 → 名单 → 规则的顺序依次部署项目内所有制品，组件先于规则执行（节点 access 阶段顺序保证）。

---

## 维护原则

1. **文件即配置**：每个 JSON/Lua 文件应包含完整可部署的配置，不依赖外部上下文
2. **项目隔离**：每个需求独立目录，跨需求复用时复制而非引用
3. **命名一致**：文件名/目录名与 `rule_name` / `name` / `name_list_name` 严格一致
4. **watch 优先**：新规则 `rule_action` 初始设为 `watch`，验证无误报后改为 `block`
5. **同步更新**：修改线上配置后，同步更新本目录中的对应文件，保持一致
6. **Base64 同步**：组件 `code.lua` 修改后，必须重新生成 `code.base64`，保持两者一致
