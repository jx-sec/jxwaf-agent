# 名单 / 网站接入与配置模块规范

> 字段与枚举已对齐控制台与节点引擎行为（三版本引擎一致）。
>
> 防护组件（Lua 开发）已独立为 [component_dev.md](component_dev.md)。

## 一、名单防护（name-list）

### 字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `name_list_name` | string | 名单名（唯一） |
| `name_list_detail` | string | 描述 |
| `name_list_rule` | string | 名单规则（JSON 字符串，**扁平 `[{key, value}]` 数组**，结构见下） |
| `name_list_action` | string | 命中处置动作（枚举见下表） |
| `action_value` | string | 动作值：`bot_check` 时为人机识别方式；`network_block` 时为封禁秒数；其余为空 |
| `name_list_expire` | string | 条目是否自动过期 `"true"`/`"false"` |
| `name_list_expire_time` | string | 过期秒数（expire=true 时必填，正整数） |

### name_list_rule 结构（与 rule_matchs 不同！）

**扁平 `[{key, value}]` 数组**——引擎逐项取值后**无分隔符拼接**为条目查找键（如 `src_ip` + `host` 拼成 `1.1.1.1www.test.com`），在条目哈希表中做**纯等值查找**（无前缀/正则/范围匹配）：

```json
[{"key": "http_args", "value": "src_ip"}]
```

| key | value 语义 |
|---|---|
| `http_args` | 固定枚举（同 rule_dev.md 的 15 个：`path`/`query_string`/`method`/`src_ip`/`host`/`user_agent`/`cookie`/`referer`/`raw_header`/`high_risk_header` 等） |
| `header_args` | 任意头名（`host`/`cookie`/`referer`/`user_agent`/自定义） |
| `cookie_args` / `uri_args` / `post_args` / `json_post_args` / `ctx_args` | 自定义参数名 |

例：IP 名单用 `[{"key":"http_args","value":"src_ip"}]`，条目为 IP 值；UA 名单用 `[{"key":"header_args","value":"user_agent"}]`。

**拼接限制**：任一项取值为 nil/table 则放弃本次查找（仅接受 string/number/boolean）；多字段拼接时注意歧义（`1.1.1.1` + `www.a.com` 与 `1.1.1.1www.a.com` 其他拆分组合可能碰撞）。

### name_list_action 枚举

| 动作 | 说明 |
|---|---|
| `block` | 阻断请求 |
| `reject_response` | 拒绝响应（444 关闭连接） |
| `watch` | 观察模式（仅记录日志） |
| `bot_check` | 人机识别（action_value：`auto`/`slipper`/`puzzle`/`words`） |
| `network_block` | 网络封禁（action_value=封禁秒数） |
| `all_bypass` | **放行**：Web+流量安全防护全加白 |
| `web_bypass` | **放行**：仅 Web 安全防护加白 |
| `flow_bypass` | **放行**：仅流量安全防护加白 |

条目操作（无需 generate，直接写入命令）：

```
jxwaf-cli namelist item-add --params '{"name_list_name":"malicious_ip","name_list_item":"1.2.3.4"}' --apply
jxwaf-cli namelist item-del --params '{"name_list_name":"malicious_ip","name_list_item":"1.2.3.4"}' --apply
```

- 条目已存在时 item-add 仅刷新过期时间（幂等）；条目过期时间从父名单的 expire/expire_time 继承计算
- 删除名单级联删除其所有条目

### 使用模式

- **直接封禁/放行**：名单 action 直接处置，无需规则（执行先于所有规则，纯哈希查找，性能最好）
- **标记+规则处置**：名单 action=watch，规则用 `global_name_list_result` 引用名单名（`status_check exist`）决定最终动作（见 rule_dev.md 名单联动示例）
- 临时封禁场景必须 `name_list_expire="true"` + 过期时间，避免条目永久残留

## 二、网站接入（website / domain）

### 域名创建字段（generate domain）

| 字段 | 说明 |
|---|---|
| `domain` | 域名 |
| `detail` | 域名描述（必填） |
| `http` / `https` | `"true"`/`"false"`（不能同时为 false） |
| `ssl_domain` | 关联 SSL 证书域名（HTTPS 时必填非空，需先在证书管理创建证书；http-only 时输出空串占位） |
| `source_ip` | 回源地址数组（必填；IP 或域名，域名自动 DNS 解析） |
| `source_http_port` / `source_https_port` | 回源端口（正整数，默认 80/443；https 未显式指定时 **443**，不允许留空） |
| `origin_protocol` | `http`/`https`/`follow` |
| `balance_type` | `round_robin`/`ip_hash`；**默认不配置（空串），除非用户主动指定** |
| `pre_proxy` | 前置代理 `"true"`/`"false"` |
| `real_ip_conf` | 真实 IP 头：`XRI`（X-Real-IP）/`XFF`；**默认不配置（空串），除非用户主动指定**（仅前置代理场景需要） |
| `connect_timeout` / `send_timeout` / `read_timeout` | 超时（秒，正整数） |

租户参数自动注入：专业版自动带 `group_name`，云WAF 主账号自动带 `sub_user_name`（域名类虽路径无中缀但 body 必带），无需手写。

### 接入流程（云WAF）

1. 查询网站接入配置：`jxwaf-cli website access list`（admin）或直接创建域名
2. `generate domain` 生成 → `apply --apply` 创建；创建后控制台/DNS 平台配置 CNAME 指向返回的 `cname`
3. 证书与域名必须匹配（HTTPS 时）

### 安全的删除顺序

删除域名前先处理依赖：规则/白名单关联该域名会失效。测试环境闭环：防护配置 → verify → cleanup 清理测试规则 → 域名如需清理最后删。

## 三、网页防篡改（tamper）

走 `jxwaf-cli tamper create --params '{...}'` 直接下发（字段与服务端 check_param 一致）：

| 字段 | 说明 |
|---|---|
| `rule_name` | 规则名（唯一，删除/启停/查询的主键） |
| `rule_detail` | 规则描述 |
| `rule_matchs` | 匹配条件数组（结构同 Web 规则 rule_matchs） |
| `cache_page_url` | 被防护页面的 URL |
| `cache_page_content` | 页面缓存内容（防篡改基线） |
| `cache_content_type` | 内容类型 |

启停：`{"rule_name":"x","status":"true"|"false"}`。命中动作固定为 `page_tamper_proof`（返回缓存基线页面）。

## 四、SSL 证书（ssl）

走 `jxwaf-cli ssl create --params '{...}'`（标准版/专业版为全局模块，云WAF 归属子账号自动注入 `sub_user_name`）：

| 字段 | 说明 |
|---|---|
| `ssl_domain` | 证书域名（唯一，查询/删除主键） |
| `detail` | 描述（必填） |
| `private_key` | PEM 私钥内容 |
| `public_key` | PEM 证书内容 |

注意：私钥属于敏感材料，params 文件放 `/tmp` 或 `output/`（已 gitignore），勿提交仓库；域名 HTTPS 接入前需先创建匹配的证书。泛域名证书自动签发（request_wildcard_cert）为控制台/异步任务流，CLI 暂不覆盖。

## 五、域名组（group，仅专业版）

| 字段 | 说明 |
|---|---|
| `group_name` | 组名（唯一；创建组会自动初始化该组的引擎防护/区域封禁配置） |
| `group_detail` | 组描述（edit 仅可改此字段） |

删除域名组会**级联删除组下所有域名与防护配置**，务必先确认影响范围。专业版创建域名前必须先建域名组（CLI `--group` / 环境默认 `group_name` 引用）。

## 六、自定义配置（custom；标准版不支持）

四类模块同构（`custom request-header|response-header|response-content|upstream`），租户参数自动注入：

| 模块 | create/edit 必填字段 |
|---|---|
| request-header | `rule_name` / `rule_detail` / `rule_matchs` / `filter` / `header_name` / `header_value` |
| response-header | 同 request-header |
| response-content | `rule_name` / `rule_detail` / `rule_matchs` / `filter` / `content_type` / `return_code` / `return_content` |
| upstream | `rule_name` / `rule_detail` / `rule_matchs` / `filter` / `source_ip` / `source_http_port` / `source_https_port` |

`filter` 为生效范围（如 `web`），`rule_matchs` 结构同 Web 规则。专业版归域名组、云WAF归子账号。

## 七、缓存管理（cache；仅云WAF）

| 模块 | create 必填字段 |
|---|---|
| policy（缓存策略） | `rule_name` / `rule_detail` / `rule_matchs` / `cache_key` |
| no-cache（不缓存） | `rule_name` / `rule_detail` / `rule_matchs` |
| bypass（缓存绕过） | `rule_name` / `rule_detail` / `rule_matchs` |

缓存任务（warmup/refresh）：create/list/detail/delete；CDN 预热/刷新与缓存开关仅子账号模式（`cache cdn preheat|refresh --params '{"urls":"..."}'`，最多 100 个 URL）。

## 八、运维模块

### 网络封禁（network，三版本）
- 封禁：`network create --params '{"ip":"1.2.3.4","status":"1","expire_time":3600}'`（status：1 封禁 / 2 解封；expire_time 单位秒）
- 解封：`edit` 改 status=2；总开关：`status`（查询）/ `status-set`（block|closed）
- 应急场景：确认攻击 IP 后可直接 block（经用户确认）

### 子账号（subaccount，仅云WAF主账号）
- create：`{"sub_user_name":"x","user_password":"...","sub_otp_auth":"true|false","website_access_conf":"接入配置名"}`（自动初始化防护配置）
- `waf-auth` 重置子账号凭据（旧值立即失效）；`otp-reset` 重置 OTP（返回新密钥）
- delete 级联删除 17 张关联表并清理云 DNS A 记录

### 系统配置（sysconf，标准版不支持）
- `log`：日志远程/调试开关与日志服务器地址
- `report`：ClickHouse 连接配置（SOC 统计的数据源前置）；`report test` 验证连通性
- `page`：自定义拦截页/404 页（HTML 内容）
- `backup`/`load`：整库备份/恢复（load 高危：先清空后覆盖，务必 dry-run 确认）

### SOC 查询（soc，三版本）
- 统计/事件/用量类参数：`from_time`/`to_time`（YYYY-MM-DD HH:MM:SS 必填），可选 `domain`（`*.` 前缀通配）
- 误报处理闭环：`soc model list` 查 AI 判定记录 → `soc model result` 标记误报 → `soc model white-add` 加 Token 白名单