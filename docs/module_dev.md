# 名单 / 组件 / 网站接入规范

## 一、名单防护（name-list）

### 字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `name_list_name` | string | 名单名（唯一） |
| `name_list_detail` | string | 描述 |
| `name_list_rule` | string | 名单规则（JSON 字符串） |
| `name_list_action` | string | 命中处置动作：`block` 直接封禁 / `watch` 仅标记 / 放行类 |
| `action_value` | string | 动作值（一般为空） |
| `name_list_expire` | string | 条目是否自动过期 `"true"`/`"false"` |
| `name_list_expire_time` | string | 过期秒数（expire=true 时必填） |

条目操作（无需 generate，直接写入命令）：

```
jxwaf-cli namelist item-add --params '{"name_list_name":"malicious_ip","name_list_item":"1.2.3.4"}' --apply
jxwaf-cli namelist item-del --params '{"name_list_name":"malicious_ip","name_list_item":"1.2.3.4"}' --apply
```

### 使用模式

- **直接封禁/放行**：名单 action 直接处置，无需规则
- **标记+规则处置**：名单 action=watch，规则用 `global_name_list_result` 引用名单名（`status_check exist`）决定最终动作（见 rule_dev.md 名单联动示例）
- 条目已存在时 item-add 仅刷新过期时间（幂等）

## 二、防护组件（component）

### 字段与生成方式

```
jxwaf-cli generate component --params '{"config":{"name":"...","detail":"...","code":"<Lua源码>","conf":"{}"}}'
```

| 字段 | 说明 |
|---|---|
| `name` | 组件名（唯一） |
| `detail` | 描述 |
| `code` | Lua 源码（generate 自动 base64 编码）或 `code_base64`（已编码，二选一） |
| `conf` | 组件配置（JSON 字符串，按组件协议约定） |

### Lua 红线（必须遵守，generate 会校验拦截）

- **LuaJIT 兼容**：禁止 Lua 5.2+ 语法：位运算 `& | ~ >> <<`（用 `bit` 模块：`bit.band`/`bit.bor`/`bit.lshift`）、`//`、`goto`
- 组件内不要 `pcall`（节点已包裹）
- 组件执行动作：防护动作写入 `ngx.ctx.jxwaf_protection =\{ action="block", value=... \}`；频率统计结果可写 `ngx.ctx` 供规则 `ctx_args` 引用
- 加载失败报 "can not decode component_data" 时：检查 base64 / Lua 5.2+ 语法 / 括号匹配

## 三、网站接入（website / domain）

### 域名创建字段（generate domain）

| 字段 | 说明 |
|---|---|
| `domain` | 域名 |
| `http` / `https` | `"true"`/`"false"` |
| `ssl_domain` | 关联 SSL 证书域名（HTTPS 前先在证书管理创建证书） |
| `source_ip` | 回源地址数组（必填；IP 或域名，域名自动 DNS 解析） |
| `source_http_port` / `source_https_port` | 回源端口（默认 80/443） |
| `origin_protocol` | `http`/`https`/`follow` |
| `balance_type` | `round_robin`/`ip_hash` |
| `pre_proxy` | 前置代理 `"true"`/`"false"` |
| `real_ip_conf` | 真实 IP 头：`XRI`（X-Real-IP）/`XFF` |
| `connect_timeout` / `send_timeout` / `read_timeout` | 超时（秒） |

### 接入流程（云WAF）

1. 查询网站接入配置：`jxwaf-cli website access list`（admin）或直接创建域名
2. `generate domain` 生成 → `apply --apply` 创建；创建后控制台/DNS 平台配置 CNAME 指向返回的 `cname`
3. 证书与域名必须匹配（HTTPS 时）

### 安全的删除顺序

删除域名前先处理依赖：规则/白名单关联该域名会失效。测试环境闭环：防护配置 → verify → cleanup 清理测试规则 → 域名如需清理最后删。