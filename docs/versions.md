# 三版本差异说明

jxwaf-cli 对接 JXWAF 标准版 / 专业版 / 云WAF。**版本差异由 CLI adapter 层自动处理**：同一命令面，内部切换认证、端点命名与租户参数。本文档说明能力边界，帮助判断某需求在某版本是否可实现。

## 对比总览

| 维度 | 标准版 | 专业版 | 云WAF |
|---|---|---|---|
| 定位 | 单团队自部署 | 单团队+域名组 | 多租户 SaaS |
| 认证 | 环境变量 token 等值校验 | DB 反查账号 waf_auth | DB 反查 + 子账号双层 token |
| 租户组织 | 无 | `group_name` 域名组 | 主账号 + `sub_user_name` 子账号 |
| 防护端点 | `get_web_rule_...` | `get_group_web_rule_...` | admin: `get_sub_account_web_rule_...`；user: `/user/get_web_rule_...` |
| 域名组 | 无 | 有（域名创建前必须先建组） | 无（子账号即租户边界） |
| SSL 证书 | 全局模块（无租户） | 全局模块（无租户） | 归属子账号（admin 需 `--sub-user`） |
| 网站接入配置 | 无（仅域名） | 无（仅域名） | 有（资源配额、DNS 接入） |
| 组件 | 有 | 有 | 仅主账号可管理 |
| 名单 | 有 | 有 | admin 有；user 仅可查列表+加条目 |
| CDN/缓存 | 无 | 部分 | 完整 |
| 子账号体系 | 无 | 无 | 有 |

## 各版本操作要点

### 标准版
- `config set --version standard`：waf_auth 为部署时环境变量 `WAF_AUTH` 的值
- 无租户概念，防护操作直接配置

### 专业版
- `config set --version professional --group-name <默认组>`；每命令可用 `--group` 覆盖
- 所有防护类操作必须指定域名组；域名/组件/名单为全局
- **官方测试沙盒（`sandbox` 命令组默认目标）**：固定共享账号（`waf-demo.jxwaf.com`），`sandbox init` 自动发现域名组；所有人共用，验证后自动回到空环境

### 云WAF
- 自建云主账号（admin 模式）：`config set` 只配 `waf_auth` + `--sub-user-name`；防护操作自动注入子账号名，组件/名单/网站接入全功能
- 云WAF 用户（子账号）模式：环境同时配置 `waf_auth`（主账号）与 `sub_waf_auth`（子账号），组件与网站接入配置不可管理
- 管理 API 需在部署侧启用：`ADMIN_API_ENABLE=true` + `ADMIN_API_WHITELIST`（IP/域名；`"*"` 或空为全放行）；用户侧接口由 `USER_API_ENABLE`/`USER_API_WHITELIST` 控制

## 能力矩阵（CLI 操作 × 版本）

| 操作 | 标准 | 专业 | 云WAF 主账号 | 云WAF 子账号 |
|---|---|---|---|---|
| rule web/flow 查询/写入 | ✅ | ✅（组） | ✅（自动注入子账号名） | ✅ |
| rule web/flow engine 引擎配置 | ✅ | ✅（组） | ✅ | ✅ |
| rule flow region 区域封禁 | ✅ | ✅（组） | ✅ | ✅ |
| white web/flow 白名单 | ✅ | ✅（组） | ✅ | ✅ |
| tamper 网页防篡改 | ✅ | ✅（组） | ✅ | ✅ |
| priority 优先级调整 | ✅ | ✅（组） | ✅ | ✅（名单/组件除外） |
| backup/load 配置迁移 | ✅ | ✅ | ✅ | ❌ |
| hub-load/hub-export 配置中心 | ✅ | ✅ | ✅ | ❌ |
| ssl 证书管理（含泛域名申请） | ✅（全局） | ✅（全局） | ✅（子账号） | ✅ |
| ssl global 全局 SSL 防护 | ❌ | ❌ | ✅ | ❌ |
| group 域名组管理 | ❌ | ✅ | ❌ | ❌ |
| network 网络封禁 IP | ✅ | ✅ | ✅ | ❌ |
| soc log/event/stats/model 查询 | ✅¹ | ✅ | ✅ | 部分² |
| soc usage 用量统计 | ✅ | ✅ | ✅ | ✅ |
| subaccount 子账号管理 | ❌ | ❌ | ✅ | ❌ |
| custom 自定义配置 | ❌ | ✅（组） | ✅ | ✅（无备份/加载） |
| cache 缓存策略/任务 | ❌ | ❌ | ✅ | ✅（无备份/加载） |
| cache switch/CDN 预热刷新 | ❌ | ❌ | ❌ | ✅ |
| sysconf 系统配置 | ❌ | ✅ | ✅ | 仅报表配置只读 |
| monitor 节点监控 | ✅ | ✅ | ✅ | ❌ |
| namelist 完整管理 | ✅ | ✅ | ✅ | 部分（查列表+加条目） |
| component 管理 | ✅ | ✅ | ✅ | ❌ |
| website 域名管理 | ✅ | ✅ | ✅ | ✅ |
| website access 接入配置 | ❌ | ❌ | ✅（含 CNAME/连通测试） | ❌ |

¹ 标准版 Web 攻击统计命名与接口集不同（`get_web_attack_*`，无 geoip），由 adapter overrides 自动映射；流量攻击统计标准版不支持。
² 子账号模式支持攻击统计/事件（`/user/get_*_attack_*`），不支持 AI 模型与网络封禁。

## 明确排除的端点（不纳入 CLI）

| 类别 | 端点 | 理由 |
|---|---|---|
| 主账号认证 | account_login/regist/logout/OTP/get_waf_auth/edit_waf_auth/generate_api_key 等 9 个 | 控制台 session 鉴权体系，与 CLI 的 waf_auth Header 模型冲突；注册/OTP 属一次性人工操作 |
| api_get_* 批量 | api_get_domain_list / api_get_sub_account_list 等 | 节点/服务内部拉取专用，分页 list 已覆盖管理需求 |
| 节点侧上报 | waf_monitor / sync_network_ip / network_block（节点调用版）/ waf_update / model_update / token_ai_analysis / sync_usage_stat | 由 jxwaf_node 内部调用（body waf_auth 鉴权），非管理面操作；管理侧封禁用 `network create` |
| 服务间接口 | api_get_pending_cert_tasks 等 4 个 ssl_cert_service 接口 | ssl_cert_service Go 服务专用（IP 白名单鉴权） |
| 死路由 | edit_soc_network_block_ip / get_soc_network_block_ip | 服务端 access.lua 注册但函数未实现（请求被静默吞掉）；用 edit/get_soc_network_ip 替代 |
| /user 段独有模块 | dns_config 5 个、account_info/edit_password 等 | 子账号自助管理（Cloud user 专属控制台功能），非 Admin API 范畴 |

字段级规范以 jxwaf_admin_server 仓库各版 `ADMIN_API_DOCUMENT.md` / `USER_API_DOCUMENT.md` 为准；产品语义以 docs.jxwaf.com 各版本产品文档为准。CLI 内部端点映射以各版 `access.lua` 路由表为准。