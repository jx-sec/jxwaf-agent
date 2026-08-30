# 三版本差异说明

jxwaf-cli 对接 JXWAF 标准版 / 专业版 / 云WAF。**版本差异由 CLI adapter 层自动处理**：同一命令面，内部切换认证、端点命名与租户参数。本文档说明能力边界，帮助判断某需求在某版本是否可实现。

## 对比总览

| 维度 | 标准版 | 专业版 | 云WAF |
|---|---|---|---|
| 定位 | 单团队自部署 | 单团队+域名组 | 多租户 SaaS |
| 认证 | 环境变量 token 等值校验 | DB 反查账号 waf_auth | DB 反查 + 子账号双层 token |
| 租户组织 | 无 | `group_name` 域名组 | 主账号 + `sub_user_name` 子账号 |
| 防护端点 | `get_web_rule_...` | `get_group_web_rule_...` | admin: `get_sub_account_web_rule_...`；user: `/user/get_web_rule_...` |
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
| namelist 完整管理 | ✅ | ✅ | ✅ | 部分（查列表+加条目） |
| component 管理 | ✅ | ✅ | ✅ | ❌ |
| website 域名管理 | ✅ | ✅ | ✅ | ✅ |
| website access 接入配置 | ❌ | ❌ | ✅ | ❌ |
| soc log 查询 | ✅ | ✅ | ✅ | ✅ |

## API 权威参考

字段级规范以 jxwaf_admin_server 仓库各版 `ADMIN_API_DOCUMENT.md` / `USER_API_DOCUMENT.md` 为准；产品语义以 docs.jxwaf.com 各版本产品文档为准。CLI 内部端点映射以各版 `access.lua` 路由表为准。