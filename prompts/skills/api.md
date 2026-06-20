---
name: api_reference
description: JXWAF 控制台 API 速查（鉴权方式、接口路径、必填参数、backup/load 语义、版本差异）。需要查 API 接口路径/参数或了解 API 调用方式时加载
---

# JXWAF 控制台 API 速查

## 鉴权方式
- **控制台 API**：通过登录态 Cookie 鉴权（login_check.get_session）
- **外部 API**：通过请求体 `waf_auth` 参数鉴权（**非 HTTP Header**），路径以 `/api_` 开头
- waf_auth 获取：控制台「系统管理 → 基础信息」查看，UUID 格式
- 鉴权失败返回：`{"result": false, "message": "waf_auth fail"}`

## 版本接口映射规律
- 专业版接口路径含 `group_` 前缀，需 `group_name` 参数
- 标准版接口路径去掉 `group_` 前缀，无 `group_name` 参数
- 组件和名单接口两版相同（无 group_ 前缀）

## 通用接口模式（所有规则类模块）
每个规则类模块均提供以下接口（以 Web 规则为例，专业版路径）：
| 操作 | 接口路径 | 必填参数 |
|------|----------|---------|
| 列表查询 | /get_group_web_rule_protection_list | page, group_name |
| 全量查询 | /api_get_group_web_rule_protection_list | group_name |
| 查询单条 | /get_group_web_rule_protection | group_name, rule_name |
| 创建 | /create_group_web_rule_protection | group_name, rule_name, rule_detail, rule_matchs, rule_action, action_value |
| 编辑 | /edit_group_web_rule_protection | 同创建 |
| 删除 | /delete_group_web_rule_protection | group_name, rule_name |
| 切换状态 | /edit_group_web_rule_protection_status | group_name, rule_name, status |
| 调整优先级 | /exchange_group_web_rule_protection_priority | group_name, rule_name, type(top/exchange) |
| 导出 backup | /backup_group_web_rule_protection | group_name, rule_name_list |
| 加载 backup | /load_group_web_rule_protection | group_name, rules |
| 加载 Hub 配置 | /load_group_web_rule_protection_hub_config | hub_repo, force_load |
| 导出 Hub 配置 | /export_group_web_rule_protection_hub_config | web_rule_protection, group_name |

**优先级调整 type 参数**：
- `top`：置顶，rule_order_time 设为当前最小值 - 1
- `exchange`：交换，需额外提供 exchange_rule_name

**backup 导出格式**：JSON 数组，元素仅含业务字段（不含 status、rule_order_time）
**load 加载语义**：仅当 rule_name 不存在时插入，已存在则跳过

## Web 防护规则 API
模块路径前缀：`group_web_rule_protection`（专业版）/ `web_rule_protection`（标准版）
- 关键参数：group_name, rule_name, rule_detail, rule_matchs, rule_action, action_value
- rule_action 取值：block / watch / reject_response

## 流量防护规则 API
模块路径前缀：`group_flow_rule_protection`（专业版）/ `flow_rule_protection`（标准版）
- 额外参数：filter, entity, stat_time, exceed_count, block_time
- rule_action 取值：block / reject_response / bot_check / network_block / watch
- **无 api_get 列表接口**（无全量查询）

## Web 白名单 API
模块路径前缀：`group_web_white_rule`（专业版）/ `web_white_rule`（标准版）
- rule_action 固定为 web_bypass
- 标准版文件名：jxwaf_waf_white_rule.lua

## 流量白名单 API
模块路径前缀：`group_flow_white_rule`（专业版）/ `flow_white_rule`（标准版）
- rule_action 固定为 flow_bypass

## 防护组件 API（两版相同）
| 操作 | 接口路径 | 必填参数 |
|------|----------|---------|
| 列表查询 | /get_component_list | page |
| 查询单条 | /get_component | name |
| 创建 | /create_component | name, detail, code, conf |
| 编辑 | /edit_component | name, detail, code, conf |
| 删除 | /delete_component | name |
| 切换状态 | /edit_component_status | name, status |
| 调整优先级 | /exchange_component_priority | name, type(top/exchange) |
| 导出 backup | /backup_component | name_list |
| 加载 backup | /load_component | rules |
| 加载 Hub 配置 | /load_component_hub_config | hub_repo, force_load |
| 导出 Hub 配置 | /export_component_hub_config | component |

- code 字段存明文 Lua 源码（控制台不做 Base64 编码）
- conf 字段为 JSON 字符串

## 名单防护 API（两版相同）
### 名单管理
| 操作 | 接口路径 | 必填参数 |
|------|----------|---------|
| 名单列表 | /get_global_name_list_list | page |
| 全量列表 | /api_get_global_name_list_list | (无) |
| 查询单条 | /get_global_name_list | name_list_name |
| 创建名单 | /create_global_name_list | name_list_name, name_list_detail, name_list_rule, name_list_action, action_value, name_list_expire, name_list_expire_time |
| 编辑名单 | /edit_global_name_list | 同创建 |
| 删除名单 | /delete_global_name_list | name_list_name |
| 切换状态 | /edit_global_name_list_status | name_list_name, status |
| 调整优先级 | /exchange_global_name_list_priority | name_list_name, type |
| 导出 backup | /backup_global_name_list | name_list_name_list |
| 加载 backup | /load_global_name_list | rules |

### 名单条目管理
| 操作 | 接口路径 | 鉴权 | 必填参数 |
|------|----------|------|---------|
| 条目列表 | /get_name_list_item_list_list | Cookie | page, name_list_name |
| 创建条目 | /create_global_name_list_item | Cookie | name_list_name, name_list_item |
| 删除条目 | /delete_global_name_list_item | Cookie | name_list_name, name_list_item |
| 搜索条目 | /search_global_name_list_item | Cookie | page, name_list_name, search_value |
| 外部获取条目 | /api_get_name_list_item_list_list | waf_auth | page, name_list_name, waf_auth |
| 外部创建条目 | /api_create_global_name_list_item | waf_auth | name_list_name, name_list_item, waf_auth |
| 外部删除条目 | /api_delete_global_name_list_item | waf_auth | name_list_name, name_list_item, waf_auth |
| 外部搜索条目 | /api_search_global_name_list_item | waf_auth | page, name_list_name, search_value, waf_auth |

- 创建条目时若已存在则更新过期时间（不报错）
- 条目过期时间从父名单的 name_list_expire/name_list_expire_time 继承计算
- 删除名单时级联删除其所有条目
- 条目无 backup/load 接口
- 分页 pageSize = 50

## 网页防篡改 API
模块路径前缀：`group_web_page_tamper_proof`（专业版）/ `web_page_tamper_proof`（标准版）
- 额外字段：cache_page_url, cache_page_content, cache_content_type
- 抓取缓存页面：/waf_get_cache_page_url（输入 cache_page_url，返回页面内容和 Content-Type）

## IP 区域封禁 API（仅查询/编辑，无 CRUD 列表）
| 操作 | 专业版路径 | 标准版路径 |
|------|-----------|-----------|
| 查询 | /get_group_flow_ip_region_block | /get_flow_ip_region_block |
| 编辑 | /edit_group_flow_ip_region_block | /edit_flow_ip_region_block |
- 字段：ip_region_block(true/false), check_model(white/black), country_list(JSON), block_action, action_value

## Web 引擎防护 API（仅查询/编辑）
| 操作 | 专业版路径 | 标准版路径 |
|------|-----------|-----------|
| 查询 | /get_group_web_engine_protection | /get_web_engine_protection |
| 编辑 | /edit_group_web_engine_protection | /edit_web_engine_protection |
- 字段：ai_protection(true/false), protection_mode, model_provider, model_api_key, engine_protection(JSON)
- protection_mode 取值：learn(学习) / business_priority(日常) / security_priority(重保) / offline(离线)

## 流量引擎防护 API（仅查询/编辑）
| 操作 | 专业版路径 | 标准版路径 |
|------|-----------|-----------|
| 查询 | /get_group_flow_engine_protection | /get_flow_engine_protection |
| 编辑 | /edit_group_flow_engine_protection | /edit_flow_engine_protection |
- 专业版字段：engine_status, protection_plan, plans_config(JSON)
- protection_plan 取值：daily_observe(日常观察) / daily_protect(日常防护) / attack_protect(攻击防护) / emergency_protect(紧急防护)
- 标准版：无 protection_plan，plans_config 为扁平结构

## 自定义高级配置 API（仅专业版）
| 模块 | 路径前缀 | 额外字段 |
|------|---------|---------|
| 自定义请求头 | group_custom_request_header | header_name, header_value |
| 自定义响应头 | group_custom_response_header | header_name, header_value |
| 自定义响应内容 | group_custom_response_content | content_type, return_code, return_content |
| 自定义回源地址 | group_custom_upstream_address | source_ip, source_http_port, source_https_port |
- 均支持完整 CRUD + 优先级 + backup/load + hub_config

## 域名分组 API（仅专业版）
| 操作 | 接口路径 | 必填参数 |
|------|----------|---------|
| 分组列表 | /get_domain_group_list | page |
| 搜索分组 | /get_domain_group_search_list | page, search |
| 查询分组 | /get_domain_group | group_name |
| 创建分组 | /create_domain_group | group_name, group_detail |
| 删除分组 | /delete_domain_group | group_name |
| 编辑分组 | /edit_domain_group | group_name, group_detail |
| 全量列表 | /api_get_domain_group_list | (无) |
- 创建分组时自动初始化 Web/流量引擎防护、IP区域封禁记录
- 删除分组时级联删除 12 张关联表的数据

## SOC 日志查询 API
| 操作 | 接口路径 | 必填参数 |
|------|----------|---------|
| 日志查询 | /get_soc_log_query_list | from_time, to_time, page, sql_rules |

- 专业版：查询 ClickHouse（需配置 report_conf）
- 标准版：查询 MySQL 的 jxwaf_waf_attack_log 表
- sql_rules 数组元素：{field, operation, value}
- operation 取值：contains(LIKE '%v%') / prefix(LIKE 'v%') / suffix(LIKE '%v') / equals(=v) / not_equals(<>v)
- 可查字段：request_time, host, method, request_uri, cookie, query_string, raw_body, status, src_ip, user_agent, iso_code, waf_action, waf_module, waf_policy, waf_extra, raw_resp_headers, raw_resp_body, jxwaf_ssl_fingerprint
- 分页 pageSize = 20

## 全局备份/恢复 API（仅专业版）
| 操作 | 接口路径 | 说明 |
|------|----------|------|
| 全量备份 | /waf_conf_backup | 导出 19 张表为 JSON 对象 |
| 全量恢复 | /waf_conf_load | 请求体为表名→记录数组的字典，先 DELETE 再 INSERT |

## 系统配置 API
| 操作 | 接口路径 |
|------|----------|
| 日志配置查询 | /get_sys_log_conf |
| 日志配置编辑 | /edit_sys_log_conf |
| ClickHouse配置查询 | /get_sys_report_conf_conf |
| ClickHouse配置编辑 | /edit_sys_report_conf_conf |
| ClickHouse连接测试 | /test_sys_report_conf_conf（无鉴权） |
| 自定义页面查询 | /get_sys_custom_page_conf |
| 自定义页面编辑 | /edit_sys_custom_page_conf |
| WebTDS配置查询 | /get_sys_webtds_check_conf |
| WebTDS配置编辑 | /edit_sys_webtds_check_conf |
