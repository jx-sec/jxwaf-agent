# JXWAF 控制台 API 速查

## 鉴权
- 控制台 API：通过登录态 Cookie 鉴权
- 外部 API：通过 waf_auth Header 鉴权（控制台「系统配置」获取）

## Web 防护规则 API（专业版）
| 操作 | 接口路径 |
|------|----------|
| 列表查询 | /waf/get_group_web_rule_protection_list |
| 全量查询 | /waf/api_get_group_web_rule_protection_list |
| 查询单条 | /waf/get_group_web_rule_protection |
| 创建规则 | /waf/create_group_web_rule_protection |
| 编辑规则 | /waf/edit_group_web_rule_protection |
| 删除规则 | /waf/delete_group_web_rule_protection |
| 切换状态 | /waf/edit_group_web_rule_protection_status |
| 调整优先级 | /waf/exchange_group_web_rule_protection_priority |

关键参数：group_name, rule_name, rule_detail, rule_matchs, rule_action, action_value

## 流量防护规则 API（专业版）
| 操作 | 接口路径 |
|------|----------|
| 列表查询 | /waf/get_group_flow_rule_protection_list |
| 创建规则 | /waf/create_group_flow_rule_protection |
| 编辑规则 | /waf/edit_group_flow_rule_protection |
| 删除规则 | /waf/delete_group_flow_rule_protection |
| 切换状态 | /waf/edit_group_flow_rule_protection_status |

额外参数：filter, entity, stat_time, exceed_count, block_time

## 防护组件 API
| 操作 | 接口路径 |
|------|----------|
| 列表查询 | /waf/get_component_list |
| 创建组件 | /waf/create_component |
| 编辑组件 | /waf/edit_component |
| 删除组件 | /waf/delete_component |
| 切换状态 | /waf/edit_component_status |

关键参数：name, detail, code（Base64 编码）, conf（JSON 字符串）

## 名单防护 API
| 操作 | 接口路径 |
|------|----------|
| 名单列表 | /waf/get_global_name_list_list |
| 创建名单 | /waf/create_global_name_list |
| 编辑名单 | /waf/edit_global_name_list |
| 删除名单 | /waf/delete_global_name_list |
| 条目列表 | /waf/get_name_list_item_list_list |
| 创建条目 | /waf/create_global_name_list_item |
| 删除条目 | /waf/delete_global_name_list_item |

外部 API（waf_auth 鉴权，无需登录态）：
| 操作 | 接口路径 |
|------|----------|
| 获取条目 | /api_get_name_list_item_list_list |
| 创建条目 | /api/create_global_name_list_item |
| 删除条目 | /api/delete_global_name_list_item |

## 白名单 API（专业版）
| 操作 | 接口路径 |
|------|----------|
| Web白名单创建 | /waf/create_group_web_white_rule |
| Web白名单列表 | /waf/get_group_web_white_rule_list |
| 流量白名单创建 | /waf/create_group_flow_white_rule |
| 流量白名单列表 | /waf/get_group_flow_white_rule_list |

> 标准版接口路径去掉 group_ 前缀，且不需要 group_name 参数。
