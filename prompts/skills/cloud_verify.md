---
name: cloud_verify
description: 云端验证环境 SOP - 测试用例规范、SOC 日志查询接口、验证流程、误报处理策略
---

# 云端验证环境 SOP

## 概述
云端验证环境是官方提供的独立 JXWAF 实例，用于在配置下发生产前验证规则效果。验证通过后自动清理环境。

## 验证流程
1. `generate_*_script` → 生成配置 + test_cases（至少 1 条攻击 + 1 条正常流量）
2. `deploy_to_cloud` → 部署到云端环境（约 5 秒生效，配置同步间隔 3 秒）
3. `verify_in_cloud` → 执行测试用例获取验证报告
4. 如有失败（误报/漏报）→ 分析原因调整参数 → 回到步骤 2
5. 全部通过 → 展示最终配置 + 验证报告
6. `cleanup_cloud` → 清理云端环境（保持干净）

## 测试用例规范
- 每条 test_case 包含：name, method, path, headers(可选), body(可选), assert
- assert.type: block=应被拦截, pass=应放行
- assert.expected_status: 期望 HTTP 状态码
  - block 通常 403（block 动作）或 444（reject_response/network_block，连接被关闭）
  - pass 通常 200
- 流量规则需额外设置 flow_count 和 flow_interval
  - flow_count：测试请求次数（需超过 exceed_count 才触发）
  - flow_interval：请求间隔（秒），建议 0.1

## 验证方式
验证通过查询 SOC 攻击日志确认拦截结果：

### SOC 日志查询接口
```
POST /get_soc_log_query_list
{
  "from_time": "2026-06-20 10:00:00",
  "to_time": "2026-06-20 10:05:00",
  "page": 1,
  "sql_rules": [
    {"field": "src_ip", "operation": "equals", "value": "测试源IP"},
    {"field": "waf_module", "operation": "equals", "value": "web_rule_protection"}
  ]
}
```

### 可查字段
request_time, host, method, request_uri, cookie, query_string, raw_body, status, src_ip, user_agent, iso_code, waf_action, waf_module, waf_policy, waf_extra, raw_resp_headers, raw_resp_body, jxwaf_ssl_fingerprint

### operation 取值
| 操作符 | SQL 映射 | 说明 |
|--------|---------|------|
| contains | LIKE '%value%' | 包含 |
| prefix | LIKE 'value%' | 前缀匹配 |
| suffix | LIKE '%value' | 后缀匹配 |
| equals | = value | 等于 |
| not_equals | <> value | 不等于 |

### waf_module 取值对照
| waf_module | 对应模块 |
|-----------|---------|
| name_list | 名单防护 |
| flow_white_rule | 流量白名单 |
| flow_ip_region_block | IP 区域封禁 |
| flow_rule_protection | 流量防护规则 |
| flow_engine_protection | 流量引擎防护 |
| web_white_rule | Web 白名单 |
| web_rule_protection | Web 防护规则 |
| web_engine_protection | Web 引擎防护 |
| web_page_tamper_proof | 网页防篡改 |

### waf_action 取值对照
| waf_action | 含义 |
|-----------|------|
| block | 被拦截（403） |
| reject_response | 连接被关闭（444） |
| bot_check | 人机识别质询 |
| network_block | 网络层封禁 |
| watch | 观察记录 |
| pass | 放行 |
| web_bypass | Web 白名单放行 |
| flow_bypass | 流量白名单放行 |
| all_bypass | 全部放行 |

## 数据源差异
- **专业版**：ClickHouse（需配置 report_conf，高性能分析）
- **标准版**：MySQL 的 jxwaf_waf_attack_log 表
- 时间格式：`YYYY-MM-DD HH:MM:SS`
- 分页 pageSize = 20

## 误报处理策略
- 误报（正常流量被拦截）→ 添加更精确的匹配条件，缩小匹配范围
  - str_contain 改 str_eq / str_prefix
  - 增加 args_prepocess（lowerCase/uriDecode 等）
  - 增加额外匹配条件（AND 关系收窄范围）
- 漏报（攻击流量未拦截）→ 检查 match_operator/match_value 是否正确
  - 确认参数预处理是否遗漏（编码未解码）
  - 确认 match_args.key/value 取值正确
  - 流量规则确认 exceed_count 设置合理
- 策略调整后必须重新 deploy + verify 完整流程

## 清理策略
- 验证通过后调用 cleanup_cloud(config_type="all") 清理所有配置
- 确保下次验证从干净环境开始
- 支持按 config_type 清理：web_rule / flow_rule / component / name_list / web_white / flow_white
- 支持按 rule_names 清理指定规则

## 测试用例设计要点

### Web 防护规则测试
- 攻击流量：path/headers/body 包含恶意 payload，assert.type=block
- 正常流量：相似但不含恶意特征，assert.type=pass
- 边界测试：编码变体（URL编码/Unicode/Hex）、大小写变体

### 流量防护规则测试
- 攻击流量：高频请求（flow_count > exceed_count），assert.type=block
- 正常流量：低频请求（flow_count < exceed_count），assert.type=pass
- flow_interval 建议 0.1 秒，避免过快导致测试本身失败

### 组件测试
- 攻击流量：触发组件检测逻辑的特征，assert.type=block
- 正常流量：不触发组件检测，assert.type=pass
- 若组件设 ctx 变量由规则处置，需同时验证规则是否正确引用

### 名单测试
- 名单条目对应的 IP/特征请求，assert.type=block
- 非名单条目的请求，assert.type=pass
- 临时名单需验证过期后是否自动放行
