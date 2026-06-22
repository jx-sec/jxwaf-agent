---
name: tencent_waf
description: 腾讯云 WAF 规则语法与 API 速查（匹配字段、运算符、动作、CC 规则、IP 黑白名单、API 接口）。需要生成腾讯云 WAF 规则或调用腾讯云 WAF API 时加载
---

# 腾讯云 WAF 规则语法与 API 速查

## 产品定位
- 腾讯云 WAF 提供 SaaS 型和云原生型（CLB-WAF）两种形态
- API 版本：`2018-01-25`
- 鉴权：TC3-HMAC-SHA256 签名（SecretId + SecretKey）
- Endpoint：`waf.tencentcloudapi.com`
- 地域：`ap-guangzhou`（广州）/ `ap-seoul`（首尔）/ `ap-singapore`（新加坡）
- Edition：`sparta-waf`（SaaS 型）/ `clb-waf`（负载均衡型）

## 自定义规则字段结构（AddCustomRule）
| 字段 | 类型 | 必选 | 说明 |
|---|---|---|---|
| `Name` | String | 是 | 规则名称 |
| `SortId` | String | 是 | 优先级（1-100，越小越高） |
| `Domain` | String | 是 | 域名（`global` 表示全局） |
| `ActionType` | String | 是 | 动作类型（见下表） |
| `Strategies` | Array | 是 | 匹配条件数组（**最多 5 个**） |
| `LogicalOp` | String | 否 | `and`（默认）/ `or` |
| `Redirect` | String | 否 | 重定向地址（ActionType=4 时使用） |
| `ExpireTime` | String | 否 | 过期时间戳（秒），0=永不过期 |
| `Edition` | String | 否 | `sparta-waf` / `clb-waf` |
| `JobType` | String | 否 | `forever` / `TimedJob` / `CronJob` |

## Strategy 匹配条件结构
| 字段 | 类型 | 必选 | 说明 |
|---|---|---|---|
| `Field` | String | 是 | 匹配字段（见下表） |
| `CompareFunc` | String | 是 | 运算符（见下表） |
| `Content` | String | 是 | 匹配内容 |
| `Arg` | String | 否 | 参数名（Cookie/Header/args/post_args 时必填） |

## 匹配字段 Field 取值
| Field | 含义 | 需要 Arg |
|---|---|---|
| `URL` / `path` | 请求路径 | 否 |
| `Method` / `method` | HTTP 方法 | 否 |
| `args` | GET 参数值 | 是（参数名） |
| `args_name` | GET 参数名 | 否 |
| `post_args` / `Post` | POST 参数值 | 是 |
| `post_args_name` | POST 参数名 | 否 |
| `body` / `POST_BODY` | 完整请求体 | 否 |
| `referer` / `Referer` | Referer | 否 |
| `ua` / `User-Agent` | User-Agent | 否 |
| `COOKIE` / `cookie` | Cookie | 是（key 名） |
| `cookie_name` | Cookie 参数名 | 否 |
| `cookie_value` | Cookie 参数值 | 是 |
| `header` / `Header` | 自定义请求头 | 是（key 名） |
| `header_value` | Header 参数值 | 是 |
| `IP` / `ip` | 来源 IP（支持 CIDR） | 否 |
| `ipv6` | 来源 IPv6 | 否 |
| `IPLocation` / `ip_location` | IP 归属地 | 否 |
| `content_length` | Content-Length | 否 |

## 运算符 CompareFunc 取值
| CompareFunc | 含义 |
|---|---|
| `eq` | 等于 |
| `neq` | 不等于 |
| `contains` | 包含 |
| `ncontains` / `not_contains` | 不包含 |
| `prefix` | 前缀匹配 |
| `suffix` | 后缀匹配 |
| `ipmatch` / `belong` | IP 属于 |
| `ipnmatch` / `not_belong` | IP 不属于 |
| `len_eq` | 长度等于 |
| `len_gt` | 长度大于 |
| `len_lt` | 长度小于 |
| `regex` / `re` | 正则匹配 |
| `exists` | 存在 |
| `nexists` / `not_exists` | 不存在 |
| `empty` | 内容为空 |
| `numeq` | 数值等于 |
| `numneq` | 数值不等于 |
| `numgt` | 数值大于 |
| `numlt` | 数值小于 |
| `numge` | 数值大于等于 |
| `numle` | 数值小于等于 |
| `geo_in` | IP 地理属于 |
| `geo_not_in` | IP 地理不属于 |

## 动作 ActionType 取值
### 自定义规则
| ActionType | 动作 |
|---|---|
| `1` | 阻断（Block） |
| `2` | 人机识别（CAPTCHA） |
| `3` | 观察（Observe） |
| `4` | 重定向（Redirect） |
| `5` | JS 校验（JS Challenge） |

### CC 防护规则
| ActionType | 动作 |
|---|---|
| `20` | 观察 |
| `21` | 人机识别 |
| `22` | 拦截 |
| `23` | 精准拦截 |
| `26` | 精准人机识别 |
| `27` | JS 校验 |

### IP 黑白名单
| ActionType | 动作 |
|---|---|
| `42` | 黑名单 |
| `40` | 白名单 |

## 逻辑关系
- `LogicalOp` = `and`：所有条件匹配才生效（默认）
- `LogicalOp` = `or`：任一条件匹配即生效
- 每条规则最多 5 个匹配条件

## API 接口
### 自定义规则
| 操作 | API |
|---|---|
| 新增 | `AddCustomRule` |
| 修改 | `ModifyCustomRule` |
| 删除 | `DeleteCustomRule` |
| 查询列表 | `DescribeCustomRuleList` |
| 修改状态 | `ModifyCustomRuleStatus` |

### IP 黑白名单
| 操作 | API |
|---|---|
| 创建 | `CreateIpAccessControl` |
| 修改 | `ModifyIpAccessControl` |
| 删除 | `DeleteIpAccessControl` |
| 查询 | `DescribeIpAccessControl` |

### CC 防护
| 操作 | API |
|---|---|
| 创建/更新 | `UpsertCCRule` |
| 删除 | `DeleteCCRule` |
| 查询列表 | `DescribeCCRuleList` |

### 精准白名单
| 操作 | API |
|---|---|
| 新增 | `AddCustomWhiteRule` |
| 删除 | `DeleteCustomWhiteRule` |
| 查询 | `DescribeCustomWhiteRules` |

### 域名/实例
| 操作 | API |
|---|---|
| 域名列表 | `DescribeDomains` |
| 实例列表 | `DescribeInstances` |

## 规则示例

### 自定义规则（拦截 SQL 注入）
```json
{
  "Name": "block_sql_injection",
  "SortId": "1",
  "Domain": "www.example.com",
  "ActionType": "3",
  "LogicalOp": "and",
  "Edition": "sparta-waf",
  "ExpireTime": "0",
  "JobType": "forever",
  "Strategies": [
    {
      "Field": "args",
      "CompareFunc": "regex",
      "Content": "union[\\s/\\*]+select",
      "Arg": "id"
    }
  ]
}
```

### IP 黑名单
```json
{
  "Domain": "www.example.com",
  "IpList": ["1.1.1.1", "2.2.2.0/24"],
  "ActionType": 42,
  "Edition": "sparta-waf",
  "SourceType": "custom"
}
```

### CC 防护规则
```json
{
  "Domain": "www.example.com",
  "Name": "cc_limit",
  "Status": 1,
  "Limit": "100",
  "Interval": "60",
  "ActionType": "22",
  "Priority": 50,
  "ValidTime": 600,
  "MatchFunc": 0,
  "OptionsArr": "[{\"key\":\"URL\",\"args\":[\"\"],\"match\":\"0\",\"encodeflag\":false}]",
  "Edition": "sparta-waf",
  "RuleId": 0,
  "LogicalOp": "and",
  "ActionRatio": 100,
  "JobType": "forever"
}
```

## CC 规则 MatchFunc 数字枚举
| 值 | 含义 |
|---|---|
| 0 | 等于 |
| 1 | 前缀匹配 |
| 2 | 包含 |
| 3 | 不等于 |
| 4 | 内容为空 |
| 5 | 不存在 |
| 6 | 后缀匹配 |
| 7 | 不包含 |
| 12 | 存在 |
| 13 | 属于 |
| 14 | 不属于 |
| 15 | 数值等于 |
| 16 | 数值不等于 |
| 17 | 数值大于 |
| 18 | 数值小于 |
| 19 | 数值大于等于 |
| 20 | 数值小于等于 |

## 红线规则
1. 新规则建议先用 `ActionType=3`（观察），验证无误报后改 `1`（阻断）
2. CC 防护 Limit 不低于业务峰值 QPS 的 2 倍
3. 每条规则最多 5 个匹配条件
4. 优先级 SortId 范围 1-100，数值越小优先级越高
5. CC 规则的 OptionsArr 中 Post/Cookie/Header 参数需 Base64 编码（设置 `encodeflag: true`）

## Function 使用指引
- `generate_tencent_custom_rule`：生成自定义规则
- `generate_tencent_cc_rule`：生成 CC 防护规则
- `generate_tencent_ip_blacklist`：生成 IP 黑白名单
- `publish_tencent_waf_rule`：通过 API 发布规则到腾讯云 WAF
- `list_tencent_waf_rules`：查询已有规则
- `delete_tencent_waf_rule`：删除规则
- `list_tencent_waf_domains`：查询域名列表
