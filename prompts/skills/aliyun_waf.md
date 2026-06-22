---
name: aliyun_waf
description: 阿里云 WAF 3.0 规则语法与 API 速查（匹配字段、运算符、动作、限速配置、DefenseScene 映射）。需要生成阿里云 WAF 规则或调用阿里云 WAF API 时加载
---

# 阿里云 WAF 3.0 规则语法与 API 速查

## 产品定位
- 阿里云 WAF 3.0 是新一代 Web 应用防火墙，采用 SeCU 计量单元
- WAF 2.0 已停止新购，仅 3.0 可购买
- API 版本：`2021-10-01`（RPC 风格）
- 鉴权：AccessKey ID + AccessKey Secret（HMAC-SHA1 签名）
- Endpoint：`wafopenapi.cn-hangzhou.aliyuncs.com`（中国内地）/ `wafopenapi.ap-southeast-1.aliyuncs.com`（海外）

## 防护场景（DefenseScene）
| DefenseScene | 说明 |
|---|---|
| `custom_acl` | **自定义规则（ACL）** |
| `cc` | **CC 防护（限速）** |
| `ip_blacklist` | **IP 黑名单** |
| `whitelist` | 白名单 |
| `waf_group` | 基础防护（规则引擎） |
| `antiscan` | 扫描防护 |
| `region_block` | 区域封禁 |
| `tamperproof` | 网页防篡改 |
| `dlp` | 信息泄露防护 |
| `bot_manager` | BOT 管理 |

## 规则字段结构（Rules JSON 数组元素）
| 字段 | 类型 | 必选 | 说明 |
|---|---|---|---|
| `name` | String | 是 | 规则名称（1~255 字符） |
| `status` | Integer | 是 | 0=关闭, 1=开启 |
| `action` | String | 是 | 处置动作（见下表） |
| `conditions` | Array | 是 | 匹配条件（**最多 5 个，AND 关系**） |
| `ccStatus` | Integer | 是 | 0=关闭限速, 1=开启限速 |
| `ratelimit` | JSON | 否 | 限速配置（ccStatus=1 时生效） |
| `effect` | String | 否 | `service`=防护对象, `rule`=单规则 |
| `origin` | String | 否 | 规则来源，如 `custom` |

## 匹配条件 conditions 字段
| 字段 | 说明 |
|---|---|
| `key` | 匹配字段（见下表） |
| `subKey` | 子字段名（Header/Cookie/Query-Arg/Post-Arg 时必填） |
| `opValue` | 逻辑符（见运算符表） |
| `values` | 匹配内容（多值用英文逗号分隔） |

## 匹配字段 key 取值
| key | 含义 |
|---|---|
| `URL` | 完整 URI（Path + Query String） |
| `URLPath` | URI 路径（仅 Path） |
| `IP` | 客户端来源 IP（支持 IPv4/IPv6/CIDR） |
| `Referer` | Referer 头 |
| `User-Agent` | UA 头 |
| `Params` | 查询字符串 |
| `Cookie` | Cookie 信息 |
| `Content-Type` | Content-Type 头 |
| `Content-Length` | 内容字节数 |
| `X-Forwarded-For` | XFF 头 |
| `Post-Body` | 请求 Body |
| `Http-Method` | 请求方法 |
| `Header` | 请求头（配合 subKey） |
| `Extension` | 文件扩展名 |
| `Filename` | 文件名 |
| `Server-Port` | 服务器端口 |
| `Host` | 域名 |
| `Cookie-Exact` | Cookie 键名（大小写敏感） |
| `Query-Arg` | URL 参数名（大小写敏感） |
| `Post-Arg` | Body 参数名（大小写敏感） |

## 运算符 opValue 取值
| opValue | 含义 |
|---|---|
| `contain` | 包含 |
| `not-contain` | 不包含 |
| `eq` | 等于 |
| `ne` | 不等于 |
| `lt` | 小于 |
| `gt` | 大于 |
| `len-lt` | 长度小于 |
| `len-eq` | 长度等于 |
| `len-gt` | 长度大于 |
| `match-one` | 等于多值之一 |
| `all-not-match` | 不等于任一值 |
| `contain-one` | 包含多值之一 |
| `all-not-contain` | 不包含任一值 |
| `prefix-match` | 前缀匹配 |
| `suffix-match` | 后缀匹配 |
| `regex` | 正则匹配（高级规则） |
| `not-regex` | 正则不匹配 |
| `regex-one` | 正则匹配其中之一 |
| `all-not-regex` | 正则均不匹配 |
| `empty` | 内容为空 |
| `exists` | 字段存在 |
| `none` | 不存在 |
| `not-match` | 不匹配 |
| `in-list` | 在地址簿中 |
| `not-in-list` | 不在地址簿中 |

## 动作 action 取值
| action | 含义 | 适用场景 |
|---|---|---|
| `block` | 拦截 | 所有规则 |
| `monitor` | 观察（仅记录日志） | 所有规则 |
| `pass` | 放行 | whitelist |
| `js` | JS 校验 | custom_acl |
| `captcha` | 滑块验证 | custom_acl |
| `captcha_strict` | 严格滑块验证 | custom_acl |

## 限速配置 ratelimit（CC 防护）
| 字段 | 说明 |
|---|---|
| `target` | 统计对象：`remote_addr`(IP) / `cookie.acw_tc`(会话) / `header` / `queryarg` / `cookie` / `account` |
| `subKey` | 子特征（target 为 header/queryarg/cookie 时必填） |
| `interval` | 统计时长（秒），1~1800 |
| `threshold` | 访问次数阈值 |
| `ttl` | 处置时长（秒），60~86400 |
| `status` | 响应码频率设置 `{"code":404,"count":200}` 或 `{"code":404,"ratio":50}` |

## 逻辑关系
- **AND**：单条规则内最多 5 个 conditions，条件间默认 AND
- **OR**：通过创建多条规则实现 OR 逻辑

## API 接口
| 操作 | API |
|---|---|
| 创建规则 | `CreateDefenseRule` |
| 修改规则 | `ModifyDefenseRule` |
| 删除规则 | `DeleteDefenseRule` |
| 查询规则列表 | `DescribeDefenseRules` |
| 修改规则状态 | `ModifyDefenseRuleStatus` |
| 查询防护对象 | `DescribeDefenseResources` |
| 查询域名 | `DescribeDomains` |
| 添加地址簿 | `AddAddress` |
| 查询地址簿 | `DescribeAddresses` |

## CreateDefenseRule 请求参数
| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `InstanceId` | string | 是 | WAF 实例 ID |
| `TemplateId` | integer | 否 | 防护模板 ID |
| `DefenseScene` | string | 是 | 防护场景（如 custom_acl） |
| `Rules` | string | 是 | 规则 JSON 字符串数组 |
| `DefenseType` | string | 否 | `template`(默认) / `resource` / `global` |
| `RegionId` | string | 否 | `cn-hangzhou` / `ap-southeast-1` |

## 规则示例

### 自定义 ACL 规则（拦截 /admin 访问）
```json
[
  {
    "name": "block_admin",
    "action": "monitor",
    "status": 1,
    "ccStatus": 0,
    "origin": "custom",
    "conditions": [
      {"key": "URL", "opValue": "contain", "values": "/admin"}
    ]
  }
]
```

### CC 防护规则（单 IP 60 秒内超过 100 次）
```json
[
  {
    "name": "cc_limit",
    "action": "block",
    "status": 1,
    "ccStatus": 1,
    "effect": "rule",
    "origin": "custom",
    "conditions": [],
    "ratelimit": {
      "target": "remote_addr",
      "interval": 60,
      "threshold": 100,
      "ttl": 1800
    }
  }
]
```

### IP 黑名单
```json
[
  {
    "name": "ip_blacklist_1",
    "action": "block",
    "status": 1,
    "remoteAddr": ["1.1.1.1", "2.2.2.0/24"]
  }
]
```

## 红线规则
1. 新规则建议先用 `monitor` 动作观察，验证无误报后改 `block`
2. CC 防护 threshold 不低于业务峰值 QPS 的 2 倍
3. IP 黑名单单规则最多 100 个 IP/CIDR
4. 匹配条件最多 5 个（AND 关系），OR 逻辑需创建多条规则
5. 使用 `regex` 运算符为高级规则，计费标准不同

## Function 使用指引
- `generate_aliyun_acl_rule`：生成自定义 ACL 规则
- `generate_aliyun_cc_rule`：生成 CC 防护规则
- `generate_aliyun_ip_blacklist`：生成 IP 黑名单
- `publish_aliyun_waf_rule`：通过 API 发布规则到阿里云 WAF
- `list_aliyun_waf_rules`：查询已有规则
- `delete_aliyun_waf_rule`：删除规则
- `list_aliyun_waf_resources`：查询防护对象（域名）
