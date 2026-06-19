---
name: playbook
description: 运维 SOP - 误报/漏报排查流程、规则调优原则、PV 级别限速建议、组件加载失败排查、性能参考
---

# 运维 SOP 速查

## 误报处理

### 排查步骤
1. 定位拦截来源：日志 waf_module 字段
   - web_rule_protection → Web 防护规则误报
   - flow_rule_protection → 流量防护规则误报
   - flow_engine_protection → 流量引擎防护误报（ip_access_limit/ip_count_limit/domain_access_limit/ssl_fingerprint/emergency）
   - web_engine_protection → Web 引擎防护误报（AI+语义分析）
   - base_component → 组件误报
   - name_list → 名单误封
2. 确认匹配条件：根据 waf_policy 中的规则名查看 rule_matchs 配置
3. 处置（按影响程度）：
   - 临时切换观察模式：rule_action 改为 watch
   - 调整匹配条件：收窄 match_value，str_contain 改 str_eq
   - 添加白名单：特定 IP/参数放行（web_white_rule / flow_white_rule）
   - 禁用规则：status="false"

### Web 规则误报 SOP
```
确认误报（waf_module=web_rule_protection）
  ├── 紧急 → status="false" 或 rule_action="watch"
  ├── 分析匹配条件
  │     ├── match_value 过宽？ → 收窄
  │     ├── args_prepocess 缺失？ → 加 lowerCase
  │     └── match_operator 不当？ → str_contain 改 str_eq
  └── 验证 → verify 复现确认放行
```

### 流量规则误报 SOP
```
确认误报（waf_module=flow_rule_protection）
  ├── 紧急 → status="false"
  ├── 分析触发原因
  │     ├── exceed_count 过低？ → 提高阈值（不低于峰值 QPS × 2）
  │     ├── stat_time 过短？ → 延长窗口
  │     ├── block_time 过长？ → 缩短处罚
  │     └── entity 范围不当？ → 增加 path 维度（src_ip + path 双维度）
  └── 特定 IP 放行 → 流量白名单（rule_action=flow_bypass）
```

### Web 引擎误报 SOP
```
确认误报（waf_module=web_engine_protection）
  ├── 紧急 → 切换 protection_mode 为 business_priority（业务优先）
  ├── 分析攻击类型（waf_extra 中的 token_hash）
  │     ├── 语义分析误判？ → 切换 learn 模式学习
  │     └── AI 模型误判？ → 等待模型蒸馏自动修正
  └── 特定接口放行 → Web 白名单
```

## 漏报排查

### 排查步骤
1. 确认请求经过 WAF（日志有记录）
2. 确认未被白名单 bypass（waf_action 含 bypass，检查 web_bypass/flow_bypass 标志）
3. 确认规则 status="true"
4. 确认未被名单 all_bypass/web_bypass/flow_bypass 跳过
5. 分析匹配条件未命中原因：
   - 匹配参数取错（match_args.key/value）
   - 参数处理缺失（编码未解码，注意 raw_body 不调用 read_body）
   - 匹配方式不当（正则未覆盖变体）
   - 流量规则 filter 配置错误或未达阈值（严格大于 exceed_count）
   - json_post_args 仅支持顶层字段，不支持 a.b.c 嵌套

### 漏报修复 SOP
```
确认漏报（waf_action=pass 且应为攻击）
  ├── 检查白名单 → 是否被 bypass（web_bypass/flow_bypass）
  ├── 检查名单 → 是否被 all_bypass/web_bypass/flow_bypass
  ├── 检查规则状态 → status 是否 "true"
  ├── 复现请求 → verify 发送攻击 payload
  │     ├── 被拦截 → 偶发问题
  │     └── 未拦截 → 匹配条件分析
  └── 修复 → 调整 rule_matchs / 新增规则 → 验证
```

## 规则调优原则

### Web 防护规则
1. 精确匹配优先：str_eq > str_contain，str_prefix > rx
2. 关键字匹配加 lowerCase，match_value 统一小写
3. 多层解码：按需叠加 uriDecode/base64Decode/uniDecode/hexDecode
4. 观察先行：新规则先 watch，观察日志无误报后改 block
5. 注意 raw_body 限制：仅返回内存中 body，大 body 可能返回 nil

### 流量防护规则
1. entity 维度选择：
   - 全局限速：src_ip 单维度
   - 接口限速：src_ip + path 双维度（避免不同接口互相影响）
   - 会话限速：cookie_args:session_id
2. 阈值设置：exceed_count = 峰值 QPS × 2-3（严格大于才触发）
3. stat_time 建议 10-60 秒
4. 处罚方式：
   - 一般 CC：bot_check（auto=5秒盾，人机识别）
   - 恶意攻击：block 或 network_block（网络层封禁）
   - 紧急防护：reject_response（444 关闭连接，节省带宽）

### 日 PV 级别与限速建议
| 日 PV 级别 | 单 IP 请求/60s | 独立 IP 数/60s | 域名总请求/60s | 阻断时长 |
|------------|----------------|----------------|----------------|----------|
| ~1 万 | 50~100 | 50~100 | 1,000~3,000 | 600s |
| ~10 万 | 200~500 | 200~500 | 5,000~10,000 | 600s |
| ~100 万 | 600~1,500 | 1,500~3,000 | 30,000~60,000 | 300~600s |
| ~1000 万 | 2,000~5,000 | 10,000~20,000 | 200,000~400,000 | 120~300s |

### 流量引擎预案默认值（专业版）
| 预案 | IP访问限制 | IP数量限制 | 域名访问限制 | SSL指纹 | 紧急防护 |
|------|-----------|-----------|-------------|---------|---------|
| daily_observe | 1000/60s, watch | 1000/60s, watch | 100000/60s, watch | 关闭 | 关闭 |
| daily_protect | 1000/60s, bot_check(auto) | 1000/60s, bot_check | 100000/60s, bot_check | 关闭 | 关闭 |
| attack_protect | 500/60s, bot_check(slipper) | 500/60s, bot_check | 50000/60s, bot_check | 开启 | 关闭 |
| emergency_protect | 100/60s, bot_check(words) | 100/60s, bot_check | 10000/60s, bot_check | 开启 | 开启 |

## 组件加载失败排查

### 现象
组件上传后节点报 `can not decode component_data`，组件未执行。

### 根本原因
组件代码使用了 LuaJIT 不支持的 Lua 5.2+ 语法，loadstring 编译失败。

### 排查步骤
1. 检查节点 error.log，搜索 "can not decode component_data"
2. 按位运算符 → 控制流 → 数值类型 → 字符串/table 顺序排查
3. 替换为 LuaJIT 兼容写法（见 component_dev.md）
4. 重新上传

### 常见错误
| 错误现象 | 原因 | 替代方案 |
|----------|------|----------|
| unexpected symbol near '&' | 按位与 | bit.band(a, b) |
| unexpected symbol near '\|' | 按位或 | bit.bor(a, b) |
| unexpected symbol near '~' | 异或/非 | bit.bxor / bit.bnot |
| unexpected symbol near '>' | 右移 >> | bit.rshift(a, n) |
| unexpected symbol near '<' | 左移 << | bit.lshift(a, n) |
| '//' expected | 整数除法 | math.floor(a / b) |
| no visible label | goto 语句 | 重构为循环 |

## 防护薄弱点

### GraphQL 注入
JXWAF 对 GraphQL 注入防护通过率仅 8.3%，涉及 GraphQL 场景时需额外配置：
- 自定义防护组件检测 GraphQL 查询结构
- Web 规则匹配 json_post_args:query 中的恶意 payload
- 建议结合业务场景定制检测逻辑

### 已知覆盖良好的攻击类型（通过率 95%+）
SQL 注入、XSS、文件包含、目录遍历、文件上传、SSTI、XXE、SSI、XPath、XSLT、反序列化（Java/PHP/.NET/Python/NodeJS/Ruby）、WAF 绕过变体

## 紧急解封
- 规则层面：临时 status="false"（影响所有 IP）
- 名单层面：加入 flow_bypass 名单（仅放行该 IP）
- 网络封禁层面：SOC → 网络封禁 IP 名单中删除或加白
- 缓存层面：等待 block_time 过期自动解封

## 性能参考
单节点 4 核 8G 性能指标：
- 纯转发：HTTP 48K QPS / HTTPS 30K QPS
- Web 防护引擎开启：HTTP 31K QPS（↓35%）/ HTTPS 21K QPS（↓30%）
- 全防护开启：HTTP 18K QPS（↓62%）/ HTTPS 13K QPS（↓56%）
- 配置同步间隔：3 秒
- 节点心跳异常阈值：10 分钟无心跳
