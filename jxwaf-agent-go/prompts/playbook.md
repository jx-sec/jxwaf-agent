# 运维 SOP 速查

## 误报处理

### 排查步骤
1. 定位拦截来源：日志 waf_module 字段
   - web_rule_protection → Web 防护规则误报
   - flow_rule_protection → 流量防护规则误报
   - base_component → 组件误报
   - name_list → 名单误封
2. 确认匹配条件：根据 waf_policy 中的规则名查看 rule_matchs 配置
3. 处置（按影响程度）：
   - 临时切换观察模式：rule_action 改为 watch
   - 调整匹配条件：收窄 match_value，str_contain 改 str_eq
   - 添加白名单：特定 IP/参数放行
   - 禁用规则：status=false

### Web 规则误报 SOP
```
确认误报（waf_module=web_rule_protection）
  ├── 紧急 → status=false 或 action=watch
  ├── 分析匹配条件
  │     ├── match_value 过宽？ → 收窄
  │     ├── args_prepocess 缺失？ → 加 lowerCase
  │     └── match_operator 不当？ → str_contain 改 str_eq
  └── 验证 → verify 复现确认放行
```

### 流量规则误报 SOP
```
确认误报（waf_module=flow_rule_protection）
  ├── 紧急 → status=false
  ├── 分析触发原因
  │     ├── exceed_count 过低？ → 提高阈值
  │     ├── stat_time 过短？ → 延长窗口
  │     ├── block_time 过长？ → 缩短处罚
  │     └── entity 范围不当？ → 增加 path 维度
  └── 特定 IP 放行 → 流量白名单
```

## 漏报排查

### 排查步骤
1. 确认请求经过 WAF（日志有记录）
2. 确认未被白名单 bypass（waf_action 含 bypass）
3. 确认规则 status=true
4. 分析匹配条件未命中原因：
   - 匹配参数取错（match_args.key/value）
   - 参数处理缺失（编码未解码）
   - 匹配方式不当（正则未覆盖变体）
   - 流量规则 filter 配置错误或未达阈值

### 漏报修复 SOP
```
确认漏报（waf_action=pass 且应为攻击）
  ├── 检查白名单 → 是否被 bypass
  ├── 检查规则状态 → status 是否 true
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

### 流量防护规则
1. entity 维度选择：
   - 全局限速：src_ip 单维度
   - 接口限速：src_ip + path 双维度
   - 会话限速：cookie_args:session_id
2. 阈值设置：exceed_count = 峰值 QPS × 2-3
3. stat_time 建议 10-60 秒
4. 处罚方式：
   - 一般 CC：bot_check（人机识别）
   - 恶意攻击：block 或 network_block
   - 紧急防护：reject_response

## 组件加载失败排查

### 现象
组件上传后节点报 `can not decode component_data`，组件未执行。

### 根本原因
组件代码使用了 LuaJIT 不支持的 Lua 5.2+ 语法，loadstring 编译失败。

### 排查步骤
1. 检查节点 error.log，搜索 "can not decode component_data"
2. 按位运算符 → 控制流 → 数值类型 → 字符串/table 顺序排查
3. 替换为 LuaJIT 兼容写法（见 component_dev.md）
4. 重新 Base64 编码上传

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

## 紧急解封
- 规则层面：临时 status=false（影响所有 IP）
- 名单层面：加入 flow_bypass 名单（仅放行该 IP）
- 缓存层面：等待 block_time 过期自动解封
