# JxWAF Agent

JxWAF 自动化配置与验证工具集，支持通过 AI 助手（Claude Code、Trae 等）完成 Web 防护规则、流量防护规则、防护组件、名单防护的开发与运维。

## 项目结构

```
jxwaf-agent/
├── AGENTS.md                # AI 工作流与红线定义
├── README.md                # 项目说明（本文件）
├── docs/                    # 知识库（纯文本，供 AI 查阅）
│   ├── waf_manual.md        # JxWAF 配置说明（字段、动作、正则引擎、组件、名单、白名单）
│   ├── playbook.md          # 运维 SOP（误报处理、漏报排查、规则调优、白名单 SOP）
│   └── security_profiles.md # 安全规则配置档案（已实施的漏洞防护方案）
├── generated/               # AI 生成的配置制品存放目录
│   ├── rules/               # 防护规则（web/flow/web_white/flow_white）
│   ├── components/          # 防护组件（code.lua + conf.json）
│   ├── name_lists/          # 名单防护（meta.json + items.txt）
│   └── solutions/           # 联合判断完整方案
├── waf_node_src/            # 节点核心处理源码（供 AI 深度排查）
│   ├── access_rule.lua      # Web/流量规则 + 白名单检测逻辑
│   ├── regex_engine.lua     # 匹配引擎（参数预处理 + 运算符）
│   ├── component_and_name_list.lua  # 防护组件与名单防护逻辑
│   └── component_example.lua # 组件代码示例（CDN 源 IP 提取）
├── tools/                   # 工具箱（独立可执行脚本）
│   ├── waf_cli.py           # 对接 JxWAF 控制台 API（含白名单子命令）
│   └── verify.py            # 验证脚本（发请求 + 判定）
├── tests/                   # 测试用例库
│   └── payloads.json        # 攻击 payload 与验证用例（含白名单用例）
└── config.env               # 环境变量配置（API 地址、Token 等）
```

## 功能模块

### Web 防护规则
单次请求即时匹配，支持字符串/数字/正则/IP 等匹配方式，动作：block / watch。

### 流量防护规则
基于频率统计的防护，支持按 IP/路径/Cookie 等维度统计，动作：block / reject_response / bot_check / network_block。

### 防护组件
自定义 Lua 代码检测，可独立执行动作或设置 `ngx.ctx` 变量供规则引用，实现组件 + 规则联合判断。

### 名单防护
基于键值查找的快速匹配，支持 IP/域名/Cookie 多维度组合，动作：block / bypass / bot_check / network_block 等。可与规则联合实现 bypass 跳过或标记后差异化处置。

## 快速开始

### 1. 配置环境

```bash
cp config.env config.env  # 编辑填写实际 API 地址和 Token
```

### 2. 使用 CLI 管理规则

```bash
# 查询 Web 防护规则
python tools/waf_cli.py web-rule list --group default

# 创建 Web 防护规则
python tools/waf_cli.py web-rule create --group default --name block_admin \
  --matchs '[{"match_args":[{"key":"http_args","value":"path"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"/admin"}]' \
  --action block

# 创建流量防护规则
python tools/waf_cli.py flow-rule create --group default --name cc_protect \
  --action bot_check --action-value slipper --filter true \
  --matchs '[{"match_args":[{"key":"http_args","value":"path"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"/api/login"}]' \
  --entity '[{"key":"http_args","value":"src_ip"}]' --stat-time 10 --exceed-count 20 --block-time 600

# 创建防护组件
python tools/waf_cli.py component create --name scan_detect --detail "恶意扫描检测" \
  --code-file my_component.lua --conf '{"patterns":["sqlmap","nikto"]}'

# 创建名单并添加条目
python tools/waf_cli.py name-list create --name ip_blacklist --action block \
  --rule '[{"key":"http_args","value":"src_ip"}]'
python tools/waf_cli.py name-list add-item --name ip_blacklist --item 1.2.3.4
```

### 3. 验证配置

```bash
# 单次验证
python tools/verify.py --url https://demo.jxwaf.com/admin --expect block

# 高频验证（流量规则）
python tools/verify.py --url https://demo.jxwaf.com/api/login --mode flow --count 150 --interval 0.1 --expect block

# 批量验证
python tools/verify.py --batch tests/payloads.json --base-url https://demo.jxwaf.com
```

## AI 助手使用

将本项目目录提供给 Claude Code 或 Trae 等 AI 助手，AI 会：

1. 阅读 `AGENTS.md` 了解工作流和红线
2. 查阅 `docs/waf_manual.md` 获取字段定义和 API 接口
3. 参考 `waf_node_src/` 理解节点检测逻辑
4. 使用 `tools/waf_cli.py` 创建/编辑配置
5. 使用 `tools/verify.py` 验证配置效果

示例指令：
- "帮我创建一条 Web 防护规则，拦截所有访问 /phpmyadmin 的请求"
- "限制 /api/login 接口，同一 IP 10 秒内超过 20 次请求触发滑块验证"
- "编写一个防护组件，检测 User-Agent 中的恶意扫描器特征，并设置 ctx 变量供后续规则使用"
- "创建一个 IP 黑名单，支持通过外部 API 动态添加条目"

## 参考资料

本项目基于 JxWAF 专业版/标准版节点源码与控制台代码整理，涵盖：
- 规则引擎：匹配参数、参数预处理、匹配运算符
- Web 防护规则：即时匹配检测
- 流量防护规则：频率统计与处罚缓存
- 防护组件：自定义 Lua 代码 + ctx 变量传递
- 名单防护：键值查找 + bypass 跳过 + 结果传递
- 联合判断：组件/名单与规则的协作机制
