# 日志分析与报表配方

> 数据获取的确定性原语全部由 CLI 命令提供；面对任意分析需求（攻击 IP 分析、防护日报、误报排查、趋势研判等），按本文配方组合命令取数，解读与呈现由 AI 完成。字段规范见 [rule_dev.md](rule_dev.md) / [module_dev.md](module_dev.md)，排查调优见 [playbook.md](playbook.md)。

## 数据原语地图（按需选命令）

| 需要什么 | 命令 | 说明 |
|---|---|---|
| 原始攻击日志（单页 20 条） | `soc log query` | 手工翻页查看 |
| **原始攻击日志（全量）** | `soc log fetch` | **自动翻页 + 字段投影 + 相对时间 + 上限保护**，分析首选 |
| 固定维度统计（服务端聚合，快） | `soc stats web\|flow count-total/api-count/ip-count/country-count/geoip/trend/api-top/type-top/ip-top/country-top` | Top/趋势/总数类直接用，无需拉日志 |
| 攻击事件与行为轨迹 | `soc event list` / `soc event track` | 聚合事件、单攻击 IP 的行为序列 |
| 网络封禁状态 | `network list/search/get` | IP 是否在封、何时过期 |
| 节点健康 | `monitor list` | 心跳与在线状态 |
| 流量/用量（QPS/带宽/延迟/状态码） | `soc usage domains/overview/qps/bandwidth/status/latency/detail` | 业务侧报表数据 |
| AI 引擎判定记录 | `soc model list` / `soc model result` / `soc model white-list` / `soc model white-add` | 判定记录、误报标记与 Token 白名单 |

## soc log fetch 用法（分析核心原语）

```bash
# 最近 24 小时某 IP 的全部日志，只看关键字段
jxwaf-cli soc log fetch --params '{
  "last": "24h",
  "sql_rules": [{"field": "src_ip", "operation": "equals", "value": "1.2.3.4"}],
  "fields": ["request_time", "host", "uri", "waf_module", "waf_policy", "waf_action", "waf_extra"]
}'

# 昨天全天某域名的拦截记录
jxwaf-cli soc log fetch --params '{
  "from_time": "2026-09-01 00:00:00", "to_time": "2026-09-01 23:59:59",
  "sql_rules": [
    {"field": "host", "operation": "equals", "value": "www.example.com"},
    {"field": "waf_action", "operation": "equals", "value": "block"}
  ]
}'
```

- `last`（`30s`/`15m`/`24h`/`7d`）与 `from_time`+`to_time` 二选一
- `fields` 投影裁剪输出（31 字段白名单内）；省略则输出全字段
- `max_records` 默认 1000（上限 10000），截断时输出 `truncated: true` 与收窄提示
- `sql_rules` 多条件 AND；field/operation 由 CLI 白名单校验
- 返回：`{total_count, fetched, truncated, pages_queried, records}`；数据为时点快照（翻页期间新日志不保证包含）

## 场景配方

### 1. 分析某个 IP 的攻击情况

```
① soc stats web ip-top（+ flow ip-top）      → 确认该 IP 在攻击来源中的排名与量级
② soc log fetch（sql_rules: src_ip equals）  → 拉取该 IP 全部日志（fields 投影）
③ network get（ip）                          → 是否已网络封禁、剩余时长
④ soc event track（attack_ip）               → 行为轨迹（攻击链路）
→ AI 汇总：时间分布 / 动作分布（block/watch/pass）/ 命中策略 Top / 目标 host+uri Top / UA 特征 / 封禁建议
```

### 2. 每日安全报告

标准模板如下（已审核定稿）。取数命令全部来自现有数据原语，AI 每日执行取数后组装；用户可随时要求增删口径，模板仅为默认基线。**默认同时生成 Markdown 与 HTML 两个版本**（内容同源，HTML 用于浏览器查看，Markdown 用于归档/粘贴）。

**组装流程**：

```
① soc stats web count-total（+ flow count-total）    → 总览指标（含环比）
② soc stats web trend                                 → 24h 攻击趋势
③ soc stats web type-top / ip-top / api-top           → 类型 / 来源 / 受攻击资产 Top
④ soc stats web geoip                                 → 来源地理分布（标准版无此接口，自动省略归属地列）
⑤ soc log fetch（sql_rules: waf_action equals watch，fields: waf_policy/waf_module）→ watch 热点分组计数
⑥ network list                                        → 当日封禁清单（AI 按创建时间过滤当日新增）
⑦ monitor list                                        → 节点健康（仅异常时显示）
⑧ soc usage overview / qps / bandwidth                → 业务流量精简概览
⑨ Top 攻击 IP 逐个 network get                        → 封禁状态核查
→ AI 按下述模板组装 Markdown 版，再渲染同内容 HTML 版；风险提示与建议由 AI 依据数据生成（建议动作需用户确认，不自动执行）
```

**报告模板**：

```markdown
# JXWAF 每日安全报告 · YYYY-MM-DD

## 一、总览
| 指标 | 数值 | 环比 |
|---|---|---|
| 攻击记录总数 | 18,200 | ↑ 12% |
| 拦截（block/reject_response） | 12,000（65.9%） | — |
| 人机识别质询（bot_check） | 3,200 | — |
| 观察（watch） | 5,000（27.5%） | — |
| 受攻击域名数 | 8 | — |
| 活跃攻击源 IP | 156 | — |
| 新增网络封禁 | 23 | — |

> 环比仅显示服务端提供的指标（count-total）；其余列固定为 —，不由 AI 手算

## 二、攻击趋势（24h）
| 时段 | 00 | 02 | 04 | 06 | 08 | 10 | 12 | 14 | 16 | 18 | 20 | 22 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 记录数 | 320 | 180 | 90 | ... | | | | | | | | 850 |

> 标注峰值时段；趋势数据以折线呈现，不用柱状

## 三、攻击类型 Top 5
| 类型 | 次数 | 占比 |
|---|---|---|

## 四、攻击来源 Top 5
| IP | 归属地 | 次数 | 主要类型 | 封禁状态 |
|---|---|---|---|---|

> 归属地依赖 geoip（标准版自动省略该列）；封禁状态为空时标"未处置"

## 五、受攻击资产 Top 5
| 域名/接口 | 次数 | 主要攻击类型 |
|---|---|---|

## 六、观察（watch）热点 Top 3
| 策略名 | 命中次数 | 说明 |
|---|---|---|

> watch = 未拦截仅记录。高频策略是潜在漏拦风险，建议复核误报后转 block（转 block 走两步审核）

## 七、网络封禁清单（当日新增）
| IP | 封禁来源 | 到期时间 |
|---|---|---|

## 八、节点健康（仅异常时显示）
| 节点 | 状态 | 最后心跳 |
|---|---|---|

> 全部节点正常时本节省略

## 九、业务流量概览
| 指标 | 数值 |
|---|---|
| QPS 峰值 | 850 |
| 带宽峰值 | 210 Mbps |

## 十、风险提示与建议（AI 结论）
- ⚠ watch 策略 block_xxx 昨日命中 2,300 次，建议复核误报后转 block
- ⚠ IP 1.2.3.4 连续 3 日高频攻击，封禁剩余 4 小时，建议延长
- ✅ 拦截率 65.9% 处于正常区间，无节点异常
```

**版本降级规则**：标准版无 flow 攻击统计（只报 web 侧）、无 geoip（省略归属地列）；云WAF 子账号按能力矩阵限制。降级时在对应小节标注"当前版本不支持"，不静默缺失。

**边界策略**：各 Top 榜单数据量小直接展示；总览指标来自服务端聚合（无上限问题）；watch 热点用 fetch（受 max_records 保护，截断时在报告标注"抽样"）。

**HTML 版本规范**（与 Markdown 内容同源，必须遵守）：

- 单文件自包含：CSS 内联、无外部依赖（图表用内联 SVG 或 ECharts CDN 二选一，离线查看场景优先 SVG），文件名 `daily-report-YYYY-MM-DD.html`
- 品牌与标题：产品名固定写 **JXWAF**（全大写），页头 `JXWAF 每日安全报告 · YYYY-MM-DD`
- 布局紧凑：卡片式分节，等高对齐；去掉无信息量的装饰元素；节顺序与 Markdown 版一致（一~十）
- 指标层级：总览区关键数值大字号突出，标签与辅助说明小号灰字；环比涨跌用颜色区分（升=红、降=绿、持平=灰）
- 趋势图：24h 攻击趋势用**折线图 + 渐变填充**，禁止柱状图；标注峰值点
- 列表与状态：Top 榜单用紧凑表格；封禁状态用彩色圆点标识（已封禁=红、未处置=橙、已解封/无=灰）；状态码/动作分布类数据用色点 + 数值
- 数值带单位：QPS、Mbps 等单位紧跟数值（如 `210 Mbps`），百分比保留一位小数
- 风险提示：⚠ 黄色警示条、✅ 绿色确认条区分展示；建议动作仅文字提示，不放可点击执行元素

### 3. 域名被什么攻击

```
① soc stats web api-top / type-top（sql 维度用 domain 参数） → 受攻击接口与类型 Top
② soc log fetch（sql_rules: host equals）→ 明细日志，fields 含 uri/query_string/raw_body
```

### 4. 哪些 watch 规则命中最多（观察转 block 评估）

```
① soc log fetch（sql_rules: waf_action equals watch，fields: waf_policy/waf_module/request_time）
→ AI 按 waf_policy 分组计数，高频策略核对无误报后转 block（两步审核）
```

### 5. 误报专项（某规则误拦排查）

```
① soc log fetch（sql_rules: waf_policy contains <规则名>）→ 该规则全部命中记录
② 结合 request_uri / raw_body 分析误报共性（某 UA？某业务接口？某参数值？）
③ 处置按 playbook.md 误报 SOP（收窄匹配 / 加白名单 / 降级 watch）
```

### 6. 攻击时段分布

```
① soc stats web trend（服务端已按跨度自适应聚合）
② 或 soc log fetch（fields: request_time）→ AI 按小时分组计数
```

## 可查字段字典（31 个，sql_rules/fields 白名单）

| 类别 | 字段 |
|---|---|
| 请求标识 | `request_uuid` / `jxwaf_devid` / `waf_node_uuid` |
| 站点与路径 | `host` / `group_name` / `uri` / `request_uri` / `query_string` / `method` / `scheme` / `version` |
| 客户端 | `src_ip` / `raw_src_ip` / `user_agent` / `cookie` / `iso_code` / `jxwaf_ssl_fingerprint` |
| 请求体/头 | `raw_body` / `raw_headers` |
| 上游 | `upstream_addr` / `upstream_response_time` / `upstream_status` |
| 响应 | `status` / `raw_resp_headers` / `raw_resp_body` |
| 性能 | `process_time` / `request_time` |
| 判定 | `waf_module` / `waf_policy` / `waf_action` / `waf_extra` |

## waf_module / waf_action 对照

| waf_module | 模块 | | waf_action | 含义 |
|---|---|---|---|---|
| `base_component` | 防护组件 | | `block` | 拦截（403） |
| `name_list` | 名单防护 | | `reject_response` | 关闭连接（444） |
| `flow_white_rule` / `web_white_rule` | 白名单 | | `bot_check` | 人机识别质询 |
| `flow_ip_region_block` | IP 区域封禁 | | `network_block` | 网络层封禁 |
| `flow_rule_protection` / `web_rule_protection` | 防护规则 | | `watch` | 观察记录 |
| `flow_engine_protection` / `web_engine_protection` | 引擎防护 | | `pass` | 放行 |
| `web_page_tamper_proof` | 网页防篡改 | | `web_bypass`/`flow_bypass`/`all_bypass` | 白名单/名单放行 |

## 大结果集策略

1. **先 stats 后 fetch**：量级先用 `soc stats`（服务端聚合）摸底，再用 `fetch` 收窄拉明细
2. **收窄维度**：时间窗（`last`）+ `sql_rules`（host / src_ip / waf_action / waf_module）组合过滤
3. **fields 投影**：raw_body / raw_resp_body / raw_headers 等大字段按需保留，可大幅减少输出
4. **超量分批**：时间窗切分（如按小时多次 fetch）覆盖全量；`truncated: true` 时必须处理
