# jxwaf-cli 命令参考

所有命令输出契约：**stdout 为 JSON**，**stderr 为错误 `{"result":false,"error":"..."}`**，退出码 0=成功 / 1=失败。不确定参数含义时以本文档为准。

## 全局参数

| 参数 | 说明 |
|---|---|
| `--env <name>` | 目标环境名称，默认取配置中的 active（见 `config show`）；**test 命令组忽略此参数**，固定使用测试环境 |
| `--group <name>` | 专业版域名组（防护类与域名类操作必填，或配置 `--group-name`） |
| `--sub-user <name>` | 云WAF 主账号操作的目标子账号名（防护类与域名类操作必填） |

## 配置文件与查找顺序

CLI 配置（环境、凭据、官方测试环境地址）从**项目目录下的 `config.json`**（与 jxwaf-cli 二进制同级）读取，查找顺序：

1. `JXWAF_CONFIG_PATH` 环境变量指定的路径（测试与多配置场景）
2. 当前目录 `./config.json`
3. jxwaf-cli 可执行文件所在目录的 `config.json`（从其他目录调用二进制的场景）
4. 都不存在时默认 `./config.json`（写入操作在此创建）

**`config.json` 含凭据，已加入 `.gitignore`，严禁提交到仓库。**

配置文件结构（节选）：

```json
{
  "active": "prod",
  "test_env": "test",
  "environments": {
    "test": {
      "name": "test",
      "version": "professional",
      "base_url": "https://waf-demo.jxwaf.com",
      "waf_auth": "<凭据>",
      "test_url": "https://waf-demo.jxwaf.com:4443"
    }
  }
}
```

- 环境级 `test_url`：**测试站点地址**——配置下发到该环境后，访问此地址验证规则是否生效（`test verify` 打流量的目标）；官方测试环境固定为 `https://waf-demo.jxwaf.com:4443`，由 CLI 内置默认自动写入

## 初始化与配置

### `jxwaf-cli test init`

配置**自定义测试环境**（项目目录 `config.json`，权限 0600）。官方测试环境**开箱即用、无需初始化**：`config.json` 缺失或为空时 CLI 自动写入内置默认值（专业版固定共享账号 + 官方预置管理地址/域名组/测试站点）；删除 `config.json` 即恢复官方默认。

```
jxwaf-cli test init --base-url URL --waf-auth AUTH --test-url URL [--name ENV] [--group-name G]
```

- 必填：管理控制台地址 `--base-url`、凭据 `--waf-auth`、测试站点地址 `--test-url`（配置下发后访问它验证）
- 专业版防护操作必须指定域名组：`--group-name` 显式指定，或留空自动发现环境里的第一个域名组
- `--name` 默认 `test`，覆盖官方测试环境即完成切换；test 命令组（verify/reset/cleanup）自动操作该环境
- **不会修改 active 配置**：通用命令（rule/namelist/apply 等）默认不会命中测试环境；test 命令组固定使用测试环境，忽略 `--env`（防止误指向生产）

### `jxwaf-cli config`

```
jxwaf-cli config show                     # 查看配置（凭据脱敏，仅保留前 4 位）
jxwaf-cli config set --name N --version standard|professional|cloud \
                     --base-url URL --waf-auth T [--sub-waf-auth T] [--sub-user-name N] \
                     [--group-name G] [--cloud-mode user|admin]
jxwaf-cli config use <环境名>              # 切换 active 环境（通用命令的默认目标）
jxwaf-cli config validate [--env E]       # 连通性自检（不可达时退出码 1）
```

- 自有环境（标准版/专业版/自建云）用 `config set` 手动添加：标准版/专业版 waf_auth 来自部署环境（标准版为环境变量 `WAF_AUTH`，专业版为控制台注册账号生成的 waf_auth）
- 自建云主账号模式：`--waf-auth` 自己的主账号 token + `--sub-user-name` 默认子账号名（防护操作自动注入）；云WAF 用户（子账号）模式：额外 `--sub-waf-auth`
- `--cloud-mode`：显式指定云WAF模式。默认按是否配置 `--sub-waf-auth` 推断；配置了子账号凭据但需要用主账号管理时，显式指定 `--cloud-mode admin`
- 更新已存在的环境时**合并字段**：未指定的可选字段（sub-waf-auth/group-name 等）保留原值
- 凭据优先级：命令行参数 > 环境变量（`JXWAF_WAF_AUTH` / `JXWAF_SUB_WAF_AUTH`，可避免凭据进入 shell history）

## 配置生成（AI 辅助核心）

### `jxwaf-cli generate <类型> --params <file|->`

类型：`web-rule` / `web-white` / `flow-rule` / `flow-white` / `name-list` / `component` / `domain`

```
jxwaf-cli generate web-rule --params /tmp/p.json [--output /tmp/cfg.json]
```

- `--params`：JSON 文件路径、`-`（stdin）或内联 JSON，含 `config` 与可选 `test_cases` 两节
- 输出：`type`、`op`、`config`（规范化请求体）、`preview`（语义摘要，用于向用户展示）、`test_cases`
- `--output`：落盘信封 `{type, op, config, test_cases}`（供 `apply`/`verify` 使用）
- 未指定 `rule_action` 时默认 `watch`（观察优先红线）

字段与校验规范见 [rule_dev.md](rule_dev.md)、[module_dev.md](module_dev.md)、[component_dev.md](component_dev.md)。

## 下发

### `jxwaf-cli apply <配置文件> [--update] [--apply]`

下发 `generate --output` 生成的配置到目标环境。

- 默认 dry-run：仅输出 `{dry_run, env, base_url, path, body}` 预览（含目标环境，防止确认与下发之间 --env 不一致），不发请求
- `--apply` 实际执行；`--update` 按编辑接口更新（否则按创建）
- 业务失败（如重名 `rule_name is exist`）走 stderr 错误

### 资源写入子命令（统一 dry-run/apply 机制）

```
jxwaf-cli rule web|flow create|edit|delete|status|priority|load|hub-load|hub-export --params '{...}' [--apply]
jxwaf-cli rule web|flow engine edit --params '{...}' [--apply]           # 引擎防护配置
jxwaf-cli rule flow region edit --params '{...}' [--apply]               # 流量区域封禁
jxwaf-cli white web|flow create|edit|delete|status|priority|load|hub-load|hub-export --params '{...}' [--apply]
jxwaf-cli tamper create|edit|delete|status|priority|load|hub-load|hub-export --params '{...}' [--apply]
jxwaf-cli ssl create|edit|delete|wildcard|retry|cert-config --params '{...}' [--apply]
jxwaf-cli ssl global edit|status --params '{...}' [--apply]              # 全局 SSL 防护（仅云WAF）
jxwaf-cli group create|edit|delete --params '{...}' [--apply]            # 域名组（仅专业版）
jxwaf-cli namelist create|edit|delete|status|priority|load|hub-load|hub-export|item-add|item-del --params '{...}' [--apply]
jxwaf-cli component create|edit|delete|status|priority|load|hub-load|hub-export --params '{...}' [--apply]
jxwaf-cli website create|edit|delete --params '{...}' [--apply]
jxwaf-cli website access create|edit|delete|connect-test|cname-edit|sync --params '{...}' [--apply]  # 仅云WAF
jxwaf-cli network create|edit|status-set --params '{...}' [--apply]      # 网络封禁 IP
jxwaf-cli subaccount create|edit|delete|waf-auth|otp-reset --params '{...}' [--apply]  # 仅云WAF主账号
jxwaf-cli custom request-header|response-header|response-content|upstream create|edit|delete|status|priority|load|hub-load|hub-export --params '{...}' [--apply]  # 标准版不支持
jxwaf-cli cache policy|no-cache|bypass create|edit|delete|status|priority|load|hub-load|hub-export --params '{...}' [--apply]  # 仅云WAF
jxwaf-cli cache warmup|refresh create|delete --params '{...}' [--apply]  # 缓存任务（仅云WAF）
jxwaf-cli cache switch edit / cache cdn preheat|refresh --params '{...}' [--apply]  # 仅云WAF子账号
jxwaf-cli sysconf log|report|page|webtds edit --params '{...}' [--apply]  # 标准版不支持
jxwaf-cli sysconf report test / sysconf load --params '{...}' [--apply]   # load 为整库恢复（高危）
jxwaf-cli monitor delete --params '{...}' [--apply]
jxwaf-cli soc model delete|result|white-add|white-del --params '{...}' [--apply]
```

- `--params` 即 API 请求体（JSON 文件/`-`/内联），租户参数自动注入，无需手写
- **默认 dry-run**，`--apply` 才落地；删除类操作务必先 dry-run 展示影响
- `load` 导入的 `rules` 数组来自配对 `backup` 命令的输出，用于配置迁移。**load 语义：仅当 rule_name（名单 `name_list_name` / 组件 `name`）不存在时插入，已存在则跳过（不覆盖）**——迁移前先删除同名配置，或改用 `edit` 更新
- `backup` 导出仅含业务字段（不含 `status`、`rule_order_time`），导出结果可直接再用于 `load` 导入
- `priority` 调整优先级：`{"rule_name":"x","type":"top"}`（置顶）或 `{"rule_name":"x","type":"exchange","exchange_rule_name":"y"}`（互换）
- `hub-load`/`hub-export` 对接 Hub 配置中心（hub.jxwaf.com）：`{"hub_repo":"...","force_load":"true|false"}`，可选 `api_key`。**hub-load 为覆盖式**（先删后插），`force_load="false"` 时同名已存在会报错——与本地 `load` 的"跳过已存在"语义不同

## 查询

```
jxwaf-cli rule web|flow list|get|backup --params '{...}'
jxwaf-cli rule web|flow engine get / rule flow region get
jxwaf-cli white web|flow list|get|backup --params '{...}'
jxwaf-cli tamper list|get|backup --params '{...}'
jxwaf-cli ssl list|search|get --params '{...}'
jxwaf-cli ssl global get                                                # 仅云WAF
jxwaf-cli group list|search|get --params '{...}'                        # 仅专业版
jxwaf-cli namelist list|get|item-list|item-search|backup --params '{...}'
jxwaf-cli component list|get|backup --params '{...}'
jxwaf-cli website list|search|get --params '{...}'
jxwaf-cli website access list|get|cname-ips|quota --params '{...}'      # 仅云WAF
jxwaf-cli soc log query --params '{...}'                                # 攻击日志（单页 20 条）
jxwaf-cli soc log fetch --params '{...}'                                # 攻击日志全量拉取（自动翻页）
jxwaf-cli soc event list|track --params '{...}'                         # 攻击事件/行为轨迹
jxwaf-cli soc stats web|flow count-total|api-count|ip-count|country-count|geoip|trend|api-top|type-top|ip-top|country-top --params '{...}'
jxwaf-cli soc model list|white-list --params '{...}'                    # AI 模型
jxwaf-cli soc usage domains|overview|qps|bandwidth|status|latency|detail --params '{...}'
jxwaf-cli network list|search|get|status|node-update --params '{...}'   # 网络封禁
jxwaf-cli subaccount list|search|get --params '{...}'                   # 仅云WAF主账号
jxwaf-cli custom request-header|response-header|response-content|upstream list|get|backup --params '{...}'
jxwaf-cli cache policy|no-cache|bypass list|get|backup --params '{...}' # 仅云WAF
jxwaf-cli cache warmup|refresh list|detail / cache switch get           # 仅云WAF
jxwaf-cli sysconf log|report|page|webtds get / sysconf backup           # 标准版不支持
jxwaf-cli monitor list --params '{...}'
```

常见参数：

- 分页列表：`{"page": 1}`
- 单条查询：规则/白名单/防篡改 `{"rule_name": "x"}`；名单 `{"name_list_name": "x"}`；组件 `{"name": "x"}`；域名 `{"domain": "x"}`；证书 `{"ssl_domain": "x"}`；域名组 `{"group_name": "x"}`；子账号 `{"sub_user_name": "x"}`；封禁 IP `{"ip": "x"}`（云WAF admin 域名操作另需 `--sub-user`）
- 搜索：域名 `{"page":1,"search_domain":"x"}`；证书/域名组/子账号 `{"page":1,"search":"x"}`；封禁 IP `{"page":1,"search_ip":"x"}`；名单条目 `{"page":1,"name_list_name":"x","search_value":"y"}`
- SOC 统计/事件/用量：`{"from_time":"2026-08-30 00:00:00","to_time":"2026-08-30 10:00:00"}`（必填），可选 `domain`（支持 `*.` 前缀通配）；攻击事件加 `page`；行为轨迹加 `attack_ip`
- 攻击日志全量拉取（soc log fetch）：`{"last":"24h"}` 或 `{"from_time":"...","to_time":"..."}`（二选一），可选 `sql_rules`（条件过滤）、`fields`（输出字段投影，31 字段白名单）、`max_records`（默认 1000，上限 10000）；返回 `{total_count, fetched, truncated, pages_queried, records}`。用法示例与分析配方见 [analysis.md](analysis.md)
- 配置导出（backup）：规则/白名单/防篡改 `{"rule_name_list": ["x"]}`；名单 `{"name_list_name_list": ["x"]}`；组件 `{"name_list": ["x"]}`
- 网络封禁：`create {"ip":"1.2.3.4","status":"1","expire_time":3600}`（status 1=封禁 2=解封，expire_time 秒）
- 攻击日志：`{"from_time":"2026-08-30 10:00:00","to_time":"2026-08-30 11:00:00","page":1,"sql_rules":[{"field":"host","operation":"equals","value":"www.example.com"}]}`；sql_rules.field 可查字段（对齐 jxlog ClickHouse 表结构）：`host, group_name, request_uuid, waf_node_uuid, upstream_addr, upstream_response_time, upstream_status, status, process_time, request_time, raw_headers, scheme, version, uri, request_uri, method, query_string, raw_body, src_ip, user_agent, cookie, raw_resp_headers, raw_resp_body, iso_code, waf_module, waf_policy, waf_action, waf_extra, jxwaf_devid, raw_src_ip, jxwaf_ssl_fingerprint`；operation: `contains/prefix/suffix/equals/not_equals`

## 测试环境验证闭环

### 官方测试环境（test 命令组，与自有环境隔离）

```
jxwaf-cli test verify <用例文件> [--url https://...] [--wait 5] [--keep] [--no-fresh]
jxwaf-cli test cleanup --type web-rule|flow-rule|web-white|flow-white|tamper|name-list|component|website --names a,b [--apply]
jxwaf-cli test reset [--apply]
```

- `test verify` 为**一键闭环**：清空基线 → 部署信封配置 → 打测试流量 → 查 SOC 日志 → 报告 → 清理本次配置（环境回到空态）。判定：`expect=block` 且状态码 403/444 → `blocked`；`expect=pass` 且非 403/444 → `passed`；否则 `unexpected`。watch 类规则返回 200，需结合 `soc_logs` 中 `waf_action` 判读（见 [verify.md](verify.md)）
  - `--no-fresh`：不清基线（连续调试）；`--keep`：验证后保留配置
  - `--url` 省略时取测试站点地址（配置下发到测试环境后访问它验证，当前固定为 `https://waf-demo.jxwaf.com:4443`）：取值顺序 `--url` > 测试环境配置的 `test_url`
- `test cleanup`：按名称批量删除测试环境中的配置，默认 dry-run，`--apply` 执行（**删除不可恢复**）
- `test reset`：测试环境全量清空规则/白名单/名单/组件（**不删域名**），默认 dry-run；官方兜底"每日空环境"可挂定时 `jxwaf-cli test reset --apply`

### 通用验证（自有环境，只发流量不动配置）

```
jxwaf-cli verify <用例文件> --url https://example.com [--wait 5]
```

通用 `verify` 仅发送测试流量 + 查 SOC 日志出报告，**不会部署或清空任何配置**。

## WAF 远程部署

### `jxwaf-cli deploy`（节点/全栈）

把 JXWAF 自动部署到用户自己的服务器（**对齐 docs.jxwaf.com 官方部署教程**）：SSH 连接 → 系统探测（OS/架构/权限/CPU/内存）→ 依赖检查（Docker 未装按官方命令安装：`curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun`，阿里云镜像源适配国内网络）→ **端口冲突检测**（列出占用进程，不擅自 kill）→ 生成并上传 docker-compose.yml → 拉取镜像并启动容器 → 验证容器状态与节点日志。

**版本形态**（先问清用户要部署哪个版本）：

| 版本 | 形态 | 必填参数 |
|---|---|---|
| `professional` | 节点接入已有控制台（官方教程"节点部署"） | `--server` 控制台地址（末尾不带 `/`）、`--waf-auth` 控制台 waf_auth |
| `cloud` | 同上（节点接入已有管理控制台） | 同上 |
| `standard` | **单机全栈**：控制台+节点+MySQL+日志采集一次部署完成（官方"一键部署"），无需 `--server` | `--waf-auth` 自设 UUID（控制台与节点一致） |

```
export JXWAF_SSH_PASSWORD='<服务器SSH密码>'    # 密码认证（或 --ssh-key 私钥路径）
jxwaf-cli deploy --host <服务器IP> --user root \
  --version standard|professional|cloud \
  [--server http://<控制台地址>] \             # professional/cloud 必填（末尾不带 /）
  --waf-auth <凭据> \
  [--http-port 80] [--https-port 443] [--admin-port 8000] [--image <镜像>] [--skip-nft] [--apply]
```

- **镜像对齐官方教程版本**：professional 节点 `jxwaf_node_professional:6.1.0`、cloud 节点 `jxwaf_node_cloud:6.2.1`（含 `CACHE_MAX_SIZE: 10g`）、standard 全栈（`jxwaf_node_standard:6.1.7` + `jxwaf_admin_server_standard:6.1.14` + `mysql:8.0` + `log_send_to_mysql:v2`）；`--image`/`--nft-image` 可覆盖
- **默认完整部署**：均含 `jxwaf_nft_node` 网络封禁节点（standard 为 7.0 版，官方带 `WAF_FILTER_PORTS`）；`--skip-nft` 可跳过
- **环境要求预检**（对齐官方）：Debian 12.x / Ubuntu 20.04+（其他系统告警不阻断）、最低 4 核 8G（低于告警）
- **两步审核**：默认 dry-run，执行只读前置检查并展示部署计划与完整 compose 内容；`--apply` 才实际变更
- **端口冲突**：host 网络直占端口（standard 全栈还检查控制台 8000/MySQL 3306/日志 12997），被占时列出占用进程并终止
- **凭据安全**：SSH 密码仅经环境变量传入不落盘；standard 版 MySQL 密码自动随机生成；远端 compose（含凭据）权限 0600；缺任何必填参数时报错并注明获取方式
- **控制台无默认账号密码**：JXWAF 控制台不存在任何预置账号（admin / jxwaf_admin 等均不存在），首次使用必须注册账号，再从「系统管理 → 基础信息」获取 waf_auth；禁止编造默认凭据
- **部署后**：professional/cloud 节点凭 waf_auth 心跳自动注册（控制台"运营中心 → 节点状态"确认上线）；standard 访问 `http://<服务器IP>:8000` 注册账号即可使用

### `jxwaf-cli deploy admin`（管理控制台，prof/cloud 从零搭建用）

从零搭建专业版/云WAF 完整环境时，先部署控制台（官方教程"控制台部署"章节）：`mysql_db`（仅本机监听，密码自动生成）+ `jxwaf_admin_server` + `ssl_cert_service`（泛域名证书自动签发/续期）。

```
jxwaf-cli deploy admin --host <IP> --version professional|cloud [--admin-port ...] [--apply]
```

- 镜像：professional `jxwaf_admin_server_professional:6.1.0` / cloud `jxwaf_admin_server_cloud:6.2.1`（默认端口均为 8000，`--admin-port` 可改）
- **端口约定**：节点是流量入口必须占 80/443，控制台默认不占 80（同机部署控制台+节点不会冲突）；仅控制台与节点分机部署、控制台独占一台服务器时，才显式 `--admin-port 80`
- cloud 版自动开启 `USER_API_ENABLE: "true"`（用户控制台依赖，官方要求必须开）；模型服务按官方各版配置（prof 39977 / cloud 39980）
- MySQL 数据目录：prof `/opt/jxwaf_data/mysql` / cloud `/opt/jxwaf_data/mysql_cloud`（对齐官方卸载命令）
- **部署后**：浏览器访问 `http://<IP>:<端口>` 注册账号 → 系统管理→基础信息 查看 `waf_auth` → 用 `deploy --server http://<IP>:<端口> --waf-auth <waf_auth>` 部署节点

### `jxwaf-cli deploy jlog`（jxlog 日志系统，prof/cloud）

SOC 报表/日志查询依赖 jxlog（官方教程"JXLOG 日志系统部署"章节）：`clickhouse`（22.8.5-alpine）+ `jxlog`（prof `jxlog_professional:1.0` / cloud `jxlog_cloud:1.0`）。

```
jxwaf-cli deploy jlog --host <IP> --version professional|cloud [--apply]
```

**部署后到控制台对接**：系统配置→日志传输配置填 `<本机IP>:8877`；日志查询配置填 `<本机IP>:9004`（用户/密码 jxlog/jxlog，库 jxwaf，表 jxlog）。

### `jxwaf-cli deploy remove`（卸载）

```
jxwaf-cli deploy remove --host <IP> [--target node|admin|jlog] [--purge-data] [--apply]
```

对齐官方"卸载系统"流程（`docker compose down`）。三类部署**分目录隔离**（node=/opt/jxwaf_node，admin=/opt/jxwaf_admin，jlog=/opt/jxwaf_jlog），单独卸载互不影响；默认保留数据目录 `/opt/jxwaf_data`（重新部署可复用），`--purge-data` 连数据一起删（不可恢复，注意同机多组件时会删全部组件数据）。默认 dry-run，`--apply` 执行。

### prof/cloud 完整环境从零搭建顺序

```
1. deploy admin --version <v> --apply          # 控制台（注册账号，拿 waf_auth）
2. deploy --version <v> --server http://<控制台IP>:<端口> --waf-auth <waf_auth> --apply   # 节点（可多台）
3. deploy jlog --version <v> --apply           # jxlog（按需；SOC 报表/日志查询依赖）→ 控制台对接
```

- **版本时效**：以上镜像 tag 为编写时官方教程的版本（时点值）。官方发布新版后，到 docs.jxwaf.com 对应版本分站（`/jxwaf-standard/`、`/jxwaf-professional/`、`/jxwaf-cloud/` → Deployment-Tutorial）确认最新镜像版本与部署要求，用 `--image`/`--nft-image` 等覆盖参数指定新版本
- **单机全栈形态**（控制台/节点/jlog 同一台服务器）：按默认参数顺序部署即可——控制台 8000、节点 80/443、jlog 8877/9000/9004，互不冲突；节点 `--server` 填 `http://<控制台IP>:8000`

## 典型工作流

```
需求分析 → generate 生成 → apply 到测试环境(--apply) → verify 验证
→ 误报/漏报则改参数重试(≤3次) → cleanup 清理 → 用户确认 → 生产 --apply
```

安全规范与红线见 [sop.md](sop.md)；三版本能力差异见 [versions.md](versions.md)；误报/漏报排查与调优见 [playbook.md](playbook.md)；可复用配置模式见 [profiles.md](profiles.md)；日志分析与报表配方见 [analysis.md](analysis.md)。