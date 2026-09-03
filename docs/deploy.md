# 自动化部署指南（Deployment）

> 本文是 JXWAF 的**部署决策与生命周期指南**：架构选型、部署规划、多节点扩展、纳管衔接、验证上线、卸载与升级。
> `deploy` 命令的**参数/用法参考**见 [cli.md](cli.md)「WAF 远程部署」章节；本文聚焦「怎么部署才正确、多节点怎么搭」，不重复罗列参数。
>
> 权威依据：官方 GitHub 仓库 `jx-sec/jxwaf` 各版本 `docker-compose.yml`（及 docs.jxwaf.com 各版本分站 `Deployment-Tutorial`）。CLI 的 `deploy` 命令默认**从官方仓库拉取最新 compose 并注入参数部署**，将官方手动流程（`git clone` + 改 `docker-compose.yml` + `docker compose up -d`）自动化；拉取失败自动降级本地生成。

## 一、部署形态总览

JXWAF 三个版本对应三种部署形态，由 `deploy` 命令统一承载：

| 版本 | 形态 | 说明 |
|---|---|---|
| `standard` | **单机全栈**（一键部署） | 控制台 + 节点 + MySQL + 日志采集 + nft_node 全部部署在一台机器，`--waf-auth` 为自设 UUID（控制台与节点一致），无需 `--server` |
| `professional` | **分离部署** | 控制台（`deploy admin`）+ 节点（`deploy`）+ jxlog（`deploy jlog`）三组件，可分离到多台服务器，**节点可多台水平扩展** |
| `cloud` | **分离部署**（多租户） | 同上，另含用户控制台 `jxwaf_cloud_user`（CLI 暂不支持部署，见 [能力边界](#八能力边界与已知限制)） |

## 二、架构组件与镜像版本

| 组件 | 作用 | 部署方式 |
|---|---|---|
| `jxwaf_admin_server` | 管理控制台（可视化运营 + API） | `deploy admin`（prof/cloud）；standard 含在全栈 |
| `jxwaf_node` / `jxwaf_base` | 流量节点（OpenResty，代理 + 实时检测） | `deploy` |
| `jxwaf_nft_node` | 网络封禁节点（网络层封禁 IP） | 随 `deploy` 默认部署（`--skip-nft` 可跳过） |
| `mysql_db` | MySQL 8.0（站点配置 + 攻击日志） | 随控制台/全栈部署（仅本机监听） |
| `ssl_cert_service` | 泛域名证书自动签发/续期 | 随 `deploy admin`（prof/cloud） |
| `jxlog` + `clickhouse` | 日志采集与 SOC 报表/查询 | `deploy jlog`（prof/cloud） |

镜像版本**默认直接从官方 GitHub 拉取**（不再硬编码，也不依赖本地缓存）：

| 组件 | 镜像（官方 GitHub 当前值，仅作参考） |
|---|---|
| 节点 standard / professional / cloud | `jxwaf_node_standard` / `_professional` / `_cloud` |
| 控制台 standard / professional / cloud | `jxwaf_admin_server_standard` / `_professional` / `_cloud` |
| nft_node | `jxwaf_nft_node` |
| MySQL / 日志采集（standard） | `mysql` / `log_send_to_mysql` |
| ssl_cert_service / clickhouse | `ssl_cert_service` / `clickhouse-server` |
| jxlog professional / cloud | `jxlog_professional` / `jxlog_cloud` |

### 部署策略（compose 来源）

部署**每次都会获取最新 compose**，注入参数后部署，保证版本与官方一致。compose 来源为三级降级链：

```
主路径：deploy 从 raw.githubusercontent.com 本地拉取官方 compose（每次实时）
降级 1：本地拉取失败（网络问题）→ 服务器 git clone 官方仓库获取
降级 2：git clone 也失败 → 本地生成（版本来自 versions.json）
       → 每次降级均输出 degraded 提示
注入参数（waf_auth / server / 端口 / MySQL 随机密码）→ dry-run 展示 → 用户确认 → 上传部署
```

- **自动刷新**：每次成功拉取官方 compose 后，自动提取镜像版本回写 `versions.json`，使本地生成兜底也保持最新
- `--source github`（默认）：本地拉取 → 降级 git clone → 降级本地生成
- `--source git`：直接服务器 git clone → 降级本地生成
- `--source generate`：强制本地生成（版本来自 versions.json，即最近一次成功拉取/手动维护的版本）
- `jxwaf-cli deploy version`：查看本地生成兜底用的镜像版本（versions.json）
- `--image` / `--nft-image` / `--ssl-cert-image` / `--clickhouse-image` 仍可单次临时覆盖
- dry-run 输出 `compose_source` 字段标明实际来源（github / git / generate），`degraded` 字段提示降级

## 三、环境要求与端口约定

**环境要求**（对齐官方，部署时自动探测，低于最低配置仅告警不阻断）：

- 操作系统：Debian 12.x / Ubuntu 20.04+（其他系统告警）
- 最低配置：4 核 8G
- 依赖：Docker + Compose（缺失时 `deploy --apply` 按官方命令自动安装，`--mirror Aliyun` 适配国内网络）

**端口约定**：

| 组件 | 端口 | 说明 |
|---|---|---|
| 节点 HTTP / HTTPS | 80 / 443 | 流量入口，host 网络直占；支持多端口逗号分隔（`--http-port 80,8080`） |
| 控制台 | **8000**（CLI 默认） | 官方专业版教程默认 80，CLI 为避免同机与节点 80/443 冲突默认改用 8000；控制台独占一台机器时可用 `--admin-port 80` |
| MySQL | 3306 | 仅绑定 `127.0.0.1`，不暴露外网 |
| 日志采集（standard） | 12997 | `log_send_to_mysql` 监听 |
| jxlog | 8877 / 9000 / 9004 | 日志接收 / ClickHouse TCP / ClickHouse MySQL 兼容 |

## 四、部署决策树（选型）

```
要部署 JXWAF？
├── 单团队、单机够用 → standard 单机全栈（最快，一条命令）
├── 需要控制台/节点/日志分离、或多节点水平扩展 → professional / cloud 分离部署
│     ├── 先 deploy admin 部署控制台 → 注册账号拿 waf_auth
│     ├── 再 deploy 部署节点（可多台，见「多节点部署」）
│     └── 按需 deploy jlog（SOC 报表/日志查询依赖）
└── 多租户 SaaS、需子账号/网站接入/CDN → cloud（另需用户控制台，CLI 暂不支持）
```

## 五、部署生命周期（从零到上线）

### 5.1 规划

1. 确定版本形态（见决策树）与机器分配（几台、各装什么组件）。
2. standard：一台机器即可；prof/cloud 分离：建议控制台、节点、jxlog 分别占机（同机部署时端口互不冲突，见 cli.md「单机全栈形态」）。
3. 多节点：确定节点台数与各节点 IP（详见 [多节点部署](#六多节点部署重点)）。

### 5.2 部署执行

所有 `deploy` 子命令默认 **dry-run**（只读预检 + 展示部署计划与完整 compose），确认后加 `--apply` 才实际变更。SSH 密码经环境变量 `JXWAF_SSH_PASSWORD` 传入（不落盘），或用 `--ssh-key` 私钥。

```bash
# standard 单机全栈
jxwaf-cli deploy --host <IP> --version standard --waf-auth <自设UUID> --apply

# prof/cloud 从零搭建（分离部署，顺序执行）
jxwaf-cli deploy admin --host <IP> --version professional --apply          # 1. 控制台
jxwaf-cli deploy --host <IP> --version professional \
  --server http://<控制台IP>:8000 --waf-auth <waf_auth> --apply            # 2. 节点
jxwaf-cli deploy jlog --host <IP> --version professional --apply          # 3. jxlog
```

### 5.3 部署后纳管（关键衔接）

CLI 部署出的控制台 **Admin API 默认关闭**（`ADMIN_API_ENABLE: "false"`），需开启后才能被 `jxwaf-cli` 纳入管理：

1. 浏览器访问控制台注册账号（**无任何预置账号**，admin/jxwaf_admin 均不存在），建议开启 OTP。
2. 控制台「系统管理 → 基础信息」查看 `waf_auth`。
3. 修改控制台所在服务器 `docker-compose.yml` 中 `jxwaf_admin_server` 的环境变量并重启：
   ```yaml
   ADMIN_API_ENABLE: "true"
   ADMIN_API_WHITELIST: "*"   # 生产建议收紧为固定 IP/网段
   ```
4. 用 `config set` 将该环境接入 CLI，`config validate` 自检连通：
   ```bash
   jxwaf-cli config set --name prod --version professional \
     --base-url http://<控制台IP>:8000 --waf-auth <waf_auth> --group-name <域名组>
   jxwaf-cli config validate
   ```

> 这是「部署 → 纳管」的**手动衔接点**：CLI 暂不自动开启 Admin API、也不自动写 `config.json`（见 [能力边界](#八能力边界与已知限制)）。

### 5.4 验证上线

- 节点上线：控制台「运营中心 → 节点状态」确认节点心跳注册成功；或 `jxwaf-cli monitor list` 查心跳（异常阈值 10 分钟）。
- 防护生效：按标准工作流 `generate → test verify → 生产 dry-run → --apply` 下发一条规则并验证（见 [verify.md](verify.md)）。

### 5.5 扩容

节点扩容即「多节点部署」（见下一章）；jxlog/控制台一般单点部署，按需另行扩展。

### 5.6 卸载

```bash
jxwaf-cli deploy remove --host <IP> [--target node|admin|jlog] [--purge-data] --apply
```

默认保留数据目录 `/opt/jxwaf_data`（重新部署可复用）；`--purge-data` 连数据一起删（**不可恢复**，同机多组件时会删全部组件数据）。卸载属极高风险，默认 dry-run，需二次确认。

### 5.7 升级

官方升级流程为 `git pull → docker compose down/up`。CLI 侧暂无专用升级命令，当前通过**重新 `deploy --apply`**（覆盖 compose + 重拉镜像）实现，或按官方教程在服务器上手动升级。镜像版本用 `--image`/`--nft-image` 指定新版。

## 六、多节点部署（重点）

### 6.1 多节点架构

官方多节点模型：**多个节点部署在不同服务器，全部指向同一个控制台地址 + 同一个 `waf_auth`**；控制台「运营中心 → 节点状态」统一查看各节点是否上线。

```
                    ┌─────────────────────────┐
   DNS / 负载均衡 ──▶│  节点 1（nginx+检测+nft）│──┐
   （用户架构决定）    └─────────────────────────┘  │
                    ┌─────────────────────────┐  │  心跳/配置拉取
                    │  节点 2（nginx+检测+nft）│──┼──▶ 管理控制台（唯一）
                    └─────────────────────────┘  │   （同一 waf_auth）
                    ┌─────────────────────────┐  │
                    │  节点 3（...）           │──┘
                    └─────────────────────────┘
```

### 6.2 执行方式：单次部署一台，多次调用水平扩展

**当前 CLI 已支持**：`deploy` 是无状态的，每次 `--host` 独立执行并覆盖该机 compose。多节点部署只需对每个节点各执行一次 `deploy`，**保持 `--server` 与 `--waf-auth` 一致**即可水平扩展，无需额外参数：

```bash
export JXWAF_SSH_PASSWORD='<SSH密码>'

# 同一控制台 + 同一 waf_auth，逐台部署节点（水平扩展）
jxwaf-cli deploy --host 10.0.0.11 --version professional \
  --server http://<控制台IP>:8000 --waf-auth <waf_auth> --apply
jxwaf-cli deploy --host 10.0.0.12 --version professional \
  --server http://<控制台IP>:8000 --waf-auth <waf_auth> --apply
jxwaf-cli deploy --host 10.0.0.13 --version professional \
  --server http://<控制台IP>:8000 --waf-auth <waf_auth> --apply
```

要点：

- **参数一致性**：各节点的 `--server`、`--waf-auth` 必须完全相同（对应同一控制台），否则节点无法正确接入。
- **端口可按需不同**：各节点 `--http-port`/`--https-port` 可相同（流量入口各自独立），也可不同（同一 LB 后端区分）。
- **dry-run 先行**：建议先对每台执行一次 dry-run（不加 `--apply`）确认预检与端口无冲突，再统一 `--apply`。

### 6.3 nft_node 部署策略

**每台节点都带 `jxwaf_nft_node`**（CLI 默认 `WithNFT=true`）。网络封禁需覆盖所有流量入口，因此多节点下每台节点都部署 nft_node，封禁才会对经该节点进入的流量生效；除非明确不使用「网络封禁」动作，否则不要 `--skip-nft`。

### 6.4 流量分发（用户架构决定，WAF 侧不关心）

多节点后业务流量如何进入各节点，**默认由 DNS 解决，其余（云 SLB/CLB、自建 nginx/LVS/keepalived 等）由用户自身架构决定**，与 WAF 无关。WAF 侧唯一要求：

- **每个节点都能（经内网或公网）访问管理控制台**（配置拉取 + 心跳上报）；
- 业务流量分发到任意节点后，防护行为一致（各节点配置由控制台统一下发）。

### 6.5 节点上线确认与健康

- 上线确认：控制台「运营中心 → 节点状态」看到新节点即为接入成功；或 `jxwaf-cli monitor list` 查心跳。
- 异常节点：心跳异常阈值 10 分钟；流量分发层应配合做节点探活/摘除（属用户 LB/DNS 侧职责）。

### 6.6 待补能力

| 能力 | 现状 |
|---|---|
| 批量部署 / 清单管理（`--hosts` 清单文件一次部署多台） | ❌ 未支持，当前为「单次部署一台、多次调用」 |
| 部署后自动纳管（自动开 Admin API / 自动写 config.json） | ❌ 未支持，需手动衔接（见 5.3） |
| 部署状态查询 / 幂等清单持久化 | ❌ 未支持，重复 `deploy` 会覆盖该机 compose |
| 节点升级命令 | ❌ 未支持，重新 `deploy --apply` 或官方手动升级 |

## 七、安全规范

1. **两步审核**：所有 `deploy` 子命令默认 dry-run，`--apply` 才实际变更；卸载属极高风险需二次确认。
2. **凭据安全**：SSH 密码仅经环境变量 `JXWAF_SSH_PASSWORD` 传入（不落盘、不进命令行参数）；standard/admin 版 MySQL 密码自动随机生成；远端 compose（含凭据）权限 0600；本地不留存任何密码。
3. **无默认账号**：控制台不存在预置账号，禁止编造 admin/jxwaf_admin 等默认凭据，首次必须注册。
4. **端口冲突**：host 网络直占端口，被占时 CLI 列出占用进程并终止（不擅自 kill），需换端口或用户自行处理。

## 八、能力边界与已知限制

- CLI 的 `deploy` 覆盖：节点（standard 全栈 / prof / cloud 接入已有控制台）、控制台（prof/cloud）、jxlog（prof/cloud）、卸载。**不覆盖**：云WAF 用户控制台 `jxwaf_cloud_user`（子账号自助控制台，需按官方教程手动部署）。
- 多节点当前为「逐台执行」，无批量/清单能力（见 6.6）。
- 部署出的控制台 Admin API 默认关闭，需手动开启后才可纳入 CLI 管理（见 5.3）。
- `deploy exec` 提供诊断命令执行通道（只读直接执行），但风险命令（kill/stop/rm/down/重启关机/磁盘格式化/防火墙修改）由 CLI 强制拦截、需 `--approve` 审批（见 9.2）。
- 镜像版本为时点值，官方发布新版后以 docs.jxwaf.com 为准。

## 九、排障（AI 自主诊断 + 风险审批）

### 9.1 排障范式

部署/运行中的问题是**开放、不可穷举**的，不依赖固定场景对照表，而是：**AI 登录目标服务器自主收集信息 → 判断根因 → 给出处置方案；其中风险操作必须经用户审批后才执行**。

诊断信息收集（按需组合，不限于此）：

| 来源 | 手段 | 类型 |
|---|---|---|
| 部署预检报告 | `deploy` dry-run 的 `report`（`sys_info` / `port_checks` / `steps` / `node_logs`） | 只读 |
| 服务器现场 | `deploy exec --host <IP> --cmd "<命令>"`（`docker ps -a`、`docker logs`、`ss -tlnp`、`df -h`、`free -m`、`systemctl status` 等） | 只读（风险命令自动拦截） |
| 控制台侧 | `monitor list`（节点心跳）、`config validate`（连通性） | 只读 |

> 服务器现场命令通过 `deploy exec` 执行：AI 可直接登录服务器收集信息；只读诊断命令直接返回输出，命中风险红线的命令由 CLI 强制拦截、需 `--approve`（用户已审批）才执行（见 9.2）。

### 9.2 风险分级与审批

| 级别 | 操作示例 | 处理 |
|---|---|---|
| 只读诊断 | `docker ps/logs`、`ss -tlnp`、`df/free`、`systemctl status` | 直接执行，无需审批 |
| 低风险变更 | 换端口重部署、`--image` 换镜像、补装 Docker/compose | 展示变更，dry-run 后用户确认 `--apply` |
| 高风险变更 | `kill`/`pkill` 进程、`systemctl stop` 停服务、`--purge-data` 删数据、`deploy remove` 卸载、`docker compose down`、改动非 jxwaf 程序 | **展示影响范围，必须用户明确审批**后执行 |

**风险操作红线**（AI 不得自主执行，须审批）：

- `kill` / `kill -9` / `pkill` 结束进程
- `systemctl stop` / `disable` 停止或禁用服务
- `rm -rf` 删除数据目录（含 `--purge-data`）
- `deploy remove` 卸载
- 修改/删除非 jxwaf 的其他程序（nginx、MySQL、防火墙等）配置

> 通过 `deploy exec` 执行的命令，命中上述红线（以及重启关机、磁盘格式化、防火墙修改等）时由 **CLI 强制拦截**，不加 `--approve` 直接拒绝——把「风险审批」从文档约定下沉为 CLI 强制兜底。

### 9.3 常见问题速查（起点参考，非穷举）

| 现象 | 常见根因 | 处置方向 |
|---|---|---|
| SSH 连接失败 | 地址/端口/账号/密钥错误 | 核对连接参数，看 SSH 报错 |
| 端口冲突 | 端口被其他程序占用 | 见下方「端口冲突专项处理」 |
| 镜像拉取失败 | 无法访问镜像仓库 | `--image` 指定可达镜像，或检查仓库连通 |
| 容器启动后状态异常 | 配置错误/依赖未就绪 | `docker ps -a` + `docker logs <容器>` 定位 |
| 节点未上线 | `--server` / `--waf-auth` 不一致 | 核对参数，查控制台「运营中心 → 节点状态」 |
| 部署后 CLI 无法管理 | Admin API 未开启 | 见 5.3 开启后重启容器 |

> 遇到表中未列出的问题，按 9.1 / 9.2 范式自主诊断，风险操作走审批。

### 端口冲突专项处理（最典型的风险场景示例）

端口被其他程序占用是部署最常见的中断。CLI 预检会列出占用进程（`report.port_checks`，来自 `ss -tlnp`），但**不擅自 kill**，需按以下任一方式处理。

先确认占用情况（在目标服务器上执行）：

```bash
ss -tlnp | grep -E ':(80|443|8000|3306|12997|8877|9000|9004)[[:space:]]'
# 或定位具体端口：lsof -i :80
```

三种处理路径：

1. **换端口**（最安全）：改用空闲端口继续部署。
   ```bash
   jxwaf-cli deploy --host <IP> --version standard --waf-auth <uuid> \
     --http-port 8080 --https-port 8443 --admin-port 8000 --apply
   ```
2. **停掉占用进程**（WAF 需接管 80/443 时）：最常见是原服务器已跑 nginx/apache/caddy，而 WAF 节点本身基于 OpenResty，部署后即替代它。确认可停后由**用户手动**停掉（CLI 不会自动 kill），再重新 `--apply`：
   ```bash
   ss -tlnp | grep ':80'      # 确认占用进程
   systemctl stop nginx       # 或 docker stop <容器名>
   ```
3. **跳过检查**（明确接受占用）：`--skip-port-check`。仅在确认占用进程可与 WAF 并存或无需处理时使用；否则跳过检查会导致容器启动失败。

常见冲突场景：

| 占用端口 | 常见进程 | 建议 |
|---|---|---|
| 80 / 443 | nginx / apache / caddy / 其他反代 | 停掉或迁移（WAF 节点基于 OpenResty 会替代），或换端口 |
| 8000 | 其他控制台/服务 | 换 `--admin-port` |
| 3306 | 已装 MySQL | 停掉本机 MySQL（WAF 自带 MySQL，仅监听 127.0.0.1） |
| 8877 / 9000 / 9004 | 已装 ClickHouse / jxlog | 换部署机器或停掉旧实例 |

> 相关：命令参数见 [cli.md](cli.md)「WAF 远程部署」；三版本差异见 [versions.md](versions.md)；安全工作规范见 [sop.md](sop.md)。
