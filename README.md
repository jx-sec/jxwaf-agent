# JXWAF Agent

通过 AI Agent 运维 JXWAF：Go 命令行工具 + 文档体系，让 AI 在 IDE（Claude Code / Trae / Cursor 等）中用自然语言完成 WAF 防护配置的生成、验证与下发。

支持 JXWAF 三个版本：**标准版 / 专业版 / 云WAF**。版本差异（认证、端点命名、租户参数）由 CLI 内部适配层自动处理，对使用者与 AI 是统一命令面。

## 环境前置条件（必读）

CLI 按用途区分**测试环境**与**生产环境**两类，`config.json` 是唯一配置来源，**必须在首次使用前初始化**：

| 环境用途 | 配置方式 | 说明 |
|---|---|---|
| **测试环境**（配置下发生产前先验证） | 官方沙盒（推荐）或自建 | 官方沙盒：免费云测试环境，`sandbox init` 即开即用，凭据经 `JXWAF_OFFICIAL_MASTER_AUTH` 环境变量注入（向官方获取）；**不用官方沙盒则需自行搭建一套测试环境**，用 `config set` 配置后以 `--env <名称>` 操作 |
| **生产环境**（自有环境，防护正式生效） | `config set` | 标准版/专业版/自建云控制台，需控制台地址与 waf_auth；**需先开启控制台 Admin API（默认关闭）**，见下文 |

环境隔离：`sandbox` 命令组固定只操作官方沙盒（忽略 `--env`）；自建测试环境与生产环境共存于 `config.json`，经 `config use` / `--env` 切换，两类环境可同时配置、互不影响。

**生产环境（自有环境）必须先开启 Admin API**：控制台默认关闭 `/admin_api/` 接口（`ADMIN_API_ENABLE: "false"`），CLI 的全部管理命令都依赖它（自建测试环境同样适用）。需修改控制台所在服务器 docker-compose.yml 中 `jxwaf_admin_server` 服务的环境变量并重启容器：

```yaml
environment:
  ADMIN_API_ENABLE: "true"
  ADMIN_API_WHITELIST: "*"   # 白名单：逗号分隔 IP/域名/网段；"*" 或空为全放行
```

`ADMIN_API_WHITELIST` 默认 `agent.jxwaf.com`，CLI 所在机器出口 IP 不命中会被拒绝（"ip not allowed"）。办公电脑出口 IP 不固定，一般直接设 `*` 即可（接口本身仍受 waf_auth 认证保护）；生产环境建议收紧为固定 IP/网段。通过 `jxwaf-cli deploy` 部署的环境同样默认关闭，需修改 `/opt/jxwaf_node/docker-compose.yml` 后 `docker compose up -d` 生效。官方沙盒已开启，无需此操作。

未初始化时，除 `config`/`generate` 外的所有操作命令（apply / verify / rule / sandbox verify 等）都会**直接终止并报错**，不会执行任何下发或验证动作。初始化后用 `config show`（凭据脱敏）与 `config validate`（连通性自检）确认就绪。

## 快速开始

```bash
# 构建（或下载 Release 二进制）
go build -o jxwaf-cli ./cmd/cli

# 初始化测试环境（官方沙盒：免费云测试环境，独立命令组，与自有环境隔离）
# 沙盒凭据经环境变量注入（凭据红线：不落源码/文件），向官方获取
export JXWAF_OFFICIAL_MASTER_AUTH=<沙盒凭据>
./jxwaf-cli sandbox init

# 查看配置（凭据脱敏）与连通性
./jxwaf-cli config show
./jxwaf-cli config validate
```

配置文件为**项目目录下的 `config.json`**（与 jxwaf-cli 二进制同级，含凭据，已 gitignore 严禁提交）。沙盒测试站点地址（配置下发到沙盒后访问验证，当前固定 `https://waf-demo.jxwaf.com:4443`）保存在沙盒环境定义的 `test_url` 字段，`sandbox init` 自动写入；均可用环境变量或命令行参数覆盖。

生产环境接入（自有环境，标准版/专业版/自建云）：

```bash
./jxwaf-cli config set --name prod --version professional \
  --base-url https://your-console --waf-auth <token> --group-name <域名组>
```

前提：控制台已按上文开启 Admin API（`ADMIN_API_ENABLE: "true"` 且白名单放行，一般设 `*`），可用 `./jxwaf-cli config validate` 自检。不用官方沙盒时，测试环境同样用 `config set` 配置（如 `--name test`），验证时以 `--env test` 指定。

## 典型闭环

```bash
# 1. 生成配置（语义参数 → 规范请求体；拦截类默认 watch 观察）
./jxwaf-cli generate web-rule --params /tmp/rule.json --output /tmp/rule_cfg.json

# 2. 官方沙盒一键验证（清空基线→部署→打流量→查日志→报告→清理，环境回到空态）
./jxwaf-cli sandbox verify /tmp/rule_cfg.json

# 3. 沙盒手动清理与查询
./jxwaf-cli sandbox reset
./jxwaf-cli rule web list --params '{"page":1}' --env sandbox
./jxwaf-cli soc log query --params '{"from_time":"...","to_time":"...","page":1,"sql_rules":[...]}' --env sandbox
```

## 输出契约

- stdout 仅 JSON；stderr 为 `{"result":false,"error":"..."}`；退出码 0=成功 / 1=失败
- 写操作默认 **dry-run**（仅预览请求），显式 `--apply` 才落地

## 文档

| 文档 | 内容 |
|---|---|
| [docs/requirements.md](docs/requirements.md) | 需求基线（范围、架构、安全模型、验收标准） |
| [docs/cli.md](docs/cli.md) | 完整命令参考 |
| [docs/rule_dev.md](docs/rule_dev.md) | 规则与白名单开发规范（匹配参数/运算符全集、AND-OR 语义、正则规范） |
| [docs/module_dev.md](docs/module_dev.md) | 名单 / 组件（LuaJIT、共享字典、unify_action）/ 网站接入规范 |
| [docs/playbook.md](docs/playbook.md) | 运维手册（误报/漏报排查、调优原则、PV 限速建议、紧急解封） |
| [docs/profiles.md](docs/profiles.md) | 实战防护方案库（Log4j / CC 攻击 / CDN 源 IP 等可复用模式） |
| [docs/verify.md](docs/verify.md) | 验证方法与 SOC 日志分析 |
| [docs/sop.md](docs/sop.md) | 安全工作规范（两步审核 / 红线 / SOP） |
| [docs/versions.md](docs/versions.md) | 三版本差异与能力矩阵 |

## WAF 远程部署

```
export JXWAF_SSH_PASSWORD='<服务器SSH密码>'
jxwaf-cli deploy --host <IP> --version standard --waf-auth <自设UUID> --apply   # 标准版单机全栈

# 专业版/云WAF 从零搭建（分离部署）：
jxwaf-cli deploy admin --host <IP> --version professional --apply    # 1. 控制台（注册拿 waf_auth）
jxwaf-cli deploy --host <IP> --version professional \
  --server http://<控制台地址> --waf-auth <凭据> --apply              # 2. 节点（可多台）
jxwaf-cli deploy jlog --host <IP> --version professional --apply    # 3. jxlog 日志系统（SOC 依赖）

jxwaf-cli deploy remove --host <IP> [--target node|admin|jlog] [--purge-data] --apply   # 卸载
```

对齐 docs.jxwaf.com 官方部署教程：Docker 缺失按官方命令安装（`--mirror Aliyun` 适配国内网络）；standard 单机全栈，professional/cloud 支持控制台/节点/jxlog 三组件分离部署；自动完成环境探测（OS/配置告警）、端口冲突检测（列出占用进程）、上传 compose（0600）、拉起容器、验证。默认 dry-run 展示计划，`--apply` 执行。**注意**：部署出的控制台 Admin API 默认关闭，需按"环境前置条件"开启后方可纳入 CLI 管理。

## AI IDE 接入

- [AGENTS.md](AGENTS.md) — Claude Code / Cursor / Copilot 等通用接入说明
- `.trae/rules/` — Trae 工作规则

多 IDE 通用：仅凭本仓库文档与 CLI，任何 AI IDE 均可完成运维闭环。

## 开发

```bash
go test ./...   # 单元 + 集成（含完整闭环 E2E 模拟测试）
go vet ./...
```

依赖：Go 1.25+、cobra、golang.org/x/term。