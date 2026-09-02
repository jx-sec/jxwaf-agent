# JXWAF Agent

通过 AI Agent 运维 JXWAF：Go 命令行工具 + 文档体系，让 AI 在 IDE（Claude Code / Trae / Cursor 等）中用自然语言完成 WAF 防护配置的生成、验证与下发。

支持 JXWAF 三个版本：**标准版 / 专业版 / 云WAF**。版本差异由 CLI 内部适配层自动处理，对使用者与 AI 是统一命令面。

## 环境前置条件（必读）

CLI 按用途区分**测试环境**与**生产环境**两类，`config.json` 是唯一配置来源（官方测试环境自动生成，生产环境需手动配置）：

| 环境用途 | 配置方式 | 说明 |
|---|---|---|
| **测试环境**（配置下发生产前先验证） | 官方测试环境（开箱即用）或自建（`test init`） | 官方环境由 CLI 内置默认值自动写入（管理地址、共享凭据、域名组、测试站点全部预置），无需任何初始化；**若需改用自建测试环境**，用 `test init` 配置或直接修改 `config.json` |
| **生产环境**（自有环境，防护正式生效） | `config set` | 标准版/专业版/自建云控制台，需控制台地址与 waf_auth；**需先开启控制台 Admin API（默认关闭）**，见下文 |

> **测试环境默认由官方提供，开箱即用**：`config.json` 缺失或为空时，CLI 自动写入内置的官方测试环境默认值（管理地址、共享凭据、域名组、测试站点 `test_url` 均为官方预置设施），`test verify` 可直接使用；用户需要自行配置的是**生产环境**（以及选择自建时的测试环境）。删除 `config.json` 即恢复官方默认。

环境隔离：`test` 命令组固定只操作测试环境（默认官方，`test init` 自建后自动切换）；自建测试环境与生产环境共存于 `config.json`。

**生产环境（自有环境）必须先开启 Admin API**：控制台默认关闭 `/admin_api/` 接口（`ADMIN_API_ENABLE: "false"`），CLI 的全部管理命令都依赖它（自建测试环境同样适用）。需修改控制台所在服务器 docker-compose.yml 中 `jxwaf_admin_server` 服务的环境变量并重启容器：

```yaml
environment:
  ADMIN_API_ENABLE: "true"
  ADMIN_API_WHITELIST: "*"   # 白名单：逗号分隔 IP/域名/网段；"*" 或空为全放行
```

`ADMIN_API_WHITELIST` 是IP白名单列表，CLI 所在机器出口 IP 不命中会被拒绝（"ip not allowed"）。办公电脑出口 IP 不固定，一般直接设 `*` 即可（接口本身仍受 waf_auth 认证保护）；生产环境建议收紧为固定 IP/网段。通过 `jxwaf-cli deploy` 部署的环境同样默认关闭，需修改 `docker-compose.yml` 后 `docker compose up -d` 生效。

自有环境未配置时，除 `config`/`generate`/`test` 外的操作命令（apply / verify / rule 等）都会**直接终止并报错**，不会执行任何下发或验证动作；官方测试环境开箱即用，`test verify` 可直接使用。配置后用 `config show`（凭据脱敏）与 `config validate`（连通性自检）确认就绪。

## 快速开始

配置文件为**项目目录下的 `config.json`**，与 jxwaf-cli 程序同级。测试站点地址（配置下发到测试环境后访问验证，当前固定 `https://waf-demo.jxwaf.com:4443`）保存在测试环境定义的 `test_url` 字段。

官方测试环境开箱即用：`config.json` 缺失或为空时 CLI 自动写入内置默认（管理地址、共享凭据、域名组、测试站点全部预置），无需任何初始化即可 `test verify`。自建测试环境用 `test init` 覆盖配置（`--base-url` / `--waf-auth` / `--test-url` 必填，域名组留空自动发现）：

```bash
./jxwaf-cli test init --base-url https://your-test-console \
  --waf-auth <凭据> --test-url <测试站点>
```

生产环境接入（自有环境，标准版/专业版/自建云）：

```bash
./jxwaf-cli config set --name prod --version professional \
  --base-url https://your-console --waf-auth <token> --group-name <域名组>
```

前提：控制台已按上文开启 Admin API（`ADMIN_API_ENABLE: "true"` 且白名单放行，一般设 `*`），可用 `./jxwaf-cli config validate` 自检。不用官方测试环境时，自建测试环境用 `test init` 配置（test 命令组自动切换到该环境）。

## 典型闭环

```bash
# 1. 生成配置（语义参数 → 规范请求体；拦截类默认 watch 观察）
./jxwaf-cli generate web-rule --params /tmp/rule.json --output /tmp/rule_cfg.json

# 2. 官方测试环境一键验证（清空基线→部署→打流量→查日志→报告→清理，环境回到空态）
./jxwaf-cli test verify /tmp/rule_cfg.json

# 3. 测试环境手动清理与查询
./jxwaf-cli test reset
./jxwaf-cli rule web list --params '{"page":1}' --env test
./jxwaf-cli soc log query --params '{"from_time":"...","to_time":"...","page":1,"sql_rules":[...]}' --env test
```

## 输出契约

- stdout 仅 JSON；stderr 为 `{"result":false,"error":"..."}`；退出码 0=成功 / 1=失败
- 写操作默认 **dry-run**（仅预览请求），显式 `--apply` 才落地

## 文档

| 文档 | 内容 |
|---|---|
| [docs/cli.md](docs/cli.md) | 完整命令参考 |
| [docs/rule_dev.md](docs/rule_dev.md) | 规则与白名单开发规范（匹配参数/运算符全集、AND-OR 语义、正则规范） |
| [docs/module_dev.md](docs/module_dev.md) | 名单 / 网站接入 / 防篡改 / SSL / 域名组 / custom / cache 等模块规范 |
| [docs/component_dev.md](docs/component_dev.md) | 防护组件开发（LuaJIT、共享字典、unify_action、性能红线） |
| [docs/playbook.md](docs/playbook.md) | 运维手册（误报/漏报排查、调优原则、PV 限速建议、紧急解封） |
| [docs/profiles.md](docs/profiles.md) | 实战防护方案库（Log4j / CC 攻击 / CDN 源 IP 等可复用模式） |
| [docs/verify.md](docs/verify.md) | 验证方法与 SOC 日志分析 |
| [docs/analysis.md](docs/analysis.md) | 日志分析与报表配方（数据原语地图、场景配方、字段字典） |
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

多 IDE 通用：仅凭本仓库文档与 CLI，任何 AI IDE 均可完成运维闭环。