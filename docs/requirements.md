# JXWAF Agent 需求文档

- 版本：v1（已确认，作为开发基线）
- 日期：2026-08-30
- 状态：需求定稿，待进入开发

## 1. 背景与目标

通过 AI Agent 运维 JXWAF 系统（产品介绍见 docs.jxwaf.com）。此前尝试过两种方案均不理想：

1. **独立 AI Agent**：需自建工具循环、上下文管理、记忆、沙盒、安全体系，开发难度大、效果不佳；
2. **Skill**：约束太软，模型直接拼接 API 调用，复杂字段格式（编码、嵌套结构）必然出错，效果不佳。

现方案：**开发一个命令程序（CLI）对接 JXWAF 控制台 + 编写文档 + 通过 AI IDE（Claude Code / Trae / Cursor 等）执行**。

本质是三层职责分离：

| 层 | 载体 | 职责 |
|---|---|---|
| 编排层（模糊） | AI IDE | 自然语言理解、任务规划、多轮推理、人工审批交互 |
| 执行层（确定） | CLI | 对接控制台 API，处理认证、复杂字段、输出稳定契约，可独立测试 |
| 知识层（增量） | 文档 | 命令参考、模块规范、SOP、安全红线，即 agent 的"系统知识" |

## 2. 核心决策汇总

| 决策项 | 结论 |
|---|---|
| CLI 覆盖范围（v1） | 防护配置闭环：规则/名单/组件/网站的查询、生成、下发、验证；不含报表、节点管理、系统维护 |
| 运行形态 | 纯交互式（人在 IDE 发起任务），无定时/常驻能力 |
| 目标环境 | 多 IDE 通用（Claude Code / Trae / Cursor），按最低公分母编写 |
| 技术栈 | Go，单二进制分发 |
| 交付形态 | 开源 GitHub 仓库 |
| 目标产品版本 | JXWAF 标准版 / 专业版 / 云WAF 三个版本；官方提供免费云WAF测试环境，默认用它验证 |
| 测试凭据获取 | CLI 内置引导（init 命令注册/登录云测试环境，自动写入本地配置） |
| WebTDS | v1 不涉及 |
| 文档语言 | 中文 |
| 仓库处理 | 已清空历史内容与 git 历史，从零开始 |
| CLI 命名 | jxwaf-cli |

## 3. 目标用户与交付形态

- **用户**：JXWAF 三版本的使用者，通过本项目在 AI IDE 中用自然语言运维自己的 WAF 环境。
- **交付**：开源 GitHub 仓库，含 CLI 源码、二进制发布、文档、各 IDE 集成文件。用户 clone/下载后运行 `jxwaf-cli init` 完成初始化即可使用。
- **官方角色**：提供默认免费云WAF测试环境；本身也是项目的使用者（内部运维）。

## 4. 系统架构

```
┌──────────────────────────────────────────────┐
│  AI IDE（Claude Code / Trae / Cursor）        │
│  任务规划 → 查文档(docs/) → 调 CLI → 汇总报告  │
└──────────────────────┬───────────────────────┘
                       │ 子命令 + JSON 输出
┌──────────────────────▼───────────────────────┐
│  jxwaf-cli（Go 单二进制）                     │
│  ┌─────────────┐ ┌─────────────────────────┐ │
│  │ 命令层       │ │ adapter 层（版本适配）    │ │
│  │ rule/list/   │ │ 认证模式（3 种）         │ │
│  │ component/   │ │ 端点命名映射             │ │
│  │ website/     │ │ 租户参数注入             │ │
│  │ generate/…   │ └─────────────────────────┘ │
│  └─────────────┘ ┌─────────────────────────┐ │
│                  │ generate 层（配置生成）    │ │
│                  │ 复杂字段由代码处理，AI 只给 │ │
│                  │ 语义参数                   │ │
│                  └─────────────────────────┘ │
└──────────────────────┬───────────────────────┘
                       │ HTTP + JSON
┌──────────────────────▼───────────────────────┐
│  JXWAF 管理后端（三版本，各自独立实现）        │
│  Standard / Professional / Cloud             │
└──────────────────────────────────────────────┘
```

### 三版本 API 差异（jxwaf_admin_server 调研结论）

三版是"同构风格、各自实现"的三套 API，共享 `/admin_api/` 前缀、IP 白名单、`{result, message}` JSON 契约，但以下维度互不兼容：

| 维度 | 标准版 | 专业版 | 云WAF |
|---|---|---|---|
| 认证 | 环境变量 token 等值比较 | DB 反查 jxwaf_admin_account | DB 反查 + 子账号双层 token |
| 租户模型 | 单租户 | 单租户 + group_name 域名组 | 主/子账号多租户 |
| 端点命名 | get_X_list | get_group_X_list | get_sub_account_X_list |
| 能力覆盖 | 最少 | 中等（域名组、WebTDS） | 最全（网站接入、CDN、/user/ 链路） |

因此 CLI 必须内置 adapter 层：同一命令面，内部按目标版本切换认证模式、端点命名、租户参数。字段规范以 jxwaf_admin_server 各版 `ADMIN_API_DOCUMENT.md` 为权威来源。

## 5. CLI 设计

### 5.1 命令面（v1）

```
jxwaf-cli init                          # 内置引导：注册/登录官方云测试环境，获取凭据写入本地
jxwaf-cli config show|validate          # 配置查看（脱敏）/ 连通性自检
jxwaf-cli rule web|flow <list|get|create|update|delete> ...
jxwaf-cli namelist  <list|get|create|update|delete|item ...> ...
jxwaf-cli component <list|get|create|update|delete> ...
jxwaf-cli website   <list|get|create|update|delete> ...
jxwaf-cli generate <类型> --params <file|->      # 语义参数 → 规范配置 JSON
jxwaf-cli apply <配置> [--dry-run|--apply]       # 下发；默认 dry-run
jxwaf-cli verify <用例文件> [--env <目标>]       # 部署测试→打流量→查日志→验证报告
jxwaf-cli cleanup [--names ...]                 # 测试环境清理
jxwaf-cli soc log query ...                     # 只读日志查询（验证误报/攻击用）
```

### 5.2 输出契约

- stdout 输出 JSON（机器可读，agent 直接解析）
- stderr 承载错误信息，退出码 0=成功 / 1=失败
- 查询命令输出结构化列表；写入命令输出请求预览与结果

### 5.3 重要设计原则

- `generate` 是 AI 辅助核心：AI 只提供语义参数（JSON 文件），枚举校验、嵌套结构、编码等复杂处理全部收敛到代码，避免模型手拼 API payload
- 写入默认 dry-run，显式 `--apply` 才落地，AI 无法绕过
- 全命令可独立测试，不依赖 AI 也能人工使用

## 6. 文档体系（agent 系统知识）

- `docs/`：
  - 快速上手（README 接入指引）
  - CLI 完整命令参考
  - 模块开发规范（规则 / 名单 / 组件 / 网站接入）
  - 验证方法与 SOC 日志分析
  - 三版本差异说明
  - 安全工作规范（SOP + 红线）
- IDE 集成文件（多 IDE 通用）：
  - `AGENTS.md`
  - `.trae/rules/`、`.cursor/rules/`
  - 各 IDE 接入说明

## 7. 安全模型

面向外部用户操作**自己的环境**，重点是防误操作：

1. 写入默认 dry-run → 展示请求内容 → 用户确认 → `--apply`；
2. 拦截类配置默认观察（watch），验证无误报后转拦截（block）；
3. 删除操作用口令确认，展示影响范围；
4. 凭据本地存储、展示脱敏，不外泄到对话输出。

## 8. 标准工作流（SOP）

```
需求分析 → 信息澄清 → 按需查文档 → generate 生成配置
→ 测试环境部署验证（attack + normal 用例）→ 误报/漏报调整（≤3 次）
→ 清理测试环境 → 展示验证报告与最终配置 → 用户确认 → 生产环境 apply
```

## 9. 非目标（v1 不包含）

- 报表、数据分析、节点管理、系统维护类控制台功能
- SSH 自动部署（三版本环境搭建）
- 定时任务 / 自主值守
- WebTDS 相关操作

## 10. 验收标准

1. 在官方云WAF测试环境完成一次真实闭环：需求 → 生成 → 部署验证 → 生产下发；
2. 换一个不同 AI IDE，仅凭仓库文档即可复现同流程；
3. CLI 全命令有自动化测试覆盖，输出契约稳定。

## 11. 开放项（开发中跟踪）

- ~~官方云测试环境凭据获取~~ 已定：**专业版固定沙盒**（waf-demo.jxwaf.com 固定共享账号），独立命令组 `jxwaf-cli sandbox`（init/verify/cleanup/reset）与自有环境命令彻底隔离；`sandbox verify` 一键闭环自动回到空环境，官方挂定时 `sandbox reset --apply` 兜底
- ~~待官方提供：官方测试域名 + demo 部署开启 Admin API~~ 已定：测试域名 `https://waf-demo.jxwaf.com:4443`（代码内 `defaultSandboxTestURL`），沙盒 Admin API 已开启（`ADMIN_API_WHITELIST=*`）
- 二进制发布方式（GitHub Release / go install）
- 仓库远端旧分支清理与首次推送方式