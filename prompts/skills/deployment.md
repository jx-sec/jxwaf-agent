---
name: deployment
description: JXWAF 自动部署运维能力 - 通过 SSH 远程部署标准版/专业版，含环境检查、计划生成、风险确认、执行验证全流程
---

# JXWAF 自动部署运维 SOP

## 部署架构

### 标准版（一键部署）
所有子系统部署在同一台服务器，通过单个 `docker-compose.yml` 完成：
- jxwaf_admin_server（控制台）
- jxwaf_node_standard（WAF 节点）
- mysql_db（数据库）
- log_send_to_mysql（日志采集）
- jxwaf_nft_node（网络封禁）

控制台访问端口：8000

### 专业版（分组件部署）
三个子系统可部署在同一台或不同服务器：
- **控制台**（jxwaf_admin_server）：Web 管理界面，端口 80
- **节点**（jxwaf_node）：流量代理与检测引擎，端口 80/443
- **JXLOG**（jxlog）：日志系统，ClickHouse + jxlog 服务

## 环境要求
| 项目 | 要求 |
|------|------|
| 操作系统 | Debian 12.x / Ubuntu 20.04+ |
| 最低配置 | 4 核 8G |
| 依赖 | Docker、Docker Compose |

## 部署工作流程

### 第一步：环境检查（必须）
调用 `check_server_environment` 检查目标服务器：
- SSH 连接是否通畅
- 操作系统版本
- Docker / Docker Compose 是否已安装
- 磁盘空间、内存、CPU 核数

根据检查结果决定是否需要在部署计划中包含 Docker 安装步骤。

### 第二步：生成部署计划
调用 `plan_jxwaf_deployment` 生成部署计划：
- 标准版：一键部署，无需选组件
- 专业版：需指定组件（console/node/log），节点需要控制台地址和 waf_auth

计划中每一步标注：
- `category: standard` — 官方文档标准流程
- `category: beyond_docs` — 超出文档的自定义操作（如 sed 修改配置文件）
- `is_risky: true/false` — 是否需要用户确认

### 第三步：展示计划并请求确认
向用户展示部署计划摘要，包括：
- 部署版本和组件
- 服务器 IP
- 每一步的命令和说明
- 哪些步骤是风险操作

等待用户确认后再执行。如果有不明确的地方（如专业版未指定组件、节点缺少控制台地址），必须先问清楚。

### 第四步：逐步执行
调用 `execute_ssh_command` 逐步执行计划中的命令：

**标准流程步骤**（is_risky=false）：直接执行。

**风险步骤**（is_risky=true，超出文档）：
1. 先以 `user_confirmed=false` 调用 → 返回 `confirmation_required`
2. 向用户说明风险，等待用户回复同意
3. 用户同意后，以 `user_confirmed=true` 重新调用执行

### 第五步：验证部署
调用 `verify_deployment` 检查：
- Docker 容器运行状态
- 端口监听情况
- 控制台 HTTP 可访问性

### 第六步：返回执行摘要
调用 `get_deployment_summary` 获取所有已执行命令的完整记录，向用户展示：
- 总命令数、成功数、失败数
- 每条命令的步骤名、命令内容、输出、退出码、耗时

## 常见部署问题处理

### Docker 安装失败
- 原因：网络问题或 curl 不可用
- 处理：尝试更换镜像源，或提示用户手动安装

### docker compose 命令不存在
- 原因：旧版 Docker 使用 `docker-compose`（带横线）
- 处理：检查 `docker-compose --version`，如果可用则使用 `docker-compose` 替代

### 端口被占用
- 原因：80/443/8000 等端口已被其他服务占用
- 处理：检查占用进程 `ss -tlnp | grep :80`，提示用户停止冲突服务或修改端口

### git clone 失败
- 原因：网络问题或 git 未安装
- 处理：提示用户检查网络，或手动下载仓库

### 容器启动后立即退出
- 原因：配置错误或依赖服务未就绪
- 处理：`docker compose logs` 查看日志，分析原因

## 安全注意事项
1. SSH 密码仅用于连接，不会记录到审计日志和执行摘要
2. 所有执行的命令都会被完整记录（不含密码）
3. 超出官方文档的操作必须经用户确认
4. 不执行任何破坏性命令（如 rm -rf）除非用户明确同意

## 专业版节点配置说明
节点部署需要修改 `docker-compose.yml` 中的关键配置：
- `JXWAF_SERVER`：控制台地址（如 `http://47.120.63.196`，末尾不带 `/`）
- `WAF_AUTH`：控制台「系统管理 → 基础信息」中的 waf_auth 值
- `HTTP_PORT` / `HTTPS_PORT`：监听端口

waf_auth 在控制台部署完成后，登录控制台 → 系统管理 → 基础信息中查看。
如果用户先部署控制台再部署节点，需要提醒用户先获取 waf_auth。

## 控制台账号说明（重要）
JXWAF 控制台**没有默认账号密码**，首次使用必须注册账号。获取 waf_auth 的完整步骤：

1. 在浏览器打开控制台地址（标准版 `http://<服务器IP>:8000`，专业版 `http://<服务器IP>`）
2. 点击「注册」按钮，注册一个新账号（用户名和密码由用户自行设定）
3. 用注册的账号登录控制台
4. 进入「系统管理 → 基础信息」
5. 找到 `waf_auth` 值并复制

**禁止编造默认账号密码**。如果用户询问如何登录控制台，必须告知上述注册流程，不要猜测或编造任何默认凭据（如 admin/jxwaf_admin 等均不存在）。
