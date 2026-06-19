# JXWAF Agent

基于 LLM 的 JXWAF 智能配置助手。通过自然语言对话，自动生成并下发 WAF 防护规则、组件、名单等配置。

## 工作流程

```
用户自然语言描述需求 → LLM 生成配置预览 → 用户确认 → 调用 JXWAF API 下发 → 自动验证生效
```

采用**两步审核**机制：先生成配置预览，用户确认后再执行，避免误操作。

## 快速开始

### 1. 配置

编辑 `config.json`：

```json
{
  "server": { "port": 8000 },
  "allow_register": true,
  "database": { "type": "sqlite", "sqlite_path": "data/agent.db" },
  "default_config": {
    "llm": {
      "api_key": "your-api-key",
      "base_url": "https://open.bigmodel.cn/api/paas/v4/",
      "model": "glm-5.2",
      "max_tokens": 65536,
      "temperature": 0.2
    },
    "jxwaf": {
      "api_url": "https://your-jxwaf-console",
      "waf_auth": "your-waf-auth-token",
      "group": "default"
    },
    "verify_url": "https://your-site.com"
  }
}
```

### 2. 启动

```bash
go run cmd/server/main.go
```

访问 `http://localhost:8000`，注册账号后在配置页面填写 LLM 和 JXWAF 连接信息即可使用。

### 3. 环境变量覆盖

| 变量 | 说明 |
|------|------|
| `SERVER_PORT` | 服务端口 |
| `ALLOW_REGISTER` | 是否开放注册（true/false） |

## 功能

- **Web 防护规则**：基于请求参数（路径、Header、Cookie 等）的匹配拦截
- **流量防护规则**：基于频率统计的 CC 攻击限速
- **防护组件**：自定义 Lua 检测逻辑（LuaJIT 兼容）
- **名单防护**：IP 黑/白名单，支持永久和临时名单
- **白名单**：Web/流量白名单放行
- **规则验证**：配置下发后自动发送测试请求验证拦截效果
- **双因素认证**：可选 TOTP 绑定（兼容 Google Authenticator）
- **多租户**：每个用户独立会话和配置
- **审计日志**：所有配置操作可追溯

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Go |
| 前端 | Vue.js 3 (CDN) + 单文件 SPA |
| 数据库 | SQLite（默认）/ MySQL |
| LLM | OpenAI 兼容 API（SSE 流式响应） |

## 项目结构

```
├── cmd/server/main.go          # 程序入口
├── internal/
│   ├── agent/                  # LLM Agent 主循环 + 提示词
│   ├── api/handler.go          # HTTP handler
│   ├── auth/                   # 认证模块（bcrypt + TOTP）
│   ├── config/                 # 用户配置读写
│   ├── db/                     # 数据库访问层
│   ├── function/               # Function Calling 注册
│   ├── jxwaf/client.go         # JXWAF API 客户端
│   └── audit/                  # 审计日志
├── prompts/                    # 系统提示词（Markdown）
├── web/index.html              # 前端 SPA
├── config.json                 # 全局配置
└── go.mod
```

## 提示词热更新

修改 `prompts/` 目录下的 Markdown 文件后，调用热更新接口（无需重启）：

```bash
curl -X POST http://localhost:8000/api/reload-prompts
```

## 数据库

默认使用 SQLite（`data/agent.db`），也支持 MySQL：

```json
{
  "database": {
    "type": "mysql",
    "host": "127.0.0.1",
    "port": 3306,
    "username": "root",
    "password": "your-password",
    "database": "jxwaf_agent"
  }
}
```

## License

MIT
