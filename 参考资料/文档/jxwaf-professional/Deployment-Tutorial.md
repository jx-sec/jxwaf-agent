# 部署教程

## 架构

![JXWAF 架构图](/images/jxwaf_deployment_architecture.png)

- **JXWAF 控制台**（jxwaf_admin_server）：Web 可视化运营界面，站点管理、防护策略配置、报表展示
- **JXWAF 节点**（jxwaf_node）：基于 OpenResty 的高性能流量代理与实时攻击检测引擎
- **JXLOG 日志系统**（jxlog）：日志采集、存储（ClickHouse）与攻击事件分析


---

## 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Debian 12.x |
| 最低配置 | 4 核 8G |
| 依赖 | Docker、Docker Compose |

---

## 一、JXWAF 控制台部署

### 1.1 系统部署

> 示例服务器：公网 `47.120.63.196` / 内网 `172.29.198.241`

```bash
# 1. 安装 Docker
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun

# 2. 克隆仓库
git clone --depth=1 https://github.com/jx-sec/jxwaf.git

# 3. 进入专业版目录并启动
cd jxwaf/Professional/jxwaf_admin_server/
docker compose up -d
```

部署完成后访问 `http://47.120.63.196`，首次使用需注册账号，强烈建议开启 OTP 双因素认证以增强账户安全。

注册并登录后，进入 **系统管理 → 基础信息** 查看 `waf_auth`，后续节点配置需要使用。

```
waf_auth: 7bafbc49-f143-4f99-85e5-224ef3e42dce
```

### 1.2 系统升级

```bash
cd jxwaf/Professional/jxwaf_admin_server/
git pull
docker compose down
docker compose up -d
```

### 1.3 卸载系统

```bash
cd jxwaf/Professional/jxwaf_admin_server/
docker compose down
rm -rf /opt/jxwaf_data/mysql   # 可选：删除数据库文件
```

### 1.4 Docker Compose 配置说明

```yaml
services:
  # MySQL 8.0 数据库
  mysql_db:
    image: ccr.ccs.tencentyun.com/jxwaf/mysql:8.0
    restart: always
    network_mode: host                              # 使用宿主机网络
    environment:
      MYSQL_ROOT_PASSWORD: 958fba75-56c6-4e81-a892-62517a9e1739  # 建议生产环境修改
      MYSQL_CHARSET: utf8mb4
      MYSQL_COLLATION: utf8mb4_0900_ai_ci
      MYSQL_DEFAULT_AUTHENTICATION_PLUGIN: mysql_native_password
    command:
      - --default-authentication-plugin=mysql_native_password
      - --character-set-server=utf8mb4
      - --collation-server=utf8mb4_0900_ai_ci
      - --innodb_buffer_pool_size=256M
      - --bind-address=127.0.0.1                    # 仅本地访问，不暴露外网
    volumes:
      - /opt/jxwaf_data/mysql:/var/lib/mysql

  # JXWAF 控制台
  jxwaf_admin_server:
    image: ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_professional:6.1.0
    restart: unless-stopped
    depends_on:
      - mysql_db
    network_mode: host                              # 使用宿主机网络
    environment:
      ENABLE_HTTPS: false
      MYSQL_HOST: 127.0.0.1
      MYSQL_PORT: 3306
      MYSQL_DATABASE: jxwaf_admin_server
      MYSQL_USER: root
      MYSQL_PASSWORD: 958fba75-56c6-4e81-a892-62517a9e1739
      HTTP_PORT: 80
      #HTTPS_PORT: 443
      JXWAF_MODEL_SERVER_HOST: model.jxwaf.com      # AI 模型服务器地址
      JXWAF_MODEL_SERVER_PORT: 39977
      JXWAF_MODEL_SERVER_SSL: true
      WAF_UPDATE_CONF_DATA_SIZE: "100m"
      CONF_DATA_SIZE: "100m"
      MODEL_DATA_SIZE: "100m"
      TZ: Asia/Shanghai
    # 如需启用 HTTPS，取消下面注释并放置证书文件
    #volumes:
    #  - ./ssl_certs/server.crt:/opt/jxwaf_admin_server/nginx/conf/server.crt
    #  - ./ssl_certs/server.key:/opt/jxwaf_admin_server/nginx/conf/server.key
```

#### 环境变量参考

##### mysql_db

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MYSQL_ROOT_PASSWORD` | MySQL root 密码 | —（建议生产环境修改） |
| `MYSQL_CHARSET` | 字符集 | `utf8mb4` |
| `MYSQL_COLLATION` | 排序规则 | `utf8mb4_0900_ai_ci` |
| `MYSQL_DEFAULT_AUTHENTICATION_PLUGIN` | 默认认证插件 | `mysql_native_password` |

##### jxwaf_admin_server

**数据库连接（必填）**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MYSQL_HOST` | MySQL 地址 | —（必填） |
| `MYSQL_PORT` | MySQL 端口 | —（必填） |
| `MYSQL_DATABASE` | 数据库名称 | —（必填） |
| `MYSQL_USER` | 数据库用户名 | —（必填） |
| `MYSQL_PASSWORD` | 数据库密码 | —（必填） |

**服务配置**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `ENABLE_HTTPS` | 是否启用 HTTPS（`true`/`false`） | `false` |
| `HTTP_PORT` | HTTP 监听端口 | `80` |
| `HTTPS_PORT` | HTTPS 监听端口 | `443` |
| `OPEN_REGIST` | 是否开放注册（`true`/`false`） | `false` |

**AI 模型服务**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `JXWAF_MODEL_SERVER_HOST` | AI 模型服务器地址 | — |
| `JXWAF_MODEL_SERVER_PORT` | AI 模型服务器端口 | — |
| `JXWAF_MODEL_SERVER_SSL` | AI 模型服务是否启用 SSL | `false` |

**缓存配置**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `WAF_UPDATE_CONF_DATA_SIZE` | WAF 配置更新缓存大小 | `100m` |
| `CONF_DATA_SIZE` | 会话数据缓存大小 | `100m` |
| `MODEL_DATA_SIZE` | AI 模型数据缓存大小 | `100m` |

**网络**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `RESOLVER_IPS` | DNS 解析器列表（空格分隔） | `223.5.5.5 119.29.29.29 114.114.114.114 1.1.1.1` |

> **说明**：系统使用 `network_mode: host` 宿主机网络模式，MySQL 绑定 `127.0.0.1` 仅允许本地访问。如需使用外部数据库，可移除 `mysql_db` 服务并修改 `MYSQL_HOST` 等环境变量。

> **启用 HTTPS**：将 `ENABLE_HTTPS` 设为 `true`，将 SSL 证书和私钥放入 `ssl_certs/` 目录，分别命名为 `server.crt` 和 `server.key`，并取消 `volumes` 注释。

---
## 二、JXWAF 节点部署

> 示例服务器：公网 `47.84.176.156` / 内网 `172.22.168.117`

### 2.1 系统部署

```bash
# 1. 安装 Docker
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun

# 2. 克隆仓库
git clone --depth=1 https://github.com/jx-sec/jxwaf.git

# 3. 修改配置后启动
cd jxwaf/Professional/jxwaf_node
vim docker-compose.yml
```

需要修改以下关键配置：

- **`jxwaf_base` 服务**：
  - `JXWAF_SERVER`：控制台地址，如 `http://47.120.63.196`（注意末尾不要带 `/`）
  - `WAF_AUTH`：控制台 **系统管理 → 基础信息** 中的 `waf_auth` 值
  - `HTTP_PORT` / `HTTPS_PORT`：支持多端口，用逗号分隔（如 `80,8080`）
- **`jxwaf_nft_node` 服务**：
  - `WAF_SERVER_URL`：控制台地址，同 `JXWAF_SERVER`
  - `WAF_AUTH`：控制台 **系统管理 → 基础信息** 中的 `waf_auth` 值

```bash
docker compose up -d
```

启动后在控制台 **运营中心 → 节点状态** 可查看节点是否上线。

### 2.2 系统升级

```bash
cd jxwaf/Professional/jxwaf_node
git pull
docker compose up -d
```

### 2.3 卸载系统

```bash
cd jxwaf/Professional/jxwaf_node
docker compose down
```

### 2.4 Docker Compose 配置说明

```yaml
services:
  jxwaf_base:
    image: "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_professional:6.1.0"
    network_mode: host
    privileged: true
    ulimits:
      nofile:
        soft: 602400
        hard: 602400
    environment:
      # 多端口用逗号分隔，如: HTTP_PORT: 80,8080,8888
      HTTP_PORT: 80,8000
      # 多端口用逗号分隔，如: HTTPS_PORT: 443,8443
      HTTPS_PORT: 443,8443
      JXWAF_INNER: 200m
      SSL_ATTACK_STAT_SIZE: 100m
      SSL_BLACK_IP_SIZE: 100m
      SSL_ATTACK_PROTECT: "false"
      SSL_ATTACK_STAT_TIME: 60
      SSL_ATTACK_STAT_COUNT: 10000
      SSL_ATTACK_BLOCK_TIME: 600
      JXWAF_SERVER: you_jxwaf_server_url
      WAF_AUTH: you_auth_key
      TZ: Asia/Shanghai
    restart: unless-stopped
    # 如需自定义 Nginx 模板，取消下面注释并修改 nginx.conf.tmpl
    #volumes:
    #  - ./nginx.conf.tmpl:/opt/jxwaf/nginx/conf/nginx.conf.tmpl:ro

  jxwaf_nft_node:
    image: ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:6.0
    container_name: jxwaf_nft_node
    restart: always
    network_mode: host
    privileged: true
    environment:
      WAF_SERVER_URL: you_jxwaf_server_url
      WAF_AUTH: you_auth_key
      SYNC_INTERVAL: 3
      TZ: Asia/Shanghai
```

#### 环境变量参考

##### jxwaf_base

**一、核心启动配置**

| 变量名 | 写入位置 | 说明 | 默认值 |
|--------|----------|------|--------|
| `HTTP_PORT` | nginx `listen` 指令 | HTTP 监听端口，支持多端口逗号分隔（如 `80,8080`） | `80` |
| `HTTPS_PORT` | nginx `listen ssl` 指令 | HTTPS 监听端口，支持多端口逗号分隔（如 `443,8443`） | `443` |
| `JXWAF_SERVER` | `jxwaf_config.json` → `jxwaf_server` | 控制台地址（末尾不要带 `/`） | —（必填） |
| `WAF_AUTH` | `jxwaf_config.json` → `waf_auth` | 认证密钥，与控制台 **系统管理 → 基础信息** 中的 `waf_auth` 一致 | —（必填） |

**二、Nginx 共享内存（`lua_shared_dict`）配置**

| 变量名 | 对应 `lua_shared_dict` 块 | 说明 | 默认值 |
|--------|---------------------------|------|--------|
| `WAF_CONF_DATA` | `waf_conf_data` | WAF 配置数据缓存 | `100m` |
| `JXWAF_INNER` | `jxwaf_inner` | WAF 内部数据缓存 | `200m` |
| `JXWAF_USER` | `jxwaf_user` | 用户自定义数据缓存 | `200m` |
| `JXWAF_REQUEST_COUNT` | `ip_access_limit_stat`、`ip_access_limit_block` | IP 访问频率限制统计与封禁缓存 | `200m` |
| `JXWAF_REQUEST_IP` | `ip_count_limit_log`、`ip_count_limit_stat` | IP 计数限制日志与统计缓存 | `200m` |
| `JXWAF_REQUEST_IP_COUNT` | `domain_access_limit_stat` | 域名级访问频率限制统计缓存 | `200m` |
| `JXWAF_LIMIT_BOT` | `jxwaf_limit_bot` | Bot 限流缓存 | `200m` |
| `SSL_ATTACK_STAT_SIZE` | `ssl_attack_stat` | SSL 攻击统计缓存 | `10m` |
| `SSL_BLACK_IP_SIZE` | `ssl_black_ip` | SSL 黑名单 IP 缓存 | `10m` |

**三、DNS 与时区**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `RESOLVER_IPS` | DNS 解析服务器 IP（空格分隔） | `223.5.5.5 119.29.29.29 114.114.114.114 1.1.1.1` |
| `TZ` | 容器时区 | `Asia/Shanghai` |

**四、SSL 攻击防护参数**（写入 `jxwaf_config.json`）

| 变量名 | JSON 字段 | 说明 | 默认值 |
|--------|-----------|------|--------|
| `SSL_ATTACK_PROTECT` | `ssl_attack_protect` | SSL 攻击防护开关，设为 `"true"` 启用 | `false` |
| `SSL_ATTACK_STAT_TIME` | `ssl_attack_stat_time` | SSL 攻击统计时间窗口（秒） | `60` |
| `SSL_ATTACK_STAT_COUNT` | `ssl_attack_stat_count` | SSL 攻击触发阈值（次） | `10000` |
| `SSL_ATTACK_BLOCK_TIME` | `ssl_attack_block_time` | SSL 攻击自动封禁时长（秒） | `600` |

> SSL 攻击防护原理：在 TLS 握手阶段，对客户端 IP 进行频率统计。若某 IP 在 `ssl_attack_stat_time` 秒内发起超过 `ssl_attack_stat_count` 次 TLS 握手，则自动封禁该 IP `ssl_attack_block_time` 秒。

##### jxwaf_nft_node

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `WAF_SERVER_URL` | 控制台地址（末尾不要带 `/`） | —（必填） |
| `WAF_AUTH` | 认证密钥，与控制台 **系统管理 → 基础信息** 中的 `waf_auth` 一致 | —（必填） |
| `SYNC_INTERVAL` | 配置同步间隔（秒） | `3` |
| `TZ` | 时区 | `Asia/Shanghai` |

##### Nginx 模板自定义

`jxwaf_node` 目录下已提供 `nginx.conf.tmpl` 模板文件，启动时通过环境变量动态渲染生成 Nginx 配置。如需自定义 Nginx 参数（如调整 `worker_connections`、`keepalive_timeout` 等），直接修改 `nginx.conf.tmpl` 后取消 `volumes` 挂载注释，执行 `docker compose down && docker compose up -d` 重启容器即可生效。

> ⚠️ **注意**：模板中的 `{{.xxx}}` 占位变量**不可修改或删除**，否则容器启动时将无法正确渲染 Nginx 配置。其他部分可自行调整。

## 三、JXLOG 日志系统部署

> 示例服务器：公网 `47.115.222.190` / 内网 `172.29.198.239`

### 3.1 系统部署

```bash
# 1. 安装 Docker
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun

# 2. 克隆仓库
git clone --depth=1 https://github.com/jx-sec/jxwaf.git

# 3. 启动
cd jxwaf/Professional/jxlog
docker compose up -d
```

部署完成后，在控制台完成以下配置：

**系统配置 → 日志传输配置**

控制台需要将攻击日志上报到 jxlog 服务，示例中 jxlog 部署在 `172.29.198.239`：

| 配置项 | 值 |
|--------|-----|
| 日志服务器地址 | `172.29.198.239` |
| 日志服务器端口 | `8877` |
| 全流量日志记录 | 关闭 |

**系统配置 → 日志查询配置**

控制台通过 ClickHouse 查询日志数据，连接信息与 docker-compose 中一致：

| 配置项 | 值 |
|--------|-----|
| ClickHouse 服务器地址 | `172.29.198.239` |
| ClickHouse 服务器端口 | `9004` |
| 用户名 | `jxlog` |
| 密码 | `jxlog` |
| 数据库名称 | `jxwaf` |
| 数据库表名 | `jxlog` |

### 3.2 系统升级

```bash
cd jxwaf/Professional/jxlog
git pull
docker compose up -d
```

### 3.3 卸载系统

```bash
cd jxwaf/Professional/jxlog
docker compose down
rm -rf /opt/jxwaf_data/clickhouse   # 可选：删除数据库文件
```

### 3.4 Docker Compose 配置说明

```yaml
networks:
  clickhouse_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.10.0.0/16

services:
  # ClickHouse 数据库
  clickhouse:
    image: "ccr.ccs.tencentyun.com/jxwaf/clickhouse-server:22.8.5-alpine"
    ports:
      - "9000:9000"                                 # TCP 协议端口
      - "9004:9004"                                 # MySQL 兼容端口
    environment:
      CLICKHOUSE_DB: jxwaf                          # 默认数据库
      CLICKHOUSE_USER: jxlog                        # 默认用户
      CLICKHOUSE_PASSWORD: jxlog                    # 用户密码（建议生产环境修改）
    volumes:
      - /opt/jxwaf_data/clickhouse:/var/lib/clickhouse
    restart: unless-stopped
    networks:
      clickhouse_network:
        ipv4_address: 172.10.0.10

  # jxlog 日志采集服务
  jxlog:
    container_name: jxlog
    image: "ccr.ccs.tencentyun.com/jxwaf/jxlog_professional:1.0"
    ports:
      - "8877:8877"                                 # 日志接收端口
    environment:
      CLICKHOUSE: 172.10.0.10:9000                  # ClickHouse 地址
      DATABASE: jxwaf                               # 数据库名
      USERNAME: jxlog                               # 数据库用户
      PASSWORD: jxlog                               # 数据库密码
      TABLE: jxlog                                  # 表名
      TCPSERVER: 0.0.0.0                            # 监听地址
      TCPPORT: 8877                                 # 监听端口
      BATCH_SIZE: 1000                              # 批量写入大小
      BATCH_WAIT_TIMEOUT: 3                         # 批量等待超时（秒）
      TTL_DAYS: 30                                  # 数据保留天数
      ENGINE: MergeTree                             # ClickHouse 表引擎
    depends_on:
      - clickhouse
    restart: unless-stopped
    networks:
      clickhouse_network:
        ipv4_address: 172.10.0.11
```

#### 环境变量参考

##### clickhouse

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `CLICKHOUSE_DB` | 默认数据库名称 | `jxwaf` |
| `CLICKHOUSE_USER` | 默认数据库用户 | `jxlog` |
| `CLICKHOUSE_PASSWORD` | 数据库用户密码（建议生产环境修改） | `jxlog` |

##### jxlog

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `CLICKHOUSE` | ClickHouse 地址（格式 `host:port`） | `127.0.0.1:9000` |
| `DATABASE` | 数据库名称 | `jxwaf` |
| `USERNAME` | 数据库用户名 | `jxlog` |
| `PASSWORD` | 数据库密码 | `jxlog` |
| `TABLE` | 日志表名 | `jxlog` |
| `TCPSERVER` | TCP 监听地址 | `0.0.0.0` |
| `TCPPORT` | TCP 监听端口 | `8877` |
| `BATCH_SIZE` | 批量写入条数 | `1000` |
| `BATCH_WAIT_TIMEOUT` | 批量写入超时（秒） | `3` |
| `TTL_DAYS` | 数据自动过期天数（0 = 不自动删除） | `180` |
| `ENGINE` | ClickHouse 表引擎 | `MergeTree` |