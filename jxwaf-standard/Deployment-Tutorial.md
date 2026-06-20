# 部署教程

## 架构

JXWAF 标准版将所有子系统部署在同一台服务器上，通过一个 `docker-compose.yml` 完成全部部署：

```
                        ┌──────────────────────────────────────────────────┐
                        │                JXWAF 标准版服务器                   │
                        │                                                  │
      Internet ────▶    │  ┌────────────────┐    ┌──────────────────────┐   │
                        │  │ WAF 节点         │    │ 控制台                 │   │
                        │  │ (OpenResty)      │◀──▶│ (jxwaf_admin_server)  │   │
                        │  └───────┬────────┘    └──────────┬───────────┘   │
                        │          │                        │               │
                        │          │ 日志上报                │ 读写          │
                        │          ▼                        ▼               │
                        │  ┌────────────────┐    ┌──────────────────────┐   │
                        │  │ log_send_to    │───▶│      MySQL 8.0        │   │
                        │  │ _mysql         │    │ (配置 + 攻击日志)      │   │
                        │  └────────────────┘    └──────────────────────┘   │
                        │                                                  │
                        │  ┌────────────────┐                              │
                        │  │ NFT 节点         │ 网络层 IP 封禁               │
                        │  └────────────────┘                              │
                        └──────────────┬───────────────────────────────────┘
                                       │ 代理转发
                                       ▼
                             ┌─────────────────┐
                             │   业务服务器      │
                             └─────────────────┘
```

| 子系统 | 说明 |
|------|------|
| `jxwaf_admin_server` | WAF 控制台，Web 可视化运营界面与 API |
| `jxwaf_node_standard` | WAF 节点（OpenResty），流量入口，高性能代理与实时攻击检测 |
| `mysql_db` | MySQL 8.0，存储站点配置与攻击日志 |
| `log_send_to_mysql` | 日志采集，将节点攻击日志异步批量写入 MySQL |
| `jxwaf_nft_node` | 网络封禁模块，在网络层封禁攻击 IP |


## 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Debian 12.x / Ubuntu 20.04+ |
| 最低配置 | 4 核 8G |
| 依赖 | Docker、Docker Compose |


## 一键部署

### 1. 安装 Docker

```bash
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
```

### 2. 克隆仓库

```bash
git clone --depth=1 https://github.com/jx-sec/jxwaf.git
cd jxwaf/Standard/
```

### 3. 启动

```bash
docker compose up -d
```

部署完成后访问 `http://<服务器IP>:8000`，首次使用需注册账号。

## 服务配置说明

### Docker Compose 完整配置

```yaml
services:
  # MySQL 8.0 数据库
  mysql_db:
    image: ccr.ccs.tencentyun.com/jxwaf/mysql:8.0
    restart: always
    network_mode: host
    environment:
      MYSQL_ROOT_PASSWORD: 958fba75-56c6-4e81-a892-62517a9e1739
      MYSQL_CHARSET: utf8mb4
      MYSQL_COLLATION: utf8mb4_0900_ai_ci
      MYSQL_DEFAULT_AUTHENTICATION_PLUGIN: mysql_native_password
    command:
      - --default-authentication-plugin=mysql_native_password
      - --character-set-server=utf8mb4
      - --collation-server=utf8mb4_0900_ai_ci
      - --innodb_buffer_pool_size=256M
      - --bind-address=127.0.0.1
      - --max-connections=1000
    volumes:
      - /opt/jxwaf_data/standard_mysql:/var/lib/mysql

  # JXWAF 控制台
  jxwaf_admin_server:
    image: ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_standard:6.1.14
    restart: unless-stopped
    network_mode: host
    depends_on:
      - mysql_db
    environment:
      # 数据库连接
      MYSQL_HOST: 127.0.0.1
      MYSQL_PORT: 3306
      MYSQL_DATABASE: jxwaf_admin_server
      MYSQL_USER: root
      MYSQL_PASSWORD: 958fba75-56c6-4e81-a892-62517a9e1739
      # 服务配置
      HTTP_PORT: 8000
      ENABLE_HTTPS: "false"
      WAF_AUTH: ade1e4c0-d644-46fe-9675-5fb59b486381
      # AI 模型服务
      JXWAF_MODEL_SERVER_HOST: model.jxwaf.com
      JXWAF_MODEL_SERVER_PORT: 39977
      JXWAF_MODEL_SERVER_SSL: "true"
      # 共享内存配置
      WAF_UPDATE_CONF_DATA_SIZE: "100m"
      CONF_DATA_SIZE: "100m"
      MODEL_DATA_SIZE: "100m"
    # HTTPS 证书挂载（启用 HTTPS 时取消注释）
    #volumes:
    #  - ./ssl_certs/server.crt:/opt/jxwaf_admin_server/nginx/conf/server.crt
    #  - ./ssl_certs/server.key:/opt/jxwaf_admin_server/nginx/conf/server.key

  # WAF 节点（OpenResty）
  jxwaf_node_standard:
    image: "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_standard:6.1.7"
    network_mode: host
    privileged: true
    ulimits:
      nofile:
        soft: 602400
        hard: 602400
    environment:
      # 监听端口
      HTTP_PORT: 80
      HTTPS_PORT: 443
      # 控制台连接
      JXWAF_SERVER: http://127.0.0.1:8000
      WAF_AUTH: ade1e4c0-d644-46fe-9675-5fb59b486381
      # 共享内存配置
      WAF_CONF_DATA: 100m
      JXWAF_INNER: 100m
      JXWAF_USER: 100m
      JXWAF_REQUEST_COUNT: 100m
      JXWAF_REQUEST_IP: 100m
      JXWAF_REQUEST_IP_COUNT: 100m
      JXWAF_LIMIT_BOT: 100m
      # DNS 解析器
      RESOLVER_IPS: "223.5.5.5 119.29.29.29 114.114.114.114 1.1.1.1"
      # SSL 攻击防护
      SSL_ATTACK_STAT_SIZE: 10m
      SSL_BLACK_IP_SIZE: 10m
      SSL_ATTACK_PROTECT: "false"
      SSL_ATTACK_STAT_TIME: 60
      SSL_ATTACK_STAT_COUNT: 10000
      SSL_ATTACK_BLOCK_TIME: 600
      # 日志上报
      LOG_IP: 127.0.0.1
      LOG_PORT: 12997
      TZ: Asia/Shanghai
    restart: unless-stopped
    # Nginx 配置模板自定义（需要时取消注释）
    #volumes:
    #  - ./nginx.conf.tmpl:/opt/jxwaf/nginx/conf/nginx.conf.tmpl:ro

  # 日志采集（写入 MySQL）
  log_send_to_mysql:
    image: ccr.ccs.tencentyun.com/jxwaf/log_send_to_mysql:v2
    container_name: data_send_to_mysql
    network_mode: host
    depends_on:
      - mysql_db
    environment:
      LISTEN_ADDR: ":12997"
      BATCH_SIZE: "50"
      BATCH_WAIT_TIMEOUT: "2s"
      MAX_CONNECTIONS: "1000"
      MAX_IDLE_CONNS: "10"
      CONN_MAX_LIFETIME: "10m"
      # 数据库连接
      DB_HOST: "127.0.0.1"
      DB_PORT: "3306"
      DB_DATABASE: "jxwaf_admin_server"
      DB_USER: "root"
      DB_PASSWORD: "958fba75-56c6-4e81-a892-62517a9e1739"
      DB_TABLE: "jxwaf_waf_attack_log"
      DB_CHARSET: "utf8mb4"
    restart: unless-stopped

  # 网络封禁节点
  jxwaf_nft_node:
    image: ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:7.0
    container_name: jxwaf_nft_node
    restart: always
    network_mode: host
    privileged: true
    environment:
      WAF_SERVER_URL: http://127.0.0.1:8000
      WAF_AUTH: ade1e4c0-d644-46fe-9675-5fb59b486381
      SYNC_INTERVAL: 3
      WAF_FILTER_PORTS: "80,443"
      TZ: Asia/Shanghai
```


### 环境变量参考

#### mysql_db

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MYSQL_ROOT_PASSWORD` | MySQL root 密码 | —（务必修改） |
| `MYSQL_CHARSET` | 字符集 | `utf8mb4` |
| `MYSQL_COLLATION` | 排序规则 | `utf8mb4_0900_ai_ci` |

#### jxwaf_admin_server

**数据库连接**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MYSQL_HOST` | MySQL 地址 | `127.0.0.1` |
| `MYSQL_PORT` | MySQL 端口 | `3306` |
| `MYSQL_DATABASE` | 数据库名称 | `jxwaf_admin_server` |
| `MYSQL_USER` | 数据库用户 | `root` |
| `MYSQL_PASSWORD` | 数据库密码 | —（必填） |

**服务配置**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `HTTP_PORT` | 控制台 HTTP 端口 | `8000` |
| `ENABLE_HTTPS` | 是否启用 HTTPS | `false` |
| `WAF_AUTH` | WAF 鉴权密钥（控制台与节点通信凭证） | —（必填，建议设为 UUID） |
| `OPEN_REGIST` | 是否开放注册 | `false` |

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

**其他**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `TZ` | 时区 | `Asia/Shanghai` |

> `RESOLVER_IPS` 已配置于 `conf/waf_config.json` 中，默认值为 `223.5.5.5 119.29.29.29 114.114.114.114 1.1.1.1`，无需在 docker-compose 中额外设置。

#### jxwaf_node_standard

**核心配置**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `HTTP_PORT` | HTTP 监听端口，支持多端口逗号分隔（如 `80,8080`） | `80` |
| `HTTPS_PORT` | HTTPS 监听端口，支持多端口逗号分隔 | `443` |
| `JXWAF_SERVER` | 控制台地址（末尾不要带 `/`） | —（必填） |
| `WAF_AUTH` | 鉴权密钥，需与控制台的 `WAF_AUTH` 一致 | —（必填） |

**共享内存配置**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `WAF_CONF_DATA` | WAF 配置数据缓存 | `100m` |
| `JXWAF_INNER` | WAF 内部数据缓存 | `100m` |
| `JXWAF_USER` | 用户自定义数据缓存 | `100m` |
| `JXWAF_REQUEST_COUNT` | IP 访问频率限制统计缓存 | `100m` |
| `JXWAF_REQUEST_IP` | IP 计数限制统计缓存 | `100m` |
| `JXWAF_REQUEST_IP_COUNT` | 域名级访问频率限制统计缓存 | `100m` |
| `JXWAF_LIMIT_BOT` | Bot 限流缓存 | `100m` |

**SSL 攻击防护**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SSL_ATTACK_STAT_SIZE` | SSL 攻击统计缓存大小 | `10m` |
| `SSL_BLACK_IP_SIZE` | SSL 黑名单 IP 缓存大小 | `10m` |
| `SSL_ATTACK_PROTECT` | SSL 攻击防护开关（`true`/`false`） | `false` |
| `SSL_ATTACK_STAT_TIME` | SSL 攻击统计时间窗口（秒） | `60` |
| `SSL_ATTACK_STAT_COUNT` | SSL 攻击触发阈值（次） | `10000` |
| `SSL_ATTACK_BLOCK_TIME` | SSL 攻击自动封禁时长（秒） | `600` |

> SSL 攻击防护原理：在 TLS 握手阶段，对客户端 IP 进行频率统计。若某 IP 在 `SSL_ATTACK_STAT_TIME` 秒内发起超过 `SSL_ATTACK_STAT_COUNT` 次 TLS 握手，则自动封禁该 IP `SSL_ATTACK_BLOCK_TIME` 秒。

**日志上报**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `LOG_IP` | log_send_to_mysql 服务地址 | `127.0.0.1` |
| `LOG_PORT` | log_send_to_mysql 服务端口 | `12997` |

**其他**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `RESOLVER_IPS` | DNS 解析服务器 IP（空格分隔） | `223.5.5.5 119.29.29.29 114.114.114.114 1.1.1.1` |
| `TZ` | 时区 | `Asia/Shanghai` |

##### Nginx 模板自定义

`docker-compose.yml` 中已预留 `nginx.conf.tmpl` 挂载注释。如需自定义 Nginx 参数（如调整 `worker_connections`、`keepalive_timeout` 等），可放置 `nginx.conf.tmpl` 文件并取消 `volumes` 注释，重启容器即可生效。

> 模板中的占位变量不可修改或删除。

#### log_send_to_mysql

**监听配置**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `LISTEN_ADDR` | 日志接收监听地址 | `:12997` |
| `BATCH_SIZE` | 批量写入条数 | `50` |
| `BATCH_WAIT_TIMEOUT` | 批量写入超时 | `2s` |

**数据库连接**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `DB_HOST` | MySQL 地址 | `127.0.0.1` |
| `DB_PORT` | MySQL 端口 | `3306` |
| `DB_DATABASE` | 数据库名称 | `jxwaf_admin_server` |
| `DB_USER` | 数据库用户 | `root` |
| `DB_PASSWORD` | 数据库密码 | —（必填） |
| `DB_TABLE` | 日志表名 | `jxwaf_waf_attack_log` |
| `DB_CHARSET` | 字符集 | `utf8mb4` |

**连接池**

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MAX_CONNECTIONS` | 最大连接数 | `1000` |
| `MAX_IDLE_CONNS` | 最大空闲连接数 | `10` |
| `CONN_MAX_LIFETIME` | 连接最大存活时间 | `10m` |

#### jxwaf_nft_node

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `WAF_SERVER_URL` | 控制台地址（末尾不要带 `/`） | —（必填） |
| `WAF_AUTH` | 鉴权密钥，需与控制台的 `WAF_AUTH` 一致 | —（必填） |
| `SYNC_INTERVAL` | 配置同步间隔（秒） | `3` |
| `WAF_FILTER_PORTS` | 需防护的端口，逗号分隔（如 `"80,443"`） | — |
| `TZ` | 时区 | `Asia/Shanghai` |

> **说明**：系统使用 `network_mode: host` 宿主机网络模式，MySQL 绑定 `127.0.0.1` 仅允许本地访问。如需使用外部数据库，可移除 `mysql_db` 服务并修改各服务中对应的数据库连接变量。


## 系统升级

```bash
cd jxwaf/Standard/
git pull
docker compose down
docker compose up -d
```

## 卸载系统

```bash
cd jxwaf/Standard/
docker compose down
rm -rf /opt/jxwaf_data/standard_mysql   # 可选：删除数据库文件
```


## 启用 HTTPS（可选）

如需为控制台启用 HTTPS 访问：

1. 准备 SSL 证书和私钥文件，放入 `ssl_certs/` 目录，分别命名为 `server.crt` 和 `server.key`

2. 修改 `docker-compose.yml` 中 `jxwaf_admin_server` 服务的环境变量：

   ```yaml
   ENABLE_HTTPS: "true"
   HTTPS_PORT: 8443
   ```

3. 取消 `volumes` 挂载注释：

   ```yaml
   volumes:
     - ./ssl_certs/server.crt:/opt/jxwaf_admin_server/nginx/conf/server.crt
     - ./ssl_certs/server.key:/opt/jxwaf_admin_server/nginx/conf/server.key
   ```

4. 重启服务：

   ```bash
   docker compose down && docker compose up -d
   ```