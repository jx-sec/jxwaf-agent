package deploy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// Version 部署的 WAF 节点版本。
const (
	VersionStandard     = "standard"
	VersionProfessional = "professional"
	VersionCloud        = "cloud"
)

// ValidVersion 校验版本取值。
func ValidVersion(v string) bool {
	return v == VersionStandard || v == VersionProfessional || v == VersionCloud
}

// 镜像常量（对齐 docs.jxwaf.com 各版部署教程的正式版本；可用 --image / --nft-image 覆盖）：
// professional/cloud 为"节点接入已有控制台"形态；standard 为单机全栈（控制台+节点+MySQL+日志采集）。
const (
	defaultProfNodeImage  = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_professional:6.1.0"
	defaultCloudNodeImage = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_cloud:6.2.1"
	defaultStdNodeImage   = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_standard:6.1.7"
	defaultStdAdminImage  = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_standard:6.1.14"
	defaultStdLogImage    = "ccr.ccs.tencentyun.com/jxwaf/log_send_to_mysql:v2"
	defaultMySQLImage     = "ccr.ccs.tencentyun.com/jxwaf/mysql:8.0"
	defaultNFTImage       = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:6.0"
	defaultStdNFTImage    = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:7.0"

	// 控制台与日志系统（prof/cloud 分离部署形态，对齐官方教程与仓库 compose）
	defaultProfAdminImage = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_professional:6.1.0"
	defaultCloudAdminImg  = "ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_cloud:6.2.1"
	defaultSSLCertImage   = "ccr.ccs.tencentyun.com/jxwaf/ssl_cert_service:6.2.2"
	defaultClickhouseImg  = "ccr.ccs.tencentyun.com/jxwaf/clickhouse-server:22.8.5-alpine"
	defaultJlogProfImage  = "ccr.ccs.tencentyun.com/jxwaf/jxlog_professional:1.0"
	defaultJlogCloudImage = "ccr.ccs.tencentyun.com/jxwaf/jxlog_cloud:1.0"
)

// RemoteStacks 各组件的远程部署目录（分目录隔离，单独 remove 时互不影响）。
const (
	RemoteDir      = "/opt/jxwaf_node"  // WAF 节点（standard 全栈也在此）
	AdminRemoteDir = "/opt/jxwaf_admin" // 管理控制台（prof/cloud）
	JlogRemoteDir  = "/opt/jxwaf_jlog"  // jxlog 日志系统（prof/cloud）
)

// ComposePath 远程 compose 文件路径（节点）。
const ComposePath = RemoteDir + "/docker-compose.yml"

// AdminComposePath 远程 compose 文件路径（控制台）。
const AdminComposePath = AdminRemoteDir + "/docker-compose.yml"

// JlogComposePath 远程 compose 文件路径（jxlog）。
const JlogComposePath = JlogRemoteDir + "/docker-compose.yml"

// defaultNodeImages 各版本 WAF 节点默认镜像。
var defaultNodeImages = map[string]string{
	VersionStandard:     defaultStdNodeImage,
	VersionProfessional: defaultProfNodeImage,
	VersionCloud:        defaultCloudNodeImage,
}

// ComposeParams 生成 docker-compose.yml 的参数。
type ComposeParams struct {
	Version   string // standard / professional / cloud
	ServerURL string // 管理端地址（JXWAF_SERVER）。standard 版为单机全栈，控制台在本机，此字段忽略
	WafAuth   string // 节点接入凭据（standard 版为自设的 WAF_AUTH，控制台与节点一致）
	HTTPPort  string // HTTP 监听端口（多端口逗号分隔）
	HTTPSPort string // HTTPS 监听端口（多端口逗号分隔）
	WithNFT   bool   // 是否部署 jxwaf_nft_node（standard/professional/cloud 均支持）
	NodeImage string // 覆盖 WAF 节点镜像（空用默认）
	NFTImage  string // 覆盖 nft_node 镜像（空用默认）

	// 仅 standard（单机全栈）：
	AdminPort     string // 控制台 HTTP 端口（默认 8000）
	MySQLPassword string // MySQL root 密码；空则自动生成随机值（只写入远端 compose，不回显）
}

// EffectiveNodeImage 返回生效的 WAF 节点镜像。
func (p ComposeParams) EffectiveNodeImage() string {
	if p.NodeImage != "" {
		return p.NodeImage
	}
	return defaultNodeImages[p.Version]
}

// EffectiveNFTImage 返回生效的 nft_node 镜像。
func (p ComposeParams) EffectiveNFTImage() string {
	if p.NFTImage != "" {
		return p.NFTImage
	}
	if p.Version == VersionStandard {
		return defaultStdNFTImage
	}
	return defaultNFTImage
}

// NormalizeServerURL 规范化管理端地址：去尾部斜杠（官方要求末尾不带 /）。
func NormalizeServerURL(u string) (string, error) {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	if u == "" {
		return "", fmt.Errorf("管理端地址为空")
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "", fmt.Errorf("管理端地址 %q 需以 http:// 或 https:// 开头（如 http://1.2.3.4 或 http://1.2.3.4:8000）", u)
	}
	return u, nil
}

// RandomPassword 生成随机密码（用于 standard 版 MySQL，凭据安全：不落本地文件）。
func RandomPassword() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateCompose 生成目标服务器的 docker-compose.yml 内容。
// professional/cloud：节点接入已有控制台（对齐官方教程"节点部署"章节）；
// standard：单机全栈（mysql + 控制台 + 节点 + 日志采集 + nft_node，对齐官方"一键部署"）。
func GenerateCompose(p ComposeParams) (string, error) {
	if !ValidVersion(p.Version) {
		return "", fmt.Errorf("未知节点版本 %q（standard/professional/cloud）", p.Version)
	}
	if p.WafAuth == "" {
		return "", fmt.Errorf("缺少节点接入凭据（--waf-auth）")
	}
	if p.HTTPPort == "" {
		p.HTTPPort = "80"
	}
	if p.HTTPSPort == "" {
		p.HTTPSPort = "443"
	}

	if p.Version == VersionStandard {
		return generateStandardCompose(p)
	}

	// professional / cloud：节点形态，管理端地址必填
	serverURL, err := NormalizeServerURL(p.ServerURL)
	if err != nil {
		return "", fmt.Errorf("--server %v", err)
	}

	var b strings.Builder
	b.WriteString("# 由 jxwaf-cli deploy 生成；WAF 节点配置（含凭据，权限 0600，勿外传）\n")
	b.WriteString("services:\n")

	// ---- jxwaf_base：WAF 主节点 ----
	fmt.Fprintf(&b, "  jxwaf_base:\n")
	fmt.Fprintf(&b, "    image: %q\n", p.EffectiveNodeImage())
	b.WriteString("    network_mode: host\n")
	b.WriteString("    privileged: true\n")
	b.WriteString("    ulimits:\n      nofile:\n        soft: 602400\n        hard: 602400\n")
	b.WriteString("    environment:\n")
	fmt.Fprintf(&b, "      HTTP_PORT: %s\n", p.HTTPPort)
	fmt.Fprintf(&b, "      HTTPS_PORT: %s\n", p.HTTPSPort)
	b.WriteString("      JXWAF_INNER: 200m\n")
	// SSL 攻击防护参数（对齐官方教程默认值）
	if p.Version == VersionProfessional {
		b.WriteString("      SSL_ATTACK_STAT_SIZE: 100m\n      SSL_BLACK_IP_SIZE: 100m\n")
	} else {
		// cloud 特有：节点缓存磁盘上限（官方 cloud 教程默认 10g）
		b.WriteString("      SSL_ATTACK_STAT_SIZE: 10m\n      SSL_BLACK_IP_SIZE: 10m\n      CACHE_MAX_SIZE: 10g\n")
	}
	b.WriteString("      SSL_ATTACK_PROTECT: \"false\"\n")
	b.WriteString("      SSL_ATTACK_STAT_TIME: 60\n      SSL_ATTACK_STAT_COUNT: 10000\n      SSL_ATTACK_BLOCK_TIME: 600\n")
	fmt.Fprintf(&b, "      JXWAF_SERVER: %s\n", serverURL)
	fmt.Fprintf(&b, "      WAF_AUTH: %s\n", p.WafAuth)
	b.WriteString("      TZ: Asia/Shanghai\n")
	b.WriteString("    restart: unless-stopped\n")

	// ---- jxwaf_nft_node：网络层节点 ----
	if p.WithNFT {
		b.WriteString("\n  jxwaf_nft_node:\n")
		fmt.Fprintf(&b, "    image: %s\n", p.EffectiveNFTImage())
		b.WriteString("    container_name: jxwaf_nft_node\n")
		b.WriteString("    restart: always\n    network_mode: host\n    privileged: true\n")
		b.WriteString("    environment:\n")
		fmt.Fprintf(&b, "      WAF_SERVER_URL: %s\n", serverURL)
		fmt.Fprintf(&b, "      WAF_AUTH: %s\n", p.WafAuth)
		b.WriteString("      SYNC_INTERVAL: 3\n      TZ: Asia/Shanghai\n")
	}
	return b.String(), nil
}

// generateStandardCompose 生成标准版单机全栈 compose（对齐官方标准版部署教程）：
// mysql_db + jxwaf_admin_server(控制台:8000) + jxwaf_node_standard + log_send_to_mysql + jxwaf_nft_node。
// 控制台与节点同机，JXWAF_SERVER 指向本机控制台。
func generateStandardCompose(p ComposeParams) (string, error) {
	if p.AdminPort == "" {
		p.AdminPort = "8000"
	}
	if p.MySQLPassword == "" {
		p.MySQLPassword = RandomPassword()
	}
	localServer := "http://127.0.0.1:" + p.AdminPort
	// 节点防护端口列表（nft_node WAF_FILTER_PORTS 用）
	filterPorts := strings.ReplaceAll(p.HTTPPort+","+p.HTTPSPort, " ", "")

	var b strings.Builder
	b.WriteString("# 由 jxwaf-cli deploy 生成；JXWAF 标准版单机全栈（含凭据，权限 0600，勿外传）\n")
	b.WriteString("services:\n")

	// ---- mysql_db ----
	b.WriteString("  mysql_db:\n")
	fmt.Fprintf(&b, "    image: %s\n", defaultMySQLImage)
	b.WriteString("    restart: always\n    network_mode: host\n    environment:\n")
	fmt.Fprintf(&b, "      MYSQL_ROOT_PASSWORD: %s\n", p.MySQLPassword)
	b.WriteString("      MYSQL_CHARSET: utf8mb4\n      MYSQL_COLLATION: utf8mb4_0900_ai_ci\n")
	b.WriteString("      MYSQL_DEFAULT_AUTHENTICATION_PLUGIN: mysql_native_password\n")
	b.WriteString("    command:\n")
	b.WriteString("      - --default-authentication-plugin=mysql_native_password\n")
	b.WriteString("      - --character-set-server=utf8mb4\n")
	b.WriteString("      - --collation-server=utf8mb4_0900_ai_ci\n")
	b.WriteString("      - --innodb_buffer_pool_size=256M\n")
	b.WriteString("      - --bind-address=127.0.0.1\n")
	b.WriteString("      - --max-connections=1000\n")
	b.WriteString("    volumes:\n")
	b.WriteString("      - /opt/jxwaf_data/standard_mysql:/var/lib/mysql\n")

	// ---- jxwaf_admin_server（控制台） ----
	b.WriteString("\n  jxwaf_admin_server:\n")
	fmt.Fprintf(&b, "    image: %s\n", defaultStdAdminImage)
	b.WriteString("    restart: unless-stopped\n    network_mode: host\n    depends_on:\n      - mysql_db\n")
	b.WriteString("    environment:\n")
	b.WriteString("      MYSQL_HOST: 127.0.0.1\n      MYSQL_PORT: 3306\n")
	b.WriteString("      MYSQL_DATABASE: jxwaf_admin_server\n      MYSQL_USER: root\n")
	fmt.Fprintf(&b, "      MYSQL_PASSWORD: %s\n", p.MySQLPassword)
	fmt.Fprintf(&b, "      HTTP_PORT: %s\n", p.AdminPort)
	b.WriteString("      ENABLE_HTTPS: \"false\"\n")
	fmt.Fprintf(&b, "      WAF_AUTH: %s\n", p.WafAuth)
	b.WriteString("      JXWAF_MODEL_SERVER_HOST: model.jxwaf.com\n      JXWAF_MODEL_SERVER_PORT: 39977\n      JXWAF_MODEL_SERVER_SSL: \"true\"\n")
	b.WriteString("      WAF_UPDATE_CONF_DATA_SIZE: \"100m\"\n      CONF_DATA_SIZE: \"100m\"\n      MODEL_DATA_SIZE: \"100m\"\n")

	// ---- jxwaf_node_standard（节点） ----
	b.WriteString("\n  jxwaf_node_standard:\n")
	fmt.Fprintf(&b, "    image: %q\n", p.EffectiveNodeImage())
	b.WriteString("    network_mode: host\n    privileged: true\n")
	b.WriteString("    ulimits:\n      nofile:\n        soft: 602400\n        hard: 602400\n")
	b.WriteString("    environment:\n")
	fmt.Fprintf(&b, "      HTTP_PORT: %s\n", p.HTTPPort)
	fmt.Fprintf(&b, "      HTTPS_PORT: %s\n", p.HTTPSPort)
	fmt.Fprintf(&b, "      JXWAF_SERVER: %s\n", localServer)
	fmt.Fprintf(&b, "      WAF_AUTH: %s\n", p.WafAuth)
	b.WriteString("      WAF_CONF_DATA: 100m\n      JXWAF_INNER: 100m\n      JXWAF_USER: 100m\n")
	b.WriteString("      JXWAF_REQUEST_COUNT: 100m\n      JXWAF_REQUEST_IP: 100m\n      JXWAF_REQUEST_IP_COUNT: 100m\n")
	b.WriteString("      JXWAF_LIMIT_BOT: 100m\n")
	b.WriteString("      RESOLVER_IPS: \"223.5.5.5 119.29.29.29 114.114.114.114 1.1.1.1\"\n")
	b.WriteString("      SSL_ATTACK_STAT_SIZE: 10m\n      SSL_BLACK_IP_SIZE: 10m\n      SSL_ATTACK_PROTECT: \"false\"\n")
	b.WriteString("      SSL_ATTACK_STAT_TIME: 60\n      SSL_ATTACK_STAT_COUNT: 10000\n      SSL_ATTACK_BLOCK_TIME: 600\n")
	b.WriteString("      LOG_IP: 127.0.0.1\n      LOG_PORT: 12997\n      TZ: Asia/Shanghai\n")
	b.WriteString("    restart: unless-stopped\n")

	// ---- log_send_to_mysql（日志采集） ----
	b.WriteString("\n  log_send_to_mysql:\n")
	fmt.Fprintf(&b, "    image: %s\n", defaultStdLogImage)
	b.WriteString("    container_name: data_send_to_mysql\n    network_mode: host\n    depends_on:\n      - mysql_db\n")
	b.WriteString("    environment:\n      LISTEN_ADDR: \":12997\"\n      BATCH_SIZE: \"50\"\n      BATCH_WAIT_TIMEOUT: \"2s\"\n")
	b.WriteString("      MAX_CONNECTIONS: \"1000\"\n      MAX_IDLE_CONNS: \"10\"\n      CONN_MAX_LIFETIME: \"10m\"\n")
	b.WriteString("      DB_HOST: \"127.0.0.1\"\n      DB_PORT: \"3306\"\n      DB_DATABASE: \"jxwaf_admin_server\"\n      DB_USER: \"root\"\n")
	fmt.Fprintf(&b, "      DB_PASSWORD: \"%s\"\n", p.MySQLPassword)
	b.WriteString("      DB_TABLE: \"jxwaf_waf_attack_log\"\n      DB_CHARSET: \"utf8mb4\"\n    restart: unless-stopped\n")

	// ---- jxwaf_nft_node（网络层节点） ----
	if p.WithNFT {
		b.WriteString("\n  jxwaf_nft_node:\n")
		fmt.Fprintf(&b, "    image: %s\n", p.EffectiveNFTImage())
		b.WriteString("    container_name: jxwaf_nft_node\n    restart: always\n    network_mode: host\n    privileged: true\n")
		b.WriteString("    environment:\n")
		fmt.Fprintf(&b, "      WAF_SERVER_URL: %s\n", localServer)
		fmt.Fprintf(&b, "      WAF_AUTH: %s\n", p.WafAuth)
		b.WriteString("      SYNC_INTERVAL: 3\n")
		fmt.Fprintf(&b, "      WAF_FILTER_PORTS: \"%s\"\n", filterPorts)
		b.WriteString("      TZ: Asia/Shanghai\n")
	}
	return b.String(), nil
}

// CheckPorts 返回该版本需要检查占用的端口列表（standard 全栈含控制台/MySQL/日志端口）。
func CheckPorts(p ComposeParams) []string {
	ports := uniquePorts(p.HTTPPort, p.HTTPSPort)
	if p.Version == VersionStandard {
		admin := p.AdminPort
		if admin == "" {
			admin = "8000"
		}
		ports = append(ports, uniquePorts(admin, "3306", "12997")...)
	}
	return uniquePorts(strings.Join(ports, ","))
}

// ---- 管理控制台（prof/cloud 分离部署形态）----

// AdminComposeParams 控制台部署参数。
type AdminComposeParams struct {
	Version       string // professional / cloud（standard 为单机全栈，走 deploy 主体，不适用此处）
	AdminPort     string // 控制台 HTTP 端口（默认 8000；分机部署需控制台独占 80 时显式指定）
	MySQLPassword string // MySQL root 密码；空则自动生成（只写入远端 compose，不回显）
	AdminImage    string // 覆盖控制台镜像
	SSLCertImage  string // 覆盖 ssl_cert_service 镜像
}

// EffectiveAdminImage 返回生效的控制台镜像。
func (p AdminComposeParams) EffectiveAdminImage() string {
	if p.AdminImage != "" {
		return p.AdminImage
	}
	if p.Version == VersionCloud {
		return defaultCloudAdminImg
	}
	return defaultProfAdminImage
}

// EffectiveAdminPort 返回生效的控制台端口（默认 8000，各版本一致，对齐官方教程 cloud 形态）。
// 控制台不走 80：节点是流量入口必须占 80/443，同机部署（控制台+节点同台）时 80 会冲突；
// 仅控制台与节点分机部署、控制台独占一台机器时，才用 --admin-port 80 显式让控制台占 80。
func (p AdminComposeParams) EffectiveAdminPort() string {
	if p.AdminPort != "" {
		return p.AdminPort
	}
	return "8000"
}

// mysqlDataDir 各版本 MySQL 数据目录（cloud 官方卸载命令为 mysql_cloud，印证差异）。
func (p AdminComposeParams) mysqlDataDir() string {
	if p.Version == VersionCloud {
		return "/opt/jxwaf_data/mysql_cloud"
	}
	return "/opt/jxwaf_data/mysql"
}

// GenerateAdminCompose 生成管理控制台 compose（对齐官方教程与仓库 compose）：
// mysql_db + jxwaf_admin_server + ssl_cert_service（泛域名证书自动签发/续期）。
// cloud 版必须开 USER_API_ENABLE（用户控制台依赖）；AI 模型服务地址按官方文档各版本配置。
func GenerateAdminCompose(p AdminComposeParams) (string, error) {
	if p.Version != VersionProfessional && p.Version != VersionCloud {
		return "", fmt.Errorf("控制台部署仅支持 professional/cloud（standard 为单机全栈，直接用 deploy 主体）")
	}
	if p.MySQLPassword == "" {
		p.MySQLPassword = RandomPassword()
	}
	port := p.EffectiveAdminPort()

	var b strings.Builder
	b.WriteString("# 由 jxwaf-cli deploy admin 生成；管理控制台（含凭据，权限 0600，勿外传）\n")
	b.WriteString("services:\n")

	// ---- mysql_db ----
	b.WriteString("  mysql_db:\n")
	fmt.Fprintf(&b, "    image: %s\n", defaultMySQLImage)
	b.WriteString("    restart: always\n    network_mode: host\n    environment:\n")
	fmt.Fprintf(&b, "      MYSQL_ROOT_PASSWORD: %s\n", p.MySQLPassword)
	b.WriteString("      MYSQL_CHARSET: utf8mb4\n      MYSQL_COLLATION: utf8mb4_0900_ai_ci\n")
	b.WriteString("      MYSQL_DEFAULT_AUTHENTICATION_PLUGIN: mysql_native_password\n")
	b.WriteString("    command:\n")
	b.WriteString("      - --default-authentication-plugin=mysql_native_password\n")
	b.WriteString("      - --character-set-server=utf8mb4\n")
	b.WriteString("      - --collation-server=utf8mb4_0900_ai_ci\n")
	b.WriteString("      - --innodb_buffer_pool_size=256M\n")
	b.WriteString("      - --bind-address=127.0.0.1\n")
	b.WriteString("      - --max-connections=1000\n")
	b.WriteString("    volumes:\n")
	fmt.Fprintf(&b, "      - %s:/var/lib/mysql\n", p.mysqlDataDir())

	// ---- jxwaf_admin_server ----
	b.WriteString("\n  jxwaf_admin_server:\n")
	fmt.Fprintf(&b, "    image: %s\n", p.EffectiveAdminImage())
	b.WriteString("    restart: unless-stopped\n    depends_on:\n      - mysql_db\n    network_mode: host\n")
	b.WriteString("    environment:\n")
	b.WriteString("      ENABLE_HTTPS: \"false\"\n")
	b.WriteString("      MYSQL_HOST: 127.0.0.1\n      MYSQL_PORT: 3306\n")
	b.WriteString("      MYSQL_DATABASE: jxwaf_admin_server\n      MYSQL_USER: root\n")
	fmt.Fprintf(&b, "      MYSQL_PASSWORD: %s\n", p.MySQLPassword)
	fmt.Fprintf(&b, "      HTTP_PORT: %s\n", port)
	if p.Version == VersionCloud {
		// cloud 特有（对齐官方 cloud 教程 1.3 与仓库 compose）
		b.WriteString("      AUTH_CODE: \"\"\n")
		b.WriteString("      OPEN_REGIST: \"false\"\n")
		b.WriteString("      JXWAF_MODEL_SERVER_HOST: model.jxwaf.com\n      JXWAF_MODEL_SERVER_PORT: 39980\n      JXWAF_MODEL_SERVER_SSL: \"true\"\n")
		b.WriteString("      # 用户（子账号）API：用户控制台依赖此功能，必须开启\n")
		b.WriteString("      USER_API_ENABLE: \"true\"\n      USER_API_WHITELIST: \"\"\n")
	} else {
		b.WriteString("      JXWAF_MODEL_SERVER_HOST: model.jxwaf.com\n      JXWAF_MODEL_SERVER_PORT: 39977\n      JXWAF_MODEL_SERVER_SSL: \"true\"\n")
	}
	b.WriteString("      WAF_UPDATE_CONF_DATA_SIZE: \"100m\"\n      CONF_DATA_SIZE: \"100m\"\n      MODEL_DATA_SIZE: \"100m\"\n")
	b.WriteString("      ADMIN_API_ENABLE: \"false\"\n      ADMIN_API_WHITELIST: \"agent.jxwaf.com\"\n")
	b.WriteString("      TZ: Asia/Shanghai\n")

	// ---- ssl_cert_service（泛域名证书自动签发/续期，两版均含）----
	sslImage := p.SSLCertImage
	if sslImage == "" {
		sslImage = defaultSSLCertImage
	}
	b.WriteString("\n  ssl_cert_service:\n")
	fmt.Fprintf(&b, "    image: %s\n", sslImage)
	b.WriteString("    container_name: ssl_cert_service\n    restart: always\n")
	b.WriteString("    depends_on:\n      - jxwaf_admin_server\n    network_mode: host\n")
	b.WriteString("    environment:\n")
	fmt.Fprintf(&b, "      CONSOLE_API_URL: http://127.0.0.1:%s\n", port)
	b.WriteString("      POLL_INTERVAL: 60s\n      RENEWAL_CHECK_INTERVAL: 6h\n      RENEWAL_DAYS: 30\n")
	b.WriteString("      ACME_DIRECTORY_URL: https://acme-v02.api.letsencrypt.org/directory\n")
	b.WriteString("      ACME_ACCOUNT_DIR: /data/acme_accounts\n      ACME_EMAIL_DOMAIN: jxwaf.com\n")
	b.WriteString("      ACME_ACCOUNT_MODE: per_user\n      TZ: Asia/Shanghai\n")
	b.WriteString("    volumes:\n      - /opt/jxwaf_data/ssl_cert_service:/data\n")
	return b.String(), nil
}

// AdminCheckPorts 控制台部署需检查的端口（控制台端口 + MySQL）。
func AdminCheckPorts(p AdminComposeParams) []string {
	return uniquePorts(p.EffectiveAdminPort(), "3306")
}

// ---- jxlog 日志系统（prof/cloud）----

// JlogComposeParams jxlog 部署参数。
type JlogComposeParams struct {
	Version   string // professional / cloud
	JlogImage string // 覆盖 jxlog 镜像
	CHImage   string // 覆盖 clickhouse 镜像
}

// EffectiveJlogImage 返回生效的 jxlog 镜像（按版本）。
func (p JlogComposeParams) EffectiveJlogImage() string {
	if p.JlogImage != "" {
		return p.JlogImage
	}
	if p.Version == VersionCloud {
		return defaultJlogCloudImage
	}
	return defaultJlogProfImage
}

// EffectiveCHImage 返回生效的 clickhouse 镜像。
func (p JlogComposeParams) EffectiveCHImage() string {
	if p.CHImage != "" {
		return p.CHImage
	}
	return defaultClickhouseImg
}

// GenerateJlogCompose 生成 jxlog 日志系统 compose（对齐仓库各版 jxlog/docker-compose.yml：
// bridge 网络 + 固定内网 IP；两版仅 jxlog 镜像名不同）。
// 部署后需在控制台"系统配置→日志传输配置/日志查询配置"指向本服务。
func GenerateJlogCompose(p JlogComposeParams) (string, error) {
	if p.Version != VersionProfessional && p.Version != VersionCloud {
		return "", fmt.Errorf("jxlog 部署仅支持 professional/cloud（standard 日志走 MySQL，已含在全栈中）")
	}
	var b strings.Builder
	b.WriteString("# 由 jxwaf-cli deploy jlog 生成；jxlog 日志系统（权限 0600）\n")
	b.WriteString("networks:\n  clickhouse_network:\n    driver: bridge\n    ipam:\n      config:\n        - subnet: 172.10.0.0/16\n\n")
	b.WriteString("services:\n")
	// ---- clickhouse ----
	b.WriteString("  clickhouse:\n")
	fmt.Fprintf(&b, "    image: %q\n", p.EffectiveCHImage())
	b.WriteString("    ports:\n      - \"9000:9000\"\n      - \"9004:9004\"\n")
	b.WriteString("    environment:\n      CLICKHOUSE_DB: jxwaf\n      CLICKHOUSE_USER: jxlog\n      CLICKHOUSE_PASSWORD: jxlog\n")
	b.WriteString("    volumes:\n      - /opt/jxwaf_data/clickhouse:/var/lib/clickhouse\n")
	b.WriteString("    restart: unless-stopped\n    networks:\n      clickhouse_network:\n        ipv4_address: 172.10.0.10\n")
	// ---- jxlog ----
	b.WriteString("\n  jxlog:\n")
	b.WriteString("    container_name: jxlog\n")
	fmt.Fprintf(&b, "    image: %q\n", p.EffectiveJlogImage())
	b.WriteString("    ports:\n      - \"8877:8877\"\n")
	b.WriteString("    environment:\n      CLICKHOUSE: 172.10.0.10:9000\n      DATABASE: jxwaf\n      USERNAME: jxlog\n      PASSWORD: jxlog\n")
	b.WriteString("      TABLE: jxlog\n      TCPSERVER: 0.0.0.0\n      TCPPORT: 8877\n")
	b.WriteString("      BATCH_SIZE: 1000\n      BATCH_WAIT_TIMEOUT: 3\n      TTL_DAYS: 30\n      ENGINE: MergeTree\n      TIMEZONE: Asia/Shanghai\n")
	b.WriteString("    depends_on:\n      - clickhouse\n    restart: unless-stopped\n    networks:\n      clickhouse_network:\n        ipv4_address: 172.10.0.11\n")
	return b.String(), nil
}

// JlogCheckPorts jxlog 部署需检查的端口（日志接收 + ClickHouse TCP/MySQL 兼容端口）。
func JlogCheckPorts() []string {
	return []string{"8877", "9000", "9004"}
}
