package deploy

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// officialRawBase 官方 GitHub 仓库 raw 文件基地址（jx-sec/jxwaf，master 分支）。
const officialRawBase = "https://raw.githubusercontent.com/jx-sec/jxwaf/master/"

// composeFiles 各部署目标与版本的官方 compose 文件路径。
// target 取值：node（节点/standard 全栈）/ admin（管理控制台）/ jlog（jxlog 日志系统）。
var composeFiles = map[string]string{
	"node:standard":      "Standard/docker-compose.yml",
	"node:professional":  "Professional/jxwaf_node/docker-compose.yml",
	"node:cloud":         "Cloud/jxwaf_node/docker-compose.yml",
	"admin:professional": "Professional/jxwaf_admin_server/docker-compose.yml",
	"admin:cloud":        "Cloud/jxwaf_admin_server/docker-compose.yml",
	"jlog:professional":  "Professional/jxlog/docker-compose.yml",
	"jlog:cloud":         "Cloud/jxlog/docker-compose.yml",
}

// InjectParams 注入官方 compose 的部署参数（空值字段不做替换，保持官方默认）。
type InjectParams struct {
	WafAuth       string // WAF_AUTH（所有版本；占位符 you_auth_key 或官方默认值统一替换）
	ServerURL     string // 管理端地址（prof/cloud 节点；standard 单机全栈为空则跳过）
	MySQLPassword string // MySQL root 密码（standard 全栈 / admin 控制台；空则保持官方默认）
	HTTPPort      string // 节点 HTTP 端口（空则保持官方默认）
	HTTPSPort     string // 节点 HTTPS 端口（空则保持官方默认）
	AdminPort     string // 控制台 HTTP 端口（空则保持官方默认，prof 官方默认 80）
}

// FetchCompose 从官方 GitHub 拉取对应版本组件的 compose 并注入部署参数。
// 返回注入后的 compose 内容；拉取失败时返回错误（调用方降级到本地生成）。
func FetchCompose(version, target string, inj InjectParams) (string, error) {
	raw, err := fetchRawCompose(version, target)
	if err != nil {
		return "", err
	}
	RefreshVersionsFromCompose(version, raw)
	return injectCompose(raw, version, target, inj), nil
}

// fetchRawCompose 拉取官方 compose 原始内容。
func fetchRawCompose(version, target string) (string, error) {
	path, ok := composeFiles[target+":"+version]
	if !ok {
		return "", fmt.Errorf("未知部署目标/版本组合：%s/%s", target, version)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(officialRawBase + path)
	if err != nil {
		return "", fmt.Errorf("拉取官方 compose 失败（%s）: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("拉取官方 compose 失败（%s）：HTTP %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取官方 compose 失败: %w", err)
	}
	return string(body), nil
}

// injectCompose 将部署参数注入官方 compose（按字段名正则替换值，不依赖官方具体默认值）。
// version 用于区分 standard 全栈（控制台+节点两组端口同名，需按官方默认值精确区分）与 prof/cloud 节点。
func injectCompose(compose, version, target string, inj InjectParams) string {
	s := compose
	if inj.WafAuth != "" {
		s = replaceEnv(s, "WAF_AUTH", inj.WafAuth)
	}
	// 管理端地址：prof/cloud 节点（standard 单机全栈地址为本机 127.0.0.1，不替换）
	if inj.ServerURL != "" {
		s = replaceEnv(s, "JXWAF_SERVER", inj.ServerURL)
		s = replaceEnv(s, "WAF_SERVER_URL", inj.ServerURL)
	}
	// MySQL 密码（standard 全栈 / admin 控制台；三个字段同名密码保持一致）
	if inj.MySQLPassword != "" {
		s = replaceEnv(s, "MYSQL_ROOT_PASSWORD", inj.MySQLPassword)
		s = replaceEnv(s, "MYSQL_PASSWORD", inj.MySQLPassword)
		s = replaceEnv(s, "DB_PASSWORD", inj.MySQLPassword)
	}
	// 端口（节点与控制台分开处理）
	switch target {
	case "node":
		if version == VersionStandard {
			// standard 全栈含控制台+节点两组同名端口，全局替换会误伤控制台端口；
			// 按官方默认值精确区分：控制台 HTTP_PORT=8000、HTTPS_PORT=8443，节点 80/443
			if inj.AdminPort != "" {
				s = replaceEnvValue(s, "HTTP_PORT", "8000", inj.AdminPort)
			}
			if inj.HTTPPort != "" {
				s = replaceEnvValue(s, "HTTP_PORT", "80", inj.HTTPPort)
			}
			if inj.HTTPSPort != "" {
				s = replaceEnvValue(s, "HTTPS_PORT", "443", inj.HTTPSPort)
			}
		} else {
			if inj.HTTPPort != "" {
				s = replaceEnv(s, "HTTP_PORT", inj.HTTPPort)
			}
			if inj.HTTPSPort != "" {
				s = replaceEnv(s, "HTTPS_PORT", inj.HTTPSPort)
			}
		}
	case "admin":
		if inj.AdminPort != "" {
			s = replaceEnv(s, "HTTP_PORT", inj.AdminPort)
		}
	}
	return s
}

// replaceEnv 按字段名替换 compose 中 environment 变量的值。
// 仅匹配行首（含缩进）的「字段名: 值」形式，跳过注释行（# 开头）。
func replaceEnv(s, key, value string) string {
	re := regexp.MustCompile(`(?m)^([ \t]*` + regexp.QuoteMeta(key) + `:[ \t]*).*$`)
	return re.ReplaceAllString(s, `${1}`+value)
}

// replaceEnvValue 按「字段名 + 旧值」精确替换，用于 standard 全栈中同名字段在
// 不同服务有不同默认值的情况（控制台 HTTP_PORT=8000 vs 节点 HTTP_PORT=80）。
func replaceEnvValue(s, key, oldValue, newValue string) string {
	re := regexp.MustCompile(`(?m)^([ \t]*` + regexp.QuoteMeta(key) + `:[ \t]*)` + regexp.QuoteMeta(oldValue) + `[ \t]*$`)
	return re.ReplaceAllString(s, `${1}`+newValue)
}

// gitCloneDir 服务器上 clone 官方仓库的临时目录。
const gitCloneDir = "/opt/jxwaf_git_repo"

// GitCloneCompose 在目标服务器上 git clone 官方仓库，读取对应 compose 并注入参数。
// 作为本地拉取 raw 失败时的兜底（服务器网络访问 GitHub 可能优于本地）。
func GitCloneCompose(c *SSHClient, version, target string, inj InjectParams) (string, error) {
	path, ok := composeFiles[target+":"+version]
	if !ok {
		return "", fmt.Errorf("未知部署目标/版本组合：%s/%s", target, version)
	}
	// clone（已存在则清理后重新 clone；depth=1 减小体积）
	cloneCmd := fmt.Sprintf("rm -rf %s && git clone --depth=1 https://github.com/jx-sec/jxwaf.git %s 2>&1 | tail -3", gitCloneDir, gitCloneDir)
	if _, err := c.RunCheck(cloneCmd); err != nil {
		return "", fmt.Errorf("服务器 git clone 官方仓库失败: %w", err)
	}
	composePath := gitCloneDir + "/" + path
	r := c.Run(fmt.Sprintf("cat %q", composePath))
	if r.Code != 0 {
		return "", fmt.Errorf("读取 clone 的 compose 失败（%s）: %s", composePath, strings.TrimSpace(r.Stderr))
	}
	RefreshVersionsFromCompose(version, r.Stdout)
	return injectCompose(r.Stdout, version, target, inj), nil
}

// imagePattern 匹配 compose 中的 image 字段值（含可选引号）。
var imagePattern = regexp.MustCompile(`(?m)^[ \t]*image:[ \t]*"?([^"\s]+)"?`)

// RefreshVersionsFromCompose 从官方 compose 提取镜像，更新 versions.json，
// 使本地生成兜底（--source generate / 降级）也能使用最新版本。刷新失败静默忽略。
func RefreshVersionsFromCompose(version, compose string) {
	v, err := LoadVersions()
	if err != nil {
		return
	}
	for _, m := range imagePattern.FindAllStringSubmatch(compose, -1) {
		if len(m) < 2 {
			continue
		}
		img := m[1]
		switch {
		case strings.Contains(img, "jxwaf_nft_node"):
			switch version {
			case VersionStandard:
				v.Standard.NFT = img
			case VersionCloud:
				v.Cloud.NFT = img
			default:
				v.Professional.NFT = img
			}
		case strings.Contains(img, "jxwaf_node_standard"):
			v.Standard.Node = img
		case strings.Contains(img, "jxwaf_admin_server_standard"):
			v.Standard.Admin = img
		case strings.Contains(img, "jxwaf_node_professional"):
			v.Professional.Node = img
		case strings.Contains(img, "jxwaf_admin_server_professional"):
			v.Professional.Admin = img
		case strings.Contains(img, "jxwaf_node_cloud"):
			v.Cloud.Node = img
		case strings.Contains(img, "jxwaf_admin_server_cloud"):
			v.Cloud.Admin = img
		case strings.Contains(img, "jxlog_professional"):
			v.Professional.Jlog = img
		case strings.Contains(img, "jxlog_cloud"):
			v.Cloud.Jlog = img
		case strings.Contains(img, "log_send_to_mysql"):
			v.LogSendToMySQL = img
		case strings.Contains(img, "mysql"):
			v.MySQL = img
		case strings.Contains(img, "ssl_cert_service"):
			v.SSLCertService = img
		case strings.Contains(img, "clickhouse"):
			v.Clickhouse = img
		}
	}
	_ = SaveVersions(v)
}
