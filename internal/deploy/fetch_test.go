package deploy

import (
	"strings"
	"testing"
)

func TestInjectCompose(t *testing.T) {
	compose := `services:
  jxwaf_base:
    image: "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_professional:6.2.9"
    environment:
      HTTP_PORT: 80
      HTTPS_PORT: 443
      JXWAF_SERVER: you_jxwaf_server_url
      WAF_AUTH: you_auth_key
      # 注释：WAF_AUTH: should_not_change
  jxwaf_nft_node:
    environment:
      WAF_SERVER_URL: you_jxwaf_server_url
      WAF_AUTH: you_auth_key
`
	got := injectCompose(compose, VersionProfessional, "node", InjectParams{
		WafAuth:   "my-auth-key",
		ServerURL: "http://admin:8000",
		HTTPPort:  "8080",
	})

	for _, want := range []string{
		"JXWAF_SERVER: http://admin:8000",
		"WAF_SERVER_URL: http://admin:8000",
		"WAF_AUTH: my-auth-key",
		"HTTP_PORT: 8080",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("注入缺失 %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "you_jxwaf_server_url") || strings.Contains(got, "you_auth_key") {
		t.Errorf("占位符未替换:\n%s", got)
	}
	if !strings.Contains(got, "WAF_AUTH: should_not_change") {
		t.Errorf("注释行被误替换:\n%s", got)
	}
	if !strings.Contains(got, "HTTPS_PORT: 443") {
		t.Errorf("未指定 HTTPSPort 时应保持官方默认:\n%s", got)
	}
}

func TestInjectComposeMySQL(t *testing.T) {
	compose := `services:
  mysql_db:
    environment:
      MYSQL_ROOT_PASSWORD: 958fba75-56c6-4e81-a892-62517a9e1739
  jxwaf_admin_server:
    environment:
      MYSQL_PASSWORD: 958fba75-56c6-4e81-a892-62517a9e1739
      HTTP_PORT: 80
      WAF_AUTH: ade1e4c0-d644-46fe-9675-5fb59b486381
`
	got := injectCompose(compose, VersionProfessional, "admin", InjectParams{
		WafAuth:       "custom-auth",
		MySQLPassword: "random-pwd",
		AdminPort:     "8000",
	})
	for _, want := range []string{
		"MYSQL_ROOT_PASSWORD: random-pwd",
		"MYSQL_PASSWORD: random-pwd",
		"WAF_AUTH: custom-auth",
		"HTTP_PORT: 8000",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("注入缺失 %q:\n%s", want, got)
		}
	}
}

func TestInjectComposeStandardPorts(t *testing.T) {
	compose := `services:
  jxwaf_admin_server:
    environment:
      HTTP_PORT: 8000
      HTTPS_PORT: 8443
  jxwaf_node_standard:
    environment:
      HTTP_PORT: 80
      HTTPS_PORT: 443
`
	got := injectCompose(compose, VersionStandard, "node", InjectParams{
		AdminPort: "9000",
		HTTPPort:  "8080",
		HTTPSPort: "8444",
	})
	for _, want := range []string{
		"HTTP_PORT: 9000",  // 控制台端口改为 adminPort
		"HTTP_PORT: 8080",  // 节点端口改为 httpPort
		"HTTPS_PORT: 8443", // 控制台 HTTPS 保持官方默认，不被误伤
		"HTTPS_PORT: 8444", // 节点 HTTPS 改为 httpsPort
	} {
		if !strings.Contains(got, want) {
			t.Errorf("standard 端口注入缺失 %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "HTTP_PORT: 80\n") || strings.Contains(got, "HTTPS_PORT: 443\n") {
		t.Errorf("standard 节点端口未被替换:\n%s", got)
	}
}

func TestRefreshVersionsFromCompose(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JXWAF_CONFIG_PATH", dir+"/config.json")

	compose := `services:
  jxwaf_base:
    image: "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_professional:9.9.9"
  jxwaf_nft_node:
    image: ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:8.8.8
  mysql_db:
    image: ccr.ccs.tencentyun.com/jxwaf/mysql:8.0
`
	RefreshVersionsFromCompose(VersionProfessional, compose)

	v, err := LoadVersions()
	if err != nil {
		t.Fatal(err)
	}
	if v.Professional.Node != "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_professional:9.9.9" {
		t.Errorf("Professional.Node 未刷新: %s", v.Professional.Node)
	}
	if v.Professional.NFT != "ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:8.8.8" {
		t.Errorf("Professional.NFT 未刷新: %s", v.Professional.NFT)
	}
	if v.MySQL != "ccr.ccs.tencentyun.com/jxwaf/mysql:8.0" {
		t.Errorf("MySQL 未刷新: %s", v.MySQL)
	}
	// 其他版本字段不应被误改（保持默认）
	if v.Standard.Node == "" || v.Cloud.Node == "" {
		t.Errorf("未涉及版本的字段不应被清空")
	}
}

// TestFetchComposeOfficial 真实拉取官方 compose（网络）。失败视为环境网络问题，跳过而非报错。
func TestFetchComposeOfficial(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过真实网络拉取测试")
	}
	yaml, err := FetchCompose(VersionProfessional, "node", InjectParams{
		WafAuth:   "test-auth",
		ServerURL: "http://admin:8000",
	})
	if err != nil {
		t.Skipf("拉取官方 compose 失败（网络环境限制）: %v", err)
	}
	if !strings.Contains(yaml, "jxwaf_base:") || !strings.Contains(yaml, "WAF_AUTH: test-auth") {
		t.Errorf("官方 compose 拉取/注入异常:\n%s", yaml)
	}
}
