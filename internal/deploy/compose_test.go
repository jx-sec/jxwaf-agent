package deploy

import (
	"os"
	"strings"
	"testing"
)

func TestGenerateComposeProfessional(t *testing.T) {
	yaml, err := GenerateCompose(ComposeParams{
		Version: VersionProfessional, ServerURL: "http://admin.example.com",
		WafAuth: "test-auth", HTTPPort: "80", HTTPSPort: "443", WithNFT: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"jxwaf_base:", "jxwaf_node_professional:6.1.0", "network_mode: host", "privileged: true",
		"JXWAF_SERVER: http://admin.example.com", "WAF_AUTH: test-auth",
		"jxwaf_nft_node:", "jxwaf_nft_node:6.0", "WAF_SERVER_URL: http://admin.example.com",
		"soft: 602400", "restart: unless-stopped",
		// 官方教程 SSL 攻击防护参数
		"SSL_ATTACK_STAT_SIZE: 100m", "SSL_BLACK_IP_SIZE: 100m",
		"SSL_ATTACK_PROTECT: \"false\"", "SSL_ATTACK_STAT_TIME: 60",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("professional compose 缺少 %q:\n%s", want, yaml)
		}
	}
}

func TestGenerateComposeServerURLRules(t *testing.T) {
	// 尾部斜杠自动去除（官方要求末尾不带 /）
	yaml, err := GenerateCompose(ComposeParams{
		Version: VersionProfessional, ServerURL: "http://admin.example.com/",
		WafAuth: "t", WithNFT: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml, "JXWAF_SERVER: http://admin.example.com\n") {
		t.Errorf("尾部斜杠应被去除:\n%s", yaml)
	}
	// 非 http(s) 前缀报错
	if _, err := GenerateCompose(ComposeParams{Version: VersionProfessional, ServerURL: "admin.example.com", WafAuth: "t"}); err == nil {
		t.Error("无 scheme 的 server 地址应报错")
	}
	// professional 缺 server 报错
	if _, err := GenerateCompose(ComposeParams{Version: VersionProfessional, WafAuth: "t"}); err == nil {
		t.Error("professional 缺 server 应报错")
	}
}

func TestGenerateComposeCloudMultiPort(t *testing.T) {
	yaml, err := GenerateCompose(ComposeParams{
		Version: VersionCloud, ServerURL: "http://a.com", WafAuth: "t",
		HTTPPort: "80,8080", HTTPSPort: "443,8443", WithNFT: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml, "HTTP_PORT: 80,8080") || !strings.Contains(yaml, "HTTPS_PORT: 443,8443") {
		t.Errorf("多端口配置错误:\n%s", yaml)
	}
	if !strings.Contains(yaml, "jxwaf_node_cloud:6.2.1") {
		t.Errorf("cloud 应使用官方 6.2.1 镜像:\n%s", yaml)
	}
	// cloud 特有 CACHE_MAX_SIZE（官方 cloud 教程默认 10g）
	if !strings.Contains(yaml, "CACHE_MAX_SIZE: 10g") {
		t.Errorf("cloud compose 缺少 CACHE_MAX_SIZE:\n%s", yaml)
	}
	// professional 不应有 CACHE_MAX_SIZE
	prof, _ := GenerateCompose(ComposeParams{Version: VersionProfessional, ServerURL: "http://a.com", WafAuth: "t"})
	if strings.Contains(prof, "CACHE_MAX_SIZE") {
		t.Error("professional compose 不应包含 CACHE_MAX_SIZE")
	}
}

func TestGenerateAdminCompose(t *testing.T) {
	// professional：两服务 + prof 镜像 + 模型 39977 + 默认端口 8000（节点必须占 80/443，控制台默认不占 80）
	yaml, err := GenerateAdminCompose(AdminComposeParams{
		Version: VersionProfessional, MySQLPassword: "pwd",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"mysql_db:", "jxwaf_admin_server_professional:6.1.0", "HTTP_PORT: 8000",
		"JXWAF_MODEL_SERVER_PORT: 39977", "ssl_cert_service:", "ssl_cert_service:6.2.2",
		"CONSOLE_API_URL: http://127.0.0.1:8000", "/opt/jxwaf_data/mysql:/var/lib/mysql",
		"MYSQL_ROOT_PASSWORD: pwd", "ADMIN_API_ENABLE: \"false\"",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("prof admin compose 缺少 %q:\n%s", want, yaml)
		}
	}
	if strings.Contains(yaml, "USER_API_ENABLE") {
		t.Error("prof admin 不应包含 USER_API_ENABLE（cloud 专属）")
	}

	// cloud：三服务 + cloud 镜像 + 模型 39980 + 端口 8000 + USER_API_ENABLE 必须 true + mysql_cloud 数据目录
	yaml, err = GenerateAdminCompose(AdminComposeParams{Version: VersionCloud})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"jxwaf_admin_server_cloud:6.2.1", "HTTP_PORT: 8000",
		"JXWAF_MODEL_SERVER_PORT: 39980", "USER_API_ENABLE: \"true\"", "USER_API_WHITELIST: \"\"",
		"AUTH_CODE: \"\"", "OPEN_REGIST: \"false\"",
		"/opt/jxwaf_data/mysql_cloud:/var/lib/mysql", "CONSOLE_API_URL: http://127.0.0.1:8000",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("cloud admin compose 缺少 %q:\n%s", want, yaml)
		}
	}
	// 端口覆盖 + 镜像覆盖
	yaml, _ = GenerateAdminCompose(AdminComposeParams{Version: VersionCloud, AdminPort: "9000", AdminImage: "reg.io/admin:v9"})
	if !strings.Contains(yaml, "HTTP_PORT: 9000") || !strings.Contains(yaml, "reg.io/admin:v9") || !strings.Contains(yaml, "CONSOLE_API_URL: http://127.0.0.1:9000") {
		t.Errorf("admin 端口/镜像覆盖未生效:\n%s", yaml)
	}
	// 分机部署场景：显式 --admin-port 80 让控制台独占 80
	yaml, _ = GenerateAdminCompose(AdminComposeParams{Version: VersionProfessional, AdminPort: "80"})
	if !strings.Contains(yaml, "HTTP_PORT: 80\n") || !strings.Contains(yaml, "CONSOLE_API_URL: http://127.0.0.1:80\n") {
		t.Errorf("显式 admin-port 80 未生效:\n%s", yaml)
	}
	// standard 拒绝
	if _, err := GenerateAdminCompose(AdminComposeParams{Version: VersionStandard}); err == nil {
		t.Error("admin 应拒绝 standard（全栈走 deploy 主体）")
	}
	// 密码自动生成
	yaml, _ = GenerateAdminCompose(AdminComposeParams{Version: VersionProfessional})
	if !strings.Contains(yaml, "MYSQL_ROOT_PASSWORD: ") {
		t.Error("admin 未提供密码时应自动生成")
	}
}

func TestAdminCheckPorts(t *testing.T) {
	if got := AdminCheckPorts(AdminComposeParams{Version: VersionProfessional}); len(got) != 2 {
		t.Errorf("prof admin 应查 2 端口: %v", got)
	}
	if got := AdminCheckPorts(AdminComposeParams{Version: VersionCloud, AdminPort: "9000"}); len(got) != 2 {
		t.Errorf("cloud admin 应查 2 端口: %v", got)
	}
}

func TestGenerateJlogCompose(t *testing.T) {
	// professional 镜像
	yaml, err := GenerateJlogCompose(JlogComposeParams{Version: VersionProfessional})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"clickhouse:", "clickhouse-server:22.8.5-alpine", "jxlog:", "jxlog_professional:1.0",
		"\"8877:8877\"", "\"9000:9000\"", "\"9004:9004\"", "172.10.0.10", "172.10.0.11",
		"CLICKHOUSE: 172.10.0.10:9000", "/opt/jxwaf_data/clickhouse:/var/lib/clickhouse",
		"TCPPORT: 8877",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("prof jlog compose 缺少 %q:\n%s", want, yaml)
		}
	}
	// cloud 镜像不同
	cloud, _ := GenerateJlogCompose(JlogComposeParams{Version: VersionCloud})
	if !strings.Contains(cloud, "jxlog_cloud:1.0") {
		t.Errorf("cloud jlog 应使用 jxlog_cloud 镜像:\n%s", cloud)
	}
	// standard 拒绝
	if _, err := GenerateJlogCompose(JlogComposeParams{Version: VersionStandard}); err == nil {
		t.Error("jlog 应拒绝 standard")
	}
	// 镜像覆盖
	ovr, _ := GenerateJlogCompose(JlogComposeParams{Version: VersionCloud, JlogImage: "reg.io/jlog:v2"})
	if !strings.Contains(ovr, "reg.io/jlog:v2") {
		t.Error("jlog 镜像覆盖未生效")
	}
}

func TestJlogCheckPorts(t *testing.T) {
	got := JlogCheckPorts()
	if len(got) != 3 {
		t.Fatalf("jlog 应查 3 端口: %v", got)
	}
	set := map[string]bool{"8877": false, "9000": false, "9004": false}
	for _, p := range got {
		if _, ok := set[p]; !ok {
			t.Errorf("意外端口 %q", p)
		}
		set[p] = true
	}
	for p, seen := range set {
		if !seen {
			t.Errorf("缺少端口 %q", p)
		}
	}
}

func TestRemoveTargets(t *testing.T) {
	// 三个目标目录互不相同（分目录隔离）
	dirs := map[string]string{}
	for _, t2 := range []string{"node", "admin", "jlog"} {
		if !ValidRemoveTarget(t2) {
			t.Errorf("%s 应为合法目标", t2)
		}
		dirs[t2] = TargetDir(t2)
	}
	if dirs["node"] == dirs["admin"] || dirs["node"] == dirs["jlog"] || dirs["admin"] == dirs["jlog"] {
		t.Errorf("三类部署目录应互不相同: %v", dirs)
	}
	if ValidRemoveTarget("bad") || TargetDir("bad") != "" {
		t.Error("非法目标应被拒绝")
	}
}

func TestGenerateComposeStandardFullStack(t *testing.T) {
	yaml, err := GenerateCompose(ComposeParams{
		Version: VersionStandard, WafAuth: "std-auth",
		MySQLPassword: "fixed-pwd-for-test", WithNFT: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 单机全栈五服务（对齐官方标准版教程）
	for _, want := range []string{
		"mysql_db:", "jxwaf/mysql:8.0", "MYSQL_ROOT_PASSWORD: fixed-pwd-for-test",
		"jxwaf_admin_server:", "jxwaf_admin_server_standard:6.2.5", "HTTP_PORT: 8000",
		"jxwaf_node_standard:", "jxwaf_node_standard:6.2.4",
		"JXWAF_SERVER: http://127.0.0.1:8000", // 控制台在本机
		"log_send_to_mysql:", "log_send_to_mysql:v2", "LISTEN_ADDR: \":12997\"",
		"jxwaf_nft_node:", "jxwaf_nft_node:7.0", "WAF_FILTER_PORTS: \"80,443\"",
		"WAF_AUTH: std-auth", "TZ: Asia/Shanghai",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("standard 全栈 compose 缺少 %q:\n%s", want, yaml)
		}
	}
	// standard 无需 --server（不要求 ServerURL）
	if _, err := GenerateCompose(ComposeParams{Version: VersionStandard, WafAuth: "t"}); err != nil {
		t.Errorf("standard 不应要求 --server: %v", err)
	}
	// 未提供 MySQL 密码时自动生成
	yaml2, err := GenerateCompose(ComposeParams{Version: VersionStandard, WafAuth: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml2, "MYSQL_ROOT_PASSWORD: ") {
		t.Error("standard 应自动生成 MySQL 密码")
	}
}

func TestGenerateComposeImageOverride(t *testing.T) {
	yaml, err := GenerateCompose(ComposeParams{
		Version: VersionProfessional, ServerURL: "http://a.com", WafAuth: "t",
		WithNFT: true, NodeImage: "registry.example.com/waf:v9", NFTImage: "registry.example.com/nft:v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yaml, `image: "registry.example.com/waf:v9"`) {
		t.Errorf("节点镜像覆盖未生效:\n%s", yaml)
	}
	if !strings.Contains(yaml, "registry.example.com/nft:v2") {
		t.Errorf("nft 镜像覆盖未生效:\n%s", yaml)
	}
}

func TestGenerateComposeValidation(t *testing.T) {
	if _, err := GenerateCompose(ComposeParams{Version: "bad", ServerURL: "s", WafAuth: "t"}); err == nil {
		t.Error("非法版本应报错")
	}
	if _, err := GenerateCompose(ComposeParams{Version: VersionStandard}); err == nil {
		t.Error("缺少 waf-auth 应报错")
	}
}

func TestOptionsValidateMissingHints(t *testing.T) {
	cases := []struct {
		opts Options
		want string
	}{
		{Options{}, "--host"},
		{Options{Host: "1.2.3.4"}, "--version"},
		{Options{Host: "1.2.3.4", Compose: ComposeParams{Version: VersionProfessional}}, "--server"},
		{Options{Host: "1.2.3.4", Compose: ComposeParams{Version: VersionProfessional, ServerURL: "http://a"}}, "--waf-auth"},
		{Options{Host: "1.2.3.4", Compose: ComposeParams{Version: VersionProfessional, ServerURL: "http://a", WafAuth: "t"}}, "JXWAF_SSH_PASSWORD"},
	}
	for i, c := range cases {
		err := c.opts.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("用例%d 应提示 %q，实际: %v", i, c.want, err)
		}
	}
	// standard 版无需 --server（无 SSH 认证时错误应指向 SSH 而非 --server）
	stdOpts := Options{Host: "1.2.3.4", Compose: ComposeParams{Version: VersionStandard, WafAuth: "t"}}
	if err := stdOpts.Validate(); err == nil || strings.Contains(err.Error(), "--server") {
		t.Errorf("standard 不应要求 --server，实际: %v", err)
	}
	// 提供密钥路径后认证校验通过
	t.Setenv(sshPasswordEnv, "")
	opts := cases[4].opts
	opts.SSHKey = "/path/to/key"
	if err := opts.Validate(); err != nil {
		t.Errorf("提供 SSH 密钥后应通过校验: %v", err)
	}
	// 密码经环境变量后通过
	opts.SSHKey = ""
	t.Setenv(sshPasswordEnv, "secret")
	if err := opts.Validate(); err != nil {
		t.Errorf("密码经环境变量后应通过校验: %v", err)
	}
	// standard + 密码：完整通过
	stdOpts.SSHKey = ""
	if err := stdOpts.Validate(); err != nil {
		t.Errorf("standard+密码应通过全部校验: %v", err)
	}
}

func TestCheckPorts(t *testing.T) {
	// professional：只查 http/https
	got := CheckPorts(ComposeParams{Version: VersionProfessional, HTTPPort: "80", HTTPSPort: "443"})
	if len(got) != 2 {
		t.Errorf("professional 应只查 2 端口: %v", got)
	}
	// standard：全栈含控制台/MySQL/日志端口
	got = CheckPorts(ComposeParams{Version: VersionStandard, HTTPPort: "80", HTTPSPort: "443,8443", AdminPort: "8000"})
	want := []string{"80", "443", "8000", "3306", "12997", "8443"}
	if len(got) != len(want) {
		t.Fatalf("standard 应查 %v，实际 %v", want, got)
	}
	set := map[string]bool{}
	for _, p := range got {
		set[p] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("standard 端口检查缺 %q: %v", w, got)
		}
	}
}

func TestNormalizeServerURL(t *testing.T) {
	if u, _ := NormalizeServerURL("http://a.com/"); u != "http://a.com" {
		t.Errorf("尾斜杠未去除: %q", u)
	}
	if u, _ := NormalizeServerURL("  http://a.com//  "); u != "http://a.com" {
		t.Errorf("多斜杠与空格未处理: %q", u)
	}
	if _, err := NormalizeServerURL("a.com"); err == nil {
		t.Error("缺 scheme 应报错")
	}
	if _, err := NormalizeServerURL(""); err == nil {
		t.Error("空地址应报错")
	}
}

func TestUniquePorts(t *testing.T) {
	got := uniquePorts("80,8080", "443,80")
	want := []string{"443", "80", "8080"}
	if len(got) != len(want) {
		t.Fatalf("端口去重错误: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("端口排序错误: %v", got)
			break
		}
	}
}

func TestDirOf(t *testing.T) {
	if d := dirOf("/opt/jxwaf_node/docker-compose.yml"); d != "/opt/jxwaf_node" {
		t.Errorf("dirOf 错误: %q", d)
	}
	if d := dirOf("/file"); d != "/" {
		t.Errorf("根路径处理错误: %q", d)
	}
}

func TestHostOnly(t *testing.T) {
	if h := hostOnly("1.2.3.4:2222"); h != "1.2.3.4" {
		t.Errorf("hostOnly 端口剥离错误: %q", h)
	}
	if h := hostOnly("1.2.3.4"); h != "1.2.3.4" {
		t.Errorf("hostOnly 无端口应原样: %q", h)
	}
}

// 确保 SSH 密码默认不出现在任何持久化产物中（compose 只含 waf_auth）。
func TestComposeNeverContainsSSHCred(t *testing.T) {
	t.Setenv(sshPasswordEnv, "super-secret-pwd")
	yaml, err := GenerateCompose(ComposeParams{
		Version: VersionProfessional, ServerURL: "http://a.com", WafAuth: "node-auth",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(yaml, "super-secret-pwd") {
		t.Error("compose 不应包含 SSH 密码")
	}
	_ = os.Getenv
}
