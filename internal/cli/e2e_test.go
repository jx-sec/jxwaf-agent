package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jx-sec/jxwaf-agent/internal/config"
)

// TestE2EClosedLoop 以模拟云WAF用户态管理 API 验证完整闭环：
// config set → generate → apply(dry/real) → 查询 → soc 日志 → cleanup 全链路输出契约。
func TestE2EClosedLoop(t *testing.T) {
	mux := http.NewServeMux()
	created := map[string]any{}
	mux.HandleFunc("/user/get_web_rule_protection_list", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"result": true, "page": 1, "records": []any{created}})
	})
	mux.HandleFunc("/user/create_web_rule_protection", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		created = body
		writeJSON(w, map[string]any{"result": true, "message": "create success"})
	})
	mux.HandleFunc("/user/delete_web_rule_protection", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"result": true, "message": "delete success"})
	})
	mux.HandleFunc("/user/get_log_query_list", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"result": true, "page": 1, "records": []any{map[string]any{
			"waf_module": "web_rule_protection", "waf_policy": "e2e_rule", "waf_action": "watch",
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// 隔离配置目录
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")
	t.Setenv("JXWAF_CONFIG_PATH", cfgPath)

	// 1. config set 建立 mock 环境（云WAF 用户态双 token）
	runCmd(t, nil, "config", "set", "--name", "e2e", "--version", "cloud",
		"--base-url", srv.URL, "--waf-auth", "master-token", "--sub-waf-auth", "sub-token")

	// 2. generate web-rule（--output 落盘）
	outDir := filepath.Join(tmp, "cfg.json")
	genOut := runCmd(t, nil, "generate", "web-rule", "--params",
		`{"config":{"rule_name":"e2e_rule","rule_detail":"e2e测试规则","rule_matchs":[{"match_args":[{"key":"http_args","value":"query_string"}],"args_prepocess":["none"],"match_operator":"rx","match_value":"union.*select"}],"rule_action":"watch"},"test_cases":[{"name":"攻击","path":"/","query":"id=1 union select 1","expect":"block"},{"name":"正常","path":"/","query":"id=1","expect":"pass"}]}`,
		"--output", outDir)
	if !strings.Contains(genOut, "watch") {
		t.Fatalf("generate 输出异常: %s", genOut)
	}

	// 3. apply dry-run 预览
	dry := runCmd(t, nil, "apply", outDir, "--env", "e2e")
	if !strings.Contains(dry, `"dry_run": true`) {
		t.Fatalf("apply 应默认 dry-run: %s", dry)
	}

	// 4. apply 实际执行
	applied := runCmd(t, nil, "apply", outDir, "--env", "e2e", "--apply")
	if !strings.Contains(applied, "create success") {
		t.Fatalf("apply --apply 应返回成功: %s", applied)
	}

	// 5. 查询列表（租户 token 场景无需 sub-user，走用户态）
	list := runCmd(t, nil, "rule", "web", "list", "--env", "e2e", "--params", `{"page":1}`)
	if !strings.Contains(list, `"page": 1`) {
		t.Fatalf("查询列表异常: %s", list)
	}

	// 6. soc 日志查询
	soc := runCmd(t, nil, "soc", "log", "query", "--env", "e2e", "--params",
		`{"from_time":"2026-08-30 00:00:00","to_time":"2026-08-30 23:59:59","page":1,"sql_rules":[{"field":"host","operation":"equals","value":"e2e.example.com"}]}`)
	if !strings.Contains(soc, "waf_action") {
		t.Fatalf("soc 查询异常: %s", soc)
	}

	// 7. cleanup dry-run 与执行
	if !strings.Contains(runCmd(t, nil, "cleanup", "--env", "e2e", "--type", "web-rule", "--names", "e2e_rule"), `"dry_run": true`) {
		t.Fatal("cleanup 应默认 dry-run")
	}
	cleaned := runCmd(t, nil, "cleanup", "--env", "e2e", "--type", "web-rule", "--names", "e2e_rule", "--apply")
	if !strings.Contains(cleaned, "delete success") {
		t.Fatalf("cleanup 执行异常: %s", cleaned)
	}

	// 8. 配置文件确认凭据落盘且权限 0600
	cfg, err := config.Load()
	if err != nil || cfg.Active != "e2e" {
		t.Fatalf("配置落盘异常: %v", err)
	}
	info, err := os.Stat(cfgPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("配置文件权限应为 0600: %v", info.Mode())
	}
}

// TestTestInitCustomEnv 验证自定义测试环境初始化：必填参数校验 + 显式域名组配置落盘。
func TestTestInitCustomEnv(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("JXWAF_CONFIG_PATH", filepath.Join(tmp, "config.json"))

	// 1. 必填参数校验：--base-url / --waf-auth / --test-url 缺一不可
	root := newRootCmd()
	root.SetArgs([]string{"test", "init"})
	if err := root.Execute(); err == nil {
		t.Fatal("缺少必填参数应报错")
	}

	// 2. 配置自定义测试环境（显式 --group-name，跳过在线发现）
	out := runCmd(t, nil, "test", "init",
		"--base-url", "http://console.example.com",
		"--waf-auth", "custom-token",
		"--test-url", "http://site.example.com",
		"--group-name", "g1")
	if !strings.Contains(out, "site.example.com") {
		t.Fatalf("test init 输出异常: %s", out)
	}

	// 3. 落盘确认：test 命令组目标切换为自定义环境
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	env, ok := cfg.Environments[cfg.TestName()]
	if !ok || env.BaseURL != "http://console.example.com" ||
		env.WafAuth != "custom-token" || env.TestURL != "http://site.example.com" ||
		env.GroupName != "g1" {
		t.Fatalf("自定义测试环境落盘异常: %+v", cfg.Environments)
	}
}

// runCmd 执行 CLI 命令（进程内），返回 stdout；失败时输出 stderr 并终止测试。
func runCmd(t *testing.T, env []string, args ...string) string {
	t.Helper()
	root := newRootCmd()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("命令 %v 失败: %v; stderr: %s", args, err, errBuf.String())
	}
	return out.String()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
