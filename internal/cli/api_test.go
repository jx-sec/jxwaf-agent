package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/jx-sec/jxwaf-agent/internal/config"
)

// testServer 构造一个模拟管理 API 的 httptest 服务器，返回收到的路径、请求体与请求头。
func testServer(t *testing.T) (*httptest.Server, *struct {
	Path   string
	Body   map[string]any
	Header http.Header
}) {
	t.Helper()
	rec := &struct {
		Path   string
		Body   map[string]any
		Header http.Header
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.Path = r.URL.Path
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec.Body = body
		rec.Header = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"result": true, "message": "ok", "data": map[string]any{"echo": true}})
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func TestCallOpProfessionalTenantInjection(t *testing.T) {
	srv, rec := testServer(t)
	a, err := adapter.New(config.Environment{Version: config.VersionProfessional, BaseURL: srv.URL, WafAuth: "t"})
	if err != nil {
		t.Fatal(err)
	}
	oldGroup := groupFlag
	groupFlag = "g1"
	t.Cleanup(func() { groupFlag = oldGroup })

	resp, err := callOp(a, client.New(srv.URL), adapter.OpWebRuleList, map[string]any{"page": 1})
	if err != nil {
		t.Fatal(err)
	}
	if resp["result"] != true {
		t.Errorf("应返回成功响应: %v", resp)
	}
	if rec.Path != "/admin_api/get_group_web_rule_protection_list" {
		t.Errorf("路径错误: %s", rec.Path)
	}
	if rec.Body["group_name"] != "g1" {
		t.Errorf("应自动注入 group_name: %v", rec.Body)
	}
	if rec.Body["page"].(float64) != 1 {
		t.Errorf("原始参数应保留: %v", rec.Body)
	}
	// 认证头必须真实到达服务端（端到端验证 HeaderMap → client.Post 链路）
	// 头名为中划线 jxwaf-waf-auth：nginx 默认丢弃下划线头，服务端经 http_jxwaf_waf_auth 变量读取
	if rec.Header.Get("jxwaf-waf-auth") != "t" {
		t.Errorf("认证头 jxwaf-waf-auth 未传递或取值错误: %v", rec.Header)
	}
}

func TestCallOpCloudAdminSubUserRequired(t *testing.T) {
	srv, _ := testServer(t)
	a, err := adapter.New(config.Environment{Version: config.VersionCloud, BaseURL: srv.URL, WafAuth: "t"})
	if err != nil {
		t.Fatal(err)
	}
	// 未指定 --sub-user 时应报错干预，而不是发出缺参请求
	if _, err := callOp(a, client.New(srv.URL), adapter.OpWebRuleList, map[string]any{}); err == nil {
		t.Fatal("云WAF主账号调用防护接口必须指定 --sub-user")
	}
}

func TestCallOpBusinessFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"result": false, "message": "waf_auth fail"})
	}))
	t.Cleanup(srv.Close)
	a, _ := adapter.New(config.Environment{Version: config.VersionStandard, BaseURL: srv.URL, WafAuth: "t"})
	_, err := callOp(a, client.New(srv.URL), adapter.OpDomainList, map[string]any{})
	if err == nil {
		t.Fatal("业务失败应返回错误")
	}
	if err.Error() == "" || err.Error()[:15] != "waf_auth fail [" {
		t.Errorf("错误应包含服务端 message 与路径: %q", err)
	}
}

func TestLoadParamsInline(t *testing.T) {
	m, err := loadParams(`{"rule_name":"x"}`)
	if err != nil || m["rule_name"] != "x" {
		t.Errorf("内联 JSON 解析失败: %v %v", m, err)
	}
	if m, err := loadParams(""); err != nil || len(m) != 0 {
		t.Errorf("空值应返回空对象: %v %v", m, err)
	}
	if _, err := loadParams("not-json"); err == nil {
		t.Error("非法 JSON 应报错")
	}
}

func TestLoadParamsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "params.json")
	if err := os.WriteFile(path, []byte(`{"rule_name":"from-file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := loadParams(path)
	if err != nil {
		t.Fatal(err)
	}
	if m["rule_name"] != "from-file" {
		t.Errorf("应按文件路径读取: %v", m)
	}
	// 目录路径不应被当作文件读取成功，也不应崩溃
	if _, err := loadParams(t.TempDir()); err == nil {
		t.Error("目录作为 params 应按内联 JSON 解析失败")
	}
}
