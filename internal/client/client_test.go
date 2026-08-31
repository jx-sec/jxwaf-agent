package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPostSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("应使用 POST，实际 %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("应设置 JSON Content-Type: %v", r.Header)
		}
		if r.Header.Get("x-auth") != "secret" {
			t.Errorf("自定义头应透传: %v", r.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["page"] != float64(1) {
			t.Errorf("请求体应为 JSON: %v %v", body, err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": true, "message": "ok"})
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL).Post("/admin_api/get_domain_list", map[string]string{"x-auth": "secret"}, map[string]any{"page": 1})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Result {
		t.Errorf("result=true 应判定成功: %+v", resp)
	}
}

func TestPostBusinessFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": false, "message": "waf_auth fail"})
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL).Post("/x", nil, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Result || resp.Message != "waf_auth fail" {
		t.Errorf("result=false 应判定失败: %+v", resp)
	}
}

func TestPostHTTPErrorStatusFailSafe(t *testing.T) {
	// 非 2xx 且 body 无 result 字段：旧实现会误判成功（fail-open），新实现必须失败
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 401, "msg": "unauthorized"})
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL).Post("/x", nil, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Result {
		t.Errorf("HTTP 401 应判定失败（fail-safe）: %+v", resp)
	}
	if !strings.Contains(resp.Message, "401") {
		t.Errorf("错误信息应包含状态码: %q", resp.Message)
	}
}

func TestPostHTML404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>404 Not Found</html>"))
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL).Post("/x", nil, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Result {
		t.Errorf("404 HTML 错误页应判定失败: %+v", resp)
	}
}

func TestPostMissingResultFieldFailSafe(t *testing.T) {
	// 200 但响应缺少 result 字段：无法确认成功，应按失败处理
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"echo": true}})
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL).Post("/x", nil, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Result {
		t.Errorf("缺少 result 字段应判定失败（fail-safe）: %+v", resp)
	}
	if !strings.Contains(resp.Message, "result") {
		t.Errorf("错误信息应说明缺少 result 字段: %q", resp.Message)
	}
}

func TestPostNonJSON200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain text"))
	}))
	t.Cleanup(srv.Close)

	resp, err := New(srv.URL).Post("/x", nil, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Result {
		t.Errorf("非 JSON 响应应判定失败: %+v", resp)
	}
}

func TestNewTrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"result": true})
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL + "/")
	if c.BaseURL != srv.URL {
		t.Errorf("尾斜杠应被规范化: %q", c.BaseURL)
	}
	if _, err := c.Post("/admin_api/x", nil, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/admin_api/x" {
		t.Errorf("路径拼接不应产生双斜杠: %q", gotPath)
	}
}

func TestPostNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // 立即关闭制造连接失败

	_, err := New(srv.URL).Post("/x", nil, map[string]any{})
	if err == nil {
		t.Fatal("网络错误应返回 error")
	}
	if !strings.Contains(err.Error(), "base_url") {
		t.Errorf("网络错误信息应包含排查指引: %v", err)
	}
}

func TestTruncateUTF8Boundary(t *testing.T) {
	s := "中文payload"
	// 前 4 字节恰在多字节字符中间，截断应回退到字符边界
	got := truncate([]byte(s), 4)
	if !strings.HasPrefix(s, strings.TrimSuffix(got, "...")) {
		t.Errorf("截断结果不应产生半个字符: %q", got)
	}
}
