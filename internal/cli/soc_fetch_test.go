package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseLastSpan(t *testing.T) {
	cases := []struct {
		in      string
		want    string // 期望 duration 字符串；错误时为空
		wantErr bool
	}{
		{"30s", "30s", false},
		{"15m", "15m0s", false},
		{"24h", "24h0m0s", false},
		{"7d", "168h0m0s", false},
		{"", "", true},
		{"24", "", true},
		{"h", "", true},
		{"0h", "", true},
		{"-5m", "", true},
		{"5w", "", true},
		{"1.5h", "", true},
	}
	for _, c := range cases {
		d, err := parseLastSpan(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseLastSpan(%q) 应报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseLastSpan(%q) 意外报错: %v", c.in, err)
			continue
		}
		if d.String() != c.want {
			t.Errorf("parseLastSpan(%q) = %s, want %s", c.in, d, c.want)
		}
	}
}

func TestSocLogRecordsExtraction(t *testing.T) {
	// 专业版/标准版：message 为数组
	prof := map[string]any{"result": true, "message": []any{map[string]any{"a": 1}}, "total_count": float64(5)}
	if got := len(socLogRecords(prof)); got != 1 {
		t.Errorf("message 数组提取异常: %d", got)
	}
	if n, ok := socLogTotal(prof); !ok || n != 5 {
		t.Errorf("total_count 提取异常: %d %v", n, ok)
	}
	// 云WAF：records 为数组，total_records
	cloud := map[string]any{"result": true, "records": []any{map[string]any{"a": 1}, map[string]any{"b": 2}}, "total_records": float64(2)}
	if got := len(socLogRecords(cloud)); got != 2 {
		t.Errorf("records 数组提取异常: %d", got)
	}
	if n, ok := socLogTotal(cloud); !ok || n != 2 {
		t.Errorf("total_records 提取异常: %d %v", n, ok)
	}
	// message 为字符串（普通业务响应）：不应误提取
	plain := map[string]any{"result": true, "message": "success"}
	if got := socLogRecords(plain); got != nil {
		t.Errorf("字符串 message 不应被提取: %v", got)
	}
}

func TestValidateSqlRules(t *testing.T) {
	ok := []any{map[string]any{"field": "src_ip", "operation": "equals", "value": "1.2.3.4"}}
	if err := validateSqlRules(ok); err != nil {
		t.Errorf("合法 sql_rules 不应报错: %v", err)
	}
	badField := []any{map[string]any{"field": "evil; DROP TABLE", "operation": "equals", "value": "1"}}
	if err := validateSqlRules(badField); err == nil {
		t.Error("白名单外 field 应报错")
	}
	badOp := []any{map[string]any{"field": "host", "operation": "regex", "value": "1"}}
	if err := validateSqlRules(badOp); err == nil {
		t.Error("非法 operation 应报错")
	}
	missValue := []any{map[string]any{"field": "host", "operation": "equals"}}
	if err := validateSqlRules(missValue); err == nil {
		t.Error("缺 value 应报错")
	}
}

func TestProjectRecords(t *testing.T) {
	recs := []any{
		map[string]any{"host": "a.com", "src_ip": "1.1.1.1", "raw_body": "xxxx"},
		map[string]any{"host": "b.com", "src_ip": "2.2.2.2", "raw_body": "yyyy"},
	}
	got := projectRecords(recs, []string{"host", "src_ip"})
	for i, r := range got {
		m := r.(map[string]any)
		if _, exists := m["raw_body"]; exists {
			t.Errorf("记录 %d 应已裁剪 raw_body", i)
		}
		if m["host"] == nil || m["src_ip"] == nil {
			t.Errorf("记录 %d 保留字段缺失", i)
		}
	}
	// 空 fields：原样返回
	if got := projectRecords(recs, nil); len(got) != 2 {
		t.Errorf("空 fields 应原样返回")
	}
}

// TestSocLogFetchE2E 模拟专业版管理 API（message 数组 + total_pages）验证：
// 自动翻页合并、字段投影、last 相对时间展开、max_records 截断。
func TestSocLogFetchE2E(t *testing.T) {
	pages := map[string][]map[string]any{
		"1": {
			{"host": "a.com", "src_ip": "1.1.1.1", "waf_action": "block"},
			{"host": "a.com", "src_ip": "1.1.1.1", "waf_action": "watch"},
		},
		"2": {
			{"host": "b.com", "src_ip": "2.2.2.2", "waf_action": "pass"},
		},
	}
	var gotFrom, gotTo string
	mux := http.NewServeMux()
	mux.HandleFunc("/admin_api/get_soc_log_query_list", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		page := "1"
		if f, ok := body["page"].(float64); ok {
			page = strconv.Itoa(int(f))
		}
		gotFrom, _ = body["from_time"].(string)
		gotTo, _ = body["to_time"].(string)
		writeJSON(w, map[string]any{
			"result": true, "message": pages[page],
			"total_count": 3, "total_pages": 2, "now_page": page,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	tmp := t.TempDir()
	t.Setenv("JXWAF_CONFIG_PATH", filepath.Join(tmp, "config.json"))
	runCmd(t, nil, "config", "set", "--name", "fetch", "--version", "professional",
		"--base-url", srv.URL, "--waf-auth", "token", "--group-name", "g1")

	// 1. 自动翻页 + 字段投影
	out := runCmd(t, nil, "soc", "log", "fetch", "--env", "fetch", "--params",
		`{"last":"1h","fields":["host","waf_action"]}`)
	var res struct {
		Fetched      int `json:"fetched"`
		TotalCount   int `json:"total_count"`
		PagesQueried int `json:"pages_queried"`
		Truncated    bool `json:"truncated"`
		Records      []map[string]any `json:"records"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("输出解析失败: %v\n%s", err, out)
	}
	if res.Fetched != 3 || res.TotalCount != 3 || res.PagesQueried != 2 || res.Truncated {
		t.Fatalf("翻页合并异常: fetched=%d total=%d pages=%d truncated=%v\n%s", res.Fetched, res.TotalCount, res.PagesQueried, res.Truncated, out)
	}
	for _, r := range res.Records {
		if _, exists := r["src_ip"]; exists {
			t.Errorf("投影后不应包含 src_ip: %v", r)
		}
	}
	if gotFrom == "" || gotTo == "" || gotFrom >= gotTo {
		t.Errorf("last 展开异常: from=%s to=%s", gotFrom, gotTo)
	}

	// 2. max_records 截断
	out = runCmd(t, nil, "soc", "log", "fetch", "--env", "fetch", "--params",
		`{"last":"1h","max_records":2}`)
	var res2 struct {
		Fetched   int  `json:"fetched"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(out), &res2); err != nil {
		t.Fatalf("输出解析失败: %v", err)
	}
	if res2.Fetched != 2 || !res2.Truncated {
		t.Fatalf("max_records 截断异常: %s", out)
	}

	// 3. last 与 from_time 互斥
	root := newRootCmd()
	root.SetArgs([]string{"soc", "log", "fetch", "--env", "fetch", "--params", `{"last":"1h","from_time":"x"}`})
	if err := root.Execute(); err == nil {
		t.Fatal("last 与 from_time 同时指定应报错")
	}

	// 4. 白名单外字段
	root = newRootCmd()
	root.SetArgs([]string{"soc", "log", "fetch", "--env", "fetch", "--params",
		`{"last":"1h","sql_rules":[{"field":"evil","operation":"equals","value":"1"}]}`})
	if err := root.Execute(); err == nil {
		t.Fatal("白名单外 field 应报错")
	}
}
