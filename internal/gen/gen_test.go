package gen

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestGenWebRule(t *testing.T) {
	params := map[string]any{
		"config": map[string]any{
			"rule_name":   "block_sql",
			"rule_detail": "拦截SQL注入",
			"rule_matchs": []any{
				map[string]any{
					"match_args":     []any{map[string]any{"key": "http_args", "value": "query_string"}},
					"args_prepocess": []any{"none"},
					"match_operator": "rx",
					"match_value":    "union.*select",
				},
			},
			// 未指定 rule_action：应默认 watch（观察优先）
		},
		"test_cases": []any{
			map[string]any{"name": "攻击", "path": "/", "query": "id=1 union select 1", "expect": "block"},
			map[string]any{"name": "正常", "path": "/", "query": "id=1", "expect": "pass"},
		},
	}
	r, err := Generate("web-rule", params)
	if err != nil {
		t.Fatal(err)
	}
	if r.Op != "web_rule_create" {
		t.Errorf("op 错误: %s", r.Op)
	}
	cfg := r.Config
	if cfg["rule_action"] != "watch" {
		t.Errorf("未指定动作应默认 watch，实际 %v", cfg["rule_action"])
	}
	// rule_matchs 必须输出 JSON 字符串
	var conds []map[string]any
	if err := json.Unmarshal([]byte(mustStr(cfg["rule_matchs"])), &conds); err != nil || len(conds) != 1 {
		t.Errorf("rule_matchs 应为合法 JSON 字符串: %v %v", cfg["rule_matchs"], err)
	}
	if len(r.TestCases) != 2 {
		t.Errorf("应回显 2 个用例: %v", r.TestCases)
	}
}

func TestGenWebRuleInvalidOperator(t *testing.T) {
	params := map[string]any{"config": map[string]any{
		"rule_name":   "x",
		"rule_detail": "x",
		"rule_matchs": []any{map[string]any{
			"match_args":     []any{map[string]any{"key": "http_args", "value": "path"}},
			"args_prepocess": []any{"none"},
			"match_operator": "regexp_bad",
			"match_value":    "x",
		}},
		"rule_action": "block",
	}}
	if _, err := Generate("web-rule", params); err == nil {
		t.Fatal("非法操作符应报错")
	}
}

func TestGenComponentBase64(t *testing.T) {
	lua := `local function check()
    return bit.band(1, 1)
end
`
	params := map[string]any{"config": map[string]any{
		"name":   "comp1",
		"detail": "测试组件",
		"code":   lua,
		"conf":   `{"key":"value"}`,
	}}
	r, err := Generate("component", params)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(mustStr(r.Config["code"]))
	if err != nil || string(decoded) != lua {
		t.Errorf("code 应 base64 编码后与原文一致: %v", err)
	}
}

func TestGenComponentRejectLua52(t *testing.T) {
	params := map[string]any{"config": map[string]any{
		"name":   "c",
		"detail": "d",
		"code":   "local x = 1 // 2\ngoto skip\n::skip::\n",
		"conf":   "",
	}}
	if _, err := Generate("component", params); err == nil {
		t.Fatal("Lua 5.2+ 语法应被拒绝")
	}
}

func TestGenDomainSourceIPStringify(t *testing.T) {
	params := map[string]any{"config": map[string]any{
		"domain": "www.example.com", "http": "true", "https": "false",
		"ssl_domain": "www.example.com", "source_ip": []any{"1.2.3.4", "origin.example.com"},
		"source_http_port": "80", "source_https_port": "443",
		"origin_protocol": "http", "balance_type": "round_robin",
		"pre_proxy": "false", "real_ip_conf": "XFF",
		"connect_timeout": "5", "send_timeout": "5", "read_timeout": "5",
	}}
	r, err := Generate("domain", params)
	if err != nil {
		t.Fatal(err)
	}
	var ips []string
	if err := json.Unmarshal([]byte(mustStr(r.Config["source_ip"])), &ips); err != nil || len(ips) != 2 {
		t.Errorf("source_ip 应为 JSON 数组字符串: %v %v", r.Config["source_ip"], err)
	}
}

func TestGenFlowRuleFrequency(t *testing.T) {
	params := map[string]any{"config": map[string]any{
		"rule_name": "flow_limit", "rule_detail": "限速",
		"rule_matchs": []any{map[string]any{
			"match_args":     []any{map[string]any{"key": "http_args", "value": "method"}},
			"args_prepocess": []any{"none"},
			"match_operator": "str_eq", "match_value": "GET",
		}},
		"rule_action": "block", "action_value": "",
		"filter": "true", "entity": []any{"src_ip"},
		"stat_time": 60, "exceed_count": 100, "block_time": 600,
	}}
	r, err := Generate("flow-rule", params)
	if err != nil {
		t.Fatal(err)
	}
	var entity []string
	if err := json.Unmarshal([]byte(mustStr(r.Config["entity"])), &entity); err != nil {
		t.Errorf("entity 应为 JSON 字符串: %v", r.Config["entity"])
	}
	assertStr(t, "60", r.Config["stat_time"])
	assertStr(t, "100", r.Config["exceed_count"])
}

func assertStr(t *testing.T, want string, got any) {
	t.Helper()
	s, _ := got.(string)
	if s != want {
		t.Errorf("期望 %q，实际 %v", want, s)
	}
}
