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

func TestGenComponentRejectBitwiseNot(t *testing.T) {
	params := map[string]any{"config": map[string]any{
		"name": "c", "detail": "d", "conf": "{}",
		"code": "local x = ~1\n",
	}}
	if _, err := Generate("component", params); err == nil {
		t.Fatal("按位非 ~ 应被拒绝")
	}
}

func TestGenComponentAcceptNotEqual(t *testing.T) {
	// ~= 是 LuaJIT 标准不等比较，不能误杀
	params := map[string]any{"config": map[string]any{
		"name": "c", "detail": "d", "conf": "{}",
		"code": "local a = 1\nif a ~= 2 then\n  return true\nend\n",
	}}
	if _, err := Generate("component", params); err != nil {
		t.Fatalf("~= 不等比较是合法 LuaJIT 语法: %v", err)
	}
}

func TestGenComponentAcceptStringsAndComments(t *testing.T) {
	// 字符串与注释中的 http://、&、~ 不应触发误杀
	params := map[string]any{"config": map[string]any{
		"name": "c", "detail": "d", "conf": "{}",
		"code": "-- check http://example.com & a~b\nlocal u = \"http://example.com?a=1&b=2\"\n--[[ long comment with | pipe ]]\nlocal s = '&amp;'\nreturn u ~= s\n",
	}}
	if _, err := Generate("component", params); err != nil {
		t.Fatalf("字符串/注释中的 5.2+ token 不应误杀: %v", err)
	}
}

func TestGenRuleMissingDetail(t *testing.T) {
	// rule_detail 声明必填，缺失必须报错（曾因错误被 _ 丢弃而静默放行）
	params := map[string]any{"config": map[string]any{
		"rule_name": "x",
		"rule_matchs": []any{map[string]any{
			"match_args":     []any{map[string]any{"key": "http_args", "value": "path"}},
			"match_operator": "str_eq", "match_value": "x",
		}},
	}}
	if _, err := Generate("web-rule", params); err == nil {
		t.Fatal("缺少必填字段 rule_detail 应报错")
	}
}

func TestGenRuleMissingMatchValue(t *testing.T) {
	// 非 status_check 操作符缺失 match_value 应报错
	params := map[string]any{"config": map[string]any{
		"rule_name":   "x",
		"rule_detail": "x",
		"rule_matchs": []any{map[string]any{
			"match_args":     []any{map[string]any{"key": "http_args", "value": "path"}},
			"match_operator": "rx",
		}},
	}}
	if _, err := Generate("web-rule", params); err == nil {
		t.Fatal("rx 操作符缺少 match_value 应报错")
	}
}

func TestGenTestCaseValidation(t *testing.T) {
	// expect 非 block/pass 应报错
	params := map[string]any{
		"config":     validRuleConfig(),
		"test_cases": []any{map[string]any{"name": "n", "expect": "deny"}},
	}
	if _, err := Generate("web-rule", params); err == nil {
		t.Fatal("非法 expect 应报错")
	}
	// header 值非字符串应报错
	params = map[string]any{
		"config":     validRuleConfig(),
		"test_cases": []any{map[string]any{"header": map[string]any{"X-A": 123}}},
	}
	if _, err := Generate("web-rule", params); err == nil {
		t.Fatal("header 非字符串值应报错")
	}
	// 用例元素非对象应报错
	params = map[string]any{
		"config":     validRuleConfig(),
		"test_cases": []any{"not-an-object"},
	}
	if _, err := Generate("web-rule", params); err == nil {
		t.Fatal("非对象用例元素应报错")
	}
}

func validRuleConfig() map[string]any {
	return map[string]any{
		"rule_name":   "x",
		"rule_detail": "x",
		"rule_matchs": []any{map[string]any{
			"match_args":     []any{map[string]any{"key": "http_args", "value": "query_string"}},
			"match_operator": "rx", "match_value": "union.*select",
		}},
	}
}

func TestGenFlowWhite(t *testing.T) {
	r, err := Generate("flow-white", map[string]any{"config": validRuleConfig()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Op != "flow_white_create" {
		t.Errorf("flow-white 操作名错误: %s", r.Op)
	}
	if CreateToDelete()["flow_white_create"] != "flow_white_delete" {
		t.Errorf("flow-white 应有对应自动清理操作")
	}
}

func TestGenNameListStructureValidation(t *testing.T) {
	// name_list_rule 为扁平 [{key,value}] 数组：未知 key 应报错
	params := map[string]any{"config": map[string]any{
		"name_list_name":   "n",
		"name_list_detail": "d",
		"name_list_rule":   []any{map[string]any{"key": "http_args", "value": "src_ip"}},
		"name_list_action": "block", "name_list_expire": "false",
	}}
	r, err := Generate("name-list", params)
	if err != nil {
		t.Fatalf("扁平 [{key,value}] 结构应通过校验: %v", err)
	}
	assertStr(t, `[{"key":"http_args","value":"src_ip"}]`, r.Config["name_list_rule"])
	// 未知 key 报错
	params["config"].(map[string]any)["name_list_rule"] = []any{map[string]any{"key": "bad_key", "value": "x"}}
	if _, err := Generate("name-list", params); err == nil {
		t.Fatal("name_list_rule 未知 key 应报错")
	}
	// rule_matchs 式结构（含 match_operator）应报错
	params["config"].(map[string]any)["name_list_rule"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "http_args", "value": "src_ip"}},
		"match_operator": "str_eq", "match_value": "x",
	}}
	if _, err := Generate("name-list", params); err == nil {
		t.Fatal("name_list_rule 不接受 rule_matchs 式结构")
	}
	// expire_time 非正整数应报错
	params["config"].(map[string]any)["name_list_rule"] = []any{map[string]any{"key": "http_args", "value": "src_ip"}}
	params["config"].(map[string]any)["name_list_expire"] = "true"
	params["config"].(map[string]any)["name_list_expire_time"] = "abc"
	if _, err := Generate("name-list", params); err == nil {
		t.Fatal("expire_time 非正整数应报错")
	}
}

func TestGenNameListActionEnum(t *testing.T) {
	base := func(action, av string) map[string]any {
		return map[string]any{"config": map[string]any{
			"name_list_name": "n", "name_list_detail": "d",
			"name_list_rule":   []any{map[string]any{"key": "http_args", "value": "src_ip"}},
			"name_list_action": action, "action_value": av,
			"name_list_expire": "false",
		}}
	}
	// 放行类动作合法
	for _, action := range []string{"all_bypass", "web_bypass", "flow_bypass", "reject_response", "watch"} {
		if _, err := Generate("name-list", base(action, "")); err != nil {
			t.Fatalf("name_list_action=%s 应合法: %v", action, err)
		}
	}
	// network_block 需要封禁秒数
	if _, err := Generate("name-list", base("network_block", "600")); err != nil {
		t.Fatalf("network_block+秒数 应合法: %v", err)
	}
	if _, err := Generate("name-list", base("network_block", "")); err == nil {
		t.Fatal("network_block 缺少秒数应报错")
	}
	// bot_check 需要人机识别方式
	if _, err := Generate("name-list", base("bot_check", "slipper")); err != nil {
		t.Fatalf("bot_check+slipper 应合法: %v", err)
	}
	// 非法动作（直觉上的 pass 不存在）
	if _, err := Generate("name-list", base("pass", "")); err == nil {
		t.Fatal("name_list_action=pass 应报错（放行类为 all_bypass/web_bypass/flow_bypass）")
	}
}

func TestGenWhiteRuleActions(t *testing.T) {
	// web-white：放行动作为 web_bypass，watch 合法，block 非法
	cfg := validRuleConfig()
	cfg["rule_action"] = "web_bypass"
	if _, err := Generate("web-white", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("web-white 的 web_bypass 应合法: %v", err)
	}
	cfg["rule_action"] = "block"
	if _, err := Generate("web-white", map[string]any{"config": cfg}); err == nil {
		t.Fatal("web-white 不应接受 block")
	}
	// flow-white：放行动作为 flow_bypass
	cfg["rule_action"] = "flow_bypass"
	if _, err := Generate("flow-white", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("flow-white 的 flow_bypass 应合法: %v", err)
	}
	// 白名单类型默认用例 expect=pass（命中即放行）
	cfg["rule_action"] = ""
	r, err := Generate("web-white", map[string]any{"config": cfg})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.TestCases) == 0 || r.TestCases[0].Expect != "pass" {
		t.Errorf("白名单默认用例应为 pass: %v", r.TestCases)
	}
}

func TestGenRuleMatchArgsValueSemantics(t *testing.T) {
	// global_name_list_result 的 value 为名单名（任意非空），不再是 default
	cfg := validRuleConfig()
	cfg["rule_matchs"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "global_name_list_result", "value": "malicious_ip"}},
		"args_prepocess": []any{"none"},
		"match_operator": "status_check", "match_value": "exist",
	}}
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("名单联动（value=名单名）应合法: %v", err)
	}
	// header_args 的 value 为自定义头名（任意非空）
	cfg["rule_matchs"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "header_args", "value": "X-Custom-Header"}},
		"args_prepocess": []any{"none"},
		"match_operator": "str_eq", "match_value": "v",
	}}
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("header_args 自定义头名应合法: %v", err)
	}
	// http_args 的 value 仍为固定枚举
	cfg["rule_matchs"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "http_args", "value": "bad_value"}},
		"args_prepocess": []any{"none"},
		"match_operator": "str_eq", "match_value": "v",
	}}
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err == nil {
		t.Fatal("http_args 非法枚举值应报错")
	}
}

func TestGenWebRuleActionEnum(t *testing.T) {
	// web 规则节点引擎分支仅 block/watch/reject_response（bot_check 静默不生效，必须拒绝）
	cfg := validRuleConfig()
	cfg["rule_action"] = "bot_check"
	cfg["action_value"] = "auto"
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err == nil {
		t.Fatal("web-rule 不支持 bot_check（节点无该分支，会静默不生效）")
	}
	cfg["rule_action"] = "reject_response"
	cfg["action_value"] = ""
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("web-rule 应支持 reject_response: %v", err)
	}
}

func TestGenRuleEngineExtendedEnums(t *testing.T) {
	// 对齐节点引擎补齐的枚举：http_args 新增 7 值 / 顶层 string key / ip_in_cidr(s) 运算符 / type 预处理
	cfg := validRuleConfig()
	cfg["rule_matchs"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "http_args", "value": "high_risk_header"}},
		"args_prepocess": []any{"none"},
		"match_operator": "rx", "match_value": "union.*select",
	}}
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("http_args=high_risk_header 应合法: %v", err)
	}
	cfg["rule_matchs"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "http_args", "value": "raw_header_no_referer"}},
		"args_prepocess": []any{"type"},
		"match_operator": "str_eq", "match_value": "string",
	}}
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("http_args=raw_header_no_referer + type 预处理应合法: %v", err)
	}
	cfg["rule_matchs"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "http_args", "value": "src_ip"}},
		"args_prepocess": []any{"none"},
		"match_operator": "ip_in_cidrs", "match_value": "10.0.0.0/8,192.168.0.0/16",
	}}
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("ip_in_cidrs 运算符应合法: %v", err)
	}
	cfg["rule_matchs"] = []any{map[string]any{
		"match_args":     []any{map[string]any{"key": "string", "value": "const_stat_key"}},
		"args_prepocess": []any{"none"},
		"match_operator": "str_eq", "match_value": "const_stat_key",
	}}
	if _, err := Generate("web-rule", map[string]any{"config": cfg}); err != nil {
		t.Fatalf("string 常量 key 应合法: %v", err)
	}
}

func TestGenDomainConditionalFields(t *testing.T) {
	// https=false 时 ssl_domain 非必填，但键必须输出（服务端无条件检查键存在）
	params := map[string]any{"config": map[string]any{
		"domain": "www.example.com", "detail": "d", "http": "true", "https": "false",
		"source_ip":        []any{"1.2.3.4"},
		"source_http_port": "80", "origin_protocol": "http", "balance_type": "round_robin",
		"pre_proxy": "false", "real_ip_conf": "XFF",
		"connect_timeout": "5", "send_timeout": "5", "read_timeout": "5",
	}}
	r, err := Generate("domain", params)
	if err != nil {
		t.Fatalf("https=false 不应强制 ssl_domain: %v", err)
	}
	if v, ok := r.Config["ssl_domain"]; !ok || v != "" {
		t.Errorf("ssl_domain 键应存在且为空串: %v", r.Config["ssl_domain"])
	}
	// https=false 时 source_https_port 缺省也必须填 443（不流空白）
	assertStr(t, "443", r.Config["source_https_port"])
	// 显式指定时不覆盖
	params["config"].(map[string]any)["source_https_port"] = "8443"
	if r, err = Generate("domain", params); err != nil {
		t.Fatal(err)
	}
	assertStr(t, "8443", r.Config["source_https_port"])
	params["config"].(map[string]any)["source_https_port"] = ""
	// http/https 同时 false 应报错
	params["config"].(map[string]any)["http"] = "false"
	if _, err := Generate("domain", params); err == nil {
		t.Fatal("http/https 同时为 false 应报错")
	}
	// https=true 时 ssl_domain 必填非空
	params["config"].(map[string]any)["http"] = "true"
	params["config"].(map[string]any)["https"] = "true"
	if _, err := Generate("domain", params); err == nil {
		t.Fatal("https=true 缺少 ssl_domain 应报错")
	}
	// https=true 且提供 ssl_domain：source_https_port 缺省默认 443
	params["config"].(map[string]any)["ssl_domain"] = "www.example.com"
	r, err = Generate("domain", params)
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "443", r.Config["source_https_port"])
	// 端口非正整数应报错
	params["config"].(map[string]any)["source_https_port"] = "abc"
	if _, err := Generate("domain", params); err == nil {
		t.Fatal("端口非正整数应报错")
	}
}

func TestGenDomainSourceIPStringify(t *testing.T) {
	params := map[string]any{"config": map[string]any{
		"domain": "www.example.com", "detail": "测试站点", "http": "true", "https": "false",
		"ssl_domain": "", "source_ip": []any{"1.2.3.4", "origin.example.com"},
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
	if r.Config["detail"] != "测试站点" {
		t.Errorf("detail 应纳入输出: %v", r.Config["detail"])
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
		"filter": "true", "entity": []any{map[string]any{"key": "http_args", "value": "src_ip"}},
		"stat_time": 60, "exceed_count": 100, "block_time": 600,
	}}
	r, err := Generate("flow-rule", params)
	if err != nil {
		t.Fatal(err)
	}
	var entity []map[string]any
	if err := json.Unmarshal([]byte(mustStr(r.Config["entity"])), &entity); err != nil || len(entity) != 1 || entity[0]["key"] != "http_args" {
		t.Errorf("entity 应为 [{key,value}] JSON 字符串: %v %v", r.Config["entity"], err)
	}
	assertStr(t, "60", r.Config["stat_time"])
	assertStr(t, "100", r.Config["exceed_count"])
	// 旧式纯字符串数组（如 ["src_ip"]）应报错并提示正确结构
	params["config"].(map[string]any)["entity"] = []any{"src_ip"}
	if _, err := Generate("flow-rule", params); err == nil {
		t.Fatal("旧式 entity 结构应报错（需 [{key,value}]）")
	}
	// network_block 动作：action_value 为封禁秒数
	params["config"].(map[string]any)["entity"] = []any{map[string]any{"key": "http_args", "value": "src_ip"}}
	params["config"].(map[string]any)["rule_action"] = "network_block"
	params["config"].(map[string]any)["action_value"] = "600"
	if _, err := Generate("flow-rule", params); err != nil {
		t.Fatalf("flow network_block 应为合法动作: %v", err)
	}
	params["config"].(map[string]any)["action_value"] = "abc"
	if _, err := Generate("flow-rule", params); err == nil {
		t.Fatal("network_block 的 action_value 需为正整数秒数")
	}
}

func assertStr(t *testing.T, want string, got any) {
	t.Helper()
	s, _ := got.(string)
	if s != want {
		t.Errorf("期望 %q，实际 %v", want, s)
	}
}
