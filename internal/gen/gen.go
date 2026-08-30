// Package gen 实现配置生成：语义参数 → 规范化请求体（JSON 字符串字段、Base64、枚举校验全部收敛到代码）。
package gen

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Result 为 generate 的统一输出结构。
type Result struct {
	Type      string         `json:"type"`       // 生成类型：web-rule / web-white / flow-rule / name-list / component / domain
	Op        string         `json:"op"`         // 对应的逻辑操作名（写入命令使用）
	Config    map[string]any `json:"config"`     // 规范化请求体（可直接用于下发）
	Preview   string         `json:"preview"`    // 语义摘要（供向用户展示）
	TestCases []TestCase     `json:"test_cases"` // 验证用例（回显或默认生成）
}

// TestCase 为验证用例：attack 期望拦截（expect=block），normal 期望放行（expect=pass）。
type TestCase struct {
	Name   string            `json:"name"`
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Query  string            `json:"query,omitempty"`
	Body   string            `json:"body,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	Expect string            `json:"expect"` // block / pass
}

// 生成类型与逻辑操作的映射。
var typeOp = map[string]string{
	"web-rule":  "web_rule_create",
	"web-white": "web_white_create",
	"flow-rule": "flow_rule_create",
	"name-list": "name_list_create",
	"component": "component_create",
	"domain":    "domain_create",
}

// Generate 是统一入口：params 含可选 config 与 test_cases 两节。
func Generate(gtype string, params map[string]any) (*Result, error) {
	op, ok := typeOp[gtype]
	if !ok {
		return nil, fmt.Errorf("未知生成类型 %q，支持: %v", gtype, Types())
	}
	cfg, _ := asMap(params["config"])
	switch gtype {
	case "web-rule", "web-white":
		return gRule(gtype, op, cfg, params)
	case "flow-rule":
		return gFlowRule(gtype, op, cfg, params)
	case "name-list":
		return gNameList(gtype, op, cfg, params)
	case "component":
		return gComponent(gtype, op, cfg, params)
	case "domain":
		return gDomain(gtype, op, cfg, params)
	}
	return nil, fmt.Errorf("生成类型 %q 未实现", gtype)
}

// Types 返回支持的生成类型列表。
func Types() []string {
	ts := make([]string, 0, len(typeOp))
	for t := range typeOp {
		ts = append(ts, t)
	}
	sort.Strings(ts)
	return ts
}

// ---- 通用工具 ----

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func asStr(v any, required bool, field string) (string, error) {
	switch s := v.(type) {
	case string:
		if required && s == "" {
			return "", fmt.Errorf("缺少必填字段 %s", field)
		}
		return s, nil
	case float64, int, int64:
		return strconv.FormatFloat(toFloat(v), 'f', -1, 64), nil
	case nil:
		if required {
			return "", fmt.Errorf("缺少必填字段 %s", field)
		}
		return "", nil
	default:
		b, err := json.Marshal(v)
		return string(b), err
	}
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

// toJSON 将数组/对象序列化为 JSON 字符串；字符串原样透传。
func toJSON(v any, required bool, field string) (string, error) {
	switch s := v.(type) {
	case string:
		if required && strings.TrimSpace(s) == "" {
			return "", fmt.Errorf("缺少必填字段 %s", field)
		}
		var probe any
		if err := json.Unmarshal([]byte(s), &probe); err != nil && required {
			return "", fmt.Errorf("字段 %s 需为 JSON: %w", field, err)
		}
		return s, nil
	case nil:
		if required {
			return "", fmt.Errorf("缺少必填字段 %s", field)
		}
		return "", nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("字段 %s 序列化失败: %w", field, err)
		}
		return string(b), nil
	}
}

func oneOf(v, field string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("字段 %s 取值 %q 非法，允许: %v", field, v, allowed)
}

// ---- Web 规则 / Web 白名单 ----

func gRule(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	ruleName, err := asStr(cfg["rule_name"], true, "rule_name")
	if err != nil {
		return nil, err
	}
	detail, _ := asStr(cfg["rule_detail"], true, "rule_detail")
	matchs, err := matchsField(cfg["rule_matchs"])
	if err != nil {
		return nil, err
	}
	action, err := asStr(cfg["rule_action"], false, "rule_action")
	if err != nil {
		return nil, err
	}
	// 观察优先红线：未指定动作时默认 watch
	if action == "" {
		action = "watch"
	}
	if err := oneOf(action, "rule_action", "block", "watch", "bot_check"); err != nil {
		return nil, err
	}
	av, _ := asStr(cfg["action_value"], false, "action_value")
	if action == "bot_check" {
		if err := oneOf(av, "action_value", "auto", "slipper", "puzzle", "words"); err != nil {
			return nil, err
		}
	} else if av != "" {
		return nil, fmt.Errorf("仅 bot_check 动作需要 action_value")
	}
	config := map[string]any{
		"rule_name":    ruleName,
		"rule_detail":  detail,
		"rule_matchs":  matchs,
		"rule_action":  action,
		"action_value": av,
	}
	cond := firstMatchSummary(matchs)
	r := &Result{
		Type:      gtype,
		Op:        op,
		Config:    config,
		Preview:   fmt.Sprintf("%s：%s（动作 %s，%s）", ruleTypeName(gtype), detail, actionText(action, av), cond),
		TestCases: extractTestCases(params, matchs),
	}
	return r, nil
}

// matchsField 将 rule_matchs（数组或 JSON 字符串）规范化为 JSON 字符串并校验结构。
func matchsField(v any) (string, error) {
	raw, err := toJSON(v, true, "rule_matchs")
	if err != nil {
		return "", err
	}
	var conds []map[string]any
	if err := json.Unmarshal([]byte(raw), &conds); err != nil {
		return "", fmt.Errorf("字段 rule_matchs 需为匹配条件数组: %w", err)
	}
	if len(conds) == 0 {
		return "", fmt.Errorf("rule_matchs 至少需要一个匹配条件")
	}
	for i, c := range conds {
		if err := checkMatchCond(i, c); err != nil {
			return "", err
		}
	}
	return raw, nil
}

// 匹配参数 key 与 value 的合法组合。
var argValueOf = map[string][]string{
	"http_args":               {"path", "query_string", "method", "src_ip", "raw_body", "version", "scheme", "raw_header"},
	"header_args":             {"host", "cookie", "referer", "user_agent", "default"},
	"cookie_args":             {"default"},
	"uri_args":                {"default"},
	"post_args":               {"default"},
	"json_post_args":          {"default"},
	"ctx_args":                {"default"},
	"global_name_list_result": {"default"},
}

var prepocessSet = map[string]bool{
	"none": true, "lowerCase": true, "base64Decode": true, "length": true,
	"uriDecode": true, "uniDecode": true, "hexDecode": true,
}

var operatorSet = map[string]bool{
	"rx": true, "str_prefix": true, "str_suffix": true, "str_contain": true,
	"str_ncontain": true, "str_eq": true, "str_neq": true, "gt": true, "lt": true,
	"eq": true, "neq": true, "status_check": true,
}

func checkMatchCond(i int, c map[string]any) error {
	args, ok := c["match_args"].([]any)
	if !ok || len(args) == 0 {
		return fmt.Errorf("匹配条件[%d]缺少 match_args（需为数组）", i)
	}
	for _, a := range args {
		am, ok := a.(map[string]any)
		if !ok {
			return fmt.Errorf("匹配条件[%d] match_args 元素需为对象", i)
		}
		key, _ := am["key"].(string)
		vals, known := argValueOf[key]
		if !known {
			return fmt.Errorf("匹配条件[%d] 未知参数大类 %q", i, key)
		}
		val, _ := am["value"].(string)
		valid := false
		for _, allow := range vals {
			if val == allow {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("匹配条件[%d] key=%s 的 value %q 非法，允许: %v", i, key, val, vals)
		}
	}
	for _, p := range toStrSlice(c["args_prepocess"]) {
		if !prepocessSet[p] {
			return fmt.Errorf("匹配条件[%d] 未知预处理 %q", i, p)
		}
	}
	op, _ := c["match_operator"].(string)
	if op == "" {
		return fmt.Errorf("匹配条件[%d] 缺少 match_operator", i)
	}
	if !operatorSet[op] {
		return fmt.Errorf("匹配条件[%d] 未知操作符 %q", i, op)
	}
	if op == "status_check" {
		v, _ := c["match_value"].(string)
		if v != "exist" && v != "no_exist" {
			return fmt.Errorf("匹配条件[%d] status_check 的 match_value 需为 exist/no_exist", i)
		}
	}
	return nil
}

func toStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---- Flow 规则 ----

func gFlowRule(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	r, err := gRule(gtype, op, cfg, params)
	if err != nil {
		return nil, err
	}
	filter, err := asStr(cfg["filter"], true, "filter")
	if err != nil {
		return nil, err
	}
	if err := oneOf(filter, "filter", "true", "false"); err != nil {
		return nil, err
	}
	entity, err := toJSON(cfg["entity"], true, "entity")
	if err != nil {
		return nil, err
	}
	statTime, err := asStr(cfg["stat_time"], true, "stat_time")
	if err != nil {
		return nil, err
	}
	exceedCount, err := asStr(cfg["exceed_count"], true, "exceed_count")
	if err != nil {
		return nil, err
	}
	blockTime, err := asStr(cfg["block_time"], true, "block_time")
	if err != nil {
		return nil, err
	}
	r.Config["filter"] = filter
	r.Config["entity"] = entity
	r.Config["stat_time"] = statTime
	r.Config["exceed_count"] = exceedCount
	r.Config["block_time"] = blockTime
	r.Preview = fmt.Sprintf("流量规则：%s（动作 %s，%s 秒内超 %s 次封禁 %s 秒）",
		r.Config["rule_detail"], actionText(mustStr(r.Config["rule_action"]), mustStr(r.Config["action_value"])),
		statTime, exceedCount, blockTime)
	return r, nil
}

// ---- 全局名单 ----

func gNameList(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	name, err := asStr(cfg["name_list_name"], true, "name_list_name")
	if err != nil {
		return nil, err
	}
	detail, _ := asStr(cfg["name_list_detail"], true, "name_list_detail")
	rule, err := toJSON(cfg["name_list_rule"], true, "name_list_rule")
	if err != nil {
		return nil, err
	}
	action, err := asStr(cfg["name_list_action"], true, "name_list_action")
	if err != nil {
		return nil, err
	}
	av, _ := asStr(cfg["action_value"], false, "action_value")
	expire, err := asStr(cfg["name_list_expire"], true, "name_list_expire")
	if err != nil {
		return nil, err
	}
	if err := oneOf(expire, "name_list_expire", "true", "false"); err != nil {
		return nil, err
	}
	expireTime := ""
	if expire == "true" {
		expireTime, err = asStr(cfg["name_list_expire_time"], true, "name_list_expire_time")
		if err != nil {
			return nil, err
		}
	}
	config := map[string]any{
		"name_list_name":        name,
		"name_list_detail":      detail,
		"name_list_rule":        rule,
		"name_list_action":      action,
		"action_value":          av,
		"name_list_expire":      expire,
		"name_list_expire_time": expireTime,
	}
	return &Result{
		Type:      gtype,
		Op:        op,
		Config:    config,
		Preview:   fmt.Sprintf("名单：%s（动作 %s，条目过期 %s）", detail, action, expire),
		TestCases: extractTestCases(params, ""),
	}, nil
}

// ---- 防护组件 ----

// lua52Only 为 Lua 5.2+ 独有语法（JXWAF 节点为 LuaJIT，不支持）。
var lua52Only = []string{"goto ", "//", "&", "|", "~", ">>", "<<"}

func gComponent(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	name, err := asStr(cfg["name"], true, "name")
	if err != nil {
		return nil, err
	}
	detail, _ := asStr(cfg["detail"], true, "detail")
	code, err := componentCode(cfg)
	if err != nil {
		return nil, err
	}
	conf, _ := asStr(cfg["conf"], true, "conf")
	config := map[string]any{
		"name":   name,
		"detail": detail,
		"code":   code, // base64 编码后的 Lua 代码
		"conf":   conf,
	}
	return &Result{
		Type:      gtype,
		Op:        op,
		Config:    config,
		Preview:   fmt.Sprintf("组件：%s（%d 字节 Lua 代码）", detail, len([]byte(code))),
		TestCases: extractTestCases(params, ""),
	}, nil
}

// componentCode 输出 base64 编码的 Lua 代码。
// 输入契约：code = 明文 Lua 源码；code_base64 = 已 base64 的源码。二者互斥。
func componentCode(cfg map[string]any) (string, error) {
	srcAny, hasSrc := cfg["code"]
	b64Any, hasB64 := cfg["code_base64"]
	if hasSrc == hasB64 {
		return "", fmt.Errorf("code 与 code_base64 必须且只能提供一个")
	}
	src := ""
	if hasSrc {
		s, err := asStr(srcAny, true, "code")
		if err != nil {
			return "", err
		}
		src = s
	} else {
		s, err := asStr(b64Any, true, "code_base64")
		if err != nil {
			return "", err
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", fmt.Errorf("code_base64 解码失败: %w", err)
		}
		src = string(decoded)
	}
	if err := checkLua52(src); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(src)), nil
}

// checkLua52 检查 Lua 5.2+ 独有语法（JXWAF 节点 LuaJIT 不支持），命中时返回错误。
func checkLua52(src string) error {
	line := 0
	for _, s := range strings.Split(src, "\n") {
		line++
		if strings.HasPrefix(strings.TrimSpace(s), "--") {
			continue // 注释行跳过
		}
		for _, tok := range lua52Only {
			if strings.Contains(s, tok) {
				return fmt.Errorf("LuaJIT 不支持 Lua 5.2+ 语法 %q（第 %d 行）", tok, line)
			}
		}
	}
	return nil
}

// ---- 域名接入 ----

func gDomain(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	fields := []string{"domain", "http", "https", "ssl_domain", "source_ip",
		"source_http_port", "source_https_port", "origin_protocol", "balance_type",
		"pre_proxy", "real_ip_conf", "connect_timeout", "send_timeout", "read_timeout"}
	config := map[string]any{}
	for _, f := range fields {
		var val string
		var err error
		if f == "source_ip" {
			val, err = toJSON(cfg[f], true, f)
		} else {
			val, err = asStr(cfg[f], true, f)
		}
		if err != nil {
			return nil, err
		}
		config[f] = val
	}
	for _, f := range []string{"http", "https", "pre_proxy"} {
		if err := oneOf(mustStr(config[f]), f, "true", "false"); err != nil {
			return nil, err
		}
	}
	if err := oneOf(mustStr(config["origin_protocol"]), "origin_protocol", "http", "https", "follow"); err != nil {
		return nil, err
	}
	if err := oneOf(mustStr(config["balance_type"]), "balance_type", "round_robin", "ip_hash"); err != nil {
		return nil, err
	}
	if err := oneOf(mustStr(config["real_ip_conf"]), "real_ip_conf", "XRI", "XFF"); err != nil {
		return nil, err
	}
	return &Result{
		Type:      gtype,
		Op:        op,
		Config:    config,
		Preview:   fmt.Sprintf("域名：%s（http=%s https=%s 回源=%s）", mustStr(config["domain"]), mustStr(config["http"]), mustStr(config["https"]), mustStr(config["origin_protocol"])),
		TestCases: extractTestCases(params, ""),
	}, nil
}

// ---- 测试用例 ----

// extractTestCases 回显 params.test_cases；缺省时基于第一条匹配值生成攻击+正常用例。
func extractTestCases(params map[string]any, matchsJSON string) []TestCase {
	if raw, ok := params["test_cases"].([]any); ok {
		cases := make([]TestCase, 0, len(raw))
		for _, e := range raw {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			tc := TestCase{
				Name:   str(m, "name"),
				Method: str(m, "method"),
				Path:   str(m, "path"),
				Query:  str(m, "query"),
				Body:   str(m, "body"),
				Expect: str(m, "expect"),
			}
			if h, ok := m["header"].(map[string]any); ok {
				tc.Header = map[string]string{}
				for k, v := range h {
					tc.Header[k], _ = v.(string)
				}
			}
			if tc.Method == "" {
				tc.Method = "GET"
			}
			if tc.Path == "" {
				tc.Path = "/"
			}
			cases = append(cases, tc)
		}
		if len(cases) > 0 {
			return cases
		}
	}
	// 默认用例：攻击（match_value 作为 query）+ 正常
	payload := ""
	if matchsJSON != "" {
		var conds []map[string]any
		if json.Unmarshal([]byte(matchsJSON), &conds) == nil && len(conds) > 0 {
			payload, _ = conds[0]["match_value"].(string)
		}
	}
	return []TestCase{
		{Name: "攻击请求", Method: "GET", Path: "/", Query: payload, Expect: "block"},
		{Name: "正常请求", Method: "GET", Path: "/", Query: "", Expect: "pass"},
	}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func mustStr(v any) string {
	s, _ := v.(string)
	return s
}

func ruleTypeName(gtype string) string {
	if gtype == "web-white" {
		return "Web白名单"
	}
	return "Web规则"
}

func actionText(action, value string) string {
	switch action {
	case "watch":
		return "watch（观察）"
	case "block":
		return "block（拦截）"
	case "bot_check":
		return "bot_check(" + value + ")"
	}
	return action
}

// firstMatchSummary 生成首条匹配条件的语义摘要。
func firstMatchSummary(matchsJSON string) string {
	var conds []map[string]any
	if json.Unmarshal([]byte(matchsJSON), &conds) != nil || len(conds) == 0 {
		return "条件见 config"
	}
	c := conds[0]
	op, _ := c["match_operator"].(string)
	val, _ := c["match_value"].(string)
	var args []string
	for _, a := range c["match_args"].([]any) {
		if m, ok := a.(map[string]any); ok {
			k, _ := m["key"].(string)
			v, _ := m["value"].(string)
			args = append(args, k+"."+v)
		}
	}
	return fmt.Sprintf("匹配 %v %s %q", args, op, val)
}
