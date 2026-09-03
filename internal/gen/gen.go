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
	Type      string         `json:"type"`       // 生成类型：web-rule / web-white / flow-rule / flow-white / name-list / component / domain
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

// typeSpec 描述一个生成类型：逻辑操作、生成函数与验证后的自动清理操作。
// 类型注册表是唯一的类型→操作映射源，新增类型只需在此追加一行。
type typeSpec struct {
	op      string // 创建操作名
	gen     func(gtype, op string, cfg, params map[string]any) (*Result, error)
	cleanOp string // 对应删除操作名（test verify 自动清理用；空表示不自动清理）
	nameKey string // 删除时使用的名称字段
}

var typeRegistry = map[string]typeSpec{
	"web-rule":   {"web_rule_create", gRule, "web_rule_delete", "rule_name"},
	"web-white":  {"web_white_create", gRule, "web_white_delete", "rule_name"},
	"flow-rule":  {"flow_rule_create", gFlowRule, "flow_rule_delete", "rule_name"},
	"flow-white": {"flow_white_create", gRule, "flow_white_delete", "rule_name"},
	"name-list":  {"name_list_create", gNameList, "name_list_delete", "name_list_name"},
	"component":  {"component_create", gComponent, "component_delete", "name"},
	// 域名删除有接入依赖（CNAME/证书），验证后不自动清理，由显式 cleanup 处理
	"domain": {"domain_create", gDomain, "", "domain"},
}

// CreateToDelete 返回创建操作名 → 删除操作名 的映射（供验证流程自动清理派生）。
func CreateToDelete() map[string]string {
	out := map[string]string{}
	for _, spec := range typeRegistry {
		if spec.cleanOp != "" {
			out[spec.op] = spec.cleanOp
		}
	}
	return out
}

// NameKeyOfOp 返回删除操作使用的名称字段（未注册返回空）。
func NameKeyOfOp(op string) string {
	for _, spec := range typeRegistry {
		if spec.cleanOp == op {
			return spec.nameKey
		}
	}
	return ""
}

// Generate 是统一入口：params 含可选 config 与 test_cases 两节。
func Generate(gtype string, params map[string]any) (*Result, error) {
	spec, ok := typeRegistry[gtype]
	if !ok {
		return nil, fmt.Errorf("未知生成类型 %q，支持: %v", gtype, Types())
	}
	cfg, _ := asMap(params["config"])
	return spec.gen(gtype, spec.op, cfg, params)
}

// Types 返回支持的生成类型列表。
func Types() []string {
	ts := make([]string, 0, len(typeRegistry))
	for t := range typeRegistry {
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

// posIntStr 校验字段为正整数字符串。
func posIntStr(v string, field string) error {
	if n, err := strconv.Atoi(v); err != nil || n <= 0 {
		return fmt.Errorf("字段 %s 需为正整数，实际 %q", field, v)
	}
	return nil
}

// ---- Web 规则 / Web 白名单 ----

// botCheckValues 为 bot_check 人机识别方式（对齐节点引擎 unify_action.bot_check_ip）。
var botCheckValues = []string{"auto", "slipper", "puzzle", "words"}

// typeActions 各生成类型的 rule_action 枚举（对齐控制台前端与节点引擎；
// network_block 需 action_value 为封禁秒数，bot_check 需 action_value 为人机识别方式）。
var typeActions = map[string][]string{
	"web-rule":   {"block", "watch", "reject_response"},
	"web-white":  {"watch", "web_bypass"},
	"flow-rule":  {"block", "reject_response", "watch", "bot_check", "network_block"},
	"flow-white": {"watch", "flow_bypass"},
}

// validateActionValue 校验 action_value 与动作的匹配关系，返回规范化后的值。
func validateActionValue(action, av, field string) (string, error) {
	switch action {
	case "bot_check":
		if err := oneOf(av, field, botCheckValues...); err != nil {
			return "", err
		}
		return av, nil
	case "network_block":
		if err := posIntStr(av, field); err != nil {
			return "", fmt.Errorf("%s（network_block 的 %s 为封禁秒数）", err, field)
		}
		return av, nil
	default:
		if av != "" {
			return "", fmt.Errorf("仅 bot_check/network_block 动作需要 %s", field)
		}
		return "", nil
	}
}

func gRule(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	ruleName, err := asStr(cfg["rule_name"], true, "rule_name")
	if err != nil {
		return nil, err
	}
	detail, err := asStr(cfg["rule_detail"], true, "rule_detail")
	if err != nil {
		return nil, err
	}
	matchs, err := matchsField(cfg["rule_matchs"], "rule_matchs")
	if err != nil {
		return nil, err
	}
	actions := typeActions[gtype]
	action, err := asStr(cfg["rule_action"], false, "rule_action")
	if err != nil {
		return nil, err
	}
	// 观察优先红线：未指定动作时默认 watch
	if action == "" {
		action = "watch"
	}
	if err := oneOf(action, "rule_action", actions...); err != nil {
		return nil, fmt.Errorf("%v（%s 类型允许: %v）", err, gtype, actions)
	}
	av, err := asStr(cfg["action_value"], false, "action_value")
	if err != nil {
		return nil, err
	}
	av, err = validateActionValue(action, av, "action_value")
	if err != nil {
		return nil, err
	}
	testCases, err := extractTestCases(params, matchs, gtype)
	if err != nil {
		return nil, err
	}
	config := map[string]any{
		"rule_name":    ruleName,
		"rule_detail":  detail,
		"rule_matchs":  matchs,
		"rule_action":  action,
		"action_value": av,
	}
	cond := firstMatchSummary(matchs)
	return &Result{
		Type:      gtype,
		Op:        op,
		Config:    config,
		Preview:   fmt.Sprintf("%s：%s（动作 %s，%s）", ruleTypeName(gtype), detail, actionText(action, av), cond),
		TestCases: testCases,
	}, nil
}

// matchsField 将匹配条件（数组或 JSON 字符串）规范化为 JSON 字符串并校验结构。
func matchsField(v any, field string) (string, error) {
	raw, err := toJSON(v, true, field)
	if err != nil {
		return "", err
	}
	var conds []map[string]any
	if err := json.Unmarshal([]byte(raw), &conds); err != nil {
		return "", fmt.Errorf("字段 %s 需为匹配条件数组: %w", field, err)
	}
	if len(conds) == 0 {
		return "", fmt.Errorf("%s 至少需要一个匹配条件", field)
	}
	for i, c := range conds {
		if err := checkMatchCond(i, c); err != nil {
			return "", err
		}
	}
	return raw, nil
}

// 匹配参数 key 与 value 的合法组合（对齐节点引擎 request.get_args 的分派行为）：
// http_args 的 value 为固定枚举（15 个，对齐引擎 get_http_args）；
// 其余 key 的 value 为自定义参数名（header 名/cookie 名/URI 参数名等），
// global_name_list_result 的 value 为名单名；string 的 value 为常量值（tostring 比较）；
// web_rule/web_engine_protection_result 的 value 为规则名（引擎联动的结果查找键）。
var httpArgsValues = []string{
	"path", "query_string", "method", "src_ip", "raw_body", "version", "scheme",
	"raw_header", "raw_header_no_referer", "request_uri", "host", "user_agent",
	"referer", "cookie", "high_risk_header",
}

var argKeys = map[string]bool{
	"http_args": true, "header_args": true, "cookie_args": true, "uri_args": true,
	"post_args": true, "json_post_args": true, "ctx_args": true, "global_name_list_result": true,
	"string": true, "web_rule_protection_result": true, "web_engine_protection_result": true,
}

// checkArgPair 校验一个 {key, value} 参数对（match_args 元素与 name_list_rule 元素共用）。
func checkArgPair(i int, key, value string) error {
	if !argKeys[key] {
		return fmt.Errorf("匹配参数[%d] 未知参数大类 %q", i, key)
	}
	if key == "http_args" {
		for _, allow := range httpArgsValues {
			if value == allow {
				return nil
			}
		}
		return fmt.Errorf("匹配参数[%d] key=http_args 的 value %q 非法，允许: %v", i, value, httpArgsValues)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("匹配参数[%d] key=%s 的 value 不能为空（自定义参数名/名单名）", i, key)
	}
	return nil
}

var prepocessSet = map[string]bool{
	"none": true, "lowerCase": true, "base64Decode": true, "length": true,
	"uriDecode": true, "uniDecode": true, "hexDecode": true, "type": true,
}

var operatorSet = map[string]bool{
	"rx": true, "str_prefix": true, "str_suffix": true, "str_contain": true,
	"str_ncontain": true, "str_eq": true, "str_neq": true, "gt": true, "lt": true,
	"eq": true, "neq": true, "status_check": true, "ip_in_cidr": true, "ip_in_cidrs": true,
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
		val, _ := am["value"].(string)
		if err := checkArgPair(i, key, val); err != nil {
			return err
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
	mv, _ := c["match_value"].(string)
	if op == "status_check" {
		if mv != "exist" && mv != "no_exist" {
			return fmt.Errorf("匹配条件[%d] status_check 的 match_value 需为 exist/no_exist", i)
		}
	} else if strings.TrimSpace(mv) == "" {
		// 所有比较操作符（rx/str_*/gt/eq 等）都需要 match_value
		return fmt.Errorf("匹配条件[%d] 缺少 match_value（操作符 %s 需要比较值）", i, op)
	}
	return nil
}

// nameListRuleField 校验 name_list_rule：扁平的 [{key, value}] 数组（对齐节点引擎，
// 引擎逐项 request.get_args(key,value) 取值后拼接为条目查找键；与 rule_matchs 结构不同）。
func nameListRuleField(v any) (string, error) {
	raw, err := toJSON(v, true, "name_list_rule")
	if err != nil {
		return "", err
	}
	var pairs []map[string]any
	if err := json.Unmarshal([]byte(raw), &pairs); err != nil {
		return "", fmt.Errorf("字段 name_list_rule 需为 [{key,value}] 对象数组: %w", err)
	}
	if len(pairs) == 0 {
		return "", fmt.Errorf("name_list_rule 至少需要一个参数对")
	}
	for i, p := range pairs {
		key, _ := p["key"].(string)
		val, _ := p["value"].(string)
		if err := checkArgPair(i, key, val); err != nil {
			return "", fmt.Errorf("name_list_rule %v", err)
		}
	}
	return raw, nil
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

// entityKeys 为 flow 规则统计对象（entity）的合法 key（对齐控制台前端；
// http_args.src_ip 为每 IP 统计场景，string 为常量统计键）。
var entityKeys = map[string]bool{
	"http_args": true, "header_args": true, "cookie_args": true, "uri_args": true,
	"post_args": true, "json_post_args": true, "string": true,
}

// entityField 校验 entity：扁平的 [{key, value}] 数组（引擎逐项 get_args 取值拼接为统计键）。
func entityField(v any) (string, error) {
	raw, err := toJSON(v, true, "entity")
	if err != nil {
		return "", err
	}
	var pairs []map[string]any
	if err := json.Unmarshal([]byte(raw), &pairs); err != nil {
		return "", fmt.Errorf("字段 entity 需为 [{key,value}] 对象数组: %w", err)
	}
	if len(pairs) == 0 {
		return "", fmt.Errorf("entity 至少需要一个统计对象")
	}
	for i, p := range pairs {
		key, _ := p["key"].(string)
		val, _ := p["value"].(string)
		if !entityKeys[key] {
			return "", fmt.Errorf("entity[%d] 未知统计对象 key %q，允许: %v", i, key, sortedKeys(entityKeys))
		}
		if key == "http_args" {
			if err := checkArgPair(i, key, val); err != nil {
				return "", err
			}
			continue
		}
		if strings.TrimSpace(val) == "" {
			return "", fmt.Errorf("entity[%d] key=%s 的 value 不能为空", i, key)
		}
	}
	return raw, nil
}

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
	entity, err := entityField(cfg["entity"])
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
	for _, f := range []string{"stat_time", "exceed_count", "block_time"} {
		v := map[string]string{"stat_time": statTime, "exceed_count": exceedCount, "block_time": blockTime}[f]
		if err := posIntStr(v, f); err != nil {
			return nil, err
		}
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

// nameListActions 为 name_list_action 完整枚举：network_block 的 action_value 为封禁秒数，
// bot_check 为人机识别方式，放行类无需观察。
var nameListActions = []string{
	"block", "reject_response", "watch", "bot_check",
	"all_bypass", "web_bypass", "flow_bypass", "network_block",
}

func gNameList(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	name, err := asStr(cfg["name_list_name"], true, "name_list_name")
	if err != nil {
		return nil, err
	}
	detail, err := asStr(cfg["name_list_detail"], true, "name_list_detail")
	if err != nil {
		return nil, err
	}
	rule, err := nameListRuleField(cfg["name_list_rule"])
	if err != nil {
		return nil, err
	}
	action, err := asStr(cfg["name_list_action"], true, "name_list_action")
	if err != nil {
		return nil, err
	}
	if err := oneOf(action, "name_list_action", nameListActions...); err != nil {
		return nil, err
	}
	av, err := asStr(cfg["action_value"], false, "action_value")
	if err != nil {
		return nil, err
	}
	av, err = validateActionValue(action, av, "action_value")
	if err != nil {
		return nil, err
	}
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
		if err := posIntStr(expireTime, "name_list_expire_time"); err != nil {
			return nil, err
		}
	}
	testCases, err := extractTestCases(params, "", "name-list")
	if err != nil {
		return nil, err
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
		TestCases: testCases,
	}, nil
}

// ---- 防护组件 ----

func gComponent(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	name, err := asStr(cfg["name"], true, "name")
	if err != nil {
		return nil, err
	}
	detail, err := asStr(cfg["detail"], true, "detail")
	if err != nil {
		return nil, err
	}
	code, err := componentCode(cfg)
	if err != nil {
		return nil, err
	}
	conf, err := asStr(cfg["conf"], true, "conf")
	if err != nil {
		return nil, err
	}
	testCases, err := extractTestCases(params, "", "component")
	if err != nil {
		return nil, err
	}
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
		TestCases: testCases,
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

// lua52OnlyTokens 为 Lua 5.2+ 独有的位运算/整除运算符（JXWAF 节点为 LuaJIT，不支持）。
// ~ 需词法特判（~= 是 LuaJIT 合法的不等比较），不在此表。
var lua52OnlyTokens = []string{"//", "&", "|", ">>", "<<"}

// checkLua52 检查 Lua 5.2+ 独有语法（JXWAF 节点 LuaJIT 不支持），命中时返回错误。
// 先剥离字符串字面量与注释再做 token 匹配，避免代码中的 "http://"、"a &amp; b"、
// 注释里的 ~ 等合法内容被误杀（~= 为 LuaJIT 标准不等比较，仅拒绝独立的按位非 ~）。
func checkLua52(src string) error {
	code := stripLuaStringsAndComments(src)
	for line, s := range strings.Split(code, "\n") {
		if err := checkLuaLine(line+1, s); err != nil {
			return err
		}
	}
	return nil
}

func checkLuaLine(line int, s string) error {
	// goto：按词边界识别（goto xxx；标识符内出现的 goto 如 mygoto 不算）
	for pos := 0; ; {
		j := strings.Index(s[pos:], "goto")
		if j < 0 {
			break
		}
		p := pos + j
		beforeOK := p == 0 || !isIdentChar(s[p-1])
		after := p + len("goto")
		if beforeOK && after < len(s) && isIdentChar(s[after]) {
			return fmt.Errorf("LuaJIT 不支持 Lua 5.2+ 语法 %q（第 %d 行）", "goto", line)
		}
		pos = p + 1
	}
	for _, tok := range lua52OnlyTokens {
		if strings.Contains(s, tok) {
			return fmt.Errorf("LuaJIT 不支持 Lua 5.2+ 语法 %q（第 %d 行）", tok, line)
		}
	}
	// ~：~= 为合法不等比较，其余 ~ 均为 5.2+ 按位非
	for i := 0; i < len(s); i++ {
		if s[i] == '~' && (i+1 >= len(s) || s[i+1] != '=') {
			return fmt.Errorf("LuaJIT 不支持 Lua 5.2+ 语法 %q（第 %d 行）", "~（按位非，~= 不等比较除外）", line)
		}
	}
	return nil
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// stripLuaStringsAndComments 将字符串字面量与注释替换为等长空白（保持行号不变）。
// 覆盖：行注释 --、长注释 --[[ ]]（含 [=[ ]=] 级别）、短字符串 "..." '...'、长字符串 [[ ]]。
func stripLuaStringsAndComments(src string) string {
	var b strings.Builder
	i, n := 0, len(src)
	blank := func(cnt int) string { return strings.Repeat(" ", cnt) }
	for i < n {
		// 注释 --
		if src[i] == '-' && i+1 < n && src[i+1] == '-' {
			if end, ok := scanLongBracket(src, i+2); ok {
				b.WriteString(blank(end - i))
				i = end
				continue
			}
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				b.WriteString(blank(n - i))
				return b.String()
			}
			b.WriteString(blank(j))
			i += j
			continue
		}
		// 长字符串 [[ ]] / [=[ ]=]
		if src[i] == '[' {
			if end, ok := scanLongBracket(src, i); ok {
				b.WriteString(blank(end - i))
				i = end
				continue
			}
		}
		// 短字符串 "..." '...'
		if src[i] == '"' || src[i] == '\'' {
			quote := src[i]
			j := i + 1
			for j < n && src[j] != quote && src[j] != '\n' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			end := j
			if end < n && src[end] == quote {
				end++
			}
			b.WriteString(blank(end - i))
			i = end
			continue
		}
		b.WriteByte(src[i])
		i++
	}
	return b.String()
}

// scanLongBracket 从 pos 开始扫描长括号序列（[=*[ ... ]=*]），
// pos 应指向 '['（或注释的第二个 '-' 之后）。返回结束位置与是否匹配。
func scanLongBracket(src string, pos int) (int, bool) {
	if pos >= len(src) || src[pos] != '[' {
		return 0, false
	}
	level := 0
	j := pos + 1
	for j < len(src) && src[j] == '=' {
		level++
		j++
	}
	if j >= len(src) || src[j] != '[' {
		return 0, false
	}
	closeTok := "]"
	for k := 0; k < level; k++ {
		closeTok += "="
	}
	closeTok += "]"
	idx := strings.Index(src[j+1:], closeTok)
	if idx < 0 {
		return len(src), true // 未闭合：剩余全部视为字符串/注释
	}
	return j + 1 + idx + len(closeTok), true
}

// ---- 域名接入 ----

func gDomain(gtype, op string, cfg map[string]any, params map[string]any) (*Result, error) {
	httpStr, err := asStr(cfg["http"], true, "http")
	if err != nil {
		return nil, err
	}
	httpsStr, err := asStr(cfg["https"], true, "https")
	if err != nil {
		return nil, err
	}
	if err := oneOf(httpStr, "http", "true", "false"); err != nil {
		return nil, err
	}
	if err := oneOf(httpsStr, "https", "true", "false"); err != nil {
		return nil, err
	}
	if httpStr == "false" && httpsStr == "false" {
		return nil, fmt.Errorf("http 与 https 不能同时为 false（至少启用一种接入协议）")
	}
	// 服务端 check_param 无条件要求以下字段存在（detail 为域名描述）；
	// ssl_domain / source_https_port 在 https=true 时需非空，false 时输出空串占位（键必须存在）。
	required := []string{"domain", "detail", "http", "https", "source_ip",
		"source_http_port", "origin_protocol", "balance_type",
		"pre_proxy", "real_ip_conf", "connect_timeout", "send_timeout", "read_timeout"}
	config := map[string]any{}
	for _, f := range required {
		var val string
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
	sslDomain, err := asStr(cfg["ssl_domain"], false, "ssl_domain")
	if err != nil {
		return nil, err
	}
	httpsPort, err := asStr(cfg["source_https_port"], false, "source_https_port")
	if err != nil {
		return nil, err
	}
	if httpsStr == "true" && sslDomain == "" {
		return nil, fmt.Errorf("https=true 需要提供 ssl_domain（关联的 SSL 证书域名）")
	}
	// HTTPS 回源端口缺省一律填 443：即使 https=false 也不留空白（避免配置展示出现空白字段，
	// 后续切换 https=true 时回源端口即已就绪）
	if httpsPort == "" {
		httpsPort = "443"
	}
	config["ssl_domain"] = sslDomain
	config["source_https_port"] = httpsPort
	for _, f := range []string{"source_http_port", "source_https_port", "connect_timeout", "send_timeout", "read_timeout"} {
		if v, ok := config[f].(string); ok && v != "" {
			if err := posIntStr(v, f); err != nil {
				return nil, err
			}
		}
	}
	if err := oneOf(mustStr(config["pre_proxy"]), "pre_proxy", "true", "false"); err != nil {
		return nil, err
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
	testCases, err := extractTestCases(params, "", "domain")
	if err != nil {
		return nil, err
	}
	return &Result{
		Type:      gtype,
		Op:        op,
		Config:    config,
		Preview:   fmt.Sprintf("域名：%s（http=%s https=%s 回源=%s）", mustStr(config["domain"]), httpStr, httpsStr, mustStr(config["origin_protocol"])),
		TestCases: testCases,
	}, nil
}

// ---- 测试用例 ----

// extractTestCases 回显 params.test_cases；缺省时基于第一条匹配值生成默认用例。
// 白名单类型（web-white/flow-white）命中即放行，默认用例 expect=pass；其余类型攻击用例 expect=block。
// 用例元素结构非法（非对象、header 值非字符串、expect 非 block/pass）直接报错，不静默跳过。
func extractTestCases(params map[string]any, matchsJSON string, gtype string) ([]TestCase, error) {
	if raw, ok := params["test_cases"].([]any); ok && len(raw) > 0 {
		cases := make([]TestCase, 0, len(raw))
		for i, e := range raw {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("test_cases[%d] 需为对象", i)
			}
			tc := TestCase{
				Name:   str(m, "name"),
				Method: str(m, "method"),
				Path:   str(m, "path"),
				Query:  str(m, "query"),
				Body:   str(m, "body"),
				Expect: str(m, "expect"),
			}
			if tc.Method == "" {
				tc.Method = "GET"
			}
			if tc.Path == "" {
				tc.Path = "/"
			}
			if tc.Expect == "" {
				tc.Expect = "pass"
			}
			if err := oneOf(tc.Expect, fmt.Sprintf("test_cases[%d].expect", i), "block", "pass"); err != nil {
				return nil, err
			}
			if h, ok := m["header"].(map[string]any); ok {
				tc.Header = map[string]string{}
				for k, v := range h {
					s, ok := v.(string)
					if !ok {
						return nil, fmt.Errorf("test_cases[%d].header.%s 的值需为字符串", i, k)
					}
					tc.Header[k] = s
				}
			}
			cases = append(cases, tc)
		}
		return cases, nil
	}
	// 默认用例：取第一条匹配值作为 query 载荷
	payload := ""
	if matchsJSON != "" {
		var conds []map[string]any
		if json.Unmarshal([]byte(matchsJSON), &conds) == nil && len(conds) > 0 {
			payload, _ = conds[0]["match_value"].(string)
		}
	}
	matchExpect := "block"
	matchName := "攻击请求"
	if gtype == "web-white" || gtype == "flow-white" {
		// 白名单命中即放行（bypass 后请求正常到达源站）
		matchExpect = "pass"
		matchName = "命中白名单请求"
	}
	return []TestCase{
		{Name: matchName, Method: "GET", Path: "/", Query: payload, Expect: matchExpect},
		{Name: "正常请求", Method: "GET", Path: "/", Query: "", Expect: "pass"},
	}, nil
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
	switch gtype {
	case "web-white":
		return "Web白名单"
	case "flow-rule":
		return "流量规则"
	case "flow-white":
		return "流量白名单"
	}
	return "Web规则"
}

func actionText(action, value string) string {
	switch action {
	case "watch":
		return "watch（观察）"
	case "block":
		return "block（拦截）"
	case "reject_response":
		return "reject_response（拒绝响应）"
	case "network_block":
		return "network_block（封禁 " + value + " 秒）"
	case "bot_check":
		return "bot_check(" + value + ")"
	case "web_bypass":
		return "web_bypass（Web防护放行）"
	case "flow_bypass":
		return "flow_bypass（流量防护放行）"
	case "all_bypass":
		return "all_bypass（全防护放行）"
	}
	return action
}

// sortedKeys 返回 map 的排序键列表（错误信息展示用）。
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
