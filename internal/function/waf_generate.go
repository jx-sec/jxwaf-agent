package function

import (
	"context"
	"encoding/json"
	"fmt"
)

// scriptResult 脚本生成结果（推送给前端作为 config_preview 事件数据）
type scriptResult struct {
	ScriptType  string `json:"script_type"`  // web_rule | flow_rule | component | name_list | web_white | flow_white
	Name        string `json:"name"`
	Detail      string `json:"detail"`
	ConfigJSON  string `json:"config_json"`  // 完整配置 JSON（backup 导出格式数组）
	CodeLua     string `json:"code_lua,omitempty"`
	ConfJSON    string `json:"conf_json,omitempty"`
	Explanation string `json:"explanation"`
	LoadHint    string `json:"load_hint"`     // 用户导入说明
}

// testCase 测试用例（云端验证用）
type testCase struct {
	Name    string         `json:"name"`
	Method  string         `json:"method"`
	Path    string         `json:"path"`
	Headers map[string]any `json:"headers,omitempty"`
	Body    string         `json:"body,omitempty"`
	Assert  testAssert     `json:"assert"`
}

type testAssert struct {
	Type           string `json:"type"` // block | pass | extract
	ExpectedStatus int    `json:"expected_status,omitempty"`
	Field          string `json:"field,omitempty"`
	ExpectedValue  string `json:"expected_value,omitempty"`
}

// =============================================================================
// GenerateWebRuleScriptFunc：生成 Web 防护规则（输出 backup 格式数组）
// =============================================================================
type GenerateWebRuleScriptFunc struct{}

func (f *GenerateWebRuleScriptFunc) Name() string { return "generate_web_rule_script" }

func (f *GenerateWebRuleScriptFunc) Description() string {
	return "生成 Web 防护规则配置（backup 导出格式数组）。用户复制后通过「加载Web规则」导入。新规则默认 watch 模式。"
}

func (f *GenerateWebRuleScriptFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string", "description": "规则名（小写下划线，如 block_admin）"},
			"detail": map[string]any{"type": "string", "description": "规则描述"},
			"matchs": map[string]any{
				"type":        "array",
				"description": "匹配条件数组，多个为 AND 关系",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"match_args": map[string]any{
							"type":        "array",
							"description": "匹配参数，多个为 OR 关系",
							"items": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"key":   map[string]any{"type": "string", "description": "http_args/header_args/cookie_args/uri_args/post_args/json_post_args/ctx_args"},
									"value": map[string]any{"type": "string", "description": "字段名，如 path/src_ip/user_agent"},
								},
								"required": []string{"key", "value"},
							},
						},
						"args_prepocess": map[string]any{
							"type":        "array",
							"items":       map[string]any{"type": "string"},
							"description": "参数预处理：none/lowerCase/base64Decode/uriDecode/uniDecode/hexDecode",
						},
						"match_operator": map[string]any{"type": "string", "description": "匹配运算符：str_contain/str_eq/str_prefix/rx/ip_in_cidr/status_check 等"},
						"match_value":    map[string]any{"type": "string", "description": "匹配值"},
					},
				},
			},
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"watch", "block"},
				"default":     "watch",
				"description": "动作，新规则建议 watch",
			},
			"test_cases": map[string]any{
				"type":        "array",
				"description": "测试用例（云端验证用），至少 1 条攻击流量 + 1 条正常流量",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":      map[string]any{"type": "string", "description": "用例名称"},
						"method":    map[string]any{"type": "string", "description": "HTTP 方法", "default": "GET"},
						"path":      map[string]any{"type": "string", "description": "请求路径"},
						"headers":   map[string]any{"type": "object", "description": "请求头"},
						"body":      map[string]any{"type": "string", "description": "请求体"},
						"assert": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"type":            map[string]any{"type": "string", "enum": []string{"block", "pass"}, "description": "block=应被拦截, pass=应放行"},
								"expected_status": map[string]any{"type": "integer", "description": "期望的 HTTP 状态码"},
							},
						},
					},
				},
			},
		},
		"required": []string{"name", "detail", "matchs"},
	}
}

func (f *GenerateWebRuleScriptFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	detail, _ := args["detail"].(string)
	action, _ := args["action"].(string)
	actionValue, _ := args["action_value"].(string)
	if action == "" {
		action = "watch"
	}

	// 解析匹配条件
	var matchs []any
	if raw, ok := args["matchs"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &matchs)
	}
	if matchs == nil {
		matchs = []any{}
	}

	// 备份导出格式：纯数组
	rules := []map[string]any{{
		"rule_name":    name,
		"rule_detail":  detail,
		"rule_matchs":  matchs,
		"rule_action":  action,
		"action_value": actionValue,
	}}

	configJSON, _ := json.MarshalIndent(rules, "", "  ")

	result := scriptResult{
		ScriptType:  "web_rule",
		Name:        name,
		Detail:      detail,
		ConfigJSON:  string(configJSON),
		LoadHint:    "复制上方 JSON，在控制台「Web防护规则 → 加载」中粘贴导入。专业版需先选择域名分组。",
		Explanation: fmt.Sprintf("Web 防护规则 %s（action=%s）。匹配条件 %d 组。", name, action, len(matchs)),
	}
	return toJSON(result), nil
}

// =============================================================================
// GenerateFlowRuleScriptFunc：生成流量防护规则（输出 backup 格式数组）
// =============================================================================
type GenerateFlowRuleScriptFunc struct{}

func (f *GenerateFlowRuleScriptFunc) Name() string { return "generate_flow_rule_script" }

func (f *GenerateFlowRuleScriptFunc) Description() string {
	return "生成流量防护规则配置（backup 导出格式数组）。用户复制后通过「加载流量规则」导入。exceed_count 不低于业务峰值 QPS 的 2 倍。"
}

func (f *GenerateFlowRuleScriptFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":         map[string]any{"type": "string"},
			"detail":       map[string]any{"type": "string"},
			"matchs":       map[string]any{"type": "array", "description": "匹配条件，filter=true 时生效"},
			"action":       map[string]any{"type": "string", "enum": []string{"block", "reject_response", "bot_check", "network_block", "watch"}},
			"action_value": map[string]any{"type": "string", "description": "bot_check 类型(auto/slipper/puzzle/words) 或 network_block 秒数"},
			"filter":       map[string]any{"type": "string", "enum": []string{"true", "false"}, "description": "true 启用匹配条件，false 对所有请求生效"},
			"entity": map[string]any{
				"type":        "array",
				"description": "统计对象，多字段拼接为统计 key",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"key":   map[string]any{"type": "string"},
						"value": map[string]any{"type": "string"},
					},
				},
			},
			"stat_time":    map[string]any{"type": "integer", "description": "统计时间窗口（秒）"},
			"exceed_count": map[string]any{"type": "integer", "description": "触发阈值"},
			"block_time":   map[string]any{"type": "integer", "description": "处罚持续时间（秒）"},
			"test_cases": map[string]any{
				"type":        "array",
				"description": "测试用例（云端验证用），包含高频请求验证",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":    map[string]any{"type": "string"},
						"method":  map[string]any{"type": "string", "default": "GET"},
						"path":    map[string]any{"type": "string"},
						"headers": map[string]any{"type": "object"},
						"assert": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"type":            map[string]any{"type": "string", "enum": []string{"block", "pass"}},
								"expected_status": map[string]any{"type": "integer"},
							},
						},
						"flow_count":    map[string]any{"type": "integer", "description": "流量规则测试请求次数", "default": 10},
						"flow_interval": map[string]any{"type": "number", "description": "请求间隔（秒）", "default": 0.1},
					},
				},
			},
		},
		"required": []string{"name", "detail", "action", "filter", "entity", "stat_time", "exceed_count", "block_time"},
	}
}

func (f *GenerateFlowRuleScriptFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	detail, _ := args["detail"].(string)
	action, _ := args["action"].(string)
	actionValue, _ := args["action_value"].(string)
	filter, _ := args["filter"].(string)

	var matchs []any
	if raw, ok := args["matchs"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &matchs)
	}
	if matchs == nil {
		matchs = []any{}
	}

	var entity []any
	if raw, ok := args["entity"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &entity)
	}
	if entity == nil {
		entity = []any{}
	}

	statTime, _ := args["stat_time"].(float64)
	exceedCount, _ := args["exceed_count"].(float64)
	blockTime, _ := args["block_time"].(float64)

	rules := []map[string]any{{
		"rule_name":    name,
		"rule_detail":  detail,
		"rule_matchs":  matchs,
		"rule_action":  action,
		"action_value": actionValue,
		"filter":       filter,
		"entity":       entity,
		"stat_time":    int(statTime),
		"exceed_count": int(exceedCount),
		"block_time":   int(blockTime),
	}}

	configJSON, _ := json.MarshalIndent(rules, "", "  ")

	result := scriptResult{
		ScriptType:  "flow_rule",
		Name:        name,
		Detail:      detail,
		ConfigJSON:  string(configJSON),
		LoadHint:    "复制上方 JSON，在控制台「流量防护规则 → 加载」中粘贴导入。专业版需先选择域名分组。",
		Explanation: fmt.Sprintf("流量防护规则 %s（%ds 内超过 %d 次 → %s %s）。",
			name, int(statTime), int(exceedCount), action, actionValue),
	}
	return toJSON(result), nil
}

// =============================================================================
// GenerateComponentScriptFunc：生成防护组件（输出 backup 格式数组）
// =============================================================================
type GenerateComponentScriptFunc struct{}

func (f *GenerateComponentScriptFunc) Name() string { return "generate_component_script" }

func (f *GenerateComponentScriptFunc) Description() string {
	return "生成防护组件配置（backup 导出格式数组）。用户复制后通过「组件 → 加载」导入。必须兼容 LuaJIT（Lua 5.1），禁止使用 & | ~ >> << // goto 等语法。"
}

func (f *GenerateComponentScriptFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":     map[string]any{"type": "string", "description": "组件名（小写下划线）"},
			"detail":   map[string]any{"type": "string", "description": "组件描述"},
			"code_lua": map[string]any{"type": "string", "description": "Lua 源码，必须返回包含 check(conf_data) 函数的 table"},
			"conf":     map[string]any{"type": "string", "description": "组件配置 JSON 字符串", "default": "{}"},
		},
		"required": []string{"name", "detail", "code_lua"},
	}
}

func (f *GenerateComponentScriptFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	detail, _ := args["detail"].(string)
	codeLua, _ := args["code_lua"].(string)
	conf, _ := args["conf"].(string)
	if conf == "" {
		conf = "{}"
	}

	if name == "" || codeLua == "" {
		return "", fmt.Errorf("name 和 code_lua 不能为空")
	}

	rules := []map[string]any{{
		"name":   name,
		"detail": detail,
		"code":   codeLua,
		"conf":   conf,
	}}

	configJSON, _ := json.MarshalIndent(rules, "", "  ")

	result := scriptResult{
		ScriptType:  "component",
		Name:        name,
		Detail:      detail,
		ConfigJSON:  string(configJSON),
		CodeLua:     codeLua,
		ConfJSON:    conf,
		LoadHint:    "复制上方 JSON，在控制台「防护组件 → 加载」中粘贴导入。Lua 代码必须兼容 LuaJIT（Lua 5.1）。",
		Explanation: fmt.Sprintf("防护组件 %s。Lua 代码 %d 字节，请确认兼容 LuaJIT（Lua 5.1）。", name, len(codeLua)),
	}
	return toJSON(result), nil
}

// =============================================================================
// GenerateNameListScriptFunc：生成名单防护（输出 backup 格式数组）
// =============================================================================
type GenerateNameListScriptFunc struct{}

func (f *GenerateNameListScriptFunc) Name() string { return "generate_name_list_script" }

func (f *GenerateNameListScriptFunc) Description() string {
	return "生成名单防护配置（backup 导出格式数组）。用户复制后通过「全局名单 → 加载」导入。临时名单必须设置过期时间。"
}

func (f *GenerateNameListScriptFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string", "description": "名单名（小写下划线）"},
			"detail": map[string]any{"type": "string", "description": "名单描述"},
			"rule": map[string]any{
				"type":        "array",
				"description": "查找 key 构造规则，按顺序拼接字段值",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"key":   map[string]any{"type": "string"},
						"value": map[string]any{"type": "string"},
					},
				},
			},
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"block", "reject_response", "bot_check", "network_block", "watch", "all_bypass", "web_bypass", "flow_bypass"},
				"description": "执行动作",
			},
			"action_value": map[string]any{"type": "string", "description": "bot_check 类型 / network_block 秒数"},
			"expire":       map[string]any{"type": "string", "description": "false 永久 / true 临时", "default": "false"},
			"expire_time":  map[string]any{"type": "string", "description": "过期时间（秒），expire=true 时生效", "default": "0"},
			"items": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "名单条目列表（如 IP 地址），可选",
			},
		},
		"required": []string{"name", "detail", "rule", "action"},
	}
}

func (f *GenerateNameListScriptFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	detail, _ := args["detail"].(string)
	action, _ := args["action"].(string)
	actionValue, _ := args["action_value"].(string)
	expire, _ := args["expire"].(string)
	expireTime, _ := args["expire_time"].(string)
	if expire == "" {
		expire = "false"
	}
	if expireTime == "" {
		expireTime = "0"
	}

	var rule []any
	if raw, ok := args["rule"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &rule)
	}
	if rule == nil {
		rule = []any{}
	}

	// 提取条目
	items := []string{}
	if rawItems, ok := args["items"].([]any); ok {
		for _, it := range rawItems {
			if s, ok := it.(string); ok && s != "" {
				items = append(items, s)
			}
		}
	}

	rules := []map[string]any{{
		"name_list_name":        name,
		"name_list_detail":      detail,
		"name_list_rule":        rule,
		"name_list_action":      action,
		"action_value":          actionValue,
		"name_list_expire":      expire,
		"name_list_expire_time": expireTime,
	}}

	configJSON, _ := json.MarshalIndent(rules, "", "  ")

	expireHint := "永久名单。"
	if expire == "true" {
		expireHint = fmt.Sprintf("临时名单，过期时间 %s 秒。", expireTime)
	}

	result := scriptResult{
		ScriptType:  "name_list",
		Name:        name,
		Detail:      detail,
		ConfigJSON:  string(configJSON),
		LoadHint:    "复制上方 JSON，在控制台「全局名单 → 加载」中粘贴导入。条目需在名单创建后单独添加。",
		Explanation: fmt.Sprintf("名单防护 %s（action=%s）。%s 条目 %d 个。", name, action, expireHint, len(items)),
	}
	return toJSON(result), nil
}
