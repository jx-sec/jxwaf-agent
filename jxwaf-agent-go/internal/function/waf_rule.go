package function

import (
	"context"
	"encoding/json"
	"fmt"
	"jxwaf-agent-go/internal/jxwaf"
)

// CreateWebRuleFunc 创建 Web 防护规则
type CreateWebRuleFunc struct {
	Client *jxwaf.Client
}

func (f *CreateWebRuleFunc) Name() string { return "create_web_rule" }

func (f *CreateWebRuleFunc) Description() string {
	return "创建 Web 防护规则（单次请求匹配拦截）。新规则默认 watch 模式，验证无误报后改 block。"
}

func (f *CreateWebRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "规则名（小写下划线，如 block_admin）",
			},
			"detail": map[string]any{
				"type":        "string",
				"description": "规则描述",
			},
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
							"items":        map[string]any{"type": "string"},
							"description": "参数预处理：none/lowerCase/base64Decode/uriDecode/uniDecode/hexDecode",
						},
						"match_operator": map[string]any{
							"type":        "string",
							"description": "匹配运算符：str_contain/str_eq/str_prefix/rx/ip_in_cidr/status_check 等",
						},
						"match_value": map[string]any{
							"type":        "string",
							"description": "匹配值",
						},
					},
				},
			},
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"watch", "block"},
				"default":     "watch",
				"description": "动作，新规则建议 watch",
			},
		},
		"required": []string{"name", "detail", "matchs"},
	}
}

func (f *CreateWebRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	var rule jxwaf.WebRule
	b, _ := json.Marshal(args)
	if err := json.Unmarshal(b, &rule); err != nil {
		return "", fmt.Errorf("参数解析失败: %w", err)
	}
	// 红线：新规则默认 watch
	if rule.Action == "" {
		rule.Action = "watch"
	}
	result, err := f.Client.CreateWebRule(rule)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Web 规则 %s 创建成功（action=%s），响应: %s", rule.Name, rule.Action, toJSON(result)), nil
}

// CreateFlowRuleFunc 创建流量防护规则
type CreateFlowRuleFunc struct {
	Client *jxwaf.Client
}

func (f *CreateFlowRuleFunc) Name() string { return "create_flow_rule" }

func (f *CreateFlowRuleFunc) Description() string {
	return "创建流量防护规则（基于频率统计的限速）。exceed_count 不低于业务峰值 QPS 的 2 倍。"
}

func (f *CreateFlowRuleFunc) Schema() map[string]any {
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
		},
		"required": []string{"name", "detail", "action", "filter", "entity", "stat_time", "exceed_count", "block_time"},
	}
}

func (f *CreateFlowRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	var rule jxwaf.FlowRule
	b, _ := json.Marshal(args)
	if err := json.Unmarshal(b, &rule); err != nil {
		return "", fmt.Errorf("参数解析失败: %w", err)
	}
	result, err := f.Client.CreateFlowRule(rule)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("流量规则 %s 创建成功，响应: %s", rule.Name, toJSON(result)), nil
}

// ListWebRulesFunc 查询 Web 规则列表
type ListWebRulesFunc struct {
	Client *jxwaf.Client
}

func (f *ListWebRulesFunc) Name() string { return "list_web_rules" }

func (f *ListWebRulesFunc) Description() string {
	return "查询 Web 防护规则列表"
}

func (f *ListWebRulesFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"page": map[string]any{"type": "integer", "default": 1},
		},
	}
}

func (f *ListWebRulesFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	page := 1
	if p, ok := args["page"].(float64); ok {
		page = int(p)
	}
	result, err := f.Client.ListWebRules(page)
	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}

// ListFlowRulesFunc 查询流量规则列表
type ListFlowRulesFunc struct {
	Client *jxwaf.Client
}

func (f *ListFlowRulesFunc) Name() string { return "list_flow_rules" }

func (f *ListFlowRulesFunc) Description() string {
	return "查询流量防护规则列表"
}

func (f *ListFlowRulesFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"page": map[string]any{"type": "integer", "default": 1},
		},
	}
}

func (f *ListFlowRulesFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	page := 1
	if p, ok := args["page"].(float64); ok {
		page = int(p)
	}
	result, err := f.Client.ListFlowRules(page)
	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
