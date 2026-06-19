package function

import (
	"context"
	"encoding/json"
)

// ListWebRulesFunc 查询 Web 规则列表
type ListWebRulesFunc struct {
	Client interface {
		ListWebRules(page int) (map[string]any, error)
	}
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
	Client interface {
		ListFlowRules(page int) (map[string]any, error)
	}
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
