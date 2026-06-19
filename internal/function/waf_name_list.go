package function

import (
	"context"
	"fmt"
	"jxwaf-agent-go/internal/jxwaf"
)

// CreateNameListFunc 创建名单
type CreateNameListFunc struct {
	Client *jxwaf.Client
}

func (f *CreateNameListFunc) Name() string { return "create_name_list" }

func (f *CreateNameListFunc) Description() string {
	return "创建名单防护（基于键值查找的快速匹配）。临时名单必须设置过期时间。"
}

func (f *CreateNameListFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "名单名（小写下划线）",
			},
			"detail": map[string]any{
				"type":        "string",
				"description": "名单描述",
			},
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
			"action_value": map[string]any{
				"type":        "string",
				"description": "bot_check 类型 / network_block 秒数",
			},
			"expire": map[string]any{
				"type":        "string",
				"description": "false 永久 / true 临时",
				"default":     "false",
			},
			"expire_time": map[string]any{
				"type":        "string",
				"description": "过期时间（秒），expire=true 时生效",
				"default":     "0",
			},
		},
		"required": []string{"name", "detail", "rule", "action"},
	}
}

func (f *CreateNameListFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	var list jxwaf.NameList
	b, _ := jsonMarshal(args)
	if err := jsonUnmarshal(b, &list); err != nil {
		return "", fmt.Errorf("参数解析失败: %w", err)
	}
	if list.Expire == "" {
		list.Expire = "false"
	}
	if list.ExpireTime == "" {
		list.ExpireTime = "0"
	}
	result, err := f.Client.CreateNameList(list)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("名单 %s 创建成功，响应: %s", list.Name, toJSON(result)), nil
}

// AddNameListItemFunc 添加名单条目
type AddNameListItemFunc struct {
	Client *jxwaf.Client
}

func (f *AddNameListItemFunc) Name() string { return "add_name_list_item" }

func (f *AddNameListItemFunc) Description() string {
	return "向名单添加条目"
}

func (f *AddNameListItemFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string", "description": "名单名"},
			"item": map[string]any{"type": "string", "description": "条目值（如 IP 地址）"},
		},
		"required": []string{"name", "item"},
	}
}

func (f *AddNameListItemFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	item, _ := args["item"].(string)
	if name == "" || item == "" {
		return "", fmt.Errorf("name 和 item 不能为空")
	}
	result, err := f.Client.AddNameListItem(name, item)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("条目 %s 添加到名单 %s 成功，响应: %s", item, name, toJSON(result)), nil
}

// CreateWebWhiteRuleFunc 创建 Web 白名单
type CreateWebWhiteRuleFunc struct {
	Client *jxwaf.Client
}

func (f *CreateWebWhiteRuleFunc) Name() string { return "create_web_white_rule" }

func (f *CreateWebWhiteRuleFunc) Description() string {
	return "创建 Web 白名单规则（命中跳过 Web 防护）"
}

func (f *CreateWebWhiteRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string"},
			"detail": map[string]any{"type": "string"},
			"matchs": map[string]any{
				"type":        "array",
				"description": "匹配条件，多个为 AND 关系",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"match_args":     map[string]any{"type": "array"},
						"args_prepocess": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"match_operator": map[string]any{"type": "string"},
						"match_value":    map[string]any{"type": "string"},
					},
				},
			},
		},
		"required": []string{"name", "detail", "matchs"},
	}
}

func (f *CreateWebWhiteRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	var rule jxwaf.WhiteRule
	b, _ := jsonMarshal(args)
	if err := jsonUnmarshal(b, &rule); err != nil {
		return "", fmt.Errorf("参数解析失败: %w", err)
	}
	result, err := f.Client.CreateWebWhiteRule(rule)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Web 白名单 %s 创建成功，响应: %s", rule.Name, toJSON(result)), nil
}

// CreateFlowWhiteRuleFunc 创建流量白名单
type CreateFlowWhiteRuleFunc struct {
	Client *jxwaf.Client
}

func (f *CreateFlowWhiteRuleFunc) Name() string { return "create_flow_white_rule" }

func (f *CreateFlowWhiteRuleFunc) Description() string {
	return "创建流量白名单规则（命中跳过流量防护）"
}

func (f *CreateFlowWhiteRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string"},
			"detail": map[string]any{"type": "string"},
			"matchs": map[string]any{"type": "array"},
		},
		"required": []string{"name", "detail", "matchs"},
	}
}

func (f *CreateFlowWhiteRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	var rule jxwaf.WhiteRule
	b, _ := jsonMarshal(args)
	if err := jsonUnmarshal(b, &rule); err != nil {
		return "", fmt.Errorf("参数解析失败: %w", err)
	}
	result, err := f.Client.CreateFlowWhiteRule(rule)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("流量白名单 %s 创建成功，响应: %s", rule.Name, toJSON(result)), nil
}
