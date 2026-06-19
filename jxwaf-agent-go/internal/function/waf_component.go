package function

import (
	"context"
	"fmt"
	"jxwaf-agent-go/internal/jxwaf"
)

// CreateComponentFunc 创建防护组件
type CreateComponentFunc struct {
	Client *jxwaf.Client
}

func (f *CreateComponentFunc) Name() string { return "create_component" }

func (f *CreateComponentFunc) Description() string {
	return "创建防护组件（自定义 Lua 检测逻辑）。code_lua 为 Lua 源码，会自动 Base64 编码。必须兼容 LuaJIT（Lua 5.1），禁止使用 & | ~ >> << // goto 等语法。"
}

func (f *CreateComponentFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "组件名（小写下划线）",
			},
			"detail": map[string]any{
				"type":        "string",
				"description": "组件描述",
			},
			"code_lua": map[string]any{
				"type":        "string",
				"description": "Lua 源码，必须返回包含 check(conf_data) 函数的 table",
			},
			"conf": map[string]any{
				"type":        "string",
				"description": "组件配置 JSON 字符串",
			},
		},
		"required": []string{"name", "detail", "code_lua"},
	}
}

func (f *CreateComponentFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	detail, _ := args["detail"].(string)
	codeLua, _ := args["code_lua"].(string)
	conf, _ := args["conf"].(string)

	if name == "" || codeLua == "" {
		return "", fmt.Errorf("name 和 code_lua 不能为空")
	}

	// Base64 编码 Lua 代码
	codeBase64 := jxwaf.EncodeBase64([]byte(codeLua))

	comp := jxwaf.Component{
		Name:   name,
		Detail: detail,
		Code:   codeBase64,
		Conf:   conf,
	}
	result, err := f.Client.CreateComponent(comp)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("组件 %s 创建成功，响应: %s", name, toJSON(result)), nil
}

// ListComponentsFunc 查询组件列表
type ListComponentsFunc struct {
	Client *jxwaf.Client
}

func (f *ListComponentsFunc) Name() string { return "list_components" }

func (f *ListComponentsFunc) Description() string {
	return "查询防护组件列表"
}

func (f *ListComponentsFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"page": map[string]any{"type": "integer", "default": 1},
		},
	}
}

func (f *ListComponentsFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	page := 1
	if p, ok := args["page"].(float64); ok {
		page = int(p)
	}
	result, err := f.Client.ListComponents(page)
	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}
