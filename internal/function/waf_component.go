package function

import (
	"context"
)

// ListComponentsFunc 查询组件列表
type ListComponentsFunc struct {
	Client interface {
		ListComponents(page int) (map[string]any, error)
	}
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
