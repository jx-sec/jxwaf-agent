// Package function 实现 LLM function calling 的注册与执行
package function

import "context"

// Function 接口：所有 function 实现这个接口
type Function interface {
	Name() string
	Description() string
	Schema() map[string]any
	Execute(ctx context.Context, args map[string]any) (string, error)
}

// Registry Function 注册中心
type Registry struct {
	funcs map[string]Function
}

// NewRegistry 创建注册中心
func NewRegistry() *Registry {
	return &Registry{funcs: make(map[string]Function)}
}

// Register 注册 function
func (r *Registry) Register(f Function) {
	r.funcs[f.Name()] = f
}

// Get 获取 function
func (r *Registry) Get(name string) (Function, bool) {
	f, ok := r.funcs[name]
	return f, ok
}

// ToTools 转换为 LLM 的 tools 参数格式
func (r *Registry) ToTools() []map[string]any {
	tools := make([]map[string]any, 0, len(r.funcs))
	for _, f := range r.funcs {
		tools = append(tools, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        f.Name(),
				"description": f.Description(),
				"parameters":  f.Schema(),
			},
		})
	}
	return tools
}
