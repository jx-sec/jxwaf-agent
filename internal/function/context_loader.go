package function

import (
	"context"
	"fmt"
	"strings"
)

// LoadContextFunc 加载扩展知识（skill 机制）
// LLM 根据用户需求判断是否需要加载扩展知识，通过此函数获取完整内容
// 可用的 skill 名称由 SkillNames 动态提供（从 prompts/skills/ 自动发现）
type LoadContextFunc struct {
	// GetContent 根据名称获取扩展知识内容，返回 (内容, 是否找到)
	GetContent func(name string) (string, bool)
	// SkillNames 可用的 skill 短名列表（动态，从 frontmatter 自动发现）
	SkillNames []string
}

func (f *LoadContextFunc) Name() string { return "load_context" }

func (f *LoadContextFunc) Description() string {
	return "加载扩展知识。根据用户需求判断是否需要加载系统提示词中列出的扩展知识，可多次调用加载多个。" +
		"可用知识名称参见系统提示词中的「扩展知识」表格。"
}

func (f *LoadContextFunc) Schema() map[string]any {
	props := map[string]any{
		"name": map[string]any{
			"type":        "string",
			"description": "要加载的知识名称（参见系统提示词中的扩展知识表格）",
		},
	}
	// 动态 enum：有 skill 时添加枚举约束
	if len(f.SkillNames) > 0 {
		props["name"] = map[string]any{
			"type":        "string",
			"description": "要加载的知识名称",
			"enum":        f.SkillNames,
		}
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   []string{"name"},
	}
}

func (f *LoadContextFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, ok := args["name"].(string)
	if !ok {
		return "", fmt.Errorf("name 参数必填")
	}
	content, found := f.GetContent(name)
	if !found {
		available := "无"
		if len(f.SkillNames) > 0 {
			available = strings.Join(f.SkillNames, ", ")
		}
		return "", fmt.Errorf("未找到知识: %s，可选值: %s", name, available)
	}
	return content, nil
}
