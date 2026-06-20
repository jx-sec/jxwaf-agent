// Package agent 实现 LLM Agent 主循环与系统提示词构建
package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Skill 表示一个可按需加载的扩展知识
type Skill struct {
	Name        string // 短名（frontmatter 中的 name 字段）
	FileName    string // 文件名（如 component_dev.md）
	Description string // 描述（frontmatter 中的 description 字段）
	Content     string // 正文内容（不含 frontmatter）
}

// PromptBuilder 系统提示词构建器
// 启动时加载 prompts/core/*.md（常驻）和 prompts/skills/*.md（按需）到内存
type PromptBuilder struct {
	dir      string
	core     map[string]string // core/ 文件名 → 内容
	skills   []Skill           // skills/ 自动发现的扩展知识
	mu       sync.RWMutex
	alwaysOn []string // core/ 中常驻文件列表
}

// NewPromptBuilder 创建提示词构建器
func NewPromptBuilder(promptsDir string) (*PromptBuilder, error) {
	pb := &PromptBuilder{
		dir:      promptsDir,
		core:     make(map[string]string),
		alwaysOn: []string{"core.md", "modules.md"},
	}
	if err := pb.loadAll(); err != nil {
		return nil, err
	}
	return pb, nil
}

// loadAll 加载 core/ 和 skills/ 目录下的 md 文件
func (pb *PromptBuilder) loadAll() error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// 清空缓存
	pb.core = make(map[string]string)
	pb.skills = pb.skills[:0]

	// 1. 加载 core/ 目录（常驻提示词）
	coreDir := filepath.Join(pb.dir, "core")
	coreEntries, err := os.ReadDir(coreDir)
	if err != nil {
		return fmt.Errorf("读取 core 目录失败: %w", err)
	}
	for _, entry := range coreEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(coreDir, entry.Name()))
		if err != nil {
			return err
		}
		pb.core[entry.Name()] = string(content)
	}

	// 2. 加载 skills/ 目录（按需扩展知识，自动发现）
	skillsDir := filepath.Join(pb.dir, "skills")
	skillEntries, err := os.ReadDir(skillsDir)
	if err != nil {
		return fmt.Errorf("读取 skills 目录失败: %w", err)
	}
	for _, entry := range skillEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(skillsDir, entry.Name()))
		if err != nil {
			return err
		}
		name, desc, body := parseFrontmatter(string(raw))
		if name == "" {
			// frontmatter 缺少 name，用文件名（去 .md）作为 name
			name = strings.TrimSuffix(entry.Name(), ".md")
		}
		pb.skills = append(pb.skills, Skill{
			Name:        name,
			FileName:    entry.Name(),
			Description: desc,
			Content:     body,
		})
	}

	// 按 Name 排序，保证输出稳定
	sort.Slice(pb.skills, func(i, j int) bool {
		return pb.skills[i].Name < pb.skills[j].Name
	})

	return nil
}

// parseFrontmatter 解析 YAML 风格的 frontmatter（--- 包裹）
// 返回 name、description 和正文（不含 frontmatter）
func parseFrontmatter(content string) (name, description, body string) {
	body = content
	if !strings.HasPrefix(content, "---\n") {
		return
	}
	rest := content[4:] // 跳过 "---\n"
	idx := strings.Index(rest, "\n---\n")
	if idx < 0 {
		// 尝试以 "\n---" 结尾（无尾部换行）
		idx = strings.Index(rest, "\n---")
		if idx < 0 {
			return
		}
		frontmatter := rest[:idx]
		body = strings.TrimPrefix(rest[idx+4:], "\n")
		return parseFrontmatterFields(frontmatter, name, description, body)
	}
	frontmatter := rest[:idx]
	body = rest[idx+5:] // 跳过 "\n---\n"
	return parseFrontmatterFields(frontmatter, name, description, body)
}

func parseFrontmatterFields(frontmatter, _name, _desc, body string) (name, description, _ string) {
	name, description = _name, _desc
	for _, line := range strings.Split(frontmatter, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			name = strings.TrimSpace(line[len("name:"):])
		} else if strings.HasPrefix(line, "description:") {
			description = strings.TrimSpace(line[len("description:"):])
		}
	}
	return name, description, body
}

// GetContent 根据名称获取扩展知识内容（供 load_context function 调用）
// name 可为短名（如 "component_dev"）或文件名（如 "component_dev.md"）
func (pb *PromptBuilder) GetContent(name string) (string, bool) {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	for _, s := range pb.skills {
		if s.Name == name || s.FileName == name || s.FileName == name+".md" {
			return s.Content, true
		}
	}
	return "", false
}

// SkillNames 返回所有已发现的 skill 短名列表（供 load_context 的 enum 使用）
func (pb *PromptBuilder) SkillNames() []string {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	names := make([]string, 0, len(pb.skills))
	for _, s := range pb.skills {
		names = append(names, s.Name)
	}
	return names
}

// Build 动态构建系统提示词
func (pb *PromptBuilder) Build(userQuery string) string {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	var sb strings.Builder

	// 1. 常驻内容（core/ 目录，每次必带）
	for _, name := range pb.alwaysOn {
		if content, ok := pb.core[name]; ok {
			sb.WriteString(content)
			sb.WriteString("\n\n---\n\n")
		}
	}

	// 2. 扩展知识清单（LLM 通过 load_context 函数按需加载）
	if len(pb.skills) > 0 {
		sb.WriteString("# 扩展知识（按需加载）\n\n")
		sb.WriteString("以下扩展知识可通过调用 load_context 函数加载。根据用户需求判断是否需要加载：\n\n")
		sb.WriteString("| 知识名称 | 说明 |\n")
		sb.WriteString("|----------|------|\n")
		for _, s := range pb.skills {
			sb.WriteString("| ")
			sb.WriteString(s.Name)
			sb.WriteString(" | ")
			sb.WriteString(s.Description)
			sb.WriteString(" |\n")
		}
		sb.WriteString("\n调用方式：load_context(name=\"component_dev\")\n")
		sb.WriteString("可一次加载多个。不需要时无需加载。\n\n")
	}

	// 注：Function 使用指引与工作原则已外迁至 prompts/core/core.md，便于热更新维护

	return sb.String()
}

// Reload 热更新（修改 md 文件后调用，无需重启服务）
func (pb *PromptBuilder) Reload() error {
	return pb.loadAll()
}

// ListFiles 列出已加载的文件（调试用）
func (pb *PromptBuilder) ListFiles() []string {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	files := make([]string, 0, len(pb.core)+len(pb.skills))
	for name := range pb.core {
		files = append(files, "core/"+name)
	}
	for _, s := range pb.skills {
		files = append(files, "skills/"+s.FileName)
	}
	return files
}
