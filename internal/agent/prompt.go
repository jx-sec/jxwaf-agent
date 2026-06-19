// Package agent 实现 LLM Agent 主循环与系统提示词构建
package agent

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PromptBuilder 系统提示词构建器
// 启动时加载 prompts/*.md 到内存，请求时动态拼接系统提示词
type PromptBuilder struct {
	dir      string
	cache    map[string]string   // 文件名 → 内容
	mu       sync.RWMutex
	alwaysOn []string            // 常驻文件（每次必带）
	onDemand map[string][]string // 文件名 → 触发关键词列表
}

// NewPromptBuilder 创建提示词构建器，加载 prompts 目录下所有 md 文件
func NewPromptBuilder(promptsDir string) (*PromptBuilder, error) {
	pb := &PromptBuilder{
		dir:   promptsDir,
		cache: make(map[string]string),
		// 常驻文件：核心规则 + 模块速查 + API 速查（约 2900 token）
		alwaysOn: []string{"core.md", "modules.md", "api.md"},
		// 按需文件：根据用户提问关键词注入
		onDemand: map[string][]string{
			"component_dev.md": {"组件", "component", "lua", "检测逻辑", "自定义", "bit.", "ngx.ctx", "jxwaf_user"},
			"playbook.md":      {"误报", "漏报", "调优", "排查", "误封", "放行", "解封", "can not decode"},
			"profiles.md":      {"参考", "已有方案", "log4j", "cc攻击", "cc 攻击", "范例", "案例"},
		},
	}
	if err := pb.loadAll(); err != nil {
		return nil, err
	}
	return pb, nil
}

// loadAll 加载所有 md 文件到内存缓存
func (pb *PromptBuilder) loadAll() error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	entries, err := os.ReadDir(pb.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(pb.dir, entry.Name()))
		if err != nil {
			return err
		}
		pb.cache[entry.Name()] = string(content)
	}
	return nil
}

// Build 动态构建系统提示词
// userQuery 为用户当前提问，用于按需注入判断
func (pb *PromptBuilder) Build(userQuery string) string {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	var sb strings.Builder

	// 1. 常驻内容（每次必带）
	for _, name := range pb.alwaysOn {
		if content, ok := pb.cache[name]; ok {
			sb.WriteString(content)
			sb.WriteString("\n\n---\n\n")
		}
	}

	// 2. 按需注入（根据用户提问关键词匹配）
	queryLower := strings.ToLower(userQuery)
	injected := make(map[string]bool)
	for fileName, keywords := range pb.onDemand {
		if injected[fileName] {
			continue
		}
		for _, kw := range keywords {
			if strings.Contains(queryLower, strings.ToLower(kw)) {
				if content, ok := pb.cache[fileName]; ok {
					sb.WriteString(content)
					sb.WriteString("\n\n---\n\n")
					injected[fileName] = true
				}
				break
			}
		}
	}

	// 3. Function 使用指引
	sb.WriteString("# Function 使用指引\n\n")
	sb.WriteString("你可以调用以下 function 完成 JXWAF 配置：\n\n")
	sb.WriteString("## 脚本生成类（仅预览不执行，前端展示配置卡片）\n")
	sb.WriteString("- generate_web_rule_script：生成 Web 防护规则配置脚本\n")
	sb.WriteString("- generate_flow_rule_script：生成流量防护规则配置脚本\n")
	sb.WriteString("- generate_component_script：生成防护组件配置脚本（Lua 代码）\n")
	sb.WriteString("- generate_name_list_script：生成名单防护配置脚本\n\n")
	sb.WriteString("## 执行类（直接调用 JXWAF API 下发配置）\n")
	sb.WriteString("- create_web_rule：创建 Web 防护规则（默认 watch 模式）\n")
	sb.WriteString("- create_flow_rule：创建流量防护规则（频率统计限速）\n")
	sb.WriteString("- create_component：创建防护组件（Lua 代码自动 Base64 编码）\n")
	sb.WriteString("- create_name_list / add_name_list_item：创建名单并添加条目\n")
	sb.WriteString("- create_web_white_rule / create_flow_white_rule：创建白名单\n")
	sb.WriteString("- list_web_rules / list_flow_rules / list_components：查询已有配置\n")
	sb.WriteString("- verify_config：验证规则是否生效（创建规则后务必调用）\n\n")
	sb.WriteString("## 工作原则\n")
	sb.WriteString("1. **两步流程**：用户需求涉及\"生成/创建/配置\"时，优先调用 generate_*_script 生成配置脚本供预览；用户明确说\"应用/执行/下发\"或点击\"应用到 WAF\"按钮后，再调用 create_* 执行\n")
	sb.WriteString("2. 新规则默认 watch 模式，验证无误报后改 block\n")
	sb.WriteString("3. 创建规则后必须调用 verify_config 验证效果\n")
	sb.WriteString("4. 组件代码必须兼容 LuaJIT（Lua 5.1），禁止使用 & | ~ >> << // goto\n")
	sb.WriteString("5. 流量规则 exceed_count 不低于业务峰值 QPS 的 2 倍\n")
	sb.WriteString("6. 生成脚本后，主动提示用户可点击\"应用到 WAF\"按钮或回复\"应用\"来执行配置\n")

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
	files := make([]string, 0, len(pb.cache))
	for name := range pb.cache {
		files = append(files, name)
	}
	return files
}
