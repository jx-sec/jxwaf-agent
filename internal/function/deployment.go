package function

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"jxwaf-agent-go/internal/ssh"
)

// =============================================================================
// 部署执行器（共享状态，跟踪一次会话中所有已执行的命令）
// =============================================================================

// DeploymentExecutor 部署执行器，在单次 Agent 循环中共享
type DeploymentExecutor struct {
	mu       sync.Mutex
	commands []ExecutedCommand
}

// ExecutedCommand 已执行的命令记录
type ExecutedCommand struct {
	Step        string `json:"step"`
	Command     string `json:"command"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    int    `json:"exit_code"`
	Success     bool   `json:"success"`
	Duration    string `json:"duration"`
	Timestamp   string `json:"timestamp"`
	IsRisky     bool   `json:"is_risky"`
	ServerIP    string `json:"server_ip"`
}

// NewDeploymentExecutor 创建部署执行器
func NewDeploymentExecutor() *DeploymentExecutor {
	return &DeploymentExecutor{}
}

// Record 记录一条已执行命令
func (e *DeploymentExecutor) Record(cmd ExecutedCommand) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.commands = append(e.commands, cmd)
}

// GetSummary 返回所有已执行命令的摘要
func (e *DeploymentExecutor) GetSummary() []ExecutedCommand {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ExecutedCommand, len(e.commands))
	copy(out, e.commands)
	return out
}

// =============================================================================
// CheckServerEnvironmentFunc：检查服务器环境（部署前置检查）
// =============================================================================
type CheckServerEnvironmentFunc struct{}

func (f *CheckServerEnvironmentFunc) Name() string { return "check_server_environment" }

func (f *CheckServerEnvironmentFunc) Description() string {
	return "通过 SSH 连接目标服务器，检查部署前置条件：操作系统、Docker、Docker Compose、磁盘空间、内存。" +
		"部署前必须先调用此函数确认环境是否满足要求。密码仅用于连接，不会记录到日志。"
}

func (f *CheckServerEnvironmentFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host":     map[string]any{"type": "string", "description": "目标服务器 IP"},
			"port":     map[string]any{"type": "integer", "description": "SSH 端口，默认 22", "default": 22},
			"username": map[string]any{"type": "string", "description": "SSH 用户名（通常 root）"},
			"password": map[string]any{"type": "string", "description": "SSH 密码"},
		},
		"required": []string{"host", "username", "password"},
	}
}

func (f *CheckServerEnvironmentFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	host, _ := args["host"].(string)
	port := 22
	if p, ok := args["port"].(float64); ok && p > 0 {
		port = int(p)
	}
	username, _ := args["username"].(string)
	password, _ := args["password"].(string)

	if host == "" || username == "" || password == "" {
		return "", fmt.Errorf("host、username、password 不能为空")
	}

	client := ssh.NewClient(host, port, username, password)
	if err := client.Connect(); err != nil {
		return "", fmt.Errorf("SSH 连接失败: %w", err)
	}
	defer client.Close()

	// 并行检查项合并为一条命令，减少 SSH 往返
	checkScript := `echo "===OS==="; cat /etc/os-release 2>/dev/null | head -5; echo "===ARCH==="; uname -m; echo "===CPU==="; nproc; echo "===MEM==="; free -h 2>/dev/null | grep Mem || echo "unknown"; echo "===DISK==="; df -h / 2>/dev/null | tail -1; echo "===DOCKER==="; docker --version 2>/dev/null || echo "not_installed"; echo "===COMPOSE==="; docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo "not_installed"; echo "===GIT==="; git --version 2>/dev/null || echo "not_installed"`

	result, err := client.Exec(checkScript, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("环境检查命令执行失败: %w", err)
	}

	// 解析检查结果
	envInfo := parseEnvironmentOutput(result.Stdout)
	envInfo["ssh_connected"] = true
	envInfo["docker_installed"] = strings.Contains(result.Stdout, "Docker version") || strings.Contains(result.Stdout, "docker version")
	envInfo["compose_installed"] = !strings.Contains(result.Stdout, "not_installed") && (strings.Contains(result.Stdout, "Docker Compose") || strings.Contains(result.Stdout, "docker compose"))

	// 判断是否满足部署要求
	requirements := map[string]bool{
		"操作系统": envInfo["os_name"] != "",
		"Docker": envInfo["docker_installed"].(bool),
		"Docker Compose": envInfo["compose_installed"].(bool),
	}

	meetsReq := true
	var issues []string
	for k, v := range requirements {
		if !v {
			meetsReq = false
			issues = append(issues, k+"未就绪")
		}
	}

	envInfo["meets_requirements"] = meetsReq
	if len(issues) > 0 {
		envInfo["issues"] = issues
		envInfo["suggestion"] = "Docker 或 Docker Compose 未安装，部署计划中将包含安装步骤"
	} else {
		envInfo["suggestion"] = "环境满足部署要求，可继续部署"
	}

	return toJSON(envInfo), nil
}

// parseEnvironmentOutput 解析环境检查脚本输出
func parseEnvironmentOutput(output string) map[string]any {
	info := map[string]any{}
	sections := strings.Split(output, "===")
	for i := 0; i+1 < len(sections); i += 2 {
		key := strings.TrimSpace(sections[i])
		val := strings.TrimSpace(sections[i+1])
		switch key {
		case "OS":
			lines := strings.Split(val, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					info["os_name"] = strings.Trim(line[len("PRETTY_NAME="):], `"`)
				}
			}
		case "ARCH":
			info["arch"] = val
		case "CPU":
			info["cpu_cores"] = val
		case "MEM":
			info["memory"] = val
		case "DISK":
			info["disk_root"] = val
		case "DOCKER":
			info["docker_version"] = val
		case "COMPOSE":
			info["compose_version"] = val
		case "GIT":
			info["git_version"] = val
		}
	}
	return info
}

// =============================================================================
// PlanJxwafDeploymentFunc：生成部署计划（不执行，仅预览）
// =============================================================================
type PlanJxwafDeploymentFunc struct{}

func (f *PlanJxwafDeploymentFunc) Name() string { return "plan_jxwaf_deployment" }

func (f *PlanJxwafDeploymentFunc) Description() string {
	return "根据版本和组件生成 JXWAF 部署计划（不执行任何命令）。计划包含每一步的命令、是否超出文档标准流程、风险说明。" +
		"标准版一键部署所有组件；专业版可选部署控制台(console)、节点(node)、日志系统(log)。" +
		"返回的部署计划会展示给用户确认，用户同意后再调用 execute_ssh_command 逐步执行。"
}

func (f *PlanJxwafDeploymentFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"version": map[string]any{
				"type":        "string",
				"enum":        []string{"standard", "professional"},
				"description": "部署版本：standard=标准版(一键部署), professional=专业版(分组件部署)",
			},
			"components": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string", "enum": []string{"console", "node", "log"}},
				"description": "专业版要部署的组件列表。标准版忽略此参数（一键全部部署）。",
			},
			"server_ip": map[string]any{"type": "string", "description": "目标服务器 IP"},
			"node_config": map[string]any{
				"type": "object",
				"description": "专业版节点配置（部署 node 组件时需要）",
				"properties": map[string]any{
					"jxwaf_server": map[string]any{"type": "string", "description": "控制台地址，如 http://1.2.3.4"},
					"waf_auth":     map[string]any{"type": "string", "description": "控制台 waf_auth 值"},
					"http_port":    map[string]any{"type": "string", "description": "HTTP 监听端口", "default": "80"},
					"https_port":   map[string]any{"type": "string", "description": "HTTPS 监听端口", "default": "443"},
				},
			},
			"install_docker": map[string]any{
				"type":        "boolean",
				"description": "是否在计划中包含 Docker 安装步骤（如服务器已装则设为 false）",
				"default":     true,
			},
		},
		"required": []string{"version", "server_ip"},
	}
}

func (f *PlanJxwafDeploymentFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	version, _ := args["version"].(string)
	serverIP, _ := args["server_ip"].(string)
	installDocker := true
	if v, ok := args["install_docker"].(bool); ok {
		installDocker = v
	}

	if version == "" {
		return "", fmt.Errorf("version 不能为空")
	}

	var components []string
	if raw, ok := args["components"].([]any); ok {
		for _, c := range raw {
			if s, ok := c.(string); ok {
				components = append(components, s)
			}
		}
	}
	if version == "professional" && len(components) == 0 {
		components = []string{"console"} // 默认只部署控制台
	}

	var nodeConfig map[string]any
	if raw, ok := args["node_config"].(map[string]any); ok {
		nodeConfig = raw
	}

	plan := buildDeploymentPlan(version, components, serverIP, installDocker, nodeConfig)
	return toJSON(plan), nil
}

// deploymentPlan 部署计划结构
type deploymentPlan struct {
	Version    string         `json:"version"`
	ServerIP   string         `json:"server_ip"`
	Components []string       `json:"components"`
	Steps      []planStep     `json:"steps"`
	Summary    string         `json:"summary"`
}

// planStep 部署计划步骤
type planStep struct {
	StepID      int      `json:"step_id"`
	Category    string   `json:"category"`     // standard(文档标准流程) | beyond_docs(超出文档)
	Component   string   `json:"component"`    // common/console/node/log
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
	IsRisky     bool     `json:"is_risky"`
	RiskReason  string   `json:"risk_reason,omitempty"`
}

// buildDeploymentPlan 根据版本和组件构建部署计划（命令来自官方文档）
func buildDeploymentPlan(version string, components []string, serverIP string, installDocker bool, nodeConfig map[string]any) *deploymentPlan {
	plan := &deploymentPlan{
		Version:    version,
		ServerIP:   serverIP,
		Components: components,
		Steps:      []planStep{},
	}

	stepID := 0
	nextStep := func() int { stepID++; return stepID }

	// 通用步骤：安装 Docker、克隆仓库
	if installDocker {
		plan.Steps = append(plan.Steps, planStep{
			StepID:      nextStep(),
			Category:    "standard",
			Component:   "common",
			Description: "安装 Docker（使用阿里云镜像源，来自官方文档）",
			Commands:    []string{"curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun"},
			IsRisky:     false,
		})
	}

	plan.Steps = append(plan.Steps, planStep{
		StepID:      nextStep(),
		Category:    "standard",
		Component:   "common",
		Description: "克隆 JXWAF 仓库（来自官方文档）",
		Commands:    []string{"git clone --depth=1 https://github.com/jx-sec/jxwaf.git"},
		IsRisky:     false,
	})

	if version == "standard" {
		// 标准版一键部署
		plan.Steps = append(plan.Steps, planStep{
			StepID:      nextStep(),
			Category:    "standard",
			Component:   "standard",
			Description: "进入标准版目录并启动全部服务（来自官方文档）",
			Commands:    []string{"cd jxwaf/Standard/ && docker compose up -d"},
			IsRisky:     false,
		})
		plan.Steps = append(plan.Steps, planStep{
			StepID:      nextStep(),
			Category:    "standard",
			Component:   "standard",
			Description: "检查服务运行状态",
			Commands:    []string{"cd jxwaf/Standard/ && docker compose ps"},
			IsRisky:     false,
		})
		plan.Summary = fmt.Sprintf("标准版一键部署到 %s，共 %d 步。部署完成后访问 http://%s:8000", serverIP, len(plan.Steps), serverIP)
		return plan
	}

	// 专业版分组件部署
	for _, comp := range components {
		switch comp {
		case "console":
			plan.Steps = append(plan.Steps, planStep{
				StepID:      nextStep(),
				Category:    "standard",
				Component:   "console",
				Description: "进入专业版控制台目录并启动（来自官方文档）",
				Commands:    []string{"cd jxwaf/Professional/jxwaf_admin_server/ && docker compose up -d"},
				IsRisky:     false,
			})
			plan.Steps = append(plan.Steps, planStep{
				StepID:      nextStep(),
				Category:    "standard",
				Component:   "console",
				Description: "检查控制台服务运行状态",
				Commands:    []string{"cd jxwaf/Professional/jxwaf_admin_server/ && docker compose ps"},
				IsRisky:     false,
			})

		case "node":
			// 节点需要修改配置，属于超出标准文档流程的自定义操作
			jxwafServer, _ := nodeConfig["jxwaf_server"].(string)
			wafAuth, _ := nodeConfig["waf_auth"].(string)
			httpPort, _ := nodeConfig["http_port"].(string)
			httpsPort, _ := nodeConfig["https_port"].(string)
			if httpPort == "" {
				httpPort = "80"
			}
			if httpsPort == "" {
				httpsPort = "443"
			}

			if jxwafServer == "" || wafAuth == "" {
				// 缺少必要配置，标记为需用户确认
				plan.Steps = append(plan.Steps, planStep{
					StepID:      nextStep(),
					Category:    "beyond_docs",
					Component:   "node",
					Description: "修改节点 docker-compose.yml 配置（JXWAF_SERVER 和 WAF_AUTH）——缺少控制台地址或 waf_auth，需用户确认",
					Commands:    []string{"cd jxwaf/Professional/jxwaf_node && vim docker-compose.yml"},
					IsRisky:     true,
					RiskReason:  "节点配置需要控制台地址(jxwaf_server)和 waf_auth，当前未提供。需用户确认后手动修改或提供配置值。",
				})
			} else {
				// 使用 sed 自动替换配置值（超出文档标准流程，因为文档是手动 vim 修改）
				sedCmds := []string{
					fmt.Sprintf("cd jxwaf/Professional/jxwaf_node && sed -i 's|JXWAF_SERVER:.*|JXWAF_SERVER: %s|' docker-compose.yml", jxwafServer),
					fmt.Sprintf("cd jxwaf/Professional/jxwaf_node && sed -i 's|WAF_AUTH:.*|WAF_AUTH: %s|' docker-compose.yml", wafAuth),
				}
				if httpPort != "80" {
					sedCmds = append(sedCmds, fmt.Sprintf("cd jxwaf/Professional/jxwaf_node && sed -i 's|HTTP_PORT:.*|HTTP_PORT: %s|' docker-compose.yml", httpPort))
				}
				if httpsPort != "443" {
					sedCmds = append(sedCmds, fmt.Sprintf("cd jxwaf/Professional/jxwaf_node && sed -i 's|HTTPS_PORT:.*|HTTPS_PORT: %s|' docker-compose.yml", httpsPort))
				}
				plan.Steps = append(plan.Steps, planStep{
					StepID:      nextStep(),
					Category:    "beyond_docs",
					Component:   "node",
					Description: fmt.Sprintf("修改节点 docker-compose.yml 配置（JXWAF_SERVER=%s, WAF_AUTH=***, HTTP_PORT=%s, HTTPS_PORT=%s）", jxwafServer, httpPort, httpsPort),
					Commands:    sedCmds,
					IsRisky:     true,
					RiskReason:  "使用 sed 自动修改 docker-compose.yml 超出官方文档（文档建议手动 vim 修改）。修改配置文件有风险，需用户确认。",
				})
			}

			plan.Steps = append(plan.Steps, planStep{
				StepID:      nextStep(),
				Category:    "standard",
				Component:   "node",
				Description: "启动专业版节点服务（来自官方文档）",
				Commands:    []string{"cd jxwaf/Professional/jxwaf_node && docker compose up -d"},
				IsRisky:     false,
			})
			plan.Steps = append(plan.Steps, planStep{
				StepID:      nextStep(),
				Category:    "standard",
				Component:   "node",
				Description: "检查节点服务运行状态",
				Commands:    []string{"cd jxwaf/Professional/jxwaf_node && docker compose ps"},
				IsRisky:     false,
			})

		case "log":
			plan.Steps = append(plan.Steps, planStep{
				StepID:      nextStep(),
				Category:    "standard",
				Component:   "log",
				Description: "进入专业版 JXLOG 目录并启动（来自官方文档）",
				Commands:    []string{"cd jxwaf/Professional/jxlog && docker compose up -d"},
				IsRisky:     false,
			})
			plan.Steps = append(plan.Steps, planStep{
				StepID:      nextStep(),
				Category:    "standard",
				Component:   "log",
				Description: "检查 JXLOG 服务运行状态",
				Commands:    []string{"cd jxwaf/Professional/jxlog && docker compose ps"},
				IsRisky:     false,
			})
		}
	}

	compStr := strings.Join(components, ", ")
	plan.Summary = fmt.Sprintf("专业版部署到 %s，组件: %s，共 %d 步。", serverIP, compStr, len(plan.Steps))
	if contains(components, "console") {
		plan.Summary += fmt.Sprintf(" 控制台访问地址: http://%s", serverIP)
	}
	return plan
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// =============================================================================
// ExecuteSSHCommandFunc：通过 SSH 执行单条命令
// =============================================================================
type ExecuteSSHCommandFunc struct {
	Executor *DeploymentExecutor
}

func (f *ExecuteSSHCommandFunc) Name() string { return "execute_ssh_command" }

func (f *ExecuteSSHCommandFunc) Description() string {
	return "通过 SSH 在目标服务器上执行单条命令。对于超出官方文档标准流程的风险操作（is_risky=true），" +
		"必须先以 user_confirmed=false 调用，返回确认请求后向用户说明风险并等待用户同意，" +
		"用户确认后再以 user_confirmed=true 重新调用执行。所有执行的命令都会被记录，最终通过 get_deployment_summary 返回。"
}

func (f *ExecuteSSHCommandFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host":          map[string]any{"type": "string", "description": "目标服务器 IP"},
			"port":          map[string]any{"type": "integer", "description": "SSH 端口", "default": 22},
			"username":      map[string]any{"type": "string", "description": "SSH 用户名"},
			"password":      map[string]any{"type": "string", "description": "SSH 密码"},
			"command":       map[string]any{"type": "string", "description": "要执行的命令"},
			"step_name":     map[string]any{"type": "string", "description": "步骤名称（用于记录和展示）"},
			"is_risky":      map[string]any{"type": "boolean", "description": "是否为超出文档的风险操作", "default": false},
			"user_confirmed": map[string]any{"type": "boolean", "description": "用户是否已确认执行此风险操作", "default": false},
			"timeout_seconds": map[string]any{"type": "integer", "description": "超时时间（秒），默认 120", "default": 120},
		},
		"required": []string{"host", "username", "password", "command", "step_name"},
	}
}

func (f *ExecuteSSHCommandFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	host, _ := args["host"].(string)
	port := 22
	if p, ok := args["port"].(float64); ok && p > 0 {
		port = int(p)
	}
	username, _ := args["username"].(string)
	password, _ := args["password"].(string)
	command, _ := args["command"].(string)
	stepName, _ := args["step_name"].(string)
	isRisky := false
	if v, ok := args["is_risky"].(bool); ok {
		isRisky = v
	}
	userConfirmed := false
	if v, ok := args["user_confirmed"].(bool); ok {
		userConfirmed = v
	}
	timeoutSec := 120
	if v, ok := args["timeout_seconds"].(float64); ok && v > 0 {
		timeoutSec = int(v)
	}

	if host == "" || username == "" || password == "" || command == "" {
		return "", fmt.Errorf("host、username、password、command 不能为空")
	}

	// 风险操作未确认 → 返回确认请求，不执行
	if isRisky && !userConfirmed {
		result := map[string]any{
			"status":          "confirmation_required",
			"step_name":       stepName,
			"command":         command,
			"message":         "此操作超出官方文档标准流程，需要用户确认后才能执行",
			"action_required": "请向用户说明此操作的内容和风险，等待用户回复确认后再以 user_confirmed=true 重新调用",
		}
		return toJSON(result), nil
	}

	// 执行命令
	client := ssh.NewClient(host, port, username, password)
	if err := client.Connect(); err != nil {
		// 连接失败也记录
		f.Executor.Record(ExecutedCommand{
			Step:      stepName,
			Command:   command,
			Stderr:    fmt.Sprintf("SSH 连接失败: %v", err),
			ExitCode:  -1,
			Success:   false,
			Timestamp: time.Now().Format(time.RFC3339),
			IsRisky:   isRisky,
			ServerIP:  host,
		})
		return "", fmt.Errorf("SSH 连接失败: %w", err)
	}
	defer client.Close()

	result, err := client.Exec(command, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		// 执行出错（如超时）
		f.Executor.Record(ExecutedCommand{
			Step:      stepName,
			Command:   command,
			Stderr:    err.Error(),
			ExitCode:  -1,
			Success:   false,
			Timestamp: time.Now().Format(time.RFC3339),
			IsRisky:   isRisky,
			ServerIP:  host,
		})
		return "", fmt.Errorf("命令执行失败: %w", err)
	}

	// 记录已执行命令
	f.Executor.Record(ExecutedCommand{
		Step:      stepName,
		Command:   command,
		Stdout:    result.Stdout,
		Stderr:    result.Stderr,
		ExitCode:  result.ExitCode,
		Success:   result.Success,
		Duration:  result.Duration,
		Timestamp: time.Now().Format(time.RFC3339),
		IsRisky:   isRisky,
		ServerIP:  host,
	})

	// 返回执行结果（不包含密码）
	resp := map[string]any{
		"status":    map[bool]string{true: "success", false: "failed"}[result.Success],
		"step_name": stepName,
		"command":   command,
		"stdout":    result.Stdout,
		"stderr":    result.Stderr,
		"exit_code": result.ExitCode,
		"duration":  result.Duration,
		"is_risky":  isRisky,
	}
	if !result.Success {
		resp["suggestion"] = "命令执行失败，请分析 stderr 输出。如果是可修复的问题（如缺少依赖），可调整后重试；如无法自动修复，向用户报告问题并建议手动处理。"
	}
	return toJSON(resp), nil
}

// =============================================================================
// GetDeploymentSummaryFunc：获取部署执行摘要（所有已执行命令）
// =============================================================================
type GetDeploymentSummaryFunc struct {
	Executor *DeploymentExecutor
}

func (f *GetDeploymentSummaryFunc) Name() string { return "get_deployment_summary" }

func (f *GetDeploymentSummaryFunc) Description() string {
	return "获取本次部署会话中所有已执行的 SSH 命令摘要，包括每条命令的步骤名、命令内容、输出、退出码、耗时。" +
		"部署完成后调用此函数向用户展示完整的执行记录。"
}

func (f *GetDeploymentSummaryFunc) Schema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

func (f *GetDeploymentSummaryFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	commands := f.Executor.GetSummary()
	total := len(commands)
	successCount := 0
	failCount := 0
	for _, cmd := range commands {
		if cmd.Success {
			successCount++
		} else {
			failCount++
		}
	}

	summary := map[string]any{
		"total_commands": total,
		"success_count":  successCount,
		"fail_count":     failCount,
		"commands":       commands,
		"overall_status": "all_success",
	}
	if failCount > 0 {
		summary["overall_status"] = "has_failures"
	}
	if total == 0 {
		summary["overall_status"] = "no_commands"
		summary["message"] = "尚未执行任何命令"
	}
	return toJSON(summary), nil
}

// =============================================================================
// VerifyDeploymentFunc：验证部署结果
// =============================================================================
type VerifyDeploymentFunc struct{}

func (f *VerifyDeploymentFunc) Name() string { return "verify_deployment" }

func (f *VerifyDeploymentFunc) Description() string {
	return "通过 SSH 检查 JXWAF 部署是否成功：检查 Docker 容器运行状态、端口监听、控制台可访问性。"
}

func (f *VerifyDeploymentFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host":     map[string]any{"type": "string", "description": "目标服务器 IP"},
			"port":     map[string]any{"type": "integer", "description": "SSH 端口", "default": 22},
			"username": map[string]any{"type": "string", "description": "SSH 用户名"},
			"password": map[string]any{"type": "string", "description": "SSH 密码"},
			"version":  map[string]any{"type": "string", "enum": []string{"standard", "professional"}, "description": "部署版本"},
			"component": map[string]any{
				"type":        "string",
				"enum":        []string{"console", "node", "log", "standard"},
				"description": "验证的组件",
			},
			"console_port": map[string]any{"type": "integer", "description": "控制台端口（标准版默认 8000，专业版默认 80）", "default": 8000},
		},
		"required": []string{"host", "username", "password", "version", "component"},
	}
}

func (f *VerifyDeploymentFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	host, _ := args["host"].(string)
	port := 22
	if p, ok := args["port"].(float64); ok && p > 0 {
		port = int(p)
	}
	username, _ := args["username"].(string)
	password, _ := args["password"].(string)
	version, _ := args["version"].(string)
	component, _ := args["component"].(string)
	consolePort := 8000
	if p, ok := args["console_port"].(float64); ok && p > 0 {
		consolePort = int(p)
	}

	client := ssh.NewClient(host, port, username, password)
	if err := client.Connect(); err != nil {
		return "", fmt.Errorf("SSH 连接失败: %w", err)
	}
	defer client.Close()

	// 根据版本和组件确定检查目录
	var dir string
	if version == "standard" {
		dir = "jxwaf/Standard/"
	} else {
		switch component {
		case "console":
			dir = "jxwaf/Professional/jxwaf_admin_server/"
		case "node":
			dir = "jxwaf/Professional/jxwaf_node/"
		case "log":
			dir = "jxwaf/Professional/jxlog/"
		}
	}

	// 检查容器状态和端口
	verifyScript := fmt.Sprintf("echo '===CONTAINERS==='; cd %s && docker compose ps 2>/dev/null; echo '===PORTS==='; ss -tlnp 2>/dev/null | grep -E ':(80|443|8000|8080|3306|8877|9000|9004) ' || echo 'no_matching_ports'", dir)
	result, err := client.Exec(verifyScript, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("验证命令执行失败: %w", err)
	}

	verifyResult := map[string]any{
		"version":   version,
		"component": component,
		"server_ip": host,
		"containers": result.Stdout,
		"success":   result.Success,
	}

	// 如果是控制台，额外检查 HTTP 可访问性
	if component == "console" || component == "standard" {
		url := fmt.Sprintf("http://127.0.0.1:%d", consolePort)
		httpCheck, _ := client.Exec(fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' --max-time 5 %s || echo 'unreachable'", url), 10*time.Second)
		verifyResult["console_url"] = fmt.Sprintf("http://%s:%d", host, consolePort)
		verifyResult["console_http_status"] = httpCheck.Stdout
		if httpCheck.Stdout == "200" || strings.HasPrefix(httpCheck.Stdout, "30") {
			verifyResult["console_accessible"] = true
			verifyResult["message"] = "控制台可正常访问"
		} else {
			verifyResult["console_accessible"] = false
			verifyResult["message"] = fmt.Sprintf("控制台访问异常，HTTP 状态: %s，可能需要等待服务启动", httpCheck.Stdout)
		}
	}

	return toJSON(verifyResult), nil
}
