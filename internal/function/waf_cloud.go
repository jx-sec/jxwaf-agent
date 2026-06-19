package function

import (
	"context"
	"encoding/json"
	"fmt"

	"jxwaf-agent-go/internal/jxwaf"
)

// =============================================================================
// DeployToCloudFunc：部署配置到云端验证环境
// =============================================================================
type DeployToCloudFunc struct {
	Client *jxwaf.Client
}

func (f *DeployToCloudFunc) Name() string { return "deploy_to_cloud" }

func (f *DeployToCloudFunc) Description() string {
	return "将生成的 WAF 配置部署到云端验证环境。接受 generate_*_script 输出的 rules 数组。部署后等待约 5 秒生效。"
}

func (f *DeployToCloudFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"config_type": map[string]any{
				"type":        "string",
				"enum":        []string{"web_rule", "flow_rule", "component", "name_list", "web_white", "flow_white"},
				"description": "配置类型",
			},
			"rules": map[string]any{
				"type":        "array",
				"description": "配置规则数组（与 generate_*_script 输出格式一致）",
			},
		},
		"required": []string{"config_type", "rules"},
	}
}

func (f *DeployToCloudFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	configType, _ := args["config_type"].(string)
	if configType == "" {
		return "", fmt.Errorf("config_type 不能为空")
	}

	// TODO: 云端 API 就绪后实现实际部署逻辑
	// 当前返回成功提示，供 LLM 继续后续验证流程
	result := map[string]any{
		"status":      "deployed",
		"config_type": configType,
		"message":     fmt.Sprintf("配置已部署到云端验证环境（%s），约 5 秒后生效", configType),
		"note":        "云端 API 接口待接入",
	}
	return toJSON(result), nil
}

// =============================================================================
// VerifyInCloudFunc：在云端验证环境执行测试
// =============================================================================
type VerifyInCloudFunc struct {
	Client    *jxwaf.Client
	VerifyURL string
}

func (f *VerifyInCloudFunc) Name() string { return "verify_in_cloud" }

func (f *VerifyInCloudFunc) Description() string {
	return "在云端验证环境执行测试用例，通过攻击日志查询验证规则是否生效。支持验证拦截(block)和放行(pass)。"
}

func (f *VerifyInCloudFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"test_cases": map[string]any{
				"type":        "array",
				"description": "测试用例数组（由 generate_*_script 生成）",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":    map[string]any{"type": "string"},
						"method":  map[string]any{"type": "string", "default": "GET"},
						"path":    map[string]any{"type": "string"},
						"headers": map[string]any{"type": "object"},
						"body":    map[string]any{"type": "string"},
						"assert": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"type":            map[string]any{"type": "string"},
								"expected_status": map[string]any{"type": "integer"},
							},
						},
						"flow_count":    map[string]any{"type": "integer", "default": 1},
						"flow_interval": map[string]any{"type": "number", "default": 0.1},
					},
				},
			},
		},
		"required": []string{"test_cases"},
	}
}

func (f *VerifyInCloudFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	// 解析测试用例
	var cases []jsonCase
	if raw, ok := args["test_cases"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &cases)
	}

	if len(cases) == 0 {
		return "", fmt.Errorf("test_cases 不能为空")
	}

	// TODO: 云端 API 就绪后实现真实验证
	// 1. 逐条发送 HTTP 请求到 verify_url
	// 2. 查询攻击日志 (get_soc_log_query_list) 确认拦截结果
	// 3. 对比 assert 期望 vs 实际结果
	// 4. 返回验证报告

	report := map[string]any{
		"status":  "verified",
		"total":   len(cases),
		"message": fmt.Sprintf("已执行 %d 条测试用例验证", len(cases)),
		"note":    "云端验证 API 待接入，当前为模拟结果",
	}
	return toJSON(report), nil
}

type jsonCase struct {
	Name         string         `json:"name"`
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Headers      map[string]any `json:"headers"`
	Body         string         `json:"body"`
	Assert       jsonAssert     `json:"assert"`
	FlowCount    int            `json:"flow_count"`
	FlowInterval float64        `json:"flow_interval"`
}

type jsonAssert struct {
	Type           string `json:"type"`
	ExpectedStatus int    `json:"expected_status"`
}

// =============================================================================
// CleanupCloudFunc：清理云端验证环境
// =============================================================================
type CleanupCloudFunc struct {
	Client      *jxwaf.Client
	AutoCleanup bool
}

func (f *CleanupCloudFunc) Name() string { return "cleanup_cloud" }

func (f *CleanupCloudFunc) Description() string {
	return "清理云端验证环境中的配置。验证通过后自动删除当前 group 下所有规则、组件、名单，保持环境干净。"
}

func (f *CleanupCloudFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"config_type": map[string]any{
				"type":        "string",
				"enum":        []string{"all", "web_rule", "flow_rule", "component", "name_list", "web_white", "flow_white"},
				"description": "要清理的配置类型，all 表示全部",
				"default":     "all",
			},
			"rule_names": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "指定要删除的规则名列表（config_type 非 all 时使用）",
			},
		},
	}
}

func (f *CleanupCloudFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	configType, _ := args["config_type"].(string)
	if configType == "" {
		configType = "all"
	}

	// TODO: 云端 API 就绪后实现实际删除
	// 1. 遍历当前 group 下的所有规则/组件/名单
	// 2. 逐一调用 delete 接口清理
	// 3. 返回清理结果

	result := map[string]any{
		"status":      "cleaned",
		"config_type": configType,
		"message":     "云端环境已清理",
		"note":        "云端 API 接口待接入，当前为模拟结果",
	}
	return toJSON(result), nil
}

// =============================================================================
// ListCloudRulesFunc：查询云端环境已有配置
// =============================================================================
type ListCloudRulesFunc struct {
	Client *jxwaf.Client
}

func (f *ListCloudRulesFunc) Name() string { return "list_cloud_rules" }

func (f *ListCloudRulesFunc) Description() string {
	return "查询云端验证环境中已有的规则配置，用于排查规则冲突。"
}

func (f *ListCloudRulesFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"config_type": map[string]any{
				"type":        "string",
				"enum":        []string{"web_rule", "flow_rule", "component", "name_list"},
				"description": "查询的配置类型",
			},
			"page": map[string]any{
				"type":    "integer",
				"default": 1,
			},
		},
		"required": []string{"config_type"},
	}
}

func (f *ListCloudRulesFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	configType, _ := args["config_type"].(string)
	page := 1
	if p, ok := args["page"].(float64); ok {
		page = int(p)
	}

	// TODO: 云端 API 就绪后实现真实查询
	_ = page
	_ = configType

	result := map[string]any{
		"config_type": configType,
		"page":        page,
		"message":     "云端 API 接口待接入",
	}
	return toJSON(result), nil
}
