package function

import (
	"context"
	"encoding/json"
	"fmt"

	"jxwaf-agent-go/internal/aliyunwaf"
)

// =============================================================================
// 阿里云 WAF 规则生成函数
// =============================================================================

// aliyunScriptResult 阿里云 WAF 配置生成结果
type aliyunScriptResult struct {
	ScriptType  string `json:"script_type"` // aliyun_acl | aliyun_cc | aliyun_ip_blacklist | aliyun_whitelist
	Name        string `json:"name"`
	Detail      string `json:"detail"`
	ConfigJSON  string `json:"config_json"`  // Rules JSON 数组字符串（可直接传给 CreateDefenseRule）
	Explanation string `json:"explanation"`
	LoadHint    string `json:"load_hint"`
}

// GenerateAliyunACLRuleFunc 生成阿里云 WAF 自定义 ACL 规则
type GenerateAliyunACLRuleFunc struct{}

func (f *GenerateAliyunACLRuleFunc) Name() string { return "generate_aliyun_acl_rule" }

func (f *GenerateAliyunACLRuleFunc) Description() string {
	return "生成阿里云 WAF 3.0 自定义 ACL 规则（custom_acl 场景）。输出可直接通过 publish_aliyun_waf_rule 发布到阿里云 WAF。" +
		"匹配条件最多 5 个，条件间为 AND 关系。新规则建议先用 monitor 动作观察。"
}

func (f *GenerateAliyunACLRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string", "description": "规则名称（1~255 字符，支持中英文数字 _ . -）"},
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"block", "monitor", "js", "captcha", "captcha_strict", "pass"},
				"default":     "monitor",
				"description": "处置动作：block=拦截, monitor=观察, js=JS校验, captcha=滑块验证, captcha_strict=严格滑块, pass=放行",
			},
			"conditions": map[string]any{
				"type":        "array",
				"description": "匹配条件数组（最多 5 个，AND 关系）",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"key": map[string]any{
							"type": "string",
							"description": "匹配字段：URL/URLPath/IP/Referer/User-Agent/Params/Cookie/Content-Type/Content-Length/X-Forwarded-For/Post-Body/Http-Method/Header/Extension/Filename/Server-Port/Host/Cookie-Exact/Query-Arg/Post-Arg",
						},
						"subKey": map[string]any{"type": "string", "description": "子字段名（Header/Cookie/Query-Arg/Post-Arg 时必填，如 User-Agent 的 key 名）"},
						"opValue": map[string]any{
							"type": "string",
							"description": "逻辑符：contain/not-contain/eq/ne/lt/gt/len-lt/len-eq/len-gt/not-match/match-one/regex/not-regex/prefix-match/suffix-match/empty/exists/in-list/not-in-list",
						},
						"values": map[string]any{"type": "string", "description": "匹配内容（多值用英文逗号分隔）"},
					},
					"required": []string{"key", "opValue", "values"},
				},
			},
			"status": map[string]any{"type": "integer", "default": 1, "description": "规则状态：0=关闭, 1=开启"},
		},
		"required": []string{"name", "action", "conditions"},
	}
}

func (f *GenerateAliyunACLRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	action, _ := args["action"].(string)
	if action == "" {
		action = "monitor"
	}
	status := 1
	if s, ok := args["status"].(float64); ok {
		status = int(s)
	}

	var conditions []any
	if raw, ok := args["conditions"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &conditions)
	}
	if conditions == nil {
		conditions = []any{}
	}
	if len(conditions) > 5 {
		return "", fmt.Errorf("匹配条件最多 5 个，当前 %d 个", len(conditions))
	}

	rule := map[string]any{
		"name":       name,
		"action":     action,
		"conditions": conditions,
		"ccStatus":   0,
		"status":     status,
		"origin":     "custom",
	}

	rules := []map[string]any{rule}
	configJSON, _ := json.MarshalIndent(rules, "", "  ")

	result := aliyunScriptResult{
		ScriptType:  "aliyun_acl",
		Name:        name,
		ConfigJSON:  string(configJSON),
		LoadHint:    "可通过 publish_aliyun_waf_rule 发布到阿里云 WAF（DefenseScene=custom_acl）",
		Explanation: fmt.Sprintf("阿里云 WAF 自定义 ACL 规则 %s（action=%s），匹配条件 %d 组。", name, action, len(conditions)),
	}
	return toJSON(result), nil
}

// GenerateAliyunCCRuleFunc 生成阿里云 WAF CC 防护规则（限速）
type GenerateAliyunCCRuleFunc struct{}

func (f *GenerateAliyunCCRuleFunc) Name() string { return "generate_aliyun_cc_rule" }

func (f *GenerateAliyunCCRuleFunc) Description() string {
	return "生成阿里云 WAF 3.0 CC 防护规则（cc 场景，含限速配置）。输出可通过 publish_aliyun_waf_rule 发布。" +
		"threshold 不低于业务峰值 QPS 的 2 倍。"
}

func (f *GenerateAliyunCCRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string", "description": "规则名称"},
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"block", "monitor", "js", "captcha", "captcha_strict"},
				"default":     "monitor",
				"description": "触发限速后的处置动作",
			},
			"conditions": map[string]any{
				"type":        "array",
				"description": "匹配条件（可选，限定限速范围；为空则对所有请求生效）",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"key":     map[string]any{"type": "string"},
						"subKey":  map[string]any{"type": "string"},
						"opValue": map[string]any{"type": "string"},
						"values":  map[string]any{"type": "string"},
					},
				},
			},
			"ratelimit": map[string]any{
				"type": "object",
				"description": "限速配置",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "统计对象：remote_addr(IP) / cookie.acw_tc(会话) / header / queryarg / cookie / account",
					},
					"subKey":   map[string]any{"type": "string", "description": "子特征（target 为 header/queryarg/cookie 时必填）"},
					"interval": map[string]any{"type": "integer", "description": "统计时长（秒），1~1800"},
					"threshold": map[string]any{"type": "integer", "description": "访问次数阈值"},
					"ttl":      map[string]any{"type": "integer", "description": "处置时长（秒），60~86400"},
				},
				"required": []string{"target", "interval", "threshold", "ttl"},
			},
		},
		"required": []string{"name", "action", "ratelimit"},
	}
}

func (f *GenerateAliyunCCRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	action, _ := args["action"].(string)
	if action == "" {
		action = "monitor"
	}

	var conditions []any
	if raw, ok := args["conditions"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &conditions)
	}
	if conditions == nil {
		conditions = []any{}
	}

	var ratelimit map[string]any
	if raw, ok := args["ratelimit"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &ratelimit)
	}
	if ratelimit == nil {
		return "", fmt.Errorf("ratelimit 不能为空")
	}

	rule := map[string]any{
		"name":       name,
		"action":     action,
		"conditions": conditions,
		"ccStatus":   1,
		"ratelimit":  ratelimit,
		"effect":     "rule",
		"status":     1,
		"origin":     "custom",
	}

	rules := []map[string]any{rule}
	configJSON, _ := json.MarshalIndent(rules, "", "  ")

	interval, _ := ratelimit["interval"].(float64)
	threshold, _ := ratelimit["threshold"].(float64)

	result := aliyunScriptResult{
		ScriptType:  "aliyun_cc",
		Name:        name,
		ConfigJSON:  string(configJSON),
		LoadHint:    "可通过 publish_aliyun_waf_rule 发布到阿里云 WAF（DefenseScene=cc）",
		Explanation: fmt.Sprintf("阿里云 WAF CC 防护规则 %s（%ds 内超过 %d 次 → %s）。",
			name, int(interval), int(threshold), action),
	}
	return toJSON(result), nil
}

// GenerateAliyunIPBlacklistFunc 生成阿里云 WAF IP 黑名单
type GenerateAliyunIPBlacklistFunc struct{}

func (f *GenerateAliyunIPBlacklistFunc) Name() string { return "generate_aliyun_ip_blacklist" }

func (f *GenerateAliyunIPBlacklistFunc) Description() string {
	return "生成阿里云 WAF 3.0 IP 黑名单规则（ip_blacklist 场景）。支持 IPv4/IPv6/CIDR，单规则最多 100 个 IP。"
}

func (f *GenerateAliyunIPBlacklistFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":        map[string]any{"type": "string", "description": "规则名称"},
			"action": map[string]any{
				"type":        "string",
				"enum":        []string{"block", "monitor"},
				"default":     "block",
				"description": "处置动作",
			},
			"remote_addr": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "IP/CIDR 列表（如 [\"1.1.1.1\", \"2.2.2.0/24\"]），最多 100 个",
			},
		},
		"required": []string{"name", "remote_addr"},
	}
}

func (f *GenerateAliyunIPBlacklistFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	action, _ := args["action"].(string)
	if action == "" {
		action = "block"
	}

	var remoteAddrs []string
	if raw, ok := args["remote_addr"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				remoteAddrs = append(remoteAddrs, s)
			}
		}
	}
	if len(remoteAddrs) == 0 {
		return "", fmt.Errorf("remote_addr 不能为空")
	}
	if len(remoteAddrs) > 100 {
		return "", fmt.Errorf("IP 黑名单最多 100 个，当前 %d 个", len(remoteAddrs))
	}

	rule := map[string]any{
		"name":        name,
		"action":      action,
		"remoteAddr":  remoteAddrs,
		"status":      1,
	}

	rules := []map[string]any{rule}
	configJSON, _ := json.MarshalIndent(rules, "", "  ")

	result := aliyunScriptResult{
		ScriptType:  "aliyun_ip_blacklist",
		Name:        name,
		ConfigJSON:  string(configJSON),
		LoadHint:    "可通过 publish_aliyun_waf_rule 发布到阿里云 WAF（DefenseScene=ip_blacklist）",
		Explanation: fmt.Sprintf("阿里云 WAF IP 黑名单 %s（action=%s），IP/CIDR %d 个。", name, action, len(remoteAddrs)),
	}
	return toJSON(result), nil
}

// =============================================================================
// 阿里云 WAF 规则发布函数（通过 API 下发）
// =============================================================================

// PublishAliyunWAFRuleFunc 通过阿里云 WAF OpenAPI 发布规则
type PublishAliyunWAFRuleFunc struct {
	Client *aliyunwaf.Client
}

func (f *PublishAliyunWAFRuleFunc) Name() string { return "publish_aliyun_waf_rule" }

func (f *PublishAliyunWAFRuleFunc) Description() string {
	return "通过阿里云 WAF OpenAPI（CreateDefenseRule）发布防护规则到阿里云 WAF 3.0 实例。" +
		"接受 generate_aliyun_* 输出的 config_json 和 script_type，自动映射到对应 DefenseScene。" +
		"部署后约 5 秒生效。"
}

func (f *PublishAliyunWAFRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"script_type": map[string]any{
				"type":        "string",
				"enum":        []string{"aliyun_acl", "aliyun_cc", "aliyun_ip_blacklist", "aliyun_whitelist"},
				"description": "配置类型（对应 generate_aliyun_* 的 script_type）",
			},
			"config_json": map[string]any{
				"type":        "string",
				"description": "规则 JSON 数组字符串（generate_aliyun_* 输出的 config_json）",
			},
		},
		"required": []string{"script_type", "config_json"},
	}
}

func (f *PublishAliyunWAFRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	scriptType, _ := args["script_type"].(string)
	configJSON, _ := args["config_json"].(string)
	if scriptType == "" || configJSON == "" {
		return "", fmt.Errorf("script_type 和 config_json 不能为空")
	}

	// 映射 script_type 到 DefenseScene
	sceneMap := map[string]string{
		"aliyun_acl":          "custom_acl",
		"aliyun_cc":           "cc",
		"aliyun_ip_blacklist": "ip_blacklist",
		"aliyun_whitelist":    "whitelist",
	}
	defenseScene, ok := sceneMap[scriptType]
	if !ok {
		return "", fmt.Errorf("不支持的 script_type: %s", scriptType)
	}

	// 调用阿里云 WAF API 创建规则
	result, err := f.Client.CreateDefenseRule(defenseScene, configJSON)
	if err != nil {
		return "", fmt.Errorf("发布到阿里云 WAF 失败: %w", err)
	}

	output := map[string]any{
		"status":        "published",
		"script_type":   scriptType,
		"defense_scene": defenseScene,
		"instance_id":   f.Client.InstanceID(),
		"template_id":   f.Client.TemplateID(),
		"api_response":  result,
		"message":       fmt.Sprintf("规则已发布到阿里云 WAF（%s），约 5 秒后生效", defenseScene),
	}
	return toJSON(output), nil
}

// =============================================================================
// 阿里云 WAF 规则查询/删除函数
// =============================================================================

// ListAliyunWAFRulesFunc 查询阿里云 WAF 规则列表
type ListAliyunWAFRulesFunc struct {
	Client *aliyunwaf.Client
}

func (f *ListAliyunWAFRulesFunc) Name() string { return "list_aliyun_waf_rules" }

func (f *ListAliyunWAFRulesFunc) Description() string {
	return "查询阿里云 WAF 3.0 防护规则列表（DescribeDefenseRules）。"
}

func (f *ListAliyunWAFRulesFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"defense_scene": map[string]any{
				"type":        "string",
				"enum":        []string{"custom_acl", "cc", "ip_blacklist", "whitelist", "waf_group", "antiscan"},
				"description": "防护场景",
			},
			"page_number": map[string]any{"type": "integer", "default": 1},
			"page_size":   map[string]any{"type": "integer", "default": 20},
		},
		"required": []string{"defense_scene"},
	}
}

func (f *ListAliyunWAFRulesFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	scene, _ := args["defense_scene"].(string)
	pageNumber := 1
	if v, ok := args["page_number"].(float64); ok {
		pageNumber = int(v)
	}
	pageSize := 20
	if v, ok := args["page_size"].(float64); ok {
		pageSize = int(v)
	}

	result, err := f.Client.DescribeDefenseRules(scene, pageNumber, pageSize)
	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}

// DeleteAliyunWAFRuleFunc 删除阿里云 WAF 规则
type DeleteAliyunWAFRuleFunc struct {
	Client *aliyunwaf.Client
}

func (f *DeleteAliyunWAFRuleFunc) Name() string { return "delete_aliyun_waf_rule" }

func (f *DeleteAliyunWAFRuleFunc) Description() string {
	return "删除阿里云 WAF 3.0 防护规则（DeleteDefenseRule）。"
}

func (f *DeleteAliyunWAFRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rule_id": map[string]any{"type": "integer", "description": "规则 ID"},
		},
		"required": []string{"rule_id"},
	}
}

func (f *DeleteAliyunWAFRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	ruleID, ok := args["rule_id"].(float64)
	if !ok {
		return "", fmt.Errorf("rule_id 不能为空")
	}

	result, err := f.Client.DeleteDefenseRule(int64(ruleID))
	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}

// ListAliyunWAFResourcesFunc 查询阿里云 WAF 防护对象列表
type ListAliyunWAFResourcesFunc struct {
	Client *aliyunwaf.Client
}

func (f *ListAliyunWAFResourcesFunc) Name() string { return "list_aliyun_waf_resources" }

func (f *ListAliyunWAFResourcesFunc) Description() string {
	return "查询阿里云 WAF 3.0 防护对象列表（DescribeDefenseResources），用于查看接入的域名。"
}

func (f *ListAliyunWAFResourcesFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"page_number": map[string]any{"type": "integer", "default": 1},
			"page_size":   map[string]any{"type": "integer", "default": 20},
		},
	}
}

func (f *ListAliyunWAFResourcesFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	pageNumber := 1
	if v, ok := args["page_number"].(float64); ok {
		pageNumber = int(v)
	}
	pageSize := 20
	if v, ok := args["page_size"].(float64); ok {
		pageSize = int(v)
	}

	result, err := f.Client.DescribeDefenseResources(pageNumber, pageSize)
	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}
