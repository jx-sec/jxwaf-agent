package function

import (
	"context"
	"encoding/json"
	"fmt"

	"jxwaf-agent-go/internal/tencentwaf"
)

// =============================================================================
// 腾讯云 WAF 规则生成函数
// =============================================================================

// tencentScriptResult 腾讯云 WAF 配置生成结果
type tencentScriptResult struct {
	ScriptType  string `json:"script_type"` // tencent_custom | tencent_cc | tencent_ip_blacklist | tencent_whitelist
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	ConfigJSON  string `json:"config_json"`  // 完整请求 JSON（可直接传给 publish_tencent_waf_rule）
	Explanation string `json:"explanation"`
	LoadHint    string `json:"load_hint"`
}

// GenerateTencentCustomRuleFunc 生成腾讯云 WAF 自定义规则
type GenerateTencentCustomRuleFunc struct{}

func (f *GenerateTencentCustomRuleFunc) Name() string { return "generate_tencent_custom_rule" }

func (f *GenerateTencentCustomRuleFunc) Description() string {
	return "生成腾讯云 WAF 自定义访问控制规则（AddCustomRule）。输出可通过 publish_tencent_waf_rule 发布。" +
		"匹配条件最多 5 个，支持 AND/OR 逻辑。新规则建议先用 ActionType=3（观察）。"
}

func (f *GenerateTencentCustomRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string", "description": "规则名称"},
			"domain": map[string]any{"type": "string", "description": "域名（global 表示全局）"},
			"action_type": map[string]any{
				"type":        "string",
				"enum":        []string{"1", "2", "3", "4", "5"},
				"default":     "3",
				"description": "动作：1=阻断, 2=人机识别, 3=观察, 4=重定向, 5=JS校验",
			},
			"logical_op": map[string]any{
				"type":        "string",
				"enum":        []string{"and", "or"},
				"default":     "and",
				"description": "条件间逻辑关系",
			},
			"sort_id": map[string]any{"type": "string", "default": "1", "description": "优先级（1-100，越小越高）"},
			"strategies": map[string]any{
				"type":        "array",
				"description": "匹配条件数组（最多 5 个）",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"field": map[string]any{
							"type": "string",
							"description": "匹配字段：URL/Method/args/post_args/referer/ua/Cookie/IP/IPLocation/header/content_length/COOKIE/POST_BODY 等",
						},
						"compare_func": map[string]any{
							"type": "string",
							"description": "运算符：eq/neq/contains/ncontains/prefix/suffix/ipmatch/ipnmatch/len_eq/len_gt/len_lt/regex/exists/nexists/empty/numeq/numneq/numgt/numlt/geo_in/geo_not_in",
						},
						"content": map[string]any{"type": "string", "description": "匹配内容"},
						"arg":     map[string]any{"type": "string", "description": "参数名（Cookie/Header/args/post_args 时必填）"},
					},
					"required": []string{"field", "compare_func", "content"},
				},
			},
		},
		"required": []string{"name", "domain", "action_type", "strategies"},
	}
}

func (f *GenerateTencentCustomRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	domain, _ := args["domain"].(string)
	actionType, _ := args["action_type"].(string)
	if actionType == "" {
		actionType = "3"
	}
	logicalOp, _ := args["logical_op"].(string)
	if logicalOp == "" {
		logicalOp = "and"
	}
	sortID, _ := args["sort_id"].(string)
	if sortID == "" {
		sortID = "1"
	}

	var strategies []tencentwaf.Strategy
	if raw, ok := args["strategies"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &strategies)
	}
	if len(strategies) == 0 {
		return "", fmt.Errorf("strategies 不能为空")
	}
	if len(strategies) > 5 {
		return "", fmt.Errorf("匹配条件最多 5 个，当前 %d 个", len(strategies))
	}

	req := &tencentwaf.AddCustomRuleRequest{
		Name:       name,
		SortId:     sortID,
		Strategies: strategies,
		Domain:     domain,
		ActionType: actionType,
		LogicalOp:  logicalOp,
		Edition:    "sparta-waf",
		JobType:    "forever",
		ExpireTime: "0",
	}

	configJSON, _ := json.MarshalIndent(req, "", "  ")

	actionNames := map[string]string{"1": "阻断", "2": "人机识别", "3": "观察", "4": "重定向", "5": "JS校验"}

	result := tencentScriptResult{
		ScriptType:  "tencent_custom",
		Name:        name,
		Domain:      domain,
		ConfigJSON:  string(configJSON),
		LoadHint:    "可通过 publish_tencent_waf_rule 发布到腾讯云 WAF（AddCustomRule）",
		Explanation: fmt.Sprintf("腾讯云 WAF 自定义规则 %s（域名=%s, 动作=%s, 逻辑=%s），匹配条件 %d 组。",
			name, domain, actionNames[actionType], logicalOp, len(strategies)),
	}
	return toJSON(result), nil
}

// GenerateTencentIPBlacklistFunc 生成腾讯云 WAF IP 黑名单
type GenerateTencentIPBlacklistFunc struct{}

func (f *GenerateTencentIPBlacklistFunc) Name() string { return "generate_tencent_ip_blacklist" }

func (f *GenerateTencentIPBlacklistFunc) Description() string {
	return "生成腾讯云 WAF IP 黑白名单（CreateIpAccessControl）。支持 IPv4/CIDR。"
}

func (f *GenerateTencentIPBlacklistFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"domain": map[string]any{"type": "string", "description": "域名"},
			"ip_list": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "IP/CIDR 列表",
			},
			"action_type": map[string]any{
				"type":        "integer",
				"enum":        []int{42, 40},
				"default":     42,
				"description": "42=黑名单, 40=白名单",
			},
		},
		"required": []string{"domain", "ip_list"},
	}
}

func (f *GenerateTencentIPBlacklistFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	domain, _ := args["domain"].(string)
	actionType := 42
	if v, ok := args["action_type"].(float64); ok {
		actionType = int(v)
	}

	var ipList []string
	if raw, ok := args["ip_list"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				ipList = append(ipList, s)
			}
		}
	}
	if len(ipList) == 0 {
		return "", fmt.Errorf("ip_list 不能为空")
	}

	payload := map[string]any{
		"Domain":     domain,
		"IpList":     ipList,
		"ActionType": actionType,
		"Edition":    "sparta-waf",
		"SourceType": "custom",
	}

	configJSON, _ := json.MarshalIndent(payload, "", "  ")

	typeName := "黑名单"
	if actionType == 40 {
		typeName = "白名单"
	}

	result := tencentScriptResult{
		ScriptType:  "tencent_ip_blacklist",
		Name:        fmt.Sprintf("IP%s_%s", typeName, domain),
		Domain:      domain,
		ConfigJSON:  string(configJSON),
		LoadHint:    "可通过 publish_tencent_waf_rule 发布到腾讯云 WAF（CreateIpAccessControl）",
		Explanation: fmt.Sprintf("腾讯云 WAF IP%s（域名=%s），IP/CIDR %d 个。", typeName, domain, len(ipList)),
	}
	return toJSON(result), nil
}

// GenerateTencentCCRuleFunc 生成腾讯云 WAF CC 防护规则
type GenerateTencentCCRuleFunc struct{}

func (f *GenerateTencentCCRuleFunc) Name() string { return "generate_tencent_cc_rule" }

func (f *GenerateTencentCCRuleFunc) Description() string {
	return "生成腾讯云 WAF CC 防护规则（UpsertCCRule）。threshold 不低于业务峰值 QPS 的 2 倍。"
}

func (f *GenerateTencentCCRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":       map[string]any{"type": "string", "description": "规则名称"},
			"domain":     map[string]any{"type": "string", "description": "域名"},
			"limit":      map[string]any{"type": "string", "description": "访问次数阈值"},
			"interval":   map[string]any{"type": "string", "description": "统计时间窗口（秒）"},
			"action_type": map[string]any{
				"type":        "string",
				"enum":        []string{"20", "21", "22", "23", "26", "27"},
				"default":     "20",
				"description": "20=观察, 21=人机识别, 22=拦截, 23=精准拦截, 26=精准人机识别, 27=JS校验",
			},
			"valid_time": map[string]any{"type": "integer", "description": "处置时长（秒）", "default": 600},
			"priority":   map[string]any{"type": "integer", "description": "优先级", "default": 50},
			"match_func": map[string]any{
				"type":        "integer",
				"default":     0,
				"description": "匹配方式：0=等于, 1=前缀, 2=包含, 3=不等于, 6=后缀, 7=不包含",
			},
			"options_arr": map[string]any{
				"type":        "string",
				"description": "匹配条件 JSON 字符串（key/args/match/encodeflag），如 [{\"key\":\"URL\",\"args\":[\"/api\"],\"match\":\"0\",\"encodeflag\":false}]",
			},
		},
		"required": []string{"name", "domain", "limit", "interval", "action_type"},
	}
}

func (f *GenerateTencentCCRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	domain, _ := args["domain"].(string)
	limit, _ := args["limit"].(string)
	interval, _ := args["interval"].(string)
	actionType, _ := args["action_type"].(string)
	if actionType == "" {
		actionType = "20"
	}
	validTime := int64(600)
	if v, ok := args["valid_time"].(float64); ok {
		validTime = int64(v)
	}
	priority := int64(50)
	if v, ok := args["priority"].(float64); ok {
		priority = int64(v)
	}
	matchFunc := int64(0)
	if v, ok := args["match_func"].(float64); ok {
		matchFunc = int64(v)
	}
	optionsArr, _ := args["options_arr"].(string)
	if optionsArr == "" {
		optionsArr = `[{"key":"URL","args":[""],"match":"0","encodeflag":false}]`
	}

	req := &tencentwaf.UpsertCCRuleRequest{
		Domain:      domain,
		Name:        name,
		Status:      1,
		Advance:     "0",
		Limit:       limit,
		Interval:    interval,
		ActionType:  actionType,
		Priority:    priority,
		ValidTime:   validTime,
		MatchFunc:   matchFunc,
		OptionsArr:  optionsArr,
		Edition:     "sparta-waf",
		RuleId:      0,
		LogicalOp:   "and",
		ActionRatio: 100,
		JobType:     "forever",
	}

	configJSON, _ := json.MarshalIndent(req, "", "  ")

	actionNames := map[string]string{"20": "观察", "21": "人机识别", "22": "拦截", "23": "精准拦截", "26": "精准人机识别", "27": "JS校验"}

	result := tencentScriptResult{
		ScriptType:  "tencent_cc",
		Name:        name,
		Domain:      domain,
		ConfigJSON:  string(configJSON),
		LoadHint:    "可通过 publish_tencent_waf_rule 发布到腾讯云 WAF（UpsertCCRule）",
		Explanation: fmt.Sprintf("腾讯云 WAF CC 规则 %s（域名=%s, %ss 内超过 %s 次 → %s）。",
			name, domain, interval, limit, actionNames[actionType]),
	}
	return toJSON(result), nil
}

// =============================================================================
// 腾讯云 WAF 规则发布函数（通过 API 下发）
// =============================================================================

// PublishTencentWAFRuleFunc 通过腾讯云 WAF OpenAPI 发布规则
type PublishTencentWAFRuleFunc struct {
	Client *tencentwaf.Client
}

func (f *PublishTencentWAFRuleFunc) Name() string { return "publish_tencent_waf_rule" }

func (f *PublishTencentWAFRuleFunc) Description() string {
	return "通过腾讯云 WAF OpenAPI 发布防护规则。接受 generate_tencent_* 输出的 config_json 和 script_type，" +
		"自动调用对应 API（AddCustomRule / CreateIpAccessControl / UpsertCCRule）。部署后约 5 秒生效。"
}

func (f *PublishTencentWAFRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"script_type": map[string]any{
				"type":        "string",
				"enum":        []string{"tencent_custom", "tencent_cc", "tencent_ip_blacklist", "tencent_whitelist"},
				"description": "配置类型（对应 generate_tencent_* 的 script_type）",
			},
			"config_json": map[string]any{
				"type":        "string",
				"description": "规则 JSON 字符串（generate_tencent_* 输出的 config_json）",
			},
		},
		"required": []string{"script_type", "config_json"},
	}
}

func (f *PublishTencentWAFRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	scriptType, _ := args["script_type"].(string)
	configJSON, _ := args["config_json"].(string)
	if scriptType == "" || configJSON == "" {
		return "", fmt.Errorf("script_type 和 config_json 不能为空")
	}

	var result map[string]any
	var err error
	var apiName string

	switch scriptType {
	case "tencent_custom":
		var req tencentwaf.AddCustomRuleRequest
		if err := json.Unmarshal([]byte(configJSON), &req); err != nil {
			return "", fmt.Errorf("解析 config_json 失败: %w", err)
		}
		result, err = f.Client.AddCustomRule(&req)
		apiName = "AddCustomRule"

	case "tencent_cc":
		var req tencentwaf.UpsertCCRuleRequest
		if err := json.Unmarshal([]byte(configJSON), &req); err != nil {
			return "", fmt.Errorf("解析 config_json 失败: %w", err)
		}
		result, err = f.Client.UpsertCCRule(&req)
		apiName = "UpsertCCRule"

	case "tencent_ip_blacklist":
		var req struct {
			Domain     string   `json:"Domain"`
			IpList     []string `json:"IpList"`
			ActionType int      `json:"ActionType"`
		}
		if err := json.Unmarshal([]byte(configJSON), &req); err != nil {
			return "", fmt.Errorf("解析 config_json 失败: %w", err)
		}
		result, err = f.Client.CreateIpAccessControl(req.Domain, req.IpList, req.ActionType)
		apiName = "CreateIpAccessControl"

	case "tencent_whitelist":
		var req struct {
			Name       string                  `json:"Name"`
			Domain     string                  `json:"Domain"`
			SortId     string                  `json:"SortId"`
			Strategies []tencentwaf.Strategy   `json:"Strategies"`
		}
		if err := json.Unmarshal([]byte(configJSON), &req); err != nil {
			return "", fmt.Errorf("解析 config_json 失败: %w", err)
		}
		result, err = f.Client.AddCustomWhiteRule(req.Name, req.Domain, req.Strategies, req.SortId)
		apiName = "AddCustomWhiteRule"

	default:
		return "", fmt.Errorf("不支持的 script_type: %s", scriptType)
	}

	if err != nil {
		return "", fmt.Errorf("发布到腾讯云 WAF 失败: %w", err)
	}

	output := map[string]any{
		"status":      "published",
		"script_type": scriptType,
		"api_name":    apiName,
		"api_response": result,
		"message":     fmt.Sprintf("规则已通过 %s 发布到腾讯云 WAF，约 5 秒后生效", apiName),
	}
	return toJSON(output), nil
}

// =============================================================================
// 腾讯云 WAF 规则查询/删除函数
// =============================================================================

// ListTencentWAFRulesFunc 查询腾讯云 WAF 规则列表
type ListTencentWAFRulesFunc struct {
	Client *tencentwaf.Client
}

func (f *ListTencentWAFRulesFunc) Name() string { return "list_tencent_waf_rules" }

func (f *ListTencentWAFRulesFunc) Description() string {
	return "查询腾讯云 WAF 防护规则列表。支持自定义规则、IP 黑白名单、CC 规则。"
}

func (f *ListTencentWAFRulesFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rule_type": map[string]any{
				"type":        "string",
				"enum":        []string{"custom", "ip", "cc", "whitelist"},
				"description": "规则类型",
			},
			"domain": map[string]any{"type": "string", "description": "域名"},
			"offset": map[string]any{"type": "integer", "default": 0},
			"limit":  map[string]any{"type": "integer", "default": 20},
		},
		"required": []string{"rule_type", "domain"},
	}
}

func (f *ListTencentWAFRulesFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	ruleType, _ := args["rule_type"].(string)
	domain, _ := args["domain"].(string)
	offset := 0
	if v, ok := args["offset"].(float64); ok {
		offset = int(v)
	}
	limit := 20
	if v, ok := args["limit"].(float64); ok {
		limit = int(v)
	}

	var result map[string]any
	var err error

	switch ruleType {
	case "custom":
		result, err = f.Client.DescribeCustomRuleList(domain, offset, limit)
	case "ip":
		result, err = f.Client.DescribeIpAccessControl(domain, offset, limit)
	case "cc":
		result, err = f.Client.DescribeCCRuleList(domain, offset, limit)
	case "whitelist":
		result, err = f.Client.DescribeCustomWhiteRules(domain, offset, limit)
	default:
		return "", fmt.Errorf("不支持的 rule_type: %s", ruleType)
	}

	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}

// DeleteTencentWAFRuleFunc 删除腾讯云 WAF 规则
type DeleteTencentWAFRuleFunc struct {
	Client *tencentwaf.Client
}

func (f *DeleteTencentWAFRuleFunc) Name() string { return "delete_tencent_waf_rule" }

func (f *DeleteTencentWAFRuleFunc) Description() string {
	return "删除腾讯云 WAF 防护规则。"
}

func (f *DeleteTencentWAFRuleFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rule_type": map[string]any{
				"type":        "string",
				"enum":        []string{"custom", "ip", "cc", "whitelist"},
				"description": "规则类型",
			},
			"domain":  map[string]any{"type": "string", "description": "域名"},
			"rule_id": map[string]any{"type": "integer", "description": "规则 ID"},
		},
		"required": []string{"rule_type", "domain", "rule_id"},
	}
}

func (f *DeleteTencentWAFRuleFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	ruleType, _ := args["rule_type"].(string)
	domain, _ := args["domain"].(string)
	ruleID, ok := args["rule_id"].(float64)
	if !ok {
		return "", fmt.Errorf("rule_id 不能为空")
	}

	var result map[string]any
	var err error

	switch ruleType {
	case "custom":
		result, err = f.Client.DeleteCustomRule(domain, int64(ruleID))
	case "ip":
		result, err = f.Client.DeleteIpAccessControl(domain, int64(ruleID))
	case "cc":
		result, err = f.Client.DeleteCCRule(domain, []int64{int64(ruleID)})
	case "whitelist":
		result, err = f.Client.DeleteCustomWhiteRule(domain, int64(ruleID))
	default:
		return "", fmt.Errorf("不支持的 rule_type: %s", ruleType)
	}

	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}

// ListTencentWAFDomainsFunc 查询腾讯云 WAF 域名列表
type ListTencentWAFDomainsFunc struct {
	Client *tencentwaf.Client
}

func (f *ListTencentWAFDomainsFunc) Name() string { return "list_tencent_waf_domains" }

func (f *ListTencentWAFDomainsFunc) Description() string {
	return "查询腾讯云 WAF 接入的域名列表。"
}

func (f *ListTencentWAFDomainsFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"offset": map[string]any{"type": "integer", "default": 0},
			"limit":  map[string]any{"type": "integer", "default": 20},
		},
	}
}

func (f *ListTencentWAFDomainsFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	offset := 0
	if v, ok := args["offset"].(float64); ok {
		offset = int(v)
	}
	limit := 20
	if v, ok := args["limit"].(float64); ok {
		limit = int(v)
	}

	result, err := f.Client.DescribeDomains(offset, limit)
	if err != nil {
		return "", err
	}
	return toJSON(result), nil
}
