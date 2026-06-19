// Package jxwaf 封装 JXWAF 控制台 API 调用
package jxwaf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client JXWAF 控制台 API 客户端
type Client struct {
	apiURL  string
	wafAuth string
	group   string
	http    *http.Client
}

// New 创建 JXWAF 客户端
func New(apiURL, wafAuth, group string) *Client {
	return &Client{
		apiURL:  strings.TrimRight(apiURL, "/"),
		wafAuth: wafAuth,
		group:   group,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MatchArg 匹配参数
type MatchArg struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Match 匹配条件
type Match struct {
	MatchArgs     []MatchArg `json:"match_args"`
	ArgsPrepocess []string   `json:"args_prepocess"`
	MatchOperator string     `json:"match_operator"`
	MatchValue    string     `json:"match_value"`
}

// WebRule Web 防护规则
type WebRule struct {
	Name        string  `json:"rule_name"`
	Detail      string  `json:"rule_detail"`
	Matchs      []Match `json:"rule_matchs"`
	Action      string  `json:"rule_action"`
	ActionValue string  `json:"action_value"`
	Group       string  `json:"group_name"`
}

// FlowRule 流量防护规则
type FlowRule struct {
	Name        string     `json:"rule_name"`
	Detail      string     `json:"rule_detail"`
	Matchs      []Match    `json:"rule_matchs"`
	Action      string     `json:"rule_action"`
	ActionValue string     `json:"action_value"`
	Filter      string     `json:"filter"`
	Entity      []MatchArg `json:"entity"`
	StatTime    int        `json:"stat_time"`
	ExceedCount int        `json:"exceed_count"`
	BlockTime   int        `json:"block_time"`
	Group       string     `json:"group_name"`
}

// Component 防护组件
type Component struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Code   string `json:"code"` // Base64 编码
	Conf   string `json:"conf"` // JSON 字符串
}

// NameList 名单防护
type NameList struct {
	Name        string     `json:"name_list_name"`
	Detail      string     `json:"name_list_detail"`
	Rule        []MatchArg `json:"name_list_rule"`
	Action      string     `json:"name_list_action"`
	ActionValue string     `json:"action_value"`
	Expire      string     `json:"name_list_expire"`
	ExpireTime  string     `json:"name_list_expire_time"`
}

// WhiteRule 白名单规则
type WhiteRule struct {
	Name        string  `json:"rule_name"`
	Detail      string  `json:"rule_detail"`
	Matchs      []Match `json:"rule_matchs"`
	ActionValue string  `json:"action_value"`
	Group       string  `json:"group_name"`
}

// post 发送 POST 请求（表单格式）
func (c *Client) post(path string, params map[string]string) (map[string]any, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	if c.group != "" {
		if _, ok := params["group_name"]; !ok {
			form.Set("group_name", c.group)
		}
	}

	req, err := http.NewRequest("POST", c.apiURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.wafAuth != "" {
		req.Header.Set("waf_auth", c.wafAuth)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v, body: %s", err, string(body))
	}
	return result, nil
}

// toJSON 辅助：将任意值序列化为 JSON 字符串
func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// CreateWebRule 创建 Web 防护规则
func (c *Client) CreateWebRule(rule WebRule) (map[string]any, error) {
	rule.Group = c.group
	params := map[string]string{
		"group_name":   rule.Group,
		"rule_name":    rule.Name,
		"rule_detail":  rule.Detail,
		"rule_matchs":  toJSON(rule.Matchs),
		"rule_action":  rule.Action,
		"action_value": rule.ActionValue,
	}
	return c.post("/waf/create_group_web_rule_protection", params)
}

// ListWebRules 查询 Web 防护规则列表
func (c *Client) ListWebRules(page int) (map[string]any, error) {
	params := map[string]string{
		"page":       fmt.Sprintf("%d", page),
		"group_name": c.group,
	}
	return c.post("/waf/get_group_web_rule_protection_list", params)
}

// CreateFlowRule 创建流量防护规则
func (c *Client) CreateFlowRule(rule FlowRule) (map[string]any, error) {
	rule.Group = c.group
	params := map[string]string{
		"group_name":   rule.Group,
		"rule_name":    rule.Name,
		"rule_detail":  rule.Detail,
		"rule_matchs":  toJSON(rule.Matchs),
		"rule_action":  rule.Action,
		"action_value": rule.ActionValue,
		"filter":       rule.Filter,
		"entity":       toJSON(rule.Entity),
		"stat_time":    fmt.Sprintf("%d", rule.StatTime),
		"exceed_count": fmt.Sprintf("%d", rule.ExceedCount),
		"block_time":   fmt.Sprintf("%d", rule.BlockTime),
	}
	return c.post("/waf/create_group_flow_rule_protection", params)
}

// ListFlowRules 查询流量防护规则列表
func (c *Client) ListFlowRules(page int) (map[string]any, error) {
	params := map[string]string{
		"page":       fmt.Sprintf("%d", page),
		"group_name": c.group,
	}
	return c.post("/waf/get_group_flow_rule_protection_list", params)
}

// CreateComponent 创建防护组件
func (c *Client) CreateComponent(comp Component) (map[string]any, error) {
	params := map[string]string{
		"name":   comp.Name,
		"detail": comp.Detail,
		"code":   comp.Code,
		"conf":   comp.Conf,
	}
	return c.post("/waf/create_component", params)
}

// ListComponents 查询组件列表
func (c *Client) ListComponents(page int) (map[string]any, error) {
	params := map[string]string{
		"page": fmt.Sprintf("%d", page),
	}
	return c.post("/waf/get_component_list", params)
}

// CreateNameList 创建名单
func (c *Client) CreateNameList(list NameList) (map[string]any, error) {
	params := map[string]string{
		"name_list_name":        list.Name,
		"name_list_detail":      list.Detail,
		"name_list_rule":        toJSON(list.Rule),
		"name_list_action":      list.Action,
		"action_value":          list.ActionValue,
		"name_list_expire":      list.Expire,
		"name_list_expire_time": list.ExpireTime,
	}
	return c.post("/waf/create_global_name_list", params)
}

// AddNameListItem 添加名单条目
func (c *Client) AddNameListItem(name, item string) (map[string]any, error) {
	params := map[string]string{
		"name_list_name": name,
		"name_list_item": item,
	}
	return c.post("/waf/create_global_name_list_item", params)
}

// CreateWebWhiteRule 创建 Web 白名单
func (c *Client) CreateWebWhiteRule(rule WhiteRule) (map[string]any, error) {
	rule.Group = c.group
	params := map[string]string{
		"group_name":   rule.Group,
		"rule_name":    rule.Name,
		"rule_detail":  rule.Detail,
		"rule_matchs":  toJSON(rule.Matchs),
		"rule_action":  "web_bypass",
		"action_value": rule.ActionValue,
	}
	return c.post("/waf/create_group_web_white_rule", params)
}

// CreateFlowWhiteRule 创建流量白名单
func (c *Client) CreateFlowWhiteRule(rule WhiteRule) (map[string]any, error) {
	rule.Group = c.group
	params := map[string]string{
		"group_name":   rule.Group,
		"rule_name":    rule.Name,
		"rule_detail":  rule.Detail,
		"rule_matchs":  toJSON(rule.Matchs),
		"rule_action":  "flow_bypass",
		"action_value": rule.ActionValue,
	}
	return c.post("/waf/create_group_flow_white_rule", params)
}

// EncodeBase64 Base64 编码（用于组件代码）
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
