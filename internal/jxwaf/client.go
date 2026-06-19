// Package jxwaf 封装 JXWAF 控制台 API 调用
package jxwaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client JXWAF 控制台 API 客户端（云端验证环境专用）
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

// post 发送 POST 请求（JSON body）
func (c *Client) post(path string, body any) (map[string]any, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}

	req, err := http.NewRequest("POST", c.apiURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.wafAuth != "" {
		req.Header.Set("waf_auth", c.wafAuth)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v, body: %s", err, string(respBody))
	}
	return result, nil
}

// =============================================================================
// Web 防护规则
// =============================================================================

// ListWebRules 查询 Web 防护规则列表
func (c *Client) ListWebRules(page int) (map[string]any, error) {
	body := map[string]any{"page": page}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/get_group_web_rule_protection_list", body)
}

// DeleteWebRule 删除 Web 防护规则
func (c *Client) DeleteWebRule(ruleName string) (map[string]any, error) {
	body := map[string]any{"rule_name": ruleName}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/delete_group_web_rule_protection", body)
}

// =============================================================================
// 流量防护规则
// =============================================================================

// ListFlowRules 查询流量防护规则列表
func (c *Client) ListFlowRules(page int) (map[string]any, error) {
	body := map[string]any{"page": page}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/get_group_flow_rule_protection_list", body)
}

// DeleteFlowRule 删除流量防护规则
func (c *Client) DeleteFlowRule(ruleName string) (map[string]any, error) {
	body := map[string]any{"rule_name": ruleName}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/delete_group_flow_rule_protection", body)
}

// =============================================================================
// 防护组件
// =============================================================================

// ListComponents 查询组件列表
func (c *Client) ListComponents(page int) (map[string]any, error) {
	return c.post("/get_component_list", map[string]any{"page": page})
}

// DeleteComponent 删除组件
func (c *Client) DeleteComponent(name string) (map[string]any, error) {
	return c.post("/delete_component", map[string]any{"name": name})
}

// =============================================================================
// 全局名单
// =============================================================================

// ListNameLists 查询名单列表
func (c *Client) ListNameLists(page int) (map[string]any, error) {
	return c.post("/get_global_name_list_list", map[string]any{"page": page})
}

// DeleteNameList 删除名单（级联删除条目）
func (c *Client) DeleteNameList(name string) (map[string]any, error) {
	return c.post("/delete_global_name_list", map[string]any{"name_list_name": name})
}

// =============================================================================
// Web 白名单
// =============================================================================

// ListWebWhiteRules 查询 Web 白名单列表
func (c *Client) ListWebWhiteRules(page int) (map[string]any, error) {
	body := map[string]any{"page": page}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/get_group_web_white_rule_list", body)
}

// DeleteWebWhiteRule 删除 Web 白名单
func (c *Client) DeleteWebWhiteRule(ruleName string) (map[string]any, error) {
	body := map[string]any{"rule_name": ruleName}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/delete_group_web_white_rule", body)
}

// =============================================================================
// 流量白名单
// =============================================================================

// ListFlowWhiteRules 查询流量白名单列表
func (c *Client) ListFlowWhiteRules(page int) (map[string]any, error) {
	body := map[string]any{"page": page}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/get_group_flow_white_rule_list", body)
}

// DeleteFlowWhiteRule 删除流量白名单
func (c *Client) DeleteFlowWhiteRule(ruleName string) (map[string]any, error) {
	body := map[string]any{"rule_name": ruleName}
	if c.group != "" {
		body["group_name"] = c.group
	}
	return c.post("/delete_group_flow_white_rule", body)
}

// =============================================================================
// 攻击日志查询（云端验证用）
// =============================================================================

// LogQueryParams 日志查询参数
type LogQueryParams struct {
	FromTime string           `json:"from_time"` // 格式: YYYY-MM-DD HH:MM:SS
	ToTime   string           `json:"to_time"`
	Page     int              `json:"page"`
	Group    string           `json:"group_name,omitempty"`
	Domain   string           `json:"domain,omitempty"`
	SQLRules []map[string]any `json:"sql_rules,omitempty"`
}

// QuerySocLogs 查询 SOC 攻击日志
func (c *Client) QuerySocLogs(params LogQueryParams) (map[string]any, error) {
	body := map[string]any{
		"from_time": params.FromTime,
		"to_time":   params.ToTime,
		"page":      params.Page,
	}
	if params.Group != "" {
		body["group_name"] = params.Group
	}
	if params.Domain != "" {
		body["domain"] = params.Domain
	}
	if params.SQLRules != nil {
		body["sql_rules"] = params.SQLRules
	}
	return c.post("/get_soc_log_query_list", body)
}
