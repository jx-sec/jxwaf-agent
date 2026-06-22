// Package tencentwaf 封装腾讯云 WAF OpenAPI 调用
// 文档：https://cloud.tencent.com/document/product/627/53618
// API 版本：2018-01-25，签名方法 TC3-HMAC-SHA256
package tencentwaf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client 腾讯云 WAF OpenAPI 客户端
type Client struct {
	secretID   string
	secretKey  string
	region     string
	edition    string // sparta-waf / clb-waf
	instanceID string
	http       *http.Client
}

// New 创建腾讯云 WAF 客户端
func New(secretID, secretKey, region, edition, instanceID string) *Client {
	if region == "" {
		region = "ap-guangzhou"
	}
	if edition == "" {
		edition = "sparta-waf"
	}
	return &Client{
		secretID:   secretID,
		secretKey:  secretKey,
		region:     region,
		edition:    edition,
		instanceID: instanceID,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Edition 返回实例类型
func (c *Client) Edition() string { return c.edition }

// InstanceID 返回实例 ID
func (c *Client) InstanceID() string { return c.instanceID }

// call 发送 TC3-HMAC-SHA256 签名的 POST 请求
func (c *Client) call(action string, payload any) (map[string]any, error) {
	// 1. 序列化 payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}
	payloadStr := string(payloadBytes)

	// 2. 构建签名信息
	endpoint := "waf.tencentcloudapi.com"
	timestamp := time.Now().Unix()
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")

	// 2.1 拼接规范请求串 CanonicalRequest
	canonicalURI := "/"
	canonicalQueryString := ""
	canonicalHeaders := fmt.Sprintf("content-type:application/json; charset=utf-8\nhost:%s\nx-tc-action:%s\n",
		endpoint, strings.ToLower(action))
	signedHeaders := "content-type;host;x-tc-action"
	hashedRequestPayload := sha256Hex(payloadStr)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		"POST", canonicalURI, canonicalQueryString,
		canonicalHeaders, signedHeaders, hashedRequestPayload)

	// 2.2 拼接签名串 StringToSign
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, "waf")
	hashedCanonicalRequest := sha256Hex(canonicalRequest)
	stringToSign := fmt.Sprintf("TC3-HMAC-SHA256\n%d\n%s\n%s",
		timestamp, credentialScope, hashedCanonicalRequest)

	// 2.3 计算签名
	secretDate := hmacSHA256([]byte("TC3"+c.secretKey), date)
	secretService := hmacSHA256(secretDate, "waf")
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	// 2.4 构建 Authorization header
	authorization := fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.secretID, credentialScope, signedHeaders, signature)

	// 3. 发送请求
	reqURL := fmt.Sprintf("https://%s/", endpoint)
	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", endpoint)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", "2018-01-25")
	req.Header.Set("X-TC-Region", c.region)
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("Authorization", authorization)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求腾讯云 WAF API 失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// 4. 解析响应
	var result struct {
		Response struct {
			RequestId string         `json:"RequestId"`
			Error     *APIError      `json:"Error,omitempty"`
			Data      map[string]any `json:",inline"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v, body: %s", err, string(body))
	}

	// 5. 检查 API 错误
	if result.Response.Error != nil {
		return nil, fmt.Errorf("腾讯云 WAF API 错误: code=%s message=%s",
			result.Response.Error.Code, result.Response.Error.Message)
	}

	// 返回完整响应（包含 RequestId 和数据字段）
	output := map[string]any{
		"RequestId": result.Response.RequestId,
	}
	for k, v := range result.Response.Data {
		output[k] = v
	}
	// 如果 Data 为空，尝试解析所有字段
	if len(result.Response.Data) == 0 {
		var rawMap map[string]any
		json.Unmarshal(body, &rawMap)
		if respData, ok := rawMap["Response"].(map[string]any); ok {
			for k, v := range respData {
				if k != "Error" && k != "RequestId" {
					output[k] = v
				}
			}
		}
	}

	return output, nil
}

// APIError 腾讯云 API 错误
type APIError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// sha256Hex 计算 SHA256 并返回十六进制字符串
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hmacSHA256 计算 HMAC-SHA256
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// =============================================================================
// 自定义规则管理（访问控制）
// =============================================================================

// Strategy 匹配条件
type Strategy struct {
	Field       string `json:"Field"`
	CompareFunc string `json:"CompareFunc"`
	Content     string `json:"Content"`
	Arg         string `json:"Arg,omitempty"`
}

// AddCustomRuleRequest 新增自定义规则请求
type AddCustomRuleRequest struct {
	Name        string     `json:"Name"`
	SortId      string     `json:"SortId"`
	Strategies  []Strategy `json:"Strategies"`
	Domain      string     `json:"Domain"`
	ActionType  string     `json:"ActionType"`
	LogicalOp   string     `json:"LogicalOp,omitempty"`
	Redirect    string     `json:"Redirect,omitempty"`
	ExpireTime  string     `json:"ExpireTime,omitempty"`
	Edition     string     `json:"Edition"`
	JobType     string     `json:"JobType,omitempty"`
}

// AddCustomRule 新增自定义规则
func (c *Client) AddCustomRule(req *AddCustomRuleRequest) (map[string]any, error) {
	if req.Edition == "" {
		req.Edition = c.edition
	}
	if req.JobType == "" {
		req.JobType = "forever"
	}
	if req.ExpireTime == "" {
		req.ExpireTime = "0"
	}
	if req.LogicalOp == "" {
		req.LogicalOp = "and"
	}
	return c.call("AddCustomRule", req)
}

// ModifyCustomRule 修改自定义规则
func (c *Client) ModifyCustomRule(req *AddCustomRuleRequest, ruleID int64) (map[string]any, error) {
	if req.Edition == "" {
		req.Edition = c.edition
	}
	payload := map[string]any{
		"Name":       req.Name,
		"SortId":     req.SortId,
		"Strategies": req.Strategies,
		"Domain":     req.Domain,
		"ActionType": req.ActionType,
		"LogicalOp":  req.LogicalOp,
		"Edition":    req.Edition,
		"RuleId":     ruleID,
	}
	return c.call("ModifyCustomRule", payload)
}

// DeleteCustomRule 删除自定义规则
func (c *Client) DeleteCustomRule(domain string, ruleID int64) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"RuleId":  ruleID,
		"Edition": c.edition,
	}
	return c.call("DeleteCustomRule", payload)
}

// DescribeCustomRuleList 查询自定义规则列表
func (c *Client) DescribeCustomRuleList(domain string, offset, limit int) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"Edition": c.edition,
	}
	if offset >= 0 {
		payload["Offset"] = offset
	}
	if limit > 0 {
		payload["Limit"] = limit
	}
	return c.call("DescribeCustomRuleList", payload)
}

// ModifyCustomRuleStatus 修改自定义规则状态
func (c *Client) ModifyCustomRuleStatus(domain string, ruleID int64, status int) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"RuleId":  ruleID,
		"Status":  status,
		"Edition": c.edition,
	}
	return c.call("ModifyCustomRuleStatus", payload)
}

// =============================================================================
// 精准白名单管理
// =============================================================================

// AddCustomWhiteRule 添加精准白名单规则
func (c *Client) AddCustomWhiteRule(name, domain string, strategies []Strategy, sortID string) (map[string]any, error) {
	payload := map[string]any{
		"Name":       name,
		"Domain":     domain,
		"SortId":     sortID,
		"Strategies": strategies,
		"Edition":    c.edition,
	}
	return c.call("AddCustomWhiteRule", payload)
}

// DeleteCustomWhiteRule 删除精准白名单规则
func (c *Client) DeleteCustomWhiteRule(domain string, ruleID int64) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"RuleId":  ruleID,
		"Edition": c.edition,
	}
	return c.call("DeleteCustomWhiteRule", payload)
}

// DescribeCustomWhiteRules 查询精准白名单规则列表
func (c *Client) DescribeCustomWhiteRules(domain string, offset, limit int) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"Edition": c.edition,
	}
	if offset >= 0 {
		payload["Offset"] = offset
	}
	if limit > 0 {
		payload["Limit"] = limit
	}
	return c.call("DescribeCustomWhiteRules", payload)
}

// =============================================================================
// IP 黑白名单管理
// =============================================================================

// CreateIpAccessControl 创建 IP 黑白名单
// actionType: 42=黑名单, 40=白名单
func (c *Client) CreateIpAccessControl(domain string, ipList []string, actionType int) (map[string]any, error) {
	payload := map[string]any{
		"Domain":     domain,
		"IpList":     ipList,
		"ActionType": actionType,
		"Edition":    c.edition,
		"SourceType": "custom",
	}
	if c.instanceID != "" {
		payload["InstanceId"] = c.instanceID
	}
	return c.call("CreateIpAccessControl", payload)
}

// DeleteIpAccessControl 删除 IP 黑白名单
func (c *Client) DeleteIpAccessControl(domain string, ruleID int64) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"RuleId":  ruleID,
		"Edition": c.edition,
	}
	if c.instanceID != "" {
		payload["InstanceId"] = c.instanceID
	}
	return c.call("DeleteIpAccessControl", payload)
}

// DescribeIpAccessControl 查询 IP 黑白名单列表
func (c *Client) DescribeIpAccessControl(domain string, offset, limit int) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"Edition": c.edition,
	}
	if c.instanceID != "" {
		payload["InstanceId"] = c.instanceID
	}
	if offset >= 0 {
		payload["Offset"] = offset
	}
	if limit > 0 {
		payload["Limit"] = limit
	}
	return c.call("DescribeIpAccessControl", payload)
}

// =============================================================================
// CC 防护规则管理
// =============================================================================

// UpsertCCRuleRequest CC 规则请求
type UpsertCCRuleRequest struct {
	Domain      string `json:"Domain"`
	Name        string `json:"Name"`
	Status      int64  `json:"Status"`
	Advance     string `json:"Advance"`
	Limit       string `json:"Limit"`
	Interval    string `json:"Interval"`
	ActionType  string `json:"ActionType"`
	Priority    int64  `json:"Priority"`
	ValidTime   int64  `json:"ValidTime"`
	MatchFunc   int64  `json:"MatchFunc"`
	OptionsArr  string `json:"OptionsArr"`
	Edition     string `json:"Edition"`
	RuleId      int64  `json:"RuleId"`
	LogicalOp   string `json:"LogicalOp"`
	ActionRatio int64  `json:"ActionRatio"`
	JobType     string `json:"JobType"`
}

// UpsertCCRule 创建/更新 CC 规则
func (c *Client) UpsertCCRule(req *UpsertCCRuleRequest) (map[string]any, error) {
	if req.Edition == "" {
		req.Edition = c.edition
	}
	if req.JobType == "" {
		req.JobType = "forever"
	}
	if req.LogicalOp == "" {
		req.LogicalOp = "and"
	}
	if req.ActionRatio == 0 {
		req.ActionRatio = 100
	}
	return c.call("UpsertCCRule", req)
}

// DeleteCCRule 删除 CC 规则
func (c *Client) DeleteCCRule(domain string, ruleIDs []int64) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"RuleIds": ruleIDs,
		"Edition": c.edition,
	}
	return c.call("DeleteCCRule", payload)
}

// DescribeCCRuleList 查询 CC 规则列表
func (c *Client) DescribeCCRuleList(domain string, offset, limit int) (map[string]any, error) {
	payload := map[string]any{
		"Domain":  domain,
		"Edition": c.edition,
	}
	if offset >= 0 {
		payload["Offset"] = offset
	}
	if limit > 0 {
		payload["Limit"] = limit
	}
	return c.call("DescribeCCRuleList", payload)
}

// =============================================================================
// 域名/实例查询
// =============================================================================

// DescribeDomains 查询域名列表
func (c *Client) DescribeDomains(offset, limit int) (map[string]any, error) {
	payload := map[string]any{
		"Edition": c.edition,
	}
	if c.instanceID != "" {
		payload["InstanceId"] = c.instanceID
	}
	if offset >= 0 {
		payload["Offset"] = offset
	}
	if limit > 0 {
		payload["Limit"] = limit
	}
	return c.call("DescribeDomains", payload)
}

// DescribeInstances 查询实例列表
func (c *Client) DescribeInstances(offset, limit int) (map[string]any, error) {
	payload := map[string]any{}
	if offset >= 0 {
		payload["Offset"] = offset
	}
	if limit > 0 {
		payload["Limit"] = limit
	}
	return c.call("DescribeInstances", payload)
}
