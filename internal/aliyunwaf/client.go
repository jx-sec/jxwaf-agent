// Package aliyunwaf 封装阿里云 WAF 3.0 OpenAPI 调用
// 文档：https://help.aliyun.com/zh/waf/web-application-firewall-3-0/developer-reference/
// API 版本：2021-10-01，RPC 风格，签名机制 HMAC-SHA1
package aliyunwaf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client 阿里云 WAF OpenAPI 客户端
type Client struct {
	accessKeyID     string
	accessKeySecret string
	region          string
	endpoint        string
	instanceID      string
	templateID      int64
	http            *http.Client
}

// New 创建阿里云 WAF 客户端
func New(accessKeyID, accessKeySecret, region, endpoint, instanceID string, templateID int64) *Client {
	if endpoint == "" {
		// 根据地域自动选择 endpoint
		if region == "ap-southeast-1" {
			endpoint = "wafopenapi.ap-southeast-1.aliyuncs.com"
		} else {
			endpoint = "wafopenapi.cn-hangzhou.aliyuncs.com"
		}
	}
	if region == "" {
		region = "cn-hangzhou"
	}
	return &Client{
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret + "&", // 签名时末尾加 &
		region:          region,
		endpoint:        endpoint,
		instanceID:      instanceID,
		templateID:      templateID,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// InstanceID 返回实例 ID
func (c *Client) InstanceID() string { return c.instanceID }

// TemplateID 返回模板 ID
func (c *Client) TemplateID() int64 { return c.templateID }

// call 发送 RPC 请求（GET 方式，参数在 query string）
func (c *Client) call(action string, params map[string]string) (map[string]any, error) {
	// 1. 组装公共参数
	params["Action"] = action
	params["Version"] = "2021-10-01"
	params["Format"] = "JSON"
	params["AccessKeyId"] = c.accessKeyID
	params["SignatureMethod"] = "HMAC-SHA1"
	params["SignatureVersion"] = "1.0"
	params["SignatureNonce"] = generateNonce()
	params["Timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if _, ok := params["RegionId"]; !ok {
		params["RegionId"] = c.region
	}

	// 2. 计算签名
	signature := c.sign("GET", params)
	params["Signature"] = signature

	// 3. 构建请求 URL
	query := buildQueryString(params)
	reqURL := fmt.Sprintf("https://%s/?%s", c.endpoint, query)

	// 4. 发送请求
	resp, err := c.http.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("请求阿里云 WAF API 失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v, body: %s", err, string(body))
	}

	// 检查 API 错误
	if code, ok := result["Code"].(string); ok && code != "" && code != "0" {
		msg, _ := result["Message"].(string)
		return result, fmt.Errorf("阿里云 WAF API 错误: code=%s message=%s", code, msg)
	}

	return result, nil
}

// sign 计算 RPC 签名
// 签名算法：HMAC-SHA1(StringToSign, AccessKeySecret + "&")
// StringToSign = HTTPMethod + "&" + percentEncode("/") + "&" + percentEncode(canonicalQueryString)
func (c *Client) sign(httpMethod string, params map[string]string) string {
	// 1. 排序参数 key
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 2. 构建规范化 query string
	var buf strings.Builder
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(percentEncode(k))
		buf.WriteByte('=')
		buf.WriteString(percentEncode(params[k]))
	}
	canonicalQueryString := buf.String()

	// 3. 构建 StringToSign
	stringToSign := httpMethod + "&" + percentEncode("/") + "&" + percentEncode(canonicalQueryString)

	// 4. HMAC-SHA1
	h := hmac.New(sha1.New, []byte(c.accessKeySecret))
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return signature
}

// percentEncode RFC 3986 百分号编码（阿里云专用）
func percentEncode(s string) string {
	s = url.QueryEscape(s)
	// url.QueryEscape 将空格编码为 +，阿里云需要 %20
	s = strings.ReplaceAll(s, "+", "%20")
	s = strings.ReplaceAll(s, "*", "%2A")
	s = strings.ReplaceAll(s, "%7E", "~")
	return s
}

// buildQueryString 构建查询字符串（不编码，签名后使用）
func buildQueryString(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf strings.Builder
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(percentEncode(k))
		buf.WriteByte('=')
		buf.WriteString(percentEncode(params[k]))
	}
	return buf.String()
}

// generateNonce 生成随机签名 nonce
func generateNonce() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), time.Now().UnixMicro()%100000)
}

// =============================================================================
// 防护规则管理
// =============================================================================

// CreateDefenseRule 创建防护规则
// defenseScene: custom_acl / ip_blacklist / cc / whitelist 等
// rules: 规则 JSON 字符串数组
func (c *Client) CreateDefenseRule(defenseScene, rulesJSON string) (map[string]any, error) {
	params := map[string]string{
		"InstanceId":   c.instanceID,
		"DefenseScene": defenseScene,
		"Rules":        rulesJSON,
	}
	if c.templateID > 0 {
		params["TemplateId"] = fmt.Sprintf("%d", c.templateID)
	}
	return c.call("CreateDefenseRule", params)
}

// ModifyDefenseRule 修改防护规则
func (c *Client) ModifyDefenseRule(ruleID int64, defenseScene, rulesJSON string) (map[string]any, error) {
	params := map[string]string{
		"InstanceId":   c.instanceID,
		"DefenseScene": defenseScene,
		"RuleId":       fmt.Sprintf("%d", ruleID),
		"Rules":        rulesJSON,
	}
	if c.templateID > 0 {
		params["TemplateId"] = fmt.Sprintf("%d", c.templateID)
	}
	return c.call("ModifyDefenseRule", params)
}

// DeleteDefenseRule 删除防护规则
func (c *Client) DeleteDefenseRule(ruleID int64) (map[string]any, error) {
	params := map[string]string{
		"InstanceId": c.instanceID,
		"RuleId":     fmt.Sprintf("%d", ruleID),
	}
	if c.templateID > 0 {
		params["TemplateId"] = fmt.Sprintf("%d", c.templateID)
	}
	return c.call("DeleteDefenseRule", params)
}

// ModifyDefenseRuleStatus 修改规则状态（0=关闭, 1=开启）
func (c *Client) ModifyDefenseRuleStatus(ruleID int64, status int) (map[string]any, error) {
	params := map[string]string{
		"InstanceId": c.instanceID,
		"RuleId":     fmt.Sprintf("%d", ruleID),
		"Status":     fmt.Sprintf("%d", status),
	}
	if c.templateID > 0 {
		params["TemplateId"] = fmt.Sprintf("%d", c.templateID)
	}
	return c.call("ModifyDefenseRuleStatus", params)
}

// DescribeDefenseRules 查询防护规则列表
func (c *Client) DescribeDefenseRules(defenseScene string, pageNumber, pageSize int) (map[string]any, error) {
	params := map[string]string{
		"InstanceId":   c.instanceID,
		"DefenseScene": defenseScene,
	}
	if c.templateID > 0 {
		params["TemplateId"] = fmt.Sprintf("%d", c.templateID)
	}
	if pageNumber > 0 {
		params["PageNumber"] = fmt.Sprintf("%d", pageNumber)
	}
	if pageSize > 0 {
		params["PageSize"] = fmt.Sprintf("%d", pageSize)
	}
	return c.call("DescribeDefenseRules", params)
}

// =============================================================================
// 防护对象/域名查询
// =============================================================================

// DescribeDefenseResources 查询防护对象列表
func (c *Client) DescribeDefenseResources(pageNumber, pageSize int) (map[string]any, error) {
	params := map[string]string{
		"InstanceId": c.instanceID,
	}
	if pageNumber > 0 {
		params["PageNumber"] = fmt.Sprintf("%d", pageNumber)
	}
	if pageSize > 0 {
		params["PageSize"] = fmt.Sprintf("%d", pageSize)
	}
	return c.call("DescribeDefenseResources", params)
}

// DescribeDomains 查询 CNAME 接入域名列表
func (c *Client) DescribeDomains(pageNumber, pageSize int) (map[string]any, error) {
	params := map[string]string{
		"InstanceId": c.instanceID,
	}
	if pageNumber > 0 {
		params["PageNumber"] = fmt.Sprintf("%d", pageNumber)
	}
	if pageSize > 0 {
		params["PageSize"] = fmt.Sprintf("%d", pageSize)
	}
	return c.call("DescribeDomains", params)
}

// =============================================================================
// 地址簿管理（IP 地址簿）
// =============================================================================

// AddAddress 添加地址簿条目
func (c *Client) AddAddress(addressName, addressType, group string, addresses []string) (map[string]any, error) {
	addrJSON, _ := json.Marshal(addresses)
	params := map[string]string{
		"InstanceId":  c.instanceID,
		"AddressName": addressName,
		"Type":        addressType, // ipv4 / ipv6
		"Group":       group,
		"Addresses":   string(addrJSON),
	}
	return c.call("AddAddress", params)
}

// DescribeAddresses 查询地址簿列表
func (c *Client) DescribeAddresses(pageNumber, pageSize int) (map[string]any, error) {
	params := map[string]string{
		"InstanceId": c.instanceID,
	}
	if pageNumber > 0 {
		params["PageNumber"] = fmt.Sprintf("%d", pageNumber)
	}
	if pageSize > 0 {
		params["PageSize"] = fmt.Sprintf("%d", pageSize)
	}
	return c.call("DescribeAddresses", params)
}

// DeleteAddress 删除地址簿条目
func (c *Client) DeleteAddress(addressName string) (map[string]any, error) {
	params := map[string]string{
		"InstanceId":  c.instanceID,
		"AddressName": addressName,
	}
	return c.call("DeleteAddress", params)
}

// =============================================================================
// 辅助方法
// =============================================================================

// PostBody 发送 POST 请求（部分接口需要 POST body）
func (c *Client) PostBody(action string, body any) (map[string]any, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/", c.endpoint), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

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
	_ = action
	return result, nil
}
