package function

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VerifyFunc 验证规则是否生效
type VerifyFunc struct {
	VerifyURL string // 默认验证目标 URL
}

func (f *VerifyFunc) Name() string { return "verify_config" }

func (f *VerifyFunc) Description() string {
	return "验证规则是否生效（发送请求测试拦截/放行）。支持单次验证和高频验证（流量规则）。"
}

func (f *VerifyFunc) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "验证 URL，如 https://demo.jxwaf.com/admin",
			},
			"expect": map[string]any{
				"type":        "string",
				"enum":        []string{"block", "pass"},
				"description": "期望结果：block（被拦截）/ pass（放行）",
			},
			"mode": map[string]any{
				"type":        "string",
				"enum":        []string{"single", "flow"},
				"default":     "single",
				"description": "验证模式：single 单次 / flow 高频（流量规则）",
			},
			"count": map[string]any{
				"type":        "integer",
				"default":     1,
				"description": "flow 模式下的请求次数",
			},
			"interval": map[string]any{
				"type":        "number",
				"default":     0.1,
				"description": "flow 模式下的请求间隔（秒）",
			},
			"headers": map[string]any{
				"type":        "object",
				"description": "自定义请求头",
			},
		},
		"required": []string{"url", "expect"},
	}
}

func (f *VerifyFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	urlStr, _ := args["url"].(string)
	expect, _ := args["expect"].(string)
	mode, _ := args["mode"].(string)
	if mode == "" {
		mode = "single"
	}

	if urlStr == "" {
		return "", fmt.Errorf("url 不能为空")
	}

	// 解析 headers
	headers := make(map[string]string)
	if h, ok := args["headers"].(map[string]any); ok {
		for k, v := range h {
			if vs, ok := v.(string); ok {
				headers[k] = vs
			}
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	if mode == "flow" {
		count := 1
		if c, ok := args["count"].(float64); ok {
			count = int(c)
		}
		interval := 0.1
		if i, ok := args["interval"].(float64); ok {
			interval = i
		}
		return f.verifyFlow(client, urlStr, headers, count, interval, expect)
	}
	return f.verifySingle(client, urlStr, headers, expect)
}

// verifySingle 单次验证
func (f *VerifyFunc) verifySingle(client *http.Client, urlStr string, headers map[string]string, expect string) (string, error) {
	blocked, statusCode, err := f.sendRequest(client, urlStr, headers)
	if err != nil {
		return "", err
	}
	result := "pass"
	if blocked {
		result = "block"
	}
	status := "✓ 符合预期"
	if result != expect {
		status = "✗ 不符合预期"
	}
	return fmt.Sprintf("单次验证: url=%s, 状态码=%d, 实际=%s, 期望=%s, %s",
		urlStr, statusCode, result, expect, status), nil
}

// verifyFlow 高频验证
func (f *VerifyFunc) verifyFlow(client *http.Client, urlStr string, headers map[string]string, count int, interval float64, expect string) (string, error) {
	blockedCount := 0
	for i := 0; i < count; i++ {
		blocked, _, err := f.sendRequest(client, urlStr, headers)
		if err != nil {
			return "", err
		}
		if blocked {
			blockedCount++
		}
		time.Sleep(time.Duration(interval * float64(time.Second)))
	}
	result := "pass"
	if blockedCount > 0 {
		result = "block"
	}
	status := "✓ 符合预期"
	if result != expect {
		status = "✗ 不符合预期"
	}
	return fmt.Sprintf("高频验证: url=%s, 总请求=%d, 被拦截=%d, 实际=%s, 期望=%s, %s",
		urlStr, count, blockedCount, result, expect, status), nil
}

// sendRequest 发送请求，返回是否被拦截
func (f *VerifyFunc) sendRequest(client *http.Client, urlStr string, headers map[string]string) (bool, int, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return false, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// 拦截判断：状态码 403 或响应体含拦截特征
	blocked := resp.StatusCode == 403 || resp.StatusCode == 429
	if !blocked {
		// 检查响应头中的 WAF 拦截标识
		if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
			// 简单判断：WAF 拦截页面通常状态码 403
			blocked = resp.StatusCode >= 400 && resp.StatusCode < 500
		}
	}
	return blocked, resp.StatusCode, nil
}
