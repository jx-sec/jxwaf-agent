// Package client 提供 JXWAF 管理 API 的 HTTP 调用基础能力。
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Response 统一封装管理 API 响应：{result, message, ...}。
// 注意：管理 API 业务失败也返回 HTTP 200，以 result 字段判定成败。
type Response struct {
	Result  bool
	Message string
	Raw     map[string]any
}

// Client 管理 API 客户端。
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New 构造客户端，默认 10 秒超时。
func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Post 以 JSON 调用 baseURL+path，返回统一响应。
// 仅网络层失败返回 error；业务失败（result=false）在 Response 中体现。
func (c *Client) Post(path string, headers map[string]string, body any) (*Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("请求体序列化失败: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	r := &Response{Result: true}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		r.Result = false
		r.Message = fmt.Sprintf("响应非 JSON（HTTP %d）: %s", resp.StatusCode, truncate(raw, 200))
		return r, nil
	}
	r.Raw = m
	if v, ok := m["result"].(bool); ok {
		r.Result = v
	}
	if s, ok := m["message"].(string); ok {
		r.Message = s
	}
	return r, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
