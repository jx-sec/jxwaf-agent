// Package client 提供 JXWAF 管理 API 的 HTTP 调用基础能力。
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
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

// New 构造客户端，默认 10 秒超时。BaseURL 尾部斜杠会被规范化。
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Post 以 JSON 调用 baseURL+path，返回统一响应。
// 仅网络层失败返回 error；业务失败（HTTP 非 2xx 或 result=false）在 Response 中体现。
// 判定原则为 fail-safe：非 2xx、响应非 JSON、或缺少 result 字段均视为失败。
func (c *Client) Post(path string, headers map[string]string, body any) (*Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("请求体序列化失败: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败（请检查 base_url 是否合法）: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求发起失败（请检查 base_url 与网络连通性，可用 config validate 自检）: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	r := &Response{}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// 非 2xx：网关/代理错误页、认证失败等，一律按失败处理（fail-safe）
		r.Result = false
		r.Message = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(raw, 200))
		tryDecode(raw, r)
		return r, nil
	}
	if err := tryDecode(raw, r); err != nil {
		r.Result = false
		if len(raw) >= 10<<20 {
			r.Message = fmt.Sprintf("响应超过 10MB 已截断，且截断后非 JSON: %s", truncate(raw, 200))
		} else {
			r.Message = fmt.Sprintf("响应非 JSON: %s", truncate(raw, 200))
		}
		return r, nil
	}
	if v, ok := r.Raw["result"]; !ok {
		// 响应缺少 result 字段：无法确认成功，按失败处理（fail-safe）
		r.Result = false
		r.Message = fmt.Sprintf("响应缺少 result 字段，无法判定业务结果: %s", truncate(raw, 200))
	} else if b, ok := v.(bool); ok {
		r.Result = b
	} else {
		r.Result = false
		r.Message = fmt.Sprintf("响应 result 字段类型异常（%T），无法判定业务结果", v)
	}
	if s, ok := r.Raw["message"].(string); ok && s != "" {
		r.Message = s
	}
	return r, nil
}

// tryDecode 解析响应体为 map；解析成功时填充 r.Raw。
func tryDecode(raw []byte, r *Response) error {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m != nil {
		r.Raw = m
	}
	return nil
}

// truncate 按字节截断并在 UTF-8 字符边界回退，避免产生乱码。
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return string(b[:cut]) + "..."
}
