// hub.go 提供 hub.jxwaf.com 策略共享平台的 HTTP 客户端。
// 与 WAF 管理 API 契约不同：Hub 以 HTTP 状态码判定成败，错误体为 {"message":"..."}，
// 认证为 jxwaf-api-key 请求头（登录换 Token 用 jxwaf_hub_session Cookie 中转）。
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HubClient 策略共享平台客户端。
type HubClient struct {
	BaseURL string // 形如 https://hub.jxwaf.com（尾部斜杠已规范化）
	Token   string // 用户 API Token（jxwaf-api-key）
	HTTP    *http.Client
}

// NewHub 构造 Hub 客户端，默认 15 秒超时。
func NewHub(baseURL, token string) *HubClient {
	return &HubClient{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// hubResp 统一响应：status 为 HTTP 状态码，raw 为原始响应体，cookie 为会话 Cookie（登录响应携带）。
type hubResp struct {
	status int
	raw    []byte
	cookie string
}

// OK 判定 2xx。
func (r *hubResp) OK() bool { return r.status >= 200 && r.status <= 299 }

// Message 提取错误体中的 message 字段（缺失时回退到截断原文）。
func (r *hubResp) Message() string {
	var m map[string]any
	if err := json.Unmarshal(r.raw, &m); err == nil {
		if s, ok := m["message"].(string); ok && s != "" {
			return s
		}
	}
	return truncate(r.raw, 200)
}

// hubError 将非预期响应转为错误（含状态码与平台错误信息）。
func (r *hubResp) hubError(action string) error {
	return fmt.Errorf("hub %s 失败（HTTP %d）: %s", action, r.status, r.Message())
}

// call 执行一次请求。cookie 非空时携带会话（登录换 Token 场景），
// token 非空时携带 jxwaf-api-key。body 为 nil 时不发请求体。
func (h *HubClient) call(method, path string, body any, token, cookie string) (*hubResp, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("请求体序列化失败: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, h.BaseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败（请检查 base_url 是否合法）: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if token != "" {
		req.Header.Set("jxwaf-api-key", token)
	}
	resp, err := h.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求发起失败（请检查 base_url 与网络连通性）: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	// 捕获会话 Cookie（jxwaf_hub_session），供登录后换取 API Token 使用
	sc := resp.Header.Get("Set-Cookie")
	if v, _, found := strings.Cut(sc, ";"); found || v != "" {
		if name, value, ok := strings.Cut(v, "="); ok && name == "jxwaf_hub_session" {
			return &hubResp{status: resp.StatusCode, raw: raw, cookie: "jxwaf_hub_session=" + value}, nil
		}
	}
	return &hubResp{status: resp.StatusCode, raw: raw}, nil
}

// callAPI 携带 api-key 的 JSON 请求，并把 2xx 响应解析为 map（空体返回空 map）。
func (h *HubClient) callAPI(method, path string, body any) (map[string]any, error) {
	r, err := h.call(method, path, body, h.Token, "")
	if err != nil {
		return nil, err
	}
	if !r.OK() {
		return nil, r.hubError(method + " " + path)
	}
	out := map[string]any{}
	if len(bytes.TrimSpace(r.raw)) > 0 {
		if err := json.Unmarshal(r.raw, &out); err != nil {
			return nil, fmt.Errorf("hub 响应非 JSON: %s", truncate(r.raw, 200))
		}
	}
	return out, nil
}

// Login 登录并返回会话 Cookie（jxwaf_hub_session=...）。仅用于换取 API Token，密码不落盘。
func (h *HubClient) Login(username, password, otpCode string) (string, error) {
	r, err := h.call(http.MethodPost, "/api/auth/login", map[string]string{
		"username": username,
		"password": password,
		"otp_code": otpCode,
	}, "", "")
	if err != nil {
		return "", err
	}
	if !r.OK() {
		// 登录限流（10次/分/IP）与账号密码错误均在此体现
		return "", r.hubError("登录")
	}
	if r.cookie == "" {
		return "", fmt.Errorf("hub 登录成功但未返回会话 Cookie，无法换取 Token")
	}
	return r.cookie, nil
}

// GetToken 用会话 Cookie 获取当前 API Token（has=false 表示用户从未生成过 Token）。
func (h *HubClient) GetToken(cookie string) (token string, has bool, err error) {
	r, err := h.call(http.MethodGet, "/api/user/token", nil, "", cookie)
	if err != nil {
		return "", false, err
	}
	if !r.OK() {
		return "", false, r.hubError("获取Token")
	}
	var out struct {
		Token    string `json:"token"`
		HasToken bool   `json:"has_token"`
	}
	if err := json.Unmarshal(r.raw, &out); err != nil {
		return "", false, fmt.Errorf("Token 响应解析失败: %w", err)
	}
	return out.Token, out.HasToken, nil
}

// RegenerateToken 用会话 Cookie 重新生成 API Token（旧 Token 立即失效）。
func (h *HubClient) RegenerateToken(cookie string) (string, error) {
	r, err := h.call(http.MethodPost, "/api/user/token/regenerate", nil, "", cookie)
	if err != nil {
		return "", err
	}
	if !r.OK() {
		return "", r.hubError("生成Token")
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(r.raw, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("Token 响应异常: %s", truncate(r.raw, 200))
	}
	return out.Token, nil
}

// Me 获取当前 Token 对应的账号信息（验证 Token 有效性）。
func (h *HubClient) Me() (map[string]any, error) {
	return h.callAPI(http.MethodGet, "/api/auth/me", nil)
}

// ListPolicies 分页获取当前账号策略列表。
func (h *HubClient) ListPolicies(page, pageSize int) (map[string]any, error) {
	return h.callAPI(http.MethodGet, fmt.Sprintf("/api/policies?page=%d&page_size=%d", page, pageSize), nil)
}

// GetPolicy 获取单个策略详情（含 json_content）。返回 (map, 是否存在, error)。
func (h *HubClient) GetPolicy(name string) (map[string]any, bool, error) {
	r, err := h.call(http.MethodGet, "/api/policies/"+name, nil, h.Token, "")
	if err != nil {
		return nil, false, err
	}
	if r.status == http.StatusNotFound {
		return nil, false, nil
	}
	if !r.OK() {
		return nil, false, r.hubError("查询策略 " + name)
	}
	out := map[string]any{}
	if err := json.Unmarshal(r.raw, &out); err != nil {
		return nil, false, fmt.Errorf("策略详情响应非 JSON: %s", truncate(r.raw, 200))
	}
	return out, true, nil
}

// CreatePolicy 创建策略（jsonContent 为合法 JSON 字符串，Hub 端仅校验语法）。
func (h *HubClient) CreatePolicy(name, product, scene string, isPrivate bool, description, readme, jsonContent string) (map[string]any, error) {
	return h.callAPI(http.MethodPost, "/api/policies", map[string]any{
		"name": name, "product": product, "scene": scene,
		"is_private": isPrivate, "description": description, "readme": readme,
		"json_content": jsonContent,
	})
}

// UpdatePolicy 更新策略（覆盖内容与元数据；策略名不可改）。
func (h *HubClient) UpdatePolicy(name string, fields map[string]any) error {
	_, err := h.callAPI(http.MethodPut, "/api/policies/"+name, fields)
	return err
}

// DeletePolicy 删除策略（硬删除，不可恢复）。
func (h *HubClient) DeletePolicy(name string) error {
	_, err := h.callAPI(http.MethodDelete, "/api/policies/"+name, nil)
	return err
}

// PullRepo 拉取策略原始 JSON（POST /{product}/repo；私有策略自动携带 Token）。
// 返回原始 JSON 字节（平台直出策略内容，非包装结构）。
func (h *HubClient) PullRepo(product, repo string) ([]byte, error) {
	r, err := h.call(http.MethodPost, "/"+product+"/repo", map[string]string{"repo": repo}, h.Token, "")
	if err != nil {
		return nil, err
	}
	if !r.OK() {
		return nil, r.hubError("拉取策略 " + repo)
	}
	return r.raw, nil
}
