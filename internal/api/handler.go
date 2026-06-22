// Package api 实现 HTTP handler
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"jxwaf-agent-go/internal/agent"
	"jxwaf-agent-go/internal/aliyunwaf"
	"jxwaf-agent-go/internal/audit"
	"jxwaf-agent-go/internal/auth"
	"jxwaf-agent-go/internal/config"
	"jxwaf-agent-go/internal/db"
	"jxwaf-agent-go/internal/function"
	"jxwaf-agent-go/internal/jxwaf"
	"jxwaf-agent-go/internal/tencentwaf"
)

// ChatRequest 聊天请求
type ChatRequest struct {
	SessionID string `json:"session_id"` // 会话 ID
	Message   string `json:"message"`   // 用户提问
}

// setAuthCookie 设置认证 Cookie
func setAuthCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jxwaf_auth_token",
		Value:    token,
		Path:     "/",
		MaxAge:   int(30 * 24 * 3600), // 30 天
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearAuthCookie 清除认证 Cookie
func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jxwaf_auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- 认证类 handler ---

// RegisterHandler /api/auth/register 用户注册
// RegisterConfigHandler /api/auth/config 返回注册配置（公开接口，供注册页判断是否开放注册和是否需要 OTP）
// OTPSecretHandler /api/auth/otp-secret 生成随机 TOTP 密钥（公开接口，供注册页生成密钥）
func OTPSecretHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, err := auth.GenerateOTPSecret()
		if err != nil {
			http.Error(w, "生成密钥失败", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"secret": secret})
	}
}

// RegisterHandler /api/auth/register 用户注册（可选绑定 OTP）
func RegisterHandler(database *db.DB, allowRegister bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			OTPSecret string `json:"otp_secret"`
			OTPCode   string `json:"otp_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		if req.Username == "" || req.Password == "" {
			http.Error(w, "用户名和密码不能为空", http.StatusBadRequest)
			return
		}
		token, err := auth.Register(database, allowRegister, req.Username, req.Password, req.OTPSecret, req.OTPCode)
		if err != nil {
			if errors.Is(err, auth.ErrRegisterDisabled) {
				http.Error(w, "注册已关闭", http.StatusForbidden)
				return
			}
			if errors.Is(err, auth.ErrInvalidOTP) {
				http.Error(w, "OTP 验证码错误", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, auth.ErrUserExists) {
				http.Error(w, "用户名已存在", http.StatusConflict)
				return
			}
			http.Error(w, "注册失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		setAuthCookie(w, token)
		json.NewEncoder(w).Encode(map[string]any{"token": token, "username": req.Username})
	}
}

// LoginHandler /api/auth/login 用户登录（若绑定 OTP 则返回 otp_required）
func LoginHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		token, err := auth.Login(database, req.Username, req.Password)
		if err != nil {
			if errors.Is(err, auth.ErrOTPRequired) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]any{"error": "otp_required", "message": "请输入 OTP 验证码"})
				return
			}
			http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
			return
		}
		setAuthCookie(w, token)
		json.NewEncoder(w).Encode(map[string]any{"token": token, "username": req.Username})
	}
}

// LoginOTPHandler /api/auth/login/otp 已绑定 OTP 用户的二次验证登录
func LoginOTPHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			OTPCode  string `json:"otp_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败", http.StatusBadRequest)
			return
		}
		if req.OTPCode == "" {
			http.Error(w, "OTP 验证码不能为空", http.StatusBadRequest)
			return
		}
		token, err := auth.LoginWithOTP(database, req.Username, req.Password, req.OTPCode)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidOTP) {
				http.Error(w, "OTP 验证码错误", http.StatusUnauthorized)
				return
			}
			http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
			return
		}
		setAuthCookie(w, token)
		json.NewEncoder(w).Encode(map[string]any{"token": token, "username": req.Username})
	}
}

// LogoutHandler /api/auth/logout 登出
func LogoutHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		token := auth.TokenFromContext(r)
		if token != "" {
			auth.Logout(database, token)
		}
		clearAuthCookie(w)
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}
}

// MeHandler /api/auth/me 获取当前用户信息
func MeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, username, ok := auth.UserFromContext(r)
		if !ok {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"username": username})
	}
}

// --- 配置类 handler ---

// ConfigHandler /api/config 获取或更新用户配置
// GET: 返回当前用户配置
// PUT: 更新配置
func ConfigHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, ok := auth.UserFromContext(r)
		if !ok {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case "GET":
			cfg, err := config.GetUserConfig(database, userID)
			if err != nil {
				http.Error(w, "配置读取失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"config": cfg})

		case "PUT":
			var req struct {
				Config *config.UserConfig `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "请求解析失败: "+err.Error(), http.StatusBadRequest)
				return
			}
			if req.Config == nil {
				http.Error(w, "config 不能为空", http.StatusBadRequest)
				return
			}
			if err := config.SetUserConfig(database, userID, req.Config); err != nil {
				http.Error(w, "配置保存失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "ok"})

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// --- 会话类 handler ---

// SessionsHandler /api/sessions 会话管理
// GET: 列出当前用户的所有会话（不含 messages）
// POST: 创建新会话
func SessionsHandler(sm *agent.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, ok := auth.UserFromContext(r)
		if !ok {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case "GET":
			sessions, err := sm.ListSessions(userID)
			if err != nil {
				http.Error(w, "查询会话失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			list := make([]map[string]any, 0, len(sessions))
			for _, s := range sessions {
				list = append(list, s.GetInfo())
			}
			json.NewEncoder(w).Encode(map[string]any{"sessions": list})

		case "POST":
			s, err := sm.CreateSession(userID)
			if err != nil {
				http.Error(w, "创建会话失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(s.GetInfo())

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// DeleteSessionHandler /api/sessions/{id} 单个会话管理
// GET: 获取会话消息历史
// DELETE: 删除会话（只能删自己的）
func DeleteSessionHandler(sm *agent.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, ok := auth.UserFromContext(r)
		if !ok {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}
		// 从路径提取 session_id: /api/sessions/{id}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 {
			http.Error(w, "缺少 session_id", http.StatusBadRequest)
			return
		}
		id := parts[3]

		switch r.Method {
		case "GET":
			s, err := sm.GetSession(userID, id)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Error(w, "会话不存在", http.StatusNotFound)
					return
				}
				http.Error(w, "查询失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"id":       s.ID,
				"title":    s.Title,
				"messages": s.Messages,
			})

		case "DELETE":
			if err := sm.DeleteSession(userID, id); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.Error(w, "会话不存在", http.StatusNotFound)
					return
				}
				http.Error(w, "删除失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "ok"})

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// ClearSessionHandler /api/clear-session 清空会话消息
func ClearSessionHandler(sm *agent.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		userID, _, ok := auth.UserFromContext(r)
		if !ok {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}
		var req struct {
			SessionID string `json:"session_id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.SessionID == "" {
			http.Error(w, "缺少 session_id", http.StatusBadRequest)
			return
		}
		if err := sm.ClearSession(userID, req.SessionID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "会话不存在", http.StatusNotFound)
				return
			}
			http.Error(w, "清空失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}
}

// --- 聊天类 handler ---

// ChatHandler /api/chat SSE 流式响应
// 按用户配置动态创建 LLM 客户端和 JXWAF 客户端，再创建临时 Agent 执行
func ChatHandler(database *db.DB, promptBuilder *agent.PromptBuilder, sm *agent.SessionManager, auditLog *audit.Logger, sessionLog *audit.SessionLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "请求解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Message == "" {
			http.Error(w, "message 不能为空", http.StatusBadRequest)
			return
		}

		userID, username, ok := auth.UserFromContext(r)
		if !ok {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}

		// 获取会话（校验属于该用户）
		sessionID := req.SessionID
		if sessionID == "" {
			http.Error(w, "session_id 不能为空", http.StatusBadRequest)
			return
		}
		session, err := sm.GetSession(userID, sessionID)
		if err != nil {
			http.Error(w, "会话不存在", http.StatusNotFound)
			return
		}
		history := session.Messages

		// 记录用户请求到会话日志
		if sessionLog != nil {
			sessionLog.LogWithUser(sessionID, username, "user", req.Message)
		}

		// 首条消息自动设置会话标题（截断前 30 字符）
		if len(history) == 0 {
			title := req.Message
			if len([]rune(title)) > 30 {
				title = string([]rune(title)[:30]) + "..."
			}
			sm.SetTitle(userID, sessionID, title)
		}

		// 获取用户配置
		userCfg, err := config.GetUserConfig(database, userID)
		if err != nil {
			http.Error(w, "配置读取失败: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 按用户配置创建 LLM 客户端
		llmClient := agent.NewOpenAICompatibleClient(
			userCfg.LLM.APIKey, userCfg.LLM.BaseURL, userCfg.LLM.Model,
			agent.LLMOptions{
				Thinking:        userCfg.LLM.Thinking,
				ReasoningEffort: userCfg.LLM.ReasoningEffort,
				MaxTokens:       userCfg.LLM.MaxTokens,
				Temperature:     userCfg.LLM.Temperature,
				DoSample:        userCfg.LLM.DoSample,
			},
		)

		// 创建 Registry 并注册所有 function
		reg := function.NewRegistry()

		// 知识加载类（LLM 按需加载扩展知识，skill 机制）
		reg.Register(&function.LoadContextFunc{
			GetContent: promptBuilder.GetContent,
			SkillNames: promptBuilder.SkillNames(),
		})

		// 脚本生成类（输出 backup 格式数组，用户复制后通过加载接口导入）
		reg.Register(&function.GenerateWebRuleScriptFunc{})
		reg.Register(&function.GenerateFlowRuleScriptFunc{})
		reg.Register(&function.GenerateComponentScriptFunc{})
		reg.Register(&function.GenerateNameListScriptFunc{})

		// 云端验证类（如果用户配置了 cloud_env）
		if userCfg.CloudEnv.Enabled && userCfg.CloudEnv.APIURL != "" {
			cloudClient := jxwaf.New(userCfg.CloudEnv.APIURL, userCfg.CloudEnv.WafAuth, "")
			reg.Register(&function.DeployToCloudFunc{Client: cloudClient})
			reg.Register(&function.VerifyInCloudFunc{Client: cloudClient, VerifyURL: userCfg.CloudEnv.VerifyURL})
			reg.Register(&function.CleanupCloudFunc{Client: cloudClient, AutoCleanup: userCfg.CloudEnv.AutoCleanup})
			reg.Register(&function.ListCloudRulesFunc{Client: cloudClient})
			reg.Register(&function.ListWebRulesFunc{Client: cloudClient})
			reg.Register(&function.ListFlowRulesFunc{Client: cloudClient})
			reg.Register(&function.ListComponentsFunc{Client: cloudClient})
		}

		// 自动部署类（SSH 远程部署 JXWAF 到目标服务器）
		deploymentExecutor := function.NewDeploymentExecutor()
		reg.Register(&function.CheckServerEnvironmentFunc{})
		reg.Register(&function.PlanJxwafDeploymentFunc{})
		reg.Register(&function.ExecuteSSHCommandFunc{Executor: deploymentExecutor})
		reg.Register(&function.VerifyDeploymentFunc{})
		reg.Register(&function.GetDeploymentSummaryFunc{Executor: deploymentExecutor})

		// 阿里云 WAF 规则生成与发布（用户配置了 waf_providers.aliyun 时启用）
		if userCfg.WAFProviders.Aliyun.Enabled && userCfg.WAFProviders.Aliyun.AccessKeyID != "" {
			aliyunClient := aliyunwaf.New(
				userCfg.WAFProviders.Aliyun.AccessKeyID,
				userCfg.WAFProviders.Aliyun.AccessKeySecret,
				userCfg.WAFProviders.Aliyun.Region,
				userCfg.WAFProviders.Aliyun.Endpoint,
				userCfg.WAFProviders.Aliyun.InstanceID,
				userCfg.WAFProviders.Aliyun.TemplateID,
			)
			// 规则生成类
			reg.Register(&function.GenerateAliyunACLRuleFunc{})
			reg.Register(&function.GenerateAliyunCCRuleFunc{})
			reg.Register(&function.GenerateAliyunIPBlacklistFunc{})
			// API 发布类
			reg.Register(&function.PublishAliyunWAFRuleFunc{Client: aliyunClient})
			// 查询/删除类
			reg.Register(&function.ListAliyunWAFRulesFunc{Client: aliyunClient})
			reg.Register(&function.DeleteAliyunWAFRuleFunc{Client: aliyunClient})
			reg.Register(&function.ListAliyunWAFResourcesFunc{Client: aliyunClient})
		}

		// 腾讯云 WAF 规则生成与发布（用户配置了 waf_providers.tencent 时启用）
		if userCfg.WAFProviders.Tencent.Enabled && userCfg.WAFProviders.Tencent.SecretID != "" {
			tencentClient := tencentwaf.New(
				userCfg.WAFProviders.Tencent.SecretID,
				userCfg.WAFProviders.Tencent.SecretKey,
				userCfg.WAFProviders.Tencent.Region,
				userCfg.WAFProviders.Tencent.Edition,
				userCfg.WAFProviders.Tencent.InstanceID,
			)
			// 规则生成类
			reg.Register(&function.GenerateTencentCustomRuleFunc{})
			reg.Register(&function.GenerateTencentCCRuleFunc{})
			reg.Register(&function.GenerateTencentIPBlacklistFunc{})
			// API 发布类
			reg.Register(&function.PublishTencentWAFRuleFunc{Client: tencentClient})
			// 查询/删除类
			reg.Register(&function.ListTencentWAFRulesFunc{Client: tencentClient})
			reg.Register(&function.DeleteTencentWAFRuleFunc{Client: tencentClient})
			reg.Register(&function.ListTencentWAFDomainsFunc{Client: tencentClient})
		}

		// 创建临时 Agent
		ag := &agent.Agent{
			LLM:           llmClient,
			Registry:      reg,
			Prompts:       promptBuilder,
			AuditLog:      auditLog,
			SessionLog:    sessionLog,
			MaxIterations: userCfg.Agent.MaxIterations,
		}

		// SSE 响应头
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // Nginx 禁用缓冲

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		// 运行 Agent
		out := make(chan agent.Event, 100)
		ctx := r.Context()

		// goroutine 执行 Run，通过 WaitGroup 等待返回完整 messages（含 tool_calls）
		var runMessages []map[string]any
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			runMessages = ag.Run(ctx, sessionID, username, req.Message, history, out)
		}()

		// 转发事件为 SSE
		for evt := range out {
			b, _ := json.Marshal(evt)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}

		// 等待 Run 完成，获取完整会话历史
		wg.Wait()

		// 用完整 messages 替换会话历史
		if len(runMessages) > 0 {
			sm.SetMessages(userID, sessionID, runMessages)
		}

		// 发送结束标记
		fmt.Fprintf(w, "data: {\"type\":\"done\"}\n\n")
		flusher.Flush()
	}
}

// --- 其他 handler ---

// TemplatesHandler /api/templates 返回快捷模板列表
func TemplatesHandler(templates any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"templates": templates})
	}
}

// ReloadPromptsHandler /api/reload-prompts 热更新系统提示词
func ReloadPromptsHandler(pb *agent.PromptBuilder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := pb.Reload(); err != nil {
			http.Error(w, "重载失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		files := pb.ListFiles()
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"files":  files,
		})
	}
}
