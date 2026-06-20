// Package agent 实现 LLM Agent 主循环与系统提示词构建
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"jxwaf-agent-go/internal/audit"
	"jxwaf-agent-go/internal/function"
)

// ToolCall LLM 返回的 function 调用
type ToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON 字符串
	} `json:"function"`
}

// StreamEvent 流式事件
type StreamEvent struct {
	Type      string     // "text" | "tool_calls" | "done" | "error"
	Text      string     // Type="text" 时的文本片段
	ToolCalls []ToolCall // Type="tool_calls" 时的完整 tool_calls
	Err       error      // Type="error" 时的错误
}

// LLMClient LLM 调用接口
type LLMClient interface {
	// ChatStream 流式对话，返回事件通道
	// 事件顺序：多个 text → 一个 tool_calls（若有）→ done
	ChatStream(ctx context.Context, messages []map[string]any, tools []map[string]any) (<-chan StreamEvent, error)
}

// Agent 主循环
type Agent struct {
	LLM           LLMClient
	Registry      *function.Registry
	Prompts       *PromptBuilder
	AuditLog      *audit.Logger
	SessionLog    *audit.SessionLogger
	MaxIterations int
}

// Event 输出事件（SSE 推送给前端）
type Event struct {
	Type string `json:"type"` // delta | tool_start | tool_end | error | config_preview | reasoning
	Data string `json:"data"`
}

// Run 执行 Agent 循环，返回完整 messages（含 tool_calls，供会话历史保存）
func (a *Agent) Run(ctx context.Context, sessionID, username, userQuery string, history []map[string]any, out chan<- Event) []map[string]any {
	defer close(out)

	// 1. 动态构建系统提示词
	systemPrompt := a.Prompts.Build(userQuery)
	tools := a.Registry.ToTools()

	// 2. 组装 messages
	messages := make([]map[string]any, 0, len(history)+2)
	messages = append(messages, map[string]any{
		"role":    "system",
		"content": systemPrompt,
	})
	messages = append(messages, history...)
	messages = append(messages, map[string]any{
		"role":    "user",
		"content": userQuery,
	})

	// 3. Agent 循环
	maxIter := a.MaxIterations
	if maxIter <= 0 {
		maxIter = 10
	}
	for iteration := 0; iteration < maxIter; iteration++ {
		stream, err := a.LLM.ChatStream(ctx, messages, tools)
		if err != nil {
			out <- Event{Type: "error", Data: fmt.Sprintf("LLM 调用失败: %v", err)}
			return messages[1:]
		}

		// 读取流式事件
		var textBuffer strings.Builder
		var toolCalls []ToolCall
		hasError := false

		for evt := range stream {
			switch evt.Type {
			case "text":
				textBuffer.WriteString(evt.Text)
				out <- Event{Type: "delta", Data: evt.Text}
			case "reasoning":
				out <- Event{Type: "reasoning", Data: evt.Text}
			case "tool_calls":
				toolCalls = evt.ToolCalls
			case "error":
				out <- Event{Type: "error", Data: evt.Err.Error()}
				hasError = true
			case "done":
				// 流结束
			}
		}

		if hasError {
			return messages[1:]
		}

		// 无 tool_call 则结束
		if len(toolCalls) == 0 {
			// 保存最终 assistant 文本（无 tool_calls 的最后一轮回复）
			if textBuffer.Len() > 0 {
				messages = append(messages, map[string]any{
					"role":    "assistant",
					"content": textBuffer.String(),
				})
			}
			return messages[1:]
		}

		// 记录 assistant 消息
		assistantMsg := map[string]any{
			"role":    "assistant",
			"content": textBuffer.String(),
		}
		// 转换 toolCalls 为 LLM 要求的格式
		toolCallsRaw := make([]map[string]any, 0, len(toolCalls))
		for _, tc := range toolCalls {
			toolCallsRaw = append(toolCallsRaw, map[string]any{
				"id":   tc.ID,
				"type": "function",
				"function": map[string]any{
					"name":      tc.Function.Name,
					"arguments": tc.Function.Arguments,
				},
			})
		}
		assistantMsg["tool_calls"] = toolCallsRaw
		messages = append(messages, assistantMsg)

		// 执行所有 tool_call
		for _, call := range toolCalls {
			fn, ok := a.Registry.Get(call.Function.Name)
			if !ok {
				out <- Event{Type: "tool_end", Data: fmt.Sprintf("未知 function: %s", call.Function.Name)}
				messages = append(messages, map[string]any{
					"role":         "tool",
					"tool_call_id": call.ID,
					"content":      fmt.Sprintf("未知 function: %s", call.Function.Name),
				})
				continue
			}

			out <- Event{Type: "tool_start", Data: call.Function.Name}

			// 解析参数
			var args map[string]any
			if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
				out <- Event{Type: "tool_end", Data: fmt.Sprintf("参数解析失败: %v", err)}
				messages = append(messages, map[string]any{
					"role":         "tool",
					"tool_call_id": call.ID,
					"content":      fmt.Sprintf("参数解析失败: %v", err),
				})
				continue
			}

			// 执行 function
			result, err := fn.Execute(ctx, args)
			if err != nil {
				result = fmt.Sprintf("ERROR: %v", err)
			}

			// 审计日志：记录 function 调用
			if a.AuditLog != nil {
				a.AuditLog.Log(sessionID, username, call.Function.Name, call.Function.Arguments, result, err == nil)
			}
			// 会话日志：记录 tool 调用事件
			if a.SessionLog != nil {
				a.SessionLog.LogWithUser(sessionID, username, "tool_call", fmt.Sprintf("function=%s result=%s", call.Function.Name, truncate(result, 500)))
			}

			// generate_*_script function 返回结构化配置 JSON，推送为 config_preview 事件
			if strings.HasPrefix(call.Function.Name, "generate_") {
				out <- Event{Type: "config_preview", Data: result}
			} else if call.Function.Name == "plan_jxwaf_deployment" {
				// 部署计划推送为 deployment_plan 事件，前端渲染为可确认的部署计划卡片
				out <- Event{Type: "deployment_plan", Data: result}
			} else if call.Function.Name == "get_deployment_summary" {
				// 部署执行摘要推送为 deployment_summary 事件
				out <- Event{Type: "deployment_summary", Data: result}
			} else {
				out <- Event{Type: "tool_end", Data: result}
			}

			messages = append(messages, map[string]any{
				"role":         "tool",
				"tool_call_id": call.ID,
				"content":      result,
			})
		}
	}

	out <- Event{Type: "error", Data: "超过最大循环次数"}
	return messages[1:]
}

// OpenAICompatibleClient OpenAI 兼容的 LLM 客户端
type OpenAICompatibleClient struct {
	APIKey          string
	BaseURL         string
	Model           string
	HTTP            *http.Client
	Thinking        map[string]any // 思维链控制 {"type":"enabled"|"disabled"}
	ReasoningEffort string         // 推理程度: max|xhigh|high|medium|low|minimal|none
	MaxTokens       int            // 最大输出 token 数
	Temperature     float64        // 温度采样
	DoSample        *bool          // 是否采样
}

// LLMOptions LLM 可选参数（GLM-5.2 及以上支持 thinking/reasoning_effort）
type LLMOptions struct {
	Thinking        map[string]any
	ReasoningEffort string
	MaxTokens       int
	Temperature     float64
	DoSample        *bool
}

// NewOpenAICompatibleClient 创建客户端
func NewOpenAICompatibleClient(apiKey, baseURL, model string, opts LLMOptions) *OpenAICompatibleClient {
	return &OpenAICompatibleClient{
		APIKey:          apiKey,
		BaseURL:         strings.TrimRight(baseURL, "/"),
		Model:           model,
		HTTP:            &http.Client{},
		Thinking:        opts.Thinking,
		ReasoningEffort: opts.ReasoningEffort,
		MaxTokens:       opts.MaxTokens,
		Temperature:     opts.Temperature,
		DoSample:        opts.DoSample,
	}
}

// ChatStream 实现 LLMClient 接口
func (c *OpenAICompatibleClient) ChatStream(ctx context.Context, messages []map[string]any, tools []map[string]any) (<-chan StreamEvent, error) {
	reqBody := map[string]any{
		"model":          c.Model,
		"messages":       messages,
		"stream":         true,
		"stream_options": map[string]any{"include_usage": false},
	}
	if len(tools) > 0 {
		reqBody["tools"] = tools
	}
	// GLM-5.2 及以上参数（按配置注入，未配置则不发送）
	if c.Thinking != nil {
		reqBody["thinking"] = c.Thinking
	}
	if c.ReasoningEffort != "" {
		reqBody["reasoning_effort"] = c.ReasoningEffort
	}
	if c.MaxTokens > 0 {
		reqBody["max_tokens"] = c.MaxTokens
	}
	if c.Temperature > 0 {
		reqBody["temperature"] = c.Temperature
	}
	if c.DoSample != nil {
		reqBody["do_sample"] = *c.DoSample
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/chat/completions", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("LLM API 返回 %d: %s", resp.StatusCode, string(b))
	}

	// 创建事件通道，goroutine 中处理流
	stream := make(chan StreamEvent, 100)

	go func() {
		defer resp.Body.Close()
		defer close(stream)

		// tool_calls 累积合并（流式可能分多次返回）
		toolCallMap := make(map[int]*ToolCall)

		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				// 按行处理 SSE
				for {
					idx := bytesIndex(buf, '\n')
					if idx < 0 {
						break
					}
					line := string(buf[:idx])
					buf = buf[idx+1:]
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					data := strings.TrimPrefix(line, "data: ")
					if data == "[DONE]" {
						// 发送合并后的 tool_calls
						if len(toolCallMap) > 0 {
							calls := make([]ToolCall, 0, len(toolCallMap))
							for _, tc := range toolCallMap {
								calls = append(calls, *tc)
							}
							stream <- StreamEvent{Type: "tool_calls", ToolCalls: calls}
						}
						stream <- StreamEvent{Type: "done"}
						return
					}
					// 解析 chunk
				var chunk struct {
					Choices []struct {
						Delta struct {
							Content          string `json:"content"`
							ReasoningContent string `json:"reasoning_content"` // GLM 思维链内容
							ToolCalls []struct {
								Index    int    `json:"index"`
								ID       string `json:"id"`
								Function struct {
									Name      string `json:"name"`
									Arguments string `json:"arguments"`
								} `json:"function"`
							} `json:"tool_calls"`
						} `json:"delta"`
					} `json:"choices"`
				}
				if err := json.Unmarshal([]byte(data), &chunk); err != nil {
					continue
				}
				for _, choice := range chunk.Choices {
					if choice.Delta.ReasoningContent != "" {
						stream <- StreamEvent{Type: "reasoning", Text: choice.Delta.ReasoningContent}
					}
					if choice.Delta.Content != "" {
						stream <- StreamEvent{Type: "text", Text: choice.Delta.Content}
					}
						for _, tc := range choice.Delta.ToolCalls {
							// 按 index 合并
							if existing, ok := toolCallMap[tc.Index]; ok {
								if tc.ID != "" {
									existing.ID = tc.ID
								}
								if tc.Function.Name != "" {
									existing.Function.Name += tc.Function.Name
								}
								existing.Function.Arguments += tc.Function.Arguments
							} else {
								var call ToolCall
								call.ID = tc.ID
								call.Function.Name = tc.Function.Name
								call.Function.Arguments = tc.Function.Arguments
								toolCallMap[tc.Index] = &call
							}
						}
					}
				}
			}
			if err != nil {
				if err != io.EOF {
					stream <- StreamEvent{Type: "error", Err: err}
				}
				// 流结束，发送合并后的 tool_calls
				if len(toolCallMap) > 0 {
					calls := make([]ToolCall, 0, len(toolCallMap))
					for _, tc := range toolCallMap {
						calls = append(calls, *tc)
					}
					stream <- StreamEvent{Type: "tool_calls", ToolCalls: calls}
				}
				stream <- StreamEvent{Type: "done"}
				return
			}
		}
	}()

	return stream, nil
}

// bytesIndex 查找字节位置
func bytesIndex(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// truncate 截断字符串到指定长度
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
