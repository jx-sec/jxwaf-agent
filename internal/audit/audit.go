// Package audit 操作审计日志
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry 审计日志条目
type Entry struct {
	Time      time.Time `json:"time"`
	SessionID string    `json:"session_id"`
	User      string    `json:"user"`
	Function  string    `json:"function"`
	Arguments string    `json:"arguments"`
	Result    string    `json:"result"`
	Success   bool      `json:"success"`
}

// Logger 审计日志记录器
type Logger struct {
	mu   sync.Mutex
	file *os.File
}

// NewLogger 创建审计日志记录器，写入 logDir 目录下的 audit.log
func NewLogger(logDir string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}
	logPath := filepath.Join(logDir, "audit.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("打开审计日志文件失败: %w", err)
	}
	return &Logger{file: f}, nil
}

// Log 记录一条审计日志
func (l *Logger) Log(sessionID, username, function, arguments, result string, success bool) {
	entry := Entry{
		Time:      time.Now(),
		SessionID: sessionID,
		User:      username,
		Function:  function,
		Arguments: arguments,
		Result:    result,
		Success:   success,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := json.Marshal(entry)
	l.file.Write(b)
	l.file.Write([]byte("\n"))
}

// Close 关闭日志文件
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Writer 返回一个 io.Writer 用于日志输出
func (l *Logger) Writer() io.Writer { return l.file }
