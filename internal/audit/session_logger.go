package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SessionLogger 会话日志记录器，每个会话单独一个文件
type SessionLogger struct {
	logDir string
	mu     sync.Mutex
	files  map[string]*os.File
}

// NewSessionLogger 创建会话日志记录器
func NewSessionLogger(logDir string) (*SessionLogger, error) {
	dir := filepath.Join(logDir, "sessions")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &SessionLogger{
		logDir: dir,
		files:  make(map[string]*os.File),
	}, nil
}

// getFile 获取或创建会话日志文件
func (l *SessionLogger) getFile(sessionID string) *os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.files[sessionID]; ok {
		return f
	}
	// 替换路径分隔符，避免 sessionID 含特殊字符
	safeID := sanitizeFilename(sessionID)
	path := filepath.Join(l.logDir, safeID+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil
	}
	l.files[sessionID] = f
	return f
}

// Log 记录一条会话日志
func (l *SessionLogger) Log(sessionID, eventType, data string) {
	l.LogWithUser(sessionID, "", eventType, data)
}

// LogWithUser 记录一条带用户名的会话日志
func (l *SessionLogger) LogWithUser(sessionID, username, eventType, data string) {
	f := l.getFile(sessionID)
	if f == nil {
		return
	}
	entry := map[string]any{
		"time":     time.Now().Format(time.RFC3339),
		"type":     eventType,
		"user":     username,
		"data":     data,
	}
	b, _ := json.Marshal(entry)
	l.mu.Lock()
	f.Write(b)
	f.Write([]byte("\n"))
	l.mu.Unlock()
}

// Close 关闭所有会话日志文件
func (l *SessionLogger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, f := range l.files {
		f.Close()
	}
	l.files = make(map[string]*os.File)
}

// sanitizeFilename 清理文件名中的特殊字符
func sanitizeFilename(name string) string {
	r := []rune(name)
	for i, c := range r {
		if c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|' {
			r[i] = '_'
		}
	}
	return string(r)
}
