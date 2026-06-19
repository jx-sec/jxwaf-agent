package agent

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"jxwaf-agent-go/internal/db"
)

// Session 会话数据（从数据库加载）
type Session struct {
	ID        string
	UserID    int64
	Title     string
	Messages  []map[string]any
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SessionManager 会话管理器，持久化到 SQLite
type SessionManager struct {
	db *db.DB
}

// NewSessionManager 创建会话管理器
func NewSessionManager(database *db.DB) *SessionManager {
	return &SessionManager{db: database}
}

// ListSessions 列出用户的所有会话（按更新时间倒序，不含 messages）
func (m *SessionManager) ListSessions(userID int64) ([]*Session, error) {
	rows, err := m.db.SQLDB().Query(`
		SELECT id, title, created_at, updated_at, json_array_length(messages)
		FROM chat_sessions
		WHERE user_id = ?
		ORDER BY updated_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Session
	for rows.Next() {
		var s Session
		var msgCount int
		if err := rows.Scan(&s.ID, &s.Title, &s.CreatedAt, &s.UpdatedAt, &msgCount); err != nil {
			return nil, err
		}
		s.UserID = userID
		list = append(list, &s)
	}
	return list, rows.Err()
}

// CreateSession 创建新会话并写入数据库
func (m *SessionManager) CreateSession(userID int64) (*Session, error) {
	id := generateSessionID()
	now := time.Now()
	_, err := m.db.SQLDB().Exec(
		"INSERT INTO chat_sessions (id, user_id, title, messages) VALUES (?, ?, ?, '[]')",
		id, userID, "新会话",
	)
	if err != nil {
		return nil, err
	}
	return &Session{
		ID:        id,
		UserID:    userID,
		Title:     "新会话",
		Messages:  []map[string]any{},
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// GetSession 获取会话（校验属于该用户），不存在返回错误
func (m *SessionManager) GetSession(userID int64, id string) (*Session, error) {
	var s Session
	var messagesJSON string
	err := m.db.SQLDB().QueryRow(
		"SELECT id, user_id, title, messages, created_at, updated_at FROM chat_sessions WHERE id = ? AND user_id = ?",
		id, userID,
	).Scan(&s.ID, &s.UserID, &s.Title, &messagesJSON, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.Messages = []map[string]any{}
	if messagesJSON != "" {
		json.Unmarshal([]byte(messagesJSON), &s.Messages)
	}
	return &s, nil
}

// DeleteSession 删除会话（校验所有权）
func (m *SessionManager) DeleteSession(userID int64, id string) error {
	res, err := m.db.SQLDB().Exec(
		"DELETE FROM chat_sessions WHERE id = ? AND user_id = ?",
		id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ClearSession 清空会话消息
func (m *SessionManager) ClearSession(userID int64, id string) error {
	res, err := m.db.SQLDB().Exec(
		"UPDATE chat_sessions SET messages = '[]', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
		id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetMessages 保存消息到数据库
func (m *SessionManager) SetMessages(userID int64, id string, msgs []map[string]any) error {
	b, err := json.Marshal(msgs)
	if err != nil {
		return err
	}
	_, err = m.db.SQLDB().Exec(
		"UPDATE chat_sessions SET messages = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
		string(b), id, userID,
	)
	return err
}

// SetTitle 更新会话标题
func (m *SessionManager) SetTitle(userID int64, id string, title string) error {
	_, err := m.db.SQLDB().Exec(
		"UPDATE chat_sessions SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
		title, id, userID,
	)
	return err
}

// generateSessionID 生成会话 ID（时间戳 + 随机后缀，避免碰撞）
func generateSessionID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// GetInfo 获取会话信息（不含消息内容，用于列表展示）
func (s *Session) GetInfo() map[string]any {
	return map[string]any{
		"id":         s.ID,
		"title":      s.Title,
		"created_at": s.CreatedAt.Format(time.RFC3339),
		"updated_at": s.UpdatedAt.Format(time.RFC3339),
		"msg_count":  len(s.Messages),
	}
}
