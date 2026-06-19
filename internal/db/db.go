// Package db 实现数据库访问层（支持 SQLite 和 MySQL）
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL 驱动
	_ "modernc.org/sqlite"             // 纯 Go SQLite 驱动，无需 CGO
)

// Dialect 数据库方言
type Dialect string

const (
	DialectSQLite Dialect = "sqlite"
	DialectMySQL  Dialect = "mysql"
)

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Type     string `json:"type"`     // sqlite | mysql，默认 sqlite
	SQLitePath string `json:"sqlite_path"` // SQLite 文件路径，默认 data/agent.db
	Host     string `json:"host"`     // MySQL 主机
	Port     int    `json:"port"`     // MySQL 端口
	Username string `json:"username"` // MySQL 用户名
	Password string `json:"password"` // MySQL 密码
	Database string `json:"database"` // MySQL 数据库名
}

// DB 数据库访问对象，持有 *sql.DB 连接池
type DB struct {
	db      *sql.DB
	dialect Dialect
}

// User 用户记录
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	OTPSecret    string
	CreatedAt    time.Time
}

// TokenInfo 认证令牌信息
type TokenInfo struct {
	UserID    int64
	Username  string
	ExpiresAt time.Time
}

// Open 根据配置打开数据库（SQLite 或 MySQL）
func Open(cfg DatabaseConfig) (*DB, error) {
	dialect := Dialect(cfg.Type)
	if dialect == "" {
		dialect = DialectSQLite
	}

	var sqlDB *sql.DB
	var err error

	switch dialect {
	case DialectMySQL:
		sqlDB, err = openMySQL(cfg)
	case DialectSQLite:
		fallthrough
	default:
		sqlDB, err = openSQLite(cfg)
	}
	if err != nil {
		return nil, err
	}

	d := &DB{db: sqlDB, dialect: dialect}

	// 建表
	if err := d.createTables(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	// 迁移：为旧数据库增加 otp_secret 字段（已存在时忽略错误）
	d.db.Exec("ALTER TABLE users ADD COLUMN otp_secret TEXT NOT NULL DEFAULT ''")

	return d, nil
}

func openSQLite(cfg DatabaseConfig) (*sql.DB, error) {
	path := cfg.SQLitePath
	if path == "" {
		path = "data/agent.db"
	}
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// 启用外键约束
	if _, err := sqlDB.Exec("PRAGMA foreign_keys = ON"); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return sqlDB, nil
}

func openMySQL(cfg DatabaseConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4&loc=Local",
		cfg.Username, cfg.Password, cfg.Host, cfg.Port, cfg.Database)
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	// MySQL 连接池配置
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	return sqlDB, nil
}

// createTables 根据方言执行建表 SQL
func (d *DB) createTables() error {
	if d.dialect == DialectMySQL {
		return d.createTablesMySQL()
	}
	return d.createTablesSQLite()
}

func (d *DB) createTablesSQLite() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		otp_secret TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS user_configs (
		user_id INTEGER PRIMARY KEY,
		config_json TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	CREATE TABLE IF NOT EXISTS auth_tokens (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);
	CREATE TABLE IF NOT EXISTS chat_sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		title TEXT NOT NULL DEFAULT '新会话',
		messages TEXT NOT NULL DEFAULT '[]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);`
	_, err := d.db.Exec(schema)
	return err
}

func (d *DB) createTablesMySQL() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			otp_secret TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS user_configs (
			user_id BIGINT PRIMARY KEY,
			config_json LONGTEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS auth_tokens (
			token VARCHAR(128) PRIMARY KEY,
			user_id BIGINT NOT NULL,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS chat_sessions (
			id VARCHAR(64) PRIMARY KEY,
			user_id BIGINT NOT NULL,
			title VARCHAR(255) NOT NULL DEFAULT '新会话',
			messages LONGTEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}
	for _, s := range statements {
		if _, err := d.db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// SQLDB 返回底层 *sql.DB，供其他包执行自定义查询
func (d *DB) SQLDB() *sql.DB { return d.db }

// DialectName 返回当前数据库方言
func (d *DB) DialectName() Dialect { return d.dialect }

// Close 关闭数据库连接
func (d *DB) Close() error { return d.db.Close() }

// CreateUser 创建用户，返回用户 ID（otpSecret 为空表示不绑定 OTP）
func (d *DB) CreateUser(username, passwordHash, otpSecret string) (int64, error) {
	res, err := d.db.Exec(
		"INSERT INTO users (username, password_hash, otp_secret) VALUES (?, ?, ?)",
		username, passwordHash, otpSecret,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetUserByUsername 按用户名查询用户
func (d *DB) GetUserByUsername(username string) (*User, error) {
	var u User
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, otp_secret, created_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.OTPSecret, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByID 按 ID 查询用户
func (d *DB) GetUserByID(id int64) (*User, error) {
	var u User
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, otp_secret, created_at FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.OTPSecret, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUserOTPSecret 更新用户的 OTP 密钥（空字符串表示取消绑定）
func (d *DB) UpdateUserOTPSecret(userID int64, secret string) error {
	_, err := d.db.Exec("UPDATE users SET otp_secret = ? WHERE id = ?", secret, userID)
	return err
}

// SaveToken 保存认证令牌
func (d *DB) SaveToken(token string, userID int64, expiresAt time.Time) error {
	_, err := d.db.Exec(
		"INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
		token, userID, expiresAt,
	)
	return err
}

// GetToken 查询令牌信息（仅返回未过期的令牌）
func (d *DB) GetToken(token string) (*TokenInfo, error) {
	var t TokenInfo
	err := d.db.QueryRow(`
		SELECT t.user_id, u.username, t.expires_at
		FROM auth_tokens t
		JOIN users u ON t.user_id = u.id
		WHERE t.token = ? AND t.expires_at > ?`,
		token, time.Now(),
	).Scan(&t.UserID, &t.Username, &t.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteToken 删除令牌
func (d *DB) DeleteToken(token string) error {
	_, err := d.db.Exec("DELETE FROM auth_tokens WHERE token = ?", token)
	return err
}
