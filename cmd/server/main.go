// Package main 程序入口
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"jxwaf-agent-go/internal/agent"
	"jxwaf-agent-go/internal/api"
	"jxwaf-agent-go/internal/auth"
	"jxwaf-agent-go/internal/config"
	"jxwaf-agent-go/internal/db"
)

// Config 全局配置（从 config.json 加载）
// 用户级配置（LLM/JXWAF/verify_url）存数据库，由各用户独立管理
type Config struct {
	Server        struct {
		Port int `json:"port"`
	} `json:"server"`
	AllowRegister bool                  `json:"allow_register"`
	PromptsDir    string                `json:"prompts_dir"`
	Database      db.DatabaseConfig     `json:"database"`
	DefaultConfig *config.UserConfig    `json:"default_config"`
	Templates     []TemplateItem        `json:"templates"`
}

// TemplateItem 快捷模板
type TemplateItem struct {
	Label string `json:"label"`
	Text  string `json:"text"`
}

func main() {
	// 1. 加载全局配置
	cfg := loadConfig()

	// 注入默认用户配置（从 config.json 的 default_config 段）
	if cfg.DefaultConfig != nil {
		config.DefaultUserConfig = cfg.DefaultConfig
	}

	// 2. 初始化数据库（SQLite 或 MySQL）
	database, err := db.Open(cfg.Database)
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer database.Close()
	if database.DialectName() == db.DialectMySQL {
		log.Printf("数据库: MySQL %s:%d/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.Database)
	} else {
		path := cfg.Database.SQLitePath
		if path == "" {
			path = "data/agent.db"
		}
		log.Printf("数据库: SQLite %s", path)
	}

	// 3. PromptBuilder（加载 prompts/*.md）
	promptBuilder, err := agent.NewPromptBuilder(cfg.PromptsDir)
	if err != nil {
		log.Fatalf("加载系统提示词素材失败: %v", err)
	}
	log.Printf("已加载提示词素材: %v", promptBuilder.ListFiles())

	// 4. 会话管理器
	sm := agent.NewSessionManager(database)

	// 5. HTTP server
	if cfg.AllowRegister {
		log.Printf("用户注册: 已开放")
	} else {
		log.Printf("用户注册: 已关闭")
	}

	mux := http.NewServeMux()

	// 公开路由（无需认证）
	mux.HandleFunc("/api/auth/otp-secret", api.OTPSecretHandler())
	mux.HandleFunc("/api/auth/register", api.RegisterHandler(database, cfg.AllowRegister))
	mux.HandleFunc("/api/auth/login", api.LoginHandler(database))
	mux.HandleFunc("/api/auth/login/otp", api.LoginOTPHandler(database))
	mux.HandleFunc("/api/templates", api.TemplatesHandler(cfg.Templates))

	// 受保护路由（auth.Middleware 包裹）
	mux.Handle("/api/auth/logout", auth.Middleware(database, api.LogoutHandler(database)))
	mux.Handle("/api/auth/me", auth.Middleware(database, api.MeHandler()))
	mux.Handle("/api/config", auth.Middleware(database, api.ConfigHandler(database)))
	mux.Handle("/api/sessions", auth.Middleware(database, api.SessionsHandler(sm)))
	mux.Handle("/api/sessions/", auth.Middleware(database, api.DeleteSessionHandler(sm)))
	mux.Handle("/api/clear-session", auth.Middleware(database, api.ClearSessionHandler(sm)))
	mux.Handle("/api/chat", auth.Middleware(database, api.ChatHandler(database, promptBuilder, sm)))
	mux.Handle("/api/reload-prompts", auth.Middleware(database, api.ReloadPromptsHandler(promptBuilder)))

	// 静态文件
	mux.Handle("/", http.FileServer(http.Dir("web")))

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	log.Printf("JXWAF Agent Web 启动，监听 %s", addr)
	log.Printf("聊天界面: http://localhost:%d", cfg.Server.Port)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}

// loadConfig 加载配置（从 config.json 或环境变量）
func loadConfig() *Config {
	cfg := &Config{
		AllowRegister: true,
		PromptsDir:    "prompts",
	}
	cfg.Server.Port = 8080
	cfg.Database.Type = "sqlite"
	cfg.Database.SQLitePath = "data/agent.db"

	// 尝试从 config.json 加载
	if data, err := os.ReadFile("config.json"); err == nil {
		json.Unmarshal(data, cfg)
	}

	// 环境变量覆盖
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
		}
	}
	if v := os.Getenv("ALLOW_REGISTER"); v != "" {
		cfg.AllowRegister = v == "true" || v == "1"
	}

	// SQLite 默认创建 data 目录
	if cfg.Database.Type == "" || cfg.Database.Type == "sqlite" {
		if cfg.Database.SQLitePath == "" {
			cfg.Database.SQLitePath = "data/agent.db"
		}
		os.MkdirAll("data", 0755)
	}

	return cfg
}
