// Package config 实现用户配置的读写
package config

import (
	"database/sql"
	"encoding/json"

	"jxwaf-agent-go/internal/db"
)

// LLMConfig LLM 参数配置
type LLMConfig struct {
	APIKey          string         `json:"api_key"`
	BaseURL         string         `json:"base_url"`
	Model           string         `json:"model"`
	Thinking        map[string]any `json:"thinking,omitempty"`
	ReasoningEffort string         `json:"reasoning_effort,omitempty"`
	MaxTokens       int            `json:"max_tokens,omitempty"`
	Temperature     float64        `json:"temperature,omitempty"`
	DoSample        *bool          `json:"do_sample,omitempty"`
}

// JXWAFConfig JXWAF 参数配置
type JXWAFConfig struct {
	APIURL  string `json:"api_url"`
	WafAuth string `json:"waf_auth"`
	Group   string `json:"group"`
}

// UserConfig 用户配置（存入 user_configs.config_json）
type UserConfig struct {
	LLM       LLMConfig   `json:"llm"`
	JXWAF     JXWAFConfig `json:"jxwaf"`
	VerifyURL string      `json:"verify_url"`
}

// DefaultUserConfig 全局默认配置（从 config.json 的 default_config 加载，启动时注入）
var DefaultUserConfig = &UserConfig{}

// DefaultConfig 返回全局默认配置
func DefaultConfig() *UserConfig {
	return DefaultUserConfig
}

// GetUserConfig 读取用户配置，不存在则返回全局默认
func GetUserConfig(database *db.DB, userID int64) (*UserConfig, error) {
	var cfgJSON string
	err := database.SQLDB().QueryRow(
		"SELECT config_json FROM user_configs WHERE user_id = ?",
		userID,
	).Scan(&cfgJSON)
	if err == sql.ErrNoRows {
		return DefaultConfig(), nil
	}
	if err != nil {
		return nil, err
	}
	var cfg UserConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SetUserConfig 保存用户配置（UPSERT）
func SetUserConfig(database *db.DB, userID int64, cfg *UserConfig) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = database.SQLDB().Exec(`
		INSERT INTO user_configs (user_id, config_json, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET
			config_json = excluded.config_json,
			updated_at = CURRENT_TIMESTAMP`,
		userID, string(b),
	)
	return err
}
