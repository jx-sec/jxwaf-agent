// Package config 管理 CLI 本地配置：环境定义与凭据存储（~/.jxwaf/config.json）。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Version 表示 JXWAF 产品版本。
type Version string

const (
	VersionStandard     Version = "standard"
	VersionProfessional Version = "professional"
	VersionCloud        Version = "cloud"
)

// Valid 校验版本取值。
func (v Version) Valid() bool {
	return v == VersionStandard || v == VersionProfessional || v == VersionCloud
}

// Environment 一个可对接的 JXWAF 管理环境。
type Environment struct {
	Name        string  `json:"name"`
	Version     Version `json:"version"`
	BaseURL     string  `json:"base_url"`
	WafAuth     string  `json:"waf_auth,omitempty"`
	SubWafAuth  string  `json:"sub_waf_auth,omitempty"`  // 云WAF子账号凭证，可选（用户模式）
	SubUserName string  `json:"sub_user_name,omitempty"` // 云WAF默认子账号名（主账号模式自动注入）
	GroupName   string  `json:"group_name,omitempty"`    // 专业版域名组，可选
}

// Config 本地配置，存放于 ~/.jxwaf/config.json（权限 0600）。
type Config struct {
	Active       string                 `json:"active"`
	Environments map[string]Environment `json:"environments"`
}

// Path 返回配置文件路径。支持 JXWAF_CONFIG_PATH 环境变量覆盖（测试与多配置场景）。
func Path() string {
	if p := os.Getenv("JXWAF_CONFIG_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".jxwaf", "config.json")
	}
	return filepath.Join(home, ".jxwaf", "config.json")
}

// Load 读取配置；文件不存在时返回空配置。
func Load() (*Config, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{Environments: map[string]Environment{}}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("配置文件解析失败: %w", err)
	}
	if c.Environments == nil {
		c.Environments = map[string]Environment{}
	}
	return &c, nil
}

// Save 写入配置（目录 0700，文件 0600）。
func Save(c *Config) error {
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Resolve 按优先级解析要使用的环境：--env 参数 > 配置 active。
func (c *Config) Resolve(envFlag string) (Environment, error) {
	name := envFlag
	if name == "" {
		name = c.Active
	}
	if name == "" {
		return Environment{}, errors.New("未配置环境，请先运行 jxwaf-cli init 完成初始化")
	}
	e, ok := c.Environments[name]
	if !ok {
		return Environment{}, fmt.Errorf("环境 %q 不存在，可用环境: %v", name, c.Names())
	}
	return e, nil
}

// Names 返回已排序的环境名列表。
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Environments))
	for k := range c.Environments {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Masked 返回脱敏副本：凭据仅保留前 4 位。
func (e Environment) Masked() Environment {
	mask := func(s string) string {
		if s == "" {
			return s
		}
		if len(s) <= 4 {
			return "******"
		}
		return s[:4] + "******"
	}
	e.WafAuth = mask(e.WafAuth)
	e.SubWafAuth = mask(e.SubWafAuth)
	return e
}
