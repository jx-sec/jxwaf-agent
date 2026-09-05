// Package config 管理 CLI 本地配置：环境定义与凭据存储（项目目录下 config.json，与 jxwaf-cli 同级）。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// Mode 显式指定云WAF操作模式（仅 cloud 版本有意义；空值时按凭据隐式推断以保持兼容）。
const (
	ModeUser  = "user"  // 子账号用户模式（/user 端点 + 双 token）
	ModeAdmin = "admin" // 主账号管理模式（/admin_api/sub_account_* 端点）
)

// Environment 一个可对接的 JXWAF 管理环境。
type Environment struct {
	Name        string  `json:"name"`
	Version     Version `json:"version"`
	BaseURL     string  `json:"base_url"`
	WafAuth     string  `json:"waf_auth,omitempty"`
	SubWafAuth  string  `json:"sub_waf_auth,omitempty"`  // 云WAF子账号凭证，可选（用户模式）
	SubUserName string  `json:"sub_user_name,omitempty"` // 云WAF默认子账号名（主账号模式自动注入）
	GroupName   string  `json:"group_name,omitempty"`    // 专业版域名组，可选
	CloudMode   string  `json:"cloud_mode,omitempty"`    // 云WAF模式：user/admin；空值按 SubWafAuth 是否存在推断
	TestURL     string  `json:"test_url,omitempty"`      // 测试站点地址（配置下发到该环境后，访问此地址验证规则是否生效）
}

// Valid 校验 CloudMode 取值。
func (e Environment) ValidMode() bool {
	switch e.CloudMode {
	case "", ModeUser, ModeAdmin:
		return true
	}
	return false
}

// DefaultHubBaseURL hub.jxwaf.com 策略共享平台默认地址（公开非凭据）。
const DefaultHubBaseURL = "https://hub.jxwaf.com"

// HubConfig 策略共享平台（JXWAF Hub，策略地址）接入配置。
// 认证使用用户级 API Token（请求头 jxwaf-api-key），由 hub login 用账号密码一次性换取，密码不落盘。
type HubConfig struct {
	BaseURL        string `json:"base_url"`                  // 平台地址（默认 https://hub.jxwaf.com）
	APIToken       string `json:"api_token,omitempty"`       // 用户 API Token（凭据，脱敏存储）
	DefaultProduct string `json:"default_product,omitempty"` // push 默认产品：jxwaf/webtds（默认 jxwaf）
	DefaultScene   string `json:"default_scene,omitempty"`   // push 默认分类（默认 应用安全）
}

// Masked 返回脱敏副本：api_token 仅保留前 4 位。
func (h HubConfig) Masked() HubConfig {
	if h.APIToken != "" {
		if len(h.APIToken) <= 4 {
			h.APIToken = "******"
		} else {
			h.APIToken = h.APIToken[:4] + "******"
		}
	}
	return h
}

// Config 本地配置（项目目录 config.json，权限 0600）。
type Config struct {
	Active       string                 `json:"active"`
	TestEnv      string                 `json:"test_env,omitempty"` // 测试环境名（test 命令组专用）
	Environments map[string]Environment `json:"environments"`
	Hub          *HubConfig             `json:"hub,omitempty"` // 策略共享平台（hub 命令组）
}

// DefaultTestEnvName 测试环境的默认环境名（test 命令组默认操作目标）。
// 仅是约定名称，不代表任何内置环境：测试环境必须经 test init 显式配置。
const DefaultTestEnvName = "test"

// LocalConfigName 配置文件名（与 jxwaf-cli 二进制同目录）。
const LocalConfigName = "config.json"

// Path 返回配置文件路径，查找顺序：
//  1. JXWAF_CONFIG_PATH 环境变量（测试与多配置场景）
//  2. 当前目录 ./config.json（存在时）
//  3. jxwaf-cli 可执行文件所在目录的 config.json（存在时；从其他目录调用二进制的场景）
//  4. 都不存在时默认当前目录 ./config.json（Save 会在此创建）
//
// 配置固定随项目目录走（与 jxwaf-cli 同级），不使用用户主目录。
func Path() (string, error) {
	if p := os.Getenv("JXWAF_CONFIG_PATH"); p != "" {
		return p, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("无法定位当前目录: %w", err)
	}
	local := filepath.Join(wd, LocalConfigName)
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	// 二进制所在目录（go run 时为临时构建目录，通常不存在配置，自动跳过）
	if exe, err := os.Executable(); err == nil {
		exeCfg := filepath.Join(filepath.Dir(exe), LocalConfigName)
		if exeCfg != local {
			if _, err := os.Stat(exeCfg); err == nil {
				return exeCfg, nil
			}
		}
	}
	return local, nil
}

// Lock 对配置文件加跨进程排他锁，返回解锁函数。
// 用于保护 Load→修改→Save 的读-改-写窗口，避免并发写相互覆盖（lost update）。
// 持锁期间必须完成 Save 后再解锁。
func Lock() (func(), error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开配置文件加锁失败: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("配置文件加锁失败: %w", err)
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// 配置缺失/为空的哨兵错误（LoadOrCreate 据此区分"未配置"与真正的读取失败）。
var (
	ErrConfigMissing = errors.New("配置文件不存在")
	ErrConfigEmpty   = errors.New("配置文件为空")
)

// Load 读取配置；文件不存在或为空时报错，要求先配置（测试环境用 test init，自有环境用 config set）。
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s（请先运行 jxwaf-cli test init 配置测试环境，或 jxwaf-cli config set 配置自有环境）", ErrConfigMissing, path)
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("%w: %s（请先运行 jxwaf-cli test init 配置测试环境，或 jxwaf-cli config set 配置自有环境）", ErrConfigEmpty, path)
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

// LoadOrCreate 读取配置；文件不存在或为空时返回空配置（供 test init / config set
// 等写入类命令首次创建配置使用），其余错误照常返回。
func LoadOrCreate() (*Config, error) {
	c, err := Load()
	if errors.Is(err, ErrConfigMissing) || errors.Is(err, ErrConfigEmpty) {
		return &Config{Environments: map[string]Environment{}}, nil
	}
	return c, err
}

// Save 原子写入配置（临时文件 + rename），并确保权限为 0600。
// 原子替换保证进程中途崩溃不会留下空文件或半截 JSON 损坏凭据。
func Save(c *Config) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后 Remove 报错（不存在）会被忽略
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	// chmod 在 rename 前对临时文件执行，确保替换后的正式文件即为 0600
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("设置临时文件权限失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("原子替换配置文件失败: %w", err)
	}
	// 已存在文件的旧权限可能宽于 0600（手工创建/备份恢复），每次保存时收紧
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("收紧配置文件权限失败: %w", err)
	}
	return nil
}

// Resolve 按优先级解析要使用的环境：--env 参数 > 配置 active。
func (c *Config) Resolve(envFlag string) (Environment, error) {
	name := envFlag
	if name == "" {
		name = c.Active
	}
	if name == "" {
		return Environment{}, errors.New("环境未初始化：请先运行 jxwaf-cli config set 配置自有环境（测试环境用 jxwaf-cli test init 配置），并用 config validate 确认就绪")
	}
	e, ok := c.Environments[name]
	if !ok {
		return Environment{}, fmt.Errorf("环境 %q 不存在，可用环境: %v", name, c.Names())
	}
	return e, nil
}

// TestName 返回测试环境名（未配置时为约定默认名 test）。
func (c *Config) TestName() string {
	if c.TestEnv == "" {
		return DefaultTestEnvName
	}
	return c.TestEnv
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
