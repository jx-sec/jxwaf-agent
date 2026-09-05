package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "config.json")
}

func TestSaveLoadRoundtrip(t *testing.T) {
	t.Setenv("JXWAF_CONFIG_PATH", newTestPath(t))
	c := &Config{
		Active: "prod",
		Environments: map[string]Environment{
			"prod": {Name: "prod", Version: VersionCloud, BaseURL: "https://waf.example.com",
				WafAuth: "token-12345", SubWafAuth: "sub", CloudMode: ModeUser},
			"test": {Name: "test", Version: VersionProfessional, BaseURL: "https://waf-demo.jxwaf.com", WafAuth: "demo"},
		},
		TestEnv: "test",
	}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Active != "prod" || got.TestEnv != "test" {
		t.Errorf("active/test_env 丢失: %+v", got)
	}
	if got.Environments["prod"].CloudMode != ModeUser {
		t.Errorf("cloud_mode 丢失: %+v", got.Environments["prod"])
	}
}

func TestSaveEnforces0600(t *testing.T) {
	path := newTestPath(t)
	t.Setenv("JXWAF_CONFIG_PATH", path)

	// 预置一个宽权限文件（模拟手工创建/备份恢复），Save 后应被收紧为 0600
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(&Config{Environments: map[string]Environment{}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("已存在文件权限应被收紧为 0600，实际 %v", info.Mode().Perm())
	}
}

func TestSaveAtomicNoLeftoverTemp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JXWAF_CONFIG_PATH", filepath.Join(dir, "config.json"))
	if err := Save(&Config{Environments: map[string]Environment{}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Errorf("原子写不应残留临时文件: %v", entries)
	}
}

func TestLoadEmptyFileErrors(t *testing.T) {
	path := newTestPath(t)
	t.Setenv("JXWAF_CONFIG_PATH", path)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if !errors.Is(err, ErrConfigEmpty) {
		t.Fatalf("空文件应报错要求配置，实际: %v", err)
	}
}

func TestLoadMissingErrors(t *testing.T) {
	path := newTestPath(t)
	t.Setenv("JXWAF_CONFIG_PATH", path)
	_, err := Load()
	if !errors.Is(err, ErrConfigMissing) {
		t.Fatalf("文件缺失应报错要求配置，实际: %v", err)
	}
	// 报错不应创建文件，也不应写入任何内置默认值
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("Load 报错时不应创建配置文件: %v", statErr)
	}
	// LoadOrCreate 供写入类命令首次创建配置：缺失/为空时返回空配置
	c, err := LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate 缺失时应返回空配置: %v", err)
	}
	if c.Environments == nil || len(c.Environments) != 0 {
		t.Errorf("LoadOrCreate 应返回空环境表: %+v", c.Environments)
	}
}

func TestResolvePriority(t *testing.T) {
	c := &Config{
		Active: "a",
		Environments: map[string]Environment{
			"a": {Name: "a", Version: VersionStandard},
			"b": {Name: "b", Version: VersionProfessional},
		},
	}
	if e, err := c.Resolve(""); err != nil || e.Name != "a" {
		t.Errorf("空 flag 应取 active: %v %v", e, err)
	}
	if e, err := c.Resolve("b"); err != nil || e.Name != "b" {
		t.Errorf("--env 应优先于 active: %v %v", e, err)
	}
	if _, err := c.Resolve("missing"); err == nil {
		t.Error("未知环境应报错")
	}
}

func TestResolveNoActiveHint(t *testing.T) {
	c := &Config{Environments: map[string]Environment{}}
	_, err := c.Resolve("")
	if err == nil {
		t.Fatal("未配置环境应报错")
	}
	if !strings.Contains(err.Error(), "config set") {
		t.Errorf("错误提示应引导使用 config set: %v", err)
	}
}

func TestNameDefault(t *testing.T) {
	c := &Config{Environments: map[string]Environment{}}
	if got := c.TestName(); got != "test" {
		t.Errorf("默认测试环境名应为 test，实际 %q", got)
	}
	c.TestEnv = "mybox"
	if got := c.TestName(); got != "mybox" {
		t.Errorf("已配置测试环境名应为 mybox，实际 %q", got)
	}
}

func TestMasked(t *testing.T) {
	e := Environment{WafAuth: "1234567890", SubWafAuth: "abcd"}
	m := e.Masked()
	if m.WafAuth != "1234******" {
		t.Errorf("waf_auth 脱敏错误: %q", m.WafAuth)
	}
	if m.SubWafAuth != "******" {
		t.Errorf("短凭据应全遮蔽: %q", m.SubWafAuth)
	}
	if e.WafAuth != "1234567890" {
		t.Error("Masked 不应修改原值")
	}
}

func TestPathLocalConfigPriority(t *testing.T) {
	t.Setenv("JXWAF_CONFIG_PATH", "")
	dir := t.TempDir()
	t.Chdir(dir)

	// 无任何配置时默认当前目录 ./config.json（不再回退用户主目录）
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, LocalConfigName); p != want {
		t.Errorf("默认应为当前目录 config.json: %q != %q", p, want)
	}

	// 当前目录存在 config.json → 直接命中
	local := filepath.Join(dir, LocalConfigName)
	if err := os.WriteFile(local, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err = Path()
	if err != nil {
		t.Fatal(err)
	}
	if p != local {
		t.Errorf("存在本地配置时应命中: %q != %q", p, local)
	}

	// JXWAF_CONFIG_PATH 显式设置时优先级最高
	t.Setenv("JXWAF_CONFIG_PATH", filepath.Join(dir, "override.json"))
	p, _ = Path()
	if p != filepath.Join(dir, "override.json") {
		t.Errorf("JXWAF_CONFIG_PATH 应最优先: %q", p)
	}
}

func TestLoadTestURL(t *testing.T) {
	t.Setenv("JXWAF_CONFIG_PATH", newTestPath(t))
	c := &Config{
		Environments: map[string]Environment{
			"test": {
				Name: "test", Version: VersionProfessional,
				BaseURL: "https://waf-demo.jxwaf.com", WafAuth: "t",
				TestURL: "https://waf-demo.jxwaf.com:4443",
			},
		},
	}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// test_url 是测试环境属性（配置下发到测试环境后访问它验证），不是全局字段
	if got.Environments["test"].TestURL != c.Environments["test"].TestURL {
		t.Errorf("环境 test_url 往返丢失: %+v", got.Environments["test"])
	}
}
