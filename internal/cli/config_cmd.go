package cli

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/jx-sec/jxwaf-agent/internal/config"
	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "本地配置管理（环境与凭据）",
	}
	cmd.AddCommand(
		newConfigShowCmd(),
		newConfigSetCmd(),
		newConfigUseCmd(),
		newConfigValidateCmd(),
	)
	return cmd
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "查看当前配置（凭据脱敏）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			c, err := config.Load()
			if err != nil {
				return nil, err
			}
			masked := map[string]config.Environment{}
			for k, e := range c.Environments {
				masked[k] = e.Masked()
			}
			out := map[string]any{
				"active":       c.Active,
				"test_env":  c.TestName(),
				"environments": masked,
			}
			if c.Hub != nil {
				out["hub"] = c.Hub.Masked()
			}
			return out, nil
		}),
	}
}

func newConfigSetCmd() *cobra.Command {
	var (
		name        string
		versionStr  string
		baseURL     string
		wafAuth     string
		subWafAuth  string
		subUserName string
		groupName   string
		cloudMode   string
	)
	cmd := &cobra.Command{
		Use:   "set --name N --version standard|professional|cloud --base-url URL --waf-auth TOKEN",
		Short: "新增或更新一个环境配置（更新时未指定的可选字段保留原值）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if name == "" || baseURL == "" {
				return nil, fmt.Errorf("--name、--base-url 为必填参数")
			}
			v := config.Version(versionStr)
			if !v.Valid() {
				return nil, fmt.Errorf("--version 必须为 standard/professional/cloud")
			}
			// 凭据优先级：命令行参数 > 环境变量（避免凭据进入 shell history / 进程列表）
			if wafAuth == "" {
				wafAuth = envCred("JXWAF_WAF_AUTH")
			}
			if wafAuth == "" {
				return nil, fmt.Errorf("--waf-auth 为必填参数（或设置环境变量 JXWAF_WAF_AUTH）")
			}
			if subWafAuth == "" {
				subWafAuth = envCred("JXWAF_SUB_WAF_AUTH")
			}
			if cloudMode != "" && cloudMode != config.ModeUser && cloudMode != config.ModeAdmin {
				return nil, fmt.Errorf("--cloud-mode 必须为 user 或 admin")
			}

			unlock, err := config.Lock()
			if err != nil {
				return nil, err
			}
			defer unlock()
			c, err := config.Load()
			if err != nil {
				return nil, err
			}
			if c.Active == "" {
				c.Active = name
			}
			// 环境已存在时合并字段：未指定的可选字段保留原值，避免静默清空凭据
			env, exists := c.Environments[name]
			env.Name = name
			env.Version = v
			env.BaseURL = baseURL
			env.WafAuth = wafAuth
			if subWafAuth != "" {
				env.SubWafAuth = subWafAuth
			}
			if subUserName != "" {
				env.SubUserName = subUserName
			}
			if groupName != "" {
				env.GroupName = groupName
			}
			if cloudMode != "" {
				env.CloudMode = cloudMode
			}
			if !env.ValidMode() {
				return nil, fmt.Errorf("环境 %s 的 cloud_mode 取值非法", name)
			}
			if env.Version == config.VersionCloud && env.CloudMode == config.ModeUser && env.SubWafAuth == "" {
				return nil, fmt.Errorf("cloud_mode=user 需要 --sub-waf-auth（或环境变量 JXWAF_SUB_WAF_AUTH）")
			}
			merged := ""
			if exists {
				merged = "已存在环境按传入字段合并更新"
			}
			c.Environments[name] = env
			if err := config.Save(c); err != nil {
				return nil, err
			}
			return map[string]any{"env": name, "active": c.Active, "saved": true, "note": merged}, nil
		}),
	}
	cmd.Flags().StringVar(&name, "name", "", "环境名称")
	cmd.Flags().StringVar(&versionStr, "version", "", "产品版本：standard/professional/cloud")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "管理控制台地址")
	cmd.Flags().StringVar(&wafAuth, "waf-auth", "", "管理 API 凭证（主账号 waf_auth；未指定时读环境变量 JXWAF_WAF_AUTH）")
	cmd.Flags().StringVar(&subWafAuth, "sub-waf-auth", "", "云WAF子账号凭证（用户模式，可选；未指定时读环境变量 JXWAF_SUB_WAF_AUTH）")
	cmd.Flags().StringVar(&subUserName, "sub-user-name", "", "云WAF默认子账号名（主账号模式自动注入，可选）")
	cmd.Flags().StringVar(&groupName, "group-name", "", "专业版域名组（可选）")
	cmd.Flags().StringVar(&cloudMode, "cloud-mode", "", "云WAF模式：user（子账号用户态）/ admin（主账号管理态）；不指定时按是否配置 sub-waf-auth 推断")
	return cmd
}

func newConfigUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <环境名>",
		Short: "切换 active 环境（通用命令的默认目标）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			unlock, err := config.Lock()
			if err != nil {
				return nil, err
			}
			defer unlock()
			c, err := config.Load()
			if err != nil {
				return nil, err
			}
			if _, ok := c.Environments[args[0]]; !ok {
				return nil, fmt.Errorf("环境 %q 不存在，可用环境: %v", args[0], c.Names())
			}
			c.Active = args[0]
			if err := config.Save(c); err != nil {
				return nil, err
			}
			return map[string]any{"active": c.Active}, nil
		}),
	}
}

func newConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "连通性自检：检查目标环境控制台地址可达性（不可达时退出码 1）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			c, err := config.Load()
			if err != nil {
				return nil, err
			}
			e, err := c.Resolve(envFlag)
			if err != nil {
				return nil, err
			}
			start := time.Now()
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(e.BaseURL)
			latency := time.Since(start).Milliseconds()
			if err != nil {
				return nil, fmt.Errorf("环境 %s（%s）不可达: %v", e.Name, e.BaseURL, err)
			}
			defer resp.Body.Close()
			return map[string]any{
				"env": e.Name, "version": e.Version, "base_url": e.BaseURL,
				"reachable": true, "status": resp.StatusCode, "latency_ms": latency,
			}, nil
		}),
	}
}

// envCred 读取凭据类环境变量。
func envCred(key string) string {
	return os.Getenv(key)
}
