package cli

import (
	"fmt"
	"net/http"
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
			return map[string]any{
				"active":       c.Active,
				"environments": masked,
			}, nil
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
	)
	cmd := &cobra.Command{
		Use:   "set --name N --version standard|professional|cloud --base-url URL --waf-auth TOKEN",
		Short: "新增或更新一个环境配置",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if name == "" || baseURL == "" || wafAuth == "" {
				return nil, fmt.Errorf("--name、--base-url、--waf-auth 为必填参数")
			}
			v := config.Version(versionStr)
			if !v.Valid() {
				return nil, fmt.Errorf("--version 必须为 standard/professional/cloud")
			}
			c, err := config.Load()
			if err != nil {
				return nil, err
			}
			if c.Active == "" {
				c.Active = name
			}
			c.Environments[name] = config.Environment{
				Name:        name,
				Version:     v,
				BaseURL:     baseURL,
				WafAuth:     wafAuth,
				SubWafAuth:  subWafAuth,
				SubUserName: subUserName,
				GroupName:   groupName,
			}
			if err := config.Save(c); err != nil {
				return nil, err
			}
			return map[string]any{"env": name, "active": c.Active, "saved": true}, nil
		}),
	}
	cmd.Flags().StringVar(&name, "name", "", "环境名称")
	cmd.Flags().StringVar(&versionStr, "version", "", "产品版本：standard/professional/cloud")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "管理控制台地址")
	cmd.Flags().StringVar(&wafAuth, "waf-auth", "", "管理 API 凭证（主账号 waf_auth）")
	cmd.Flags().StringVar(&subWafAuth, "sub-waf-auth", "", "云WAF子账号凭证（用户模式，可选）")
	cmd.Flags().StringVar(&subUserName, "sub-user-name", "", "云WAF默认子账号名（主账号模式自动注入，可选）")
	cmd.Flags().StringVar(&groupName, "group-name", "", "专业版域名组（可选）")
	return cmd
}

func newConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "连通性自检：检查目标环境控制台地址可达性",
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
				return map[string]any{
					"env": e.Name, "version": e.Version, "base_url": e.BaseURL,
					"reachable": false, "error": err.Error(), "latency_ms": latency,
				}, nil
			}
			defer resp.Body.Close()
			return map[string]any{
				"env": e.Name, "version": e.Version, "base_url": e.BaseURL,
				"reachable": true, "status": resp.StatusCode, "latency_ms": latency,
			}, nil
		}),
	}
}
