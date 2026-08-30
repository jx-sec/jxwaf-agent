// Package cli 提供 jxwaf-cli 命令面：AI IDE 与 JXWAF 管理 API 之间的确定执行层。
package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var envFlag string

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "jxwaf-cli",
		Short:         "JXWAF 运维命令行工具（对接标准版/专业版/云WAF 管理 API）",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVar(&envFlag, "env", "", "目标环境名称（默认取配置中的 active）")
	cmd.PersistentFlags().StringVar(&groupFlag, "group", "", "专业版域名组（默认取环境配置中的 group_name）")
	cmd.PersistentFlags().StringVar(&subUserFlag, "sub-user", "", "云WAF主账号操作的目标子账号名")
	cmd.AddCommand(newConfigCmd())
	cmd.AddCommand(newSandboxCmd())
	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newApplyCmd())
	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newCleanupCmd())
	cmd.AddCommand(newResetCmd())
	cmd.AddCommand(newRuleCmd())
	cmd.AddCommand(newNameListCmd())
	cmd.AddCommand(newComponentCmd())
	cmd.AddCommand(newWebsiteCmd())
	cmd.AddCommand(newSocCmd())
	return cmd
}

// Execute 是 CLI 入口。错误已按契约输出到 stderr，返回非 nil 表示失败（退出码 1）。
func Execute() error {
	return newRootCmd().Execute()
}

// printJSON 将结果以 JSON 输出到指定 writer（输出契约：stdout 仅含 JSON）。
// 命令返回体均为可序列化类型，序列化失败视为内部错误（panic 由上层兜底）。
func printJSON(w io.Writer, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("输出序列化失败: %v", err))
	}
	fmt.Fprintln(w, string(data))
}

// abort 按契约将错误输出到指定 writer（通常为 stderr）。
func abort(w io.Writer, err error) {
	data, _ := json.Marshal(map[string]any{"result": false, "error": err.Error()})
	fmt.Fprintln(w, string(data))
}

// runE 包装命令执行体：成功结果走 stdout JSON，错误走 stderr JSON。
func runE(fn func(cmd *cobra.Command, args []string) (any, error)) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		v, err := fn(cmd, args)
		if err != nil {
			abort(cmd.ErrOrStderr(), err)
			return err
		}
		printJSON(cmd.OutOrStdout(), v)
		return nil
	}
}
