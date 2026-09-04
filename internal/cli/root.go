// Package cli 提供 jxwaf-cli 命令面：AI IDE 与 JXWAF 管理 API 之间的确定执行层。
package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var envFlag string

// errPrinted 标记本次执行已向 stderr 输出过契约 JSON（避免重复输出）。
var errPrinted bool

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jxwaf-cli",
		Short: "JXWAF 运维命令行工具（对接标准版/专业版/云WAF 管理 API）",
	}
	// 错误输出由 abort 统一处理（含 JSON 契约），抑制 cobra 原生错误文本。
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.PersistentFlags().StringVar(&envFlag, "env", "", "目标环境名称（默认取配置中的 active；test 命令组固定使用测试环境）")
	cmd.PersistentFlags().StringVar(&groupFlag, "group", "", "专业版域名组（默认取环境配置中的 group_name）")
	cmd.PersistentFlags().StringVar(&subUserFlag, "sub-user", "", "云WAF主账号操作的目标子账号名")
	cmd.AddCommand(newConfigCmd())
	cmd.AddCommand(newTestCmd())
	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newApplyCmd())
	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newCleanupCmd())
	cmd.AddCommand(newResetCmd())
	cmd.AddCommand(newRuleCmd())
	cmd.AddCommand(newWhiteCmd())
	cmd.AddCommand(newTamperCmd())
	cmd.AddCommand(newSslCmd())
	cmd.AddCommand(newGroupCmd())
	cmd.AddCommand(newNameListCmd())
	cmd.AddCommand(newComponentCmd())
	cmd.AddCommand(newWebsiteCmd())
	cmd.AddCommand(newSocCmd())
	cmd.AddCommand(newNetworkCmd())
	cmd.AddCommand(newMonitorCmd())
	cmd.AddCommand(newSubAccountCmd())
	cmd.AddCommand(newCustomCmd())
	cmd.AddCommand(newCacheCmd())
	cmd.AddCommand(newSysConfCmd())
	cmd.AddCommand(newHubCmd())
	return cmd
}

// Execute 是 CLI 入口。错误已按契约输出到 stderr，返回非 nil 表示失败（退出码 1）。
// 覆盖两类错误：RunE 内的业务错误（abort 已输出）与 RunE 之前的 cobra 错误
// （未知命令/flag 拼写/参数个数校验，由本函数补输出），确保 stderr 始终有契约 JSON。
func Execute() error {
	cmd := newRootCmd()
	errPrinted = false
	err := cmd.Execute()
	if err != nil && !errPrinted {
		abort(cmd.ErrOrStderr(), err)
	}
	return err
}

// printJSON 将结果以 JSON 输出到指定 writer（输出契约：stdout 仅含 JSON）。
func printJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("输出序列化失败: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// abort 按契约将错误输出到指定 writer（通常为 stderr）。
func abort(w io.Writer, err error) {
	errPrinted = true
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
		if err := printJSON(cmd.OutOrStdout(), v); err != nil {
			abort(cmd.ErrOrStderr(), err)
			return err
		}
		return nil
	}
}
