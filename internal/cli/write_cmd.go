package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// writeCmd 构造写入子命令：默认 dry-run 预览（环境+路径+请求体），--apply 才实际执行。
// 预览中包含 env 与 base_url，防止 dry-run 与 --apply 两次调用间 --env 不一致导致下发到错误环境。
func writeCmd(name string, short string, op adapter.Op) *cobra.Command {
	cmd := &cobra.Command{
		Use:   name,
		Short: short,
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, err := resolve()
			if err != nil {
				return nil, err
			}
			params, err := getParams(cmd)
			if err != nil {
				return nil, err
			}
			apply, _ := cmd.Flags().GetBool("apply")
			path, err := a.Path(op)
			if err != nil {
				return nil, err
			}
			body := cloneMap(params)
			if err := a.InjectTenant(op, body, tenantOpts()); err != nil {
				return nil, err
			}
			if !apply {
				return map[string]any{
					"dry_run":  true,
					"env":      a.EnvName(),
					"base_url": c.BaseURL,
					"path":     path,
					"body":     body,
					"hint":     "预览未执行；确认后使用 --apply 实际执行",
				}, nil
			}
			resp, err := c.Post(path, a.HeaderMap(), body)
			if err != nil {
				return nil, err
			}
			if !resp.Result {
				return nil, fmt.Errorf("%s [%s]", resp.Message, path)
			}
			return resp.Raw, nil
		}),
	}
	addParamsFlag(cmd)
	cmd.Flags().Bool("apply", false, "实际执行（默认 dry-run 仅预览请求内容）")
	return cmd
}

// configEnvelope 为 generate --output 落盘的配置信封。
type configEnvelope struct {
	Type      string            `json:"type"`
	Op        string            `json:"op"`
	Config    map[string]any    `json:"config"`
	TestCases []json.RawMessage `json:"test_cases,omitempty"`
}

// createToEdit 生成类型的创建操作 → 编辑操作映射（apply --update 使用）。
var createToEdit = map[adapter.Op]adapter.Op{
	adapter.OpWebRuleCreate:   adapter.OpWebRuleEdit,
	adapter.OpWebWhiteCreate:  adapter.OpWebWhiteEdit,
	adapter.OpFlowRuleCreate:  adapter.OpFlowRuleEdit,
	adapter.OpFlowWhiteCreate: adapter.OpFlowWhiteEdit,
	adapter.OpNameListCreate:  adapter.OpNameListEdit,
	adapter.OpComponentCreate: adapter.OpComponentEdit,
	adapter.OpDomainCreate:    adapter.OpDomainEdit,
}

func newApplyCmd() *cobra.Command {
	var update bool
	cmd := &cobra.Command{
		Use:   "apply <config-file> [--update] [--apply]",
		Short: "下发 generate 生成的配置（默认 dry-run 预览，--apply 实际执行）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return nil, fmt.Errorf("读取配置文件失败: %w", err)
			}
			var env configEnvelope
			if err := json.Unmarshal(data, &env); err != nil {
				return nil, fmt.Errorf("配置文件不是 generate 输出格式: %w", err)
			}
			op := adapter.Op(env.Op)
			if update {
				edit, ok := createToEdit[op]
				if !ok {
					return nil, fmt.Errorf("该配置不支持 --update（仅创建类配置可更新）")
				}
				op = edit
			}
			a, c, err := resolve()
			if err != nil {
				return nil, err
			}
			path, err := a.Path(op)
			if err != nil {
				return nil, err
			}
			body := cloneMap(env.Config)
			if err := a.InjectTenant(op, body, tenantOpts()); err != nil {
				return nil, err
			}
			apply, _ := cmd.Flags().GetBool("apply")
			if !apply {
				return map[string]any{
					"dry_run":  true,
					"env":      a.EnvName(),
					"base_url": c.BaseURL,
					"path":     path,
					"body":     body,
					"hint":     "预览未执行；确认后使用 --apply 实际执行",
				}, nil
			}
			resp, err := c.Post(path, a.HeaderMap(), body)
			if err != nil {
				return nil, err
			}
			if !resp.Result {
				return nil, fmt.Errorf("%s [%s]", resp.Message, path)
			}
			return resp.Raw, nil
		}),
	}
	cmd.Flags().Bool("apply", false, "实际执行（默认 dry-run 仅预览请求内容）")
	cmd.Flags().BoolVar(&update, "update", false, "按编辑接口更新（默认创建）")
	return cmd
}
