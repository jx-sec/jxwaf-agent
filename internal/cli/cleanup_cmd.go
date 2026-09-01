package cli

import (
	"fmt"
	"strings"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/spf13/cobra"
)

// cleanupResource 定义可按名称清理的资源类型。
type cleanupResource struct {
	field string // 名称字段
	op    adapter.Op
}

var cleanupResources = map[string]cleanupResource{
	"web-rule":   {"rule_name", adapter.OpWebRuleDelete},
	"flow-rule":  {"rule_name", adapter.OpFlowRuleDelete},
	"web-white":  {"rule_name", adapter.OpWebWhiteDelete},
	"flow-white": {"rule_name", adapter.OpFlowWhiteDelete},
	"tamper":     {"rule_name", adapter.OpTamperDelete},
	"name-list":  {"name_list_name", adapter.OpNameListDelete},
	"component":  {"name", adapter.OpComponentDelete},
	"website":    {"domain", adapter.OpDomainDelete},
}

// runCleanup 按类型与名称批量删除配置（dry-run 预览或执行），供通用命令与云端测试环境命令复用。
func runCleanup(a *adapter.Adapter, c *client.Client, rtype, names string, apply bool) (any, error) {
	res, ok := cleanupResources[rtype]
	if !ok {
		return nil, fmt.Errorf("未知资源类型 %q，支持: %v", rtype, keys(cleanupResources))
	}
	var filtered []string
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			filtered = append(filtered, n)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("--names 不能为空")
	}
	path, err := a.Path(res.op)
	if err != nil {
		return nil, err
	}
	if !apply {
		preview := make([]map[string]any, 0, len(filtered))
		for _, n := range filtered {
			body := cloneMap(map[string]any{res.field: n})
			if err := a.InjectTenant(res.op, body, tenantOpts()); err != nil {
				return nil, err
			}
			preview = append(preview, map[string]any{"path": path, "body": body})
		}
		return map[string]any{
			"dry_run": true,
			"type":    rtype,
			"count":   len(preview),
			"plans":   preview,
			"hint":    "预览未执行；确认后使用 --apply 实际删除（删除不可恢复）",
		}, nil
	}
	results := make([]map[string]any, 0, len(filtered))
	for _, n := range filtered {
		body := map[string]any{res.field: n}
		if err := a.InjectTenant(res.op, body, tenantOpts()); err != nil {
			return nil, err
		}
		resp, err := c.Post(path, a.HeaderMap(), body)
		if err != nil {
			results = append(results, map[string]any{res.field: n, "error": err.Error()})
			continue
		}
		results = append(results, map[string]any{res.field: n, "result": resp.Result, "message": resp.Message})
	}
	// 任一条失败即报错（退出码 1），避免"全部失败仍 exit 0"的误判
	if err := summarizeFailures("删除", results); err != nil {
		return nil, fmt.Errorf("批量删除未全部完成: %w", err)
	}
	return map[string]any{"type": rtype, "results": results}, nil
}

func newCleanupCmd() *cobra.Command {
	var (
		rtype string
		names string
	)
	cmd := &cobra.Command{
		Use:   "cleanup --type <资源类型> --names a,b [--apply]",
		Short: "批量删除测试环境配置（默认 dry-run 预览）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, err := resolve()
			if err != nil {
				return nil, err
			}
			apply, _ := cmd.Flags().GetBool("apply")
			return runCleanup(a, c, rtype, names, apply)
		}),
	}
	cmd.Flags().StringVar(&rtype, "type", "", "资源类型：web-rule/flow-rule/web-white/flow-white/tamper/name-list/component/website")
	cmd.Flags().StringVar(&names, "names", "", "资源名称（逗号分隔）")
	cmd.Flags().Bool("apply", false, "实际执行删除（默认 dry-run 预览，删除不可恢复）")
	return cmd
}

func keys(m map[string]cleanupResource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
