package cli

import (
	"fmt"
	"sort"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/spf13/cobra"
)

// resetRange 定义可清空的资源类型（不含域名：官方预置测试域名必须保留）。
type resetRange struct {
	label    string // 展示名
	nameKey  string // 列表记录中的名称字段
	listOp   adapter.Op
	deleteOp adapter.Op
}

var resetRanges = []resetRange{
	{"Web规则", "rule_name", adapter.OpWebRuleList, adapter.OpWebRuleDelete},
	{"Web白名单", "rule_name", adapter.OpWebWhiteList, adapter.OpWebWhiteDelete},
	{"Flow规则", "rule_name", adapter.OpFlowRuleList, adapter.OpFlowRuleDelete},
	{"Flow白名单", "rule_name", adapter.OpFlowWhiteList, adapter.OpFlowWhiteDelete},
	{"防篡改规则", "rule_name", adapter.OpTamperList, adapter.OpTamperDelete},
	{"全局名单", "name_list_name", adapter.OpNameListList, adapter.OpNameListDelete},
	{"防护组件", "name", adapter.OpComponentList, adapter.OpComponentDelete},
}

// planItem 一条待删除计划。
type planItem struct {
	rtype string // 资源类型展示名
	name  string // 资源名称
	op    adapter.Op
}

// collectPlans 翻页收集环境内全部可清空资源。
func collectPlans(a *adapter.Adapter, c *client.Client) ([]planItem, error) {
	var plans []planItem
	for _, rg := range resetRanges {
		names, err := listNames(a, c, rg.listOp, rg.nameKey)
		if err != nil {
			return nil, fmt.Errorf("%s 列表查询失败: %w", rg.label, err)
		}
		for _, n := range names {
			plans = append(plans, planItem{rg.label, n, rg.deleteOp})
		}
	}
	return plans, nil
}

// executePlans 逐条执行删除，返回结果明细与分类计数。
// 任一条失败即返回汇总 error（退出码 1），避免"全部失败仍 exit 0"的误判。
func executePlans(a *adapter.Adapter, c *client.Client, plans []planItem) ([]map[string]any, map[string]int, error) {
	summary := map[string]int{}
	for _, p := range plans {
		summary[p.rtype]++
	}
	results := make([]map[string]any, 0, len(plans))
	for _, p := range plans {
		path, err := a.Path(p.op)
		if err != nil {
			results = append(results, map[string]any{"type": p.rtype, "name": p.name, "error": err.Error()})
			continue
		}
		body := map[string]any{nameKeyOf(p.op): p.name}
		if err := a.InjectTenant(p.op, body, tenantOpts()); err != nil {
			results = append(results, map[string]any{"type": p.rtype, "name": p.name, "error": err.Error()})
			continue
		}
		resp, err := c.Post(path, a.HeaderMap(), body)
		if err != nil {
			results = append(results, map[string]any{"type": p.rtype, "name": p.name, "error": err.Error()})
			continue
		}
		results = append(results, map[string]any{"type": p.rtype, "name": p.name, "result": resp.Result, "message": resp.Message})
	}
	return results, summary, summarizeFailures("清空", results)
}

// summarizeFailures 汇总批量操作的失败条目；全部成功时返回 nil。
func summarizeFailures(op string, results []map[string]any) error {
	var fails []string
	for _, r := range results {
		if e, ok := r["error"].(string); ok {
			fails = append(fails, fmt.Sprintf("%v: %s", r["name"], e))
			continue
		}
		if res, ok := r["result"].(bool); ok && !res {
			fails = append(fails, fmt.Sprintf("%v: %s", r["name"], r["message"]))
		}
	}
	if len(fails) == 0 {
		return nil
	}
	shown := fails
	if len(shown) > 5 {
		shown = append([]string{}, shown[:5]...)
		shown = append(shown, fmt.Sprintf("...等共 %d 项失败", len(fails)))
	}
	return fmt.Errorf("%s操作有 %d/%d 项失败: %s", op, len(fails), len(results), joinFailures(shown))
}

func joinFailures(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// newResetCmd 全量清空测试环境的业务配置（官方兜底"空环境"用，默认 dry-run）。
func newResetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset [--apply]",
		Short: "全量清空当前环境的规则/白名单/名单/组件（不删域名；默认 dry-run）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, err := resolve()
			if err != nil {
				return nil, err
			}
			apply, _ := cmd.Flags().GetBool("apply")
			plans, err := collectPlans(a, c)
			if err != nil {
				return nil, err
			}
			if !apply {
				preview := make([]map[string]any, 0, len(plans))
				for _, p := range plans {
					path, _ := a.Path(p.op)
					preview = append(preview, map[string]any{"path": path, "body": map[string]any{nameKeyOf(p.op): p.name}})
				}
				return map[string]any{
					"dry_run": true,
					"summary": countByType(plans),
					"total":   len(plans),
					"plans":   preview,
					"hint":    "预览未执行；确认后使用 --apply 清空（不可恢复；官方兜底建议挂每日定时）",
				}, nil
			}
			results, summary, execErr := executePlans(a, c, plans)
			if execErr != nil {
				return nil, fmt.Errorf("清空未全部完成: %w", execErr)
			}
			return map[string]any{"summary": summary, "results": results}, nil
		}),
	}
	cmd.Flags().Bool("apply", false, "实际执行清空（默认 dry-run 预览；删除不可恢复）")
	return cmd
}

// nameKeyOf 按删除操作类型返回记录名称字段。
func nameKeyOf(op adapter.Op) string {
	for _, rg := range resetRanges {
		if rg.deleteOp == op {
			return rg.nameKey
		}
	}
	return "name"
}

func countByType(plans []planItem) map[string]int {
	summary := map[string]int{}
	for _, p := range plans {
		summary[p.rtype]++
	}
	return summary
}

// listPageLimit 单类资源的翻页防御上限（每页条数由服务端决定，通常 10 条/页）。
const listPageLimit = 20

// listNames 翻页拉取列表并提取名称字段（跨页去重）。
// 达到翻页上限且最后一页仍有数据时报错，避免"全量清空"静默漏删。
func listNames(a *adapter.Adapter, c *client.Client, op adapter.Op, nameKey string) ([]string, error) {
	seen := map[string]bool{}
	var names []string
	lastCount := -1
	for page := 1; page <= listPageLimit; page++ {
		raw, err := callOp(a, c, op, map[string]any{"page": page})
		if err != nil {
			return nil, err
		}
		records, _ := raw["records"].([]any)
		lastCount = len(records)
		if lastCount == 0 {
			break
		}
		for _, r := range records {
			if m, ok := r.(map[string]any); ok {
				if name, ok := m[nameKey].(string); ok && name != "" && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	if lastCount > 0 && len(seen) > 0 {
		return nil, fmt.Errorf("资源数量超过翻页防御上限（%d 页），为避免静默漏删请先手动拆分处理", listPageLimit)
	}
	sort.Strings(names)
	return names, nil
}
