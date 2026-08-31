package cli

import (
	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// cacheGroup 一组缓存策略的 11 个操作（三类同构）。
type cacheGroup struct {
	name       string
	short      string
	createHint string
	ops        [11]adapter.Op
}

func (g cacheGroup) build() *cobra.Command {
	cmd := &cobra.Command{Use: g.name, Short: g.short}
	cmd.AddCommand(
		queryCmd("list", "查询列表（page）", g.ops[0]),
		queryCmd("get", "查询单条（rule_name）", g.ops[1]),
		writeCmd("create", "创建（"+g.createHint+"）", g.ops[2]),
		writeCmd("edit", "更新（"+g.createHint+"）", g.ops[3]),
		writeCmd("delete", "删除（rule_name）", g.ops[4]),
		writeCmd("status", "启停（rule_name/status）", g.ops[5]),
		writeCmd("priority", "调整优先级（rule_name/type:top|exchange）", g.ops[6]),
		queryCmd("backup", "导出配置（rule_name_list）", g.ops[7]),
		writeCmd("load", "导入配置（rules，配对 backup 输出）", g.ops[8]),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load）", g.ops[9]),
		writeCmd("hub-export", "导出到 Hub 配置中心（规则名数组）", g.ops[10]),
	)
	return cmd
}

// newCacheCmd 缓存策略与缓存任务（仅云WAF）。
func newCacheCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cache", Short: "缓存管理（缓存/不缓存/绕过策略、预热/刷新任务、CDN；仅云WAF）"}
	basicHint := "rule_name/rule_detail/rule_matchs"
	for _, g := range []cacheGroup{
		{"policy", "缓存策略", basicHint + "/cache_key", [11]adapter.Op{
			adapter.OpCachePolicyList, adapter.OpCachePolicyGet, adapter.OpCachePolicyCreate,
			adapter.OpCachePolicyDelete, adapter.OpCachePolicyEdit, adapter.OpCachePolicyStatus,
			adapter.OpCachePolicyPriority, adapter.OpCachePolicyBackup, adapter.OpCachePolicyLoad,
			adapter.OpCachePolicyHubLoad, adapter.OpCachePolicyHubExport}},
		{"no-cache", "不缓存策略", basicHint, [11]adapter.Op{
			adapter.OpNoCachePolicyList, adapter.OpNoCachePolicyGet, adapter.OpNoCachePolicyCreate,
			adapter.OpNoCachePolicyDelete, adapter.OpNoCachePolicyEdit, adapter.OpNoCachePolicyStatus,
			adapter.OpNoCachePolicyPriority, adapter.OpNoCachePolicyBackup, adapter.OpNoCachePolicyLoad,
			adapter.OpNoCachePolicyHubLoad, adapter.OpNoCachePolicyHubExport}},
		{"bypass", "缓存绕过策略", basicHint, [11]adapter.Op{
			adapter.OpCacheBypassList, adapter.OpCacheBypassGet, adapter.OpCacheBypassCreate,
			adapter.OpCacheBypassDelete, adapter.OpCacheBypassEdit, adapter.OpCacheBypassStatus,
			adapter.OpCacheBypassPriority, adapter.OpCacheBypassBackup, adapter.OpCacheBypassLoad,
			adapter.OpCacheBypassHubLoad, adapter.OpCacheBypassHubExport}},
	} {
		cmd.AddCommand(g.build())
	}

	taskHint := "URL 列表（按模块参数）"
	warmup := &cobra.Command{Use: "warmup", Short: "缓存预热任务"}
	warmup.AddCommand(
		writeCmd("create", "创建预热任务（"+taskHint+"）", adapter.OpCacheWarmupCreate),
		queryCmd("list", "查询预热任务列表", adapter.OpCacheWarmupList),
		queryCmd("detail", "查询预热任务详情", adapter.OpCacheWarmupDetail),
		writeCmd("delete", "删除预热任务", adapter.OpCacheWarmupDelete),
	)
	refresh := &cobra.Command{Use: "refresh", Short: "缓存刷新任务"}
	refresh.AddCommand(
		writeCmd("create", "创建刷新任务（"+taskHint+"）", adapter.OpCacheRefreshCreate),
		queryCmd("list", "查询刷新任务列表", adapter.OpCacheRefreshList),
		queryCmd("detail", "查询刷新任务详情", adapter.OpCacheRefreshDetail),
		writeCmd("delete", "删除刷新任务", adapter.OpCacheRefreshDelete),
	)

	switchCmd := &cobra.Command{Use: "switch", Short: "缓存总开关（仅子账号模式）"}
	switchCmd.AddCommand(
		queryCmd("get", "查询缓存开关", adapter.OpCacheSwitchGet),
		writeCmd("edit", "设置缓存开关", adapter.OpCacheSwitchEdit),
	)

	cdn := &cobra.Command{Use: "cdn", Short: "CDN 缓存预热/刷新（仅子账号模式；urls 最多 100 条）"}
	cdn.AddCommand(
		writeCmd("preheat", "CDN 缓存预热（urls）", adapter.OpCdnPreheat),
		writeCmd("refresh", "CDN 缓存刷新（urls）", adapter.OpCdnRefresh),
	)

	cmd.AddCommand(warmup, refresh, switchCmd, cdn)
	return cmd
}
