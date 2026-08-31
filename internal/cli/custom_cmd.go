package cli

import (
	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// customGroup 一组自定义配置的 11 个操作（四类模块同构）。
type customGroup struct {
	name       string        // 子命令名
	short      string        // 子命令说明
	createHint string        // create/edit 参数提示
	ops        [11]adapter.Op // list/get/create/delete/edit/status/priority/backup/load/hubLoad/hubExport
}

func (g customGroup) build() *cobra.Command {
	cmd := &cobra.Command{Use: g.name, Short: g.short}
	cmd.AddCommand(
		queryCmd("list", "查询列表（page）", g.ops[0]),
		queryCmd("get", "查询单条（rule_name）", g.ops[1]),
		writeCmd("create", "创建（"+g.createHint+"）", g.ops[2]),
		writeCmd("edit", "更新（"+g.createHint+"）", g.ops[3]),
		writeCmd("delete", "删除（rule_name）", g.ops[4]),
		writeCmd("status", "启停（rule_name/status）", g.ops[5]),
		writeCmd("priority", "调整优先级（rule_name/type:top|exchange，exchange 另需 exchange_rule_name）", g.ops[6]),
		queryCmd("backup", "导出配置（rule_name_list）", g.ops[7]),
		writeCmd("load", "导入配置（rules，配对 backup 输出）", g.ops[8]),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load，可选 api_key）", g.ops[9]),
		writeCmd("hub-export", "导出到 Hub 配置中心（规则名数组，可选 api_key）", g.ops[10]),
	)
	return cmd
}

// newCustomCmd 自定义配置（请求头/响应头/响应内容/回源地址；标准版不支持）。
func newCustomCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "custom", Short: "自定义配置（请求头/响应头/响应内容/回源地址；标准版不支持）"}
	headerHint := "rule_name/rule_detail/rule_matchs/filter/header_name/header_value"
	contentHint := "rule_name/rule_detail/rule_matchs/filter/content_type/return_code/return_content"
	upstreamHint := "rule_name/rule_detail/rule_matchs/filter/source_ip/source_http_port/source_https_port"
	for _, g := range []customGroup{
		{"request-header", "自定义请求头", headerHint, [11]adapter.Op{
			adapter.OpCustomReqHeaderList, adapter.OpCustomReqHeaderGet, adapter.OpCustomReqHeaderCreate,
			adapter.OpCustomReqHeaderDelete, adapter.OpCustomReqHeaderEdit, adapter.OpCustomReqHeaderStatus,
			adapter.OpCustomReqHeaderPriority, adapter.OpCustomReqHeaderBackup, adapter.OpCustomReqHeaderLoad,
			adapter.OpCustomReqHeaderHubLoad, adapter.OpCustomReqHeaderHubExport}},
		{"response-header", "自定义响应头", headerHint, [11]adapter.Op{
			adapter.OpCustomRespHeaderList, adapter.OpCustomRespHeaderGet, adapter.OpCustomRespHeaderCreate,
			adapter.OpCustomRespHeaderDelete, adapter.OpCustomRespHeaderEdit, adapter.OpCustomRespHeaderStatus,
			adapter.OpCustomRespHeaderPriority, adapter.OpCustomRespHeaderBackup, adapter.OpCustomRespHeaderLoad,
			adapter.OpCustomRespHeaderHubLoad, adapter.OpCustomRespHeaderHubExport}},
		{"response-content", "自定义响应内容", contentHint, [11]adapter.Op{
			adapter.OpCustomRespContentList, adapter.OpCustomRespContentGet, adapter.OpCustomRespContentCreate,
			adapter.OpCustomRespContentDelete, adapter.OpCustomRespContentEdit, adapter.OpCustomRespContentStatus,
			adapter.OpCustomRespContentPriority, adapter.OpCustomRespContentBackup, adapter.OpCustomRespContentLoad,
			adapter.OpCustomRespContentHubLoad, adapter.OpCustomRespContentHubExport}},
		{"upstream", "自定义回源地址", upstreamHint, [11]adapter.Op{
			adapter.OpCustomUpstreamList, adapter.OpCustomUpstreamGet, adapter.OpCustomUpstreamCreate,
			adapter.OpCustomUpstreamDelete, adapter.OpCustomUpstreamEdit, adapter.OpCustomUpstreamStatus,
			adapter.OpCustomUpstreamPriority, adapter.OpCustomUpstreamBackup, adapter.OpCustomUpstreamLoad,
			adapter.OpCustomUpstreamHubLoad, adapter.OpCustomUpstreamHubExport}},
	} {
		cmd.AddCommand(g.build())
	}
	return cmd
}
