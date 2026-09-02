package cli

import (
	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// socStatsOps 一组攻击统计的 10 个操作（Web/Flow 同构）。
type socStatsOps [10]adapter.Op

func (o socStatsOps) attach(cmd *cobra.Command) {
	cmd.AddCommand(
		queryCmd("count-total", "攻击总数（含环比）", o[0]),
		queryCmd("api-count", "受攻击 API 总数", o[1]),
		queryCmd("ip-count", "攻击源 IP 总数", o[2]),
		queryCmd("country-count", "攻击涉及国家总数", o[3]),
		queryCmd("geoip", "攻击地理分布", o[4]),
		queryCmd("trend", "攻击数量趋势（跨度自适应聚合）", o[5]),
		queryCmd("api-top", "受攻击 API Top", o[6]),
		queryCmd("type-top", "攻击类型 Top", o[7]),
		queryCmd("ip-top", "攻击源 IP Top", o[8]),
		queryCmd("country-top", "攻击国家 Top", o[9]),
	)
}

// socQueryHint SOC 统计/事件类命令的通用参数说明（from_time/to_time 为必填）。
const socQueryHint = "查询类操作（依赖 ClickHouse 报表配置）；统计类参数 from_time/to_time（YYYY-MM-DD HH:MM:SS）"

func newSocCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "soc", Short: "SOC 安全运营中心（日志/事件/统计/模型/用量）"}

	log := &cobra.Command{Use: "log", Short: "攻击日志查询"}
	log.AddCommand(queryCmd("query", "查询攻击日志（from_time/to_time/page/sql_rules；单页 20 条）", adapter.OpSocLogQuery))
	log.AddCommand(newSocLogFetchCmd())

	event := &cobra.Command{Use: "event", Short: "攻击事件与行为轨迹"}
	event.AddCommand(
		queryCmd("list", "查询攻击事件列表（from_time/to_time/page）", adapter.OpSocEventList),
		queryCmd("track", "查询攻击者行为轨迹（from_time/to_time/attack_ip）", adapter.OpSocBehaveTrack),
	)

	stats := &cobra.Command{Use: "stats", Short: "攻击统计（" + socQueryHint + "）"}
	web := &cobra.Command{Use: "web", Short: "Web 攻击统计"}
	socStatsOps{adapter.OpSocWebAttackCountTotal, adapter.OpSocWebAttackApiCountTotal,
		adapter.OpSocWebAttackIpCountTotal, adapter.OpSocWebAttackIsocodeCountTotal,
		adapter.OpSocWebAttackGeoip, adapter.OpSocWebAttackCountTrend,
		adapter.OpSocWebAttackApiTop, adapter.OpSocWebAttackTypeTop,
		adapter.OpSocWebAttackIpTop, adapter.OpSocWebAttackIsocodeTop}.attach(web)
	flow := &cobra.Command{Use: "flow", Short: "流量攻击统计（标准版不支持）"}
	socStatsOps{adapter.OpSocFlowAttackCountTotal, adapter.OpSocFlowAttackApiCountTotal,
		adapter.OpSocFlowAttackIpCountTotal, adapter.OpSocFlowAttackIsocodeCountTotal,
		adapter.OpSocFlowAttackGeoip, adapter.OpSocFlowAttackCountTrend,
		adapter.OpSocFlowAttackApiTop, adapter.OpSocFlowAttackTypeTop,
		adapter.OpSocFlowAttackIpTop, adapter.OpSocFlowAttackIsocodeTop}.attach(flow)
	stats.AddCommand(web, flow)

	model := &cobra.Command{Use: "model", Short: "AI 分析模型与 Token 白名单"}
	model.AddCommand(
		queryCmd("list", "查询模型判定记录（page，可选 search）", adapter.OpSocModelList),
		writeCmd("delete", "删除模型判定记录（token）", adapter.OpSocModelDelete),
		writeCmd("result", "修正模型判定结果（token/ai_analysis_result，误报标记用）", adapter.OpSocModelResultEdit),
		queryCmd("white-list", "查询模型 Token 白名单（page）", adapter.OpSocModelWhiteList),
		writeCmd("white-add", "添加模型 Token 白名单（token，可选 detail）", adapter.OpSocModelWhiteCreate),
		writeCmd("white-del", "删除模型 Token 白名单（token）", adapter.OpSocModelWhiteDelete),
	)

	usage := &cobra.Command{Use: "usage", Short: "业务用量统计（QPS/带宽/延迟/状态码；" + socQueryHint + "）"}
	usage.AddCommand(
		queryCmd("domains", "查询有流量数据的域名列表", adapter.OpUsageStatDomains),
		queryCmd("overview", "用量总览（from_time/to_time）", adapter.OpUsageStatOverview),
		queryCmd("qps", "QPS 趋势", adapter.OpUsageStatQpsTrend),
		queryCmd("bandwidth", "带宽趋势", adapter.OpUsageStatBandwidth),
		queryCmd("status", "状态码分布", adapter.OpUsageStatStatusDist),
		queryCmd("latency", "延迟趋势", adapter.OpUsageStatLatency),
		queryCmd("detail", "明细（分页，pageSize 固定 20）", adapter.OpUsageStatDetail),
	)

	cmd.AddCommand(log, event, stats, model, usage)
	return cmd
}
