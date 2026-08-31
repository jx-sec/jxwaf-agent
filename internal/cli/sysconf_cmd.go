package cli

import (
	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// newSysConfCmd 系统配置（日志/报表/自定义页面/WebTDS/整库备份；标准版不支持）。
func newSysConfCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sysconf", Short: "系统配置（日志/报表/拦截页/WebTDS/整库备份恢复；标准版不支持）"}

	logCmd := &cobra.Command{Use: "log", Short: "系统日志配置"}
	logCmd.AddCommand(
		queryCmd("get", "查询日志配置", adapter.OpSysLogConfGet),
		writeCmd("edit", "更新日志配置（log_conf_local_debug/log_conf_remote/log_ip/log_port/log_response/log_all）", adapter.OpSysLogConfEdit),
	)

	report := &cobra.Command{Use: "report", Short: "报表（ClickHouse）连接配置"}
	report.AddCommand(
		queryCmd("get", "查询报表连接配置", adapter.OpSysReportConfGet),
		writeCmd("edit", "更新报表连接配置（report_conf 及 report_conf_ch_* 六项）", adapter.OpSysReportConfEdit),
		writeCmd("test", "测试报表连接连通性（report_conf_ch_* 六项）", adapter.OpSysReportConfTest),
	)

	page := &cobra.Command{Use: "page", Short: "自定义拦截/404 页面"}
	page.AddCommand(
		queryCmd("get", "查询自定义页面配置", adapter.OpSysCustomPageGet),
		writeCmd("edit", "更新自定义页面（custom_deny_page/waf_deny_code/waf_deny_html/custom_not_find_page/not_find_code/not_find_html）", adapter.OpSysCustomPageEdit),
	)

	webtds := &cobra.Command{Use: "webtds", Short: "WebTDS 检查配置"}
	webtds.AddCommand(
		queryCmd("get", "查询 WebTDS 检查配置", adapter.OpSysWebtdsGet),
		writeCmd("edit", "更新 WebTDS 检查配置（webtds_check/webtds_node_ip/webtds_node_port）", adapter.OpSysWebtdsEdit),
	)

	cmd.AddCommand(
		logCmd, report, page, webtds,
		queryCmd("backup", "整库配置备份（导出全部配置表 JSON）", adapter.OpWafConfBackup),
		writeCmd("load", "整库配置恢复（高危：先清空后覆盖导入 backup 产物）", adapter.OpWafConfLoad),
	)
	return cmd
}
