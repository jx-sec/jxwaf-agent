package cli

import (
	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// newNetworkCmd SOC 网络封禁 IP（应急封禁/解封）。
func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "network", Short: "SOC 网络封禁 IP（应急封禁与解封）"}
	cmd.AddCommand(
		queryCmd("list", "查询封禁 IP 列表（page）", adapter.OpNetworkIpList),
		queryCmd("search", "搜索封禁 IP（page/search_ip）", adapter.OpNetworkIpSearch),
		queryCmd("get", "查询单个封禁 IP 详情（ip）", adapter.OpNetworkIpGet),
		writeCmd("create", "新增封禁 IP（ip/status:1封禁 2解封/expire_time 秒）", adapter.OpNetworkIpCreate),
		writeCmd("edit", "更新封禁 IP（ip/expire_time/status）", adapter.OpNetworkIpEdit),
		queryCmd("status", "查询网络封禁总开关", adapter.OpNetworkIpStatusGet),
		writeCmd("status-set", "设置网络封禁总开关（network_ip_status: block/closed）", adapter.OpNetworkIpStatusEdit),
		queryCmd("node-update", "查询各节点封禁同步状态", adapter.OpNetworkIpNodeUpdate),
	)
	return cmd
}

// newMonitorCmd 节点监控。
func newMonitorCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "monitor", Short: "WAF 节点监控（600s 心跳超时判离线）"}
	cmd.AddCommand(
		queryCmd("list", "查询节点监控列表", adapter.OpNodeMonitorList),
		writeCmd("delete", "删除节点监控记录（node_uuid）", adapter.OpNodeMonitorDelete),
	)
	return cmd
}
