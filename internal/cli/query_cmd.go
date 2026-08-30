package cli

import (
	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// queryCmd 构造一个查询子命令：解析 --params → 调用逻辑操作 → 输出服务器响应。
func queryCmd(name string, short string, op adapter.Op) *cobra.Command {
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
			return callOp(a, c, op, params)
		}),
	}
	addParamsFlag(cmd)
	return cmd
}

func newRuleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "防护规则（web/flow）"}
	web := &cobra.Command{Use: "web", Short: "Web 防护规则"}
	web.AddCommand(queryCmd("list", "查询规则列表", adapter.OpWebRuleList),
		queryCmd("get", "查询单条规则", adapter.OpWebRuleGet),
		writeCmd("create", "创建规则", adapter.OpWebRuleCreate),
		writeCmd("edit", "更新规则", adapter.OpWebRuleEdit),
		writeCmd("delete", "删除规则", adapter.OpWebRuleDelete),
		writeCmd("status", "启停规则", adapter.OpWebRuleStatus))
	flow := &cobra.Command{Use: "flow", Short: "流量防护规则"}
	flow.AddCommand(queryCmd("list", "查询规则列表", adapter.OpFlowRuleList),
		queryCmd("get", "查询单条规则", adapter.OpFlowRuleGet),
		writeCmd("create", "创建规则", adapter.OpFlowRuleCreate),
		writeCmd("edit", "更新规则", adapter.OpFlowRuleEdit),
		writeCmd("delete", "删除规则", adapter.OpFlowRuleDelete),
		writeCmd("status", "启停规则", adapter.OpFlowRuleStatus))
	cmd.AddCommand(web, flow)
	return cmd
}

func newNameListCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "namelist", Short: "名单防护"}
	cmd.AddCommand(
		queryCmd("list", "查询名单列表", adapter.OpNameListList),
		queryCmd("get", "查询单个名单", adapter.OpNameListGet),
		queryCmd("item-list", "查询名单条目", adapter.OpNameListItemList),
		writeCmd("create", "创建名单", adapter.OpNameListCreate),
		writeCmd("edit", "更新名单", adapter.OpNameListEdit),
		writeCmd("delete", "删除名单（级联删除条目）", adapter.OpNameListDelete),
		writeCmd("status", "启停名单", adapter.OpNameListStatus),
		writeCmd("item-add", "添加名单条目", adapter.OpNameListItemAdd),
		writeCmd("item-del", "删除名单条目", adapter.OpNameListItemDel),
	)
	return cmd
}

func newComponentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "component", Short: "防护组件"}
	cmd.AddCommand(
		queryCmd("list", "查询组件列表", adapter.OpComponentList),
		queryCmd("get", "查询单个组件", adapter.OpComponentGet),
		writeCmd("create", "创建组件", adapter.OpComponentCreate),
		writeCmd("edit", "更新组件", adapter.OpComponentEdit),
		writeCmd("delete", "删除组件", adapter.OpComponentDelete),
		writeCmd("status", "启停组件", adapter.OpComponentStatus),
	)
	return cmd
}

func newWebsiteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "website", Short: "网站/域名接入"}
	cmd.AddCommand(
		queryCmd("list", "查询域名列表", adapter.OpDomainList),
		queryCmd("get", "查询单个域名", adapter.OpDomainGet),
		writeCmd("create", "创建域名", adapter.OpDomainCreate),
		writeCmd("edit", "更新域名", adapter.OpDomainEdit),
		writeCmd("delete", "删除域名", adapter.OpDomainDelete),
	)
	access := &cobra.Command{Use: "access", Short: "网站接入配置（仅云WAF）"}
	access.AddCommand(
		queryCmd("list", "查询网站接入配置列表", adapter.OpWebsiteAccList),
		queryCmd("get", "查询单个网站接入配置", adapter.OpWebsiteAccGet),
		writeCmd("create", "创建网站接入配置", adapter.OpWebsiteAccCreate),
		writeCmd("edit", "更新网站接入配置", adapter.OpWebsiteAccEdit),
		writeCmd("delete", "删除网站接入配置", adapter.OpWebsiteAccDelete),
	)
	cmd.AddCommand(access)
	return cmd
}

func newSocCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "soc", Short: "SOC 安全运营查询"}
	log := &cobra.Command{Use: "log", Short: "攻击日志查询"}
	log.AddCommand(queryCmd("query", "查询攻击日志", adapter.OpSocLogQuery))
	cmd.AddCommand(log)
	return cmd
}
