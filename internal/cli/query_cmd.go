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
		writeCmd("status", "启停规则", adapter.OpWebRuleStatus),
		writeCmd("priority", "调整优先级（rule_name/type:top|exchange，exchange 另需 exchange_rule_name）", adapter.OpWebRulePriority),
		queryCmd("backup", "导出规则配置（参数 rule_name_list）", adapter.OpWebRuleBackup),
		writeCmd("load", "导入规则配置（参数 rules，配对 backup 输出）", adapter.OpWebRuleLoad),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load，可选 api_key）", adapter.OpWebRuleHubLoad),
		writeCmd("hub-export", "导出到 Hub 配置中心（参数 web_rule_protection 规则名数组）", adapter.OpWebRuleHubExport))
	webEngine := &cobra.Command{Use: "engine", Short: "Web 引擎防护配置"}
	webEngine.AddCommand(
		queryCmd("get", "查询 Web 引擎防护配置", adapter.OpWebEngineGet),
		writeCmd("edit", "更新 Web 引擎防护配置", adapter.OpWebEngineEdit))
	web.AddCommand(webEngine)
	flow := &cobra.Command{Use: "flow", Short: "流量防护规则"}
	flow.AddCommand(queryCmd("list", "查询规则列表", adapter.OpFlowRuleList),
		queryCmd("get", "查询单条规则", adapter.OpFlowRuleGet),
		writeCmd("create", "创建规则", adapter.OpFlowRuleCreate),
		writeCmd("edit", "更新规则", adapter.OpFlowRuleEdit),
		writeCmd("delete", "删除规则", adapter.OpFlowRuleDelete),
		writeCmd("status", "启停规则", adapter.OpFlowRuleStatus),
		writeCmd("priority", "调整优先级（rule_name/type:top|exchange）", adapter.OpFlowRulePriority),
		queryCmd("backup", "导出规则配置（参数 rule_name_list）", adapter.OpFlowRuleBackup),
		writeCmd("load", "导入规则配置（参数 rules，配对 backup 输出）", adapter.OpFlowRuleLoad),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load）", adapter.OpFlowRuleHubLoad),
		writeCmd("hub-export", "导出到 Hub 配置中心（参数 flow_rule_protection 规则名数组）", adapter.OpFlowRuleHubExport))
	flowEngine := &cobra.Command{Use: "engine", Short: "流量引擎防护配置"}
	flowEngine.AddCommand(
		queryCmd("get", "查询流量引擎防护配置", adapter.OpFlowEngineGet),
		writeCmd("edit", "更新流量引擎防护配置", adapter.OpFlowEngineEdit))
	flow.AddCommand(flowEngine)
	flowRegion := &cobra.Command{Use: "region", Short: "流量区域封禁配置"}
	flowRegion.AddCommand(
		queryCmd("get", "查询流量区域封禁配置", adapter.OpFlowIPRegionGet),
		writeCmd("edit", "更新流量区域封禁配置", adapter.OpFlowIPRegionEdit))
	flow.AddCommand(flowRegion)
	cmd.AddCommand(web, flow)
	return cmd
}

func newWhiteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "white", Short: "白名单规则（web/flow）"}
	web := &cobra.Command{Use: "web", Short: "Web 白名单规则"}
	web.AddCommand(queryCmd("list", "查询白名单列表", adapter.OpWebWhiteList),
		queryCmd("get", "查询单条白名单", adapter.OpWebWhiteGet),
		writeCmd("create", "创建白名单", adapter.OpWebWhiteCreate),
		writeCmd("edit", "更新白名单", adapter.OpWebWhiteEdit),
		writeCmd("delete", "删除白名单", adapter.OpWebWhiteDelete),
		writeCmd("status", "启停白名单", adapter.OpWebWhiteStatus),
		writeCmd("priority", "调整优先级（rule_name/type:top|exchange）", adapter.OpWebWhitePriority),
		queryCmd("backup", "导出白名单配置（参数 rule_name_list）", adapter.OpWebWhiteBackup),
		writeCmd("load", "导入白名单配置（参数 rules，配对 backup 输出）", adapter.OpWebWhiteLoad),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load）", adapter.OpWebWhiteHubLoad),
		writeCmd("hub-export", "导出到 Hub 配置中心（参数 web_white_rule 规则名数组）", adapter.OpWebWhiteHubExport))
	flow := &cobra.Command{Use: "flow", Short: "流量白名单规则"}
	flow.AddCommand(queryCmd("list", "查询白名单列表", adapter.OpFlowWhiteList),
		queryCmd("get", "查询单条白名单", adapter.OpFlowWhiteGet),
		writeCmd("create", "创建白名单", adapter.OpFlowWhiteCreate),
		writeCmd("edit", "更新白名单", adapter.OpFlowWhiteEdit),
		writeCmd("delete", "删除白名单", adapter.OpFlowWhiteDelete),
		writeCmd("status", "启停白名单", adapter.OpFlowWhiteStatus),
		writeCmd("priority", "调整优先级（rule_name/type:top|exchange）", adapter.OpFlowWhitePriority),
		queryCmd("backup", "导出白名单配置（参数 rule_name_list）", adapter.OpFlowWhiteBackup),
		writeCmd("load", "导入白名单配置（参数 rules，配对 backup 输出）", adapter.OpFlowWhiteLoad),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load）", adapter.OpFlowWhiteHubLoad),
		writeCmd("hub-export", "导出到 Hub 配置中心（参数 flow_white_rule 规则名数组）", adapter.OpFlowWhiteHubExport))
	cmd.AddCommand(web, flow)
	return cmd
}

func newTamperCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "tamper", Short: "网页防篡改规则"}
	cmd.AddCommand(
		queryCmd("list", "查询防篡改规则列表", adapter.OpTamperList),
		queryCmd("get", "查询单条防篡改规则", adapter.OpTamperGet),
		writeCmd("create", "创建防篡改规则", adapter.OpTamperCreate),
		writeCmd("edit", "更新防篡改规则", adapter.OpTamperEdit),
		writeCmd("delete", "删除防篡改规则", adapter.OpTamperDelete),
		writeCmd("status", "启停防篡改规则", adapter.OpTamperStatus),
		writeCmd("priority", "调整优先级（rule_name/type:top|exchange）", adapter.OpTamperPriority),
		queryCmd("backup", "导出防篡改配置（参数 rule_name_list）", adapter.OpTamperBackup),
		writeCmd("load", "导入防篡改配置（参数 rules，配对 backup 输出）", adapter.OpTamperLoad),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load）", adapter.OpTamperHubLoad),
		writeCmd("hub-export", "导出到 Hub 配置中心（参数 web_page_tamper_proof 规则名数组）", adapter.OpTamperHubExport),
	)
	return cmd
}

func newSslCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ssl", Short: "SSL 证书管理"}
	cmd.AddCommand(
		queryCmd("list", "查询证书列表", adapter.OpSslList),
		queryCmd("search", "搜索证书（page/search）", adapter.OpSslSearch),
		queryCmd("get", "查询单个证书", adapter.OpSslGet),
		writeCmd("create", "上传证书（ssl_domain/detail/private_key/public_key）", adapter.OpSslCreate),
		writeCmd("edit", "更新证书", adapter.OpSslEdit),
		writeCmd("delete", "删除证书", adapter.OpSslDelete),
		writeCmd("wildcard", "申请泛域名证书（ssl_domain/dns_type/dns_api_key/dns_api_secret/auto_update；ACME 异步签发）", adapter.OpSslWildcard),
		writeCmd("retry", "重试泛域名证书签发（ssl_domain）", adapter.OpSslRetry),
		writeCmd("cert-config", "更新泛域名证书 DNS 配置（ssl_domain/dns_type/dns_api_key/dns_api_secret/auto_update/detail）", adapter.OpSslCertConfig),
	)
	global := &cobra.Command{Use: "global", Short: "全局 SSL 协议防护（仅云WAF）"}
	global.AddCommand(
		queryCmd("get", "查询全局 SSL 协议防护配置", adapter.OpGlobalSslGet),
		writeCmd("edit", "更新配置（ssl_attack_protect/stat_time/stat_count/block_time）", adapter.OpGlobalSslEdit),
		writeCmd("status", "切换总开关（ssl_attack_protect:true|false）", adapter.OpGlobalSslStatus))
	cmd.AddCommand(global)
	return cmd
}

func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "域名组管理（仅专业版）"}
	cmd.AddCommand(
		queryCmd("list", "查询域名组列表", adapter.OpDomainGroupList),
		queryCmd("search", "搜索域名组（page/search）", adapter.OpDomainGroupSearch),
		queryCmd("get", "查询单个域名组", adapter.OpDomainGroupGet),
		writeCmd("create", "创建域名组（group_name/group_detail）", adapter.OpDomainGroupCreate),
		writeCmd("edit", "更新域名组描述", adapter.OpDomainGroupEdit),
		writeCmd("delete", "删除域名组（级联删除组下域名与防护配置）", adapter.OpDomainGroupDelete),
	)
	return cmd
}

func newNameListCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "namelist", Short: "名单防护"}
	cmd.AddCommand(
		queryCmd("list", "查询名单列表", adapter.OpNameListList),
		queryCmd("get", "查询单个名单", adapter.OpNameListGet),
		queryCmd("item-list", "查询名单条目", adapter.OpNameListItemList),
		queryCmd("item-search", "搜索名单条目（page/name_list_name/search_value）", adapter.OpNameListItemSearch),
		queryCmd("backup", "导出名单配置（参数 name_list_name_list）", adapter.OpNameListBackup),
		writeCmd("create", "创建名单", adapter.OpNameListCreate),
		writeCmd("edit", "更新名单", adapter.OpNameListEdit),
		writeCmd("delete", "删除名单（级联删除条目）", adapter.OpNameListDelete),
		writeCmd("status", "启停名单", adapter.OpNameListStatus),
		writeCmd("priority", "调整优先级（name_list_name/type:top|exchange）", adapter.OpNameListPriority),
		writeCmd("load", "导入名单配置（参数 rules，配对 backup 输出）", adapter.OpNameListLoad),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load）", adapter.OpNameListHubLoad),
		writeCmd("hub-export", "导出到 Hub 配置中心（参数 global_name_list 名单名数组）", adapter.OpNameListHubExport),
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
		queryCmd("backup", "导出组件配置（参数 name_list）", adapter.OpComponentBackup),
		writeCmd("create", "创建组件", adapter.OpComponentCreate),
		writeCmd("edit", "更新组件", adapter.OpComponentEdit),
		writeCmd("delete", "删除组件", adapter.OpComponentDelete),
		writeCmd("status", "启停组件", adapter.OpComponentStatus),
		writeCmd("priority", "调整优先级（name/type:top|exchange）", adapter.OpComponentPriority),
		writeCmd("load", "导入组件配置（参数 rules，配对 backup 输出）", adapter.OpComponentLoad),
		writeCmd("hub-load", "从 Hub 配置中心加载（hub_repo/force_load）", adapter.OpComponentHubLoad),
		writeCmd("hub-export", "导出到 Hub 配置中心（参数 component 组件名数组）", adapter.OpComponentHubExport),
	)
	return cmd
}

func newWebsiteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "website", Short: "网站/域名接入"}
	cmd.AddCommand(
		queryCmd("list", "查询域名列表", adapter.OpDomainList),
		queryCmd("search", "搜索域名（page/search_domain）", adapter.OpDomainSearch),
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
		writeCmd("connect-test", "测试 DNS 凭据连通性（创建/删除测试解析记录验证）", adapter.OpWebsiteAccConnectTest),
		queryCmd("cname-ips", "查询域名 CNAME 解析 IP 列表（sub_user_name/domain/website_access_conf_name）", adapter.OpWebsiteAccCnameIps),
		writeCmd("cname-edit", "修改域名 CNAME 解析 IP（切换节点；sub_user_name/domain/website_access_conf_name/ip_list）", adapter.OpWebsiteAccCnameEdit),
		writeCmd("sync", "同步更新网站接入配置（website_access_conf_name）", adapter.OpWebsiteAccSync),
		queryCmd("quota", "查询资源配额模板", adapter.OpResourceQuotaTemplate),
	)
	cmd.AddCommand(access)
	return cmd
}
