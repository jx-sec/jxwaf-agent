package adapter

import (
	"testing"

	"github.com/jx-sec/jxwaf-agent/internal/config"
)

func TestPathStandard(t *testing.T) {
	a, err := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[Op]string{
		OpWebRuleList:     "/admin_api/get_web_rule_protection_list",
		OpWebRuleCreate:   "/admin_api/create_web_rule_protection",
		OpFlowIPRegionGet: "/admin_api/get_flow_ip_region_block",
		OpDomainList:      "/admin_api/get_domain_list",
		OpNameListCreate:  "/admin_api/create_global_name_list",
		OpComponentLoad:   "/admin_api/load_component",
		OpSocLogQuery:     "/admin_api/get_soc_log_query_list",
	}
	for op, want := range cases {
		got, err := a.Path(op)
		if err != nil || got != want {
			t.Errorf("standard %s = %q, %v; want %q", op, got, err, want)
		}
	}
	if a.NeedsGroup() {
		t.Error("standard 不应要求 group_name")
	}
	// 云WAF专属操作在标准版不可用
	if _, err := a.Path(OpWebsiteAccCreate); err == nil {
		t.Error("standard 应拒绝 website_access 操作")
	}
}

func TestPathProfessional(t *testing.T) {
	a, err := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[Op]string{
		OpWebRuleList:    "/admin_api/get_group_web_rule_protection_list",
		OpFlowRuleDelete: "/admin_api/delete_group_flow_rule_protection",
		OpDomainList:     "/admin_api/get_domain_list", // 域名本身不带 group 前缀
		OpComponentList:  "/admin_api/get_component_list",
		OpSocLogQuery:    "/admin_api/get_soc_log_query_list",
	}
	for op, want := range cases {
		got, err := a.Path(op)
		if err != nil || got != want {
			t.Errorf("professional %s = %q, %v; want %q", op, got, err, want)
		}
	}
	if !a.NeedsGroup() || a.GroupName() != "g1" {
		t.Error("professional 应要求 group_name 且返回默认组")
	}
}

func TestPathCloudAdmin(t *testing.T) {
	a, err := New(config.Environment{Version: config.VersionCloud, WafAuth: "master", SubUserName: "default"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[Op]string{
		OpWebRuleList:     "/admin_api/get_sub_account_web_rule_protection_list",
		OpWebWhiteCreate:  "/admin_api/create_sub_account_web_white_rule",
		OpWebsiteAccEdit:  "/admin_api/edit_website_access_conf",
		OpNameListItemAdd: "/admin_api/create_global_name_list_item",
		OpComponentList:   "/admin_api/get_component_list",
	}
	for op, want := range cases {
		got, err := a.Path(op)
		if err != nil || got != want {
			t.Errorf("cloud admin %s = %q, %v; want %q", op, got, err, want)
		}
	}
	h := a.HeaderMap()
	if h["jxwaf-waf-auth"] != "master" {
		t.Errorf("cloud admin 主认证头错误: %v", h)
	}
	if _, ok := h["jxwaf-sub-waf-auth"]; ok {
		t.Error("cloud admin 不应带子账号认证头")
	}
	// 环境配置了默认子账号名时，未指定 --sub-user 应自动注入
	body := map[string]any{}
	if err := a.InjectTenant(OpWebRuleList, body, TenantOpts{}); err != nil {
		t.Fatalf("默认子账号名注入失败: %v", err)
	}
	if body["sub_user_name"] != "default" {
		t.Errorf("应自动注入 sub_user_name=default: %v", body)
	}
	// --sub-user 显式指定时优先
	body2 := map[string]any{}
	if err := a.InjectTenant(OpWebRuleList, body2, TenantOpts{SubUser: "other"}); err != nil {
		t.Fatal(err)
	}
	if body2["sub_user_name"] != "other" {
		t.Errorf("显式 --sub-user 应优先: %v", body2)
	}
}

func TestPathCloudUser(t *testing.T) {
	a, err := New(config.Environment{Version: config.VersionCloud, WafAuth: "master", SubWafAuth: "sub"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[Op]string{
		OpWebRuleList:     "/user/get_web_rule_protection_list",
		OpDomainCreate:    "/user/create_domain",
		OpSocLogQuery:     "/user/get_log_query_list",            // 用户端日志查询路径不同
		OpNameListList:    "/user/api_get_global_name_list_list", // 用户端名单列表带 api_ 前缀
		OpNameListItemAdd: "/user/create_global_name_list_item",
	}
	for op, want := range cases {
		got, err := a.Path(op)
		if err != nil || got != want {
			t.Errorf("cloud user %s = %q, %v; want %q", op, got, err, want)
		}
	}
	h := a.HeaderMap()
	if h["jxwaf-waf-auth"] != "master" || h["jxwaf-sub-waf-auth"] != "sub" {
		t.Errorf("cloud user 双层认证头错误: %v", h)
	}
	// 子账号不管理组件与网站接入
	if _, err := a.Path(OpComponentList); err == nil {
		t.Error("cloud user 应拒绝 component 操作")
	}
	if _, err := a.Path(OpWebsiteAccCreate); err == nil {
		t.Error("cloud user 应拒绝 website_access 操作")
	}
	// /user 段无 load_* 与域名组端点
	for _, op := range []Op{OpWebRuleLoad, OpWebWhiteLoad, OpFlowRuleLoad, OpFlowWhiteLoad, OpDomainGroupList} {
		if _, err := a.Path(op); err == nil {
			t.Errorf("cloud user 应拒绝 %s（/user 段无该路由）", op)
		}
	}
}

func TestDomainTenantInjection(t *testing.T) {
	// 专业版：域名操作路径无 group_ 中缀，但 body 必须带 group_name
	p, err := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"domain": "a.com"}
	if err := p.InjectTenant(OpDomainCreate, body, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if body["group_name"] != "g1" {
		t.Errorf("专业版域名操作应注入 group_name: %v", body)
	}
	// 云 admin：域名操作 body 必须带 sub_user_name
	c, err := New(config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	body2 := map[string]any{"domain": "a.com"}
	if err := c.InjectTenant(OpDomainCreate, body2, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if body2["sub_user_name"] != "u1" {
		t.Errorf("云 admin 域名操作应注入 sub_user_name: %v", body2)
	}
	// 标准版与云用户态：域名操作不注入租户参数
	s, err := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if err != nil {
		t.Fatal(err)
	}
	body3 := map[string]any{"domain": "a.com"}
	if err := s.InjectTenant(OpDomainCreate, body3, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if len(body3) != 1 {
		t.Errorf("标准版域名操作不应注入租户参数: %v", body3)
	}
}

func TestTamperPaths(t *testing.T) {
	// 防篡改为标准防护类：三版本 + 用户模式全支持，路径按租户中缀规律映射
	cases := []struct {
		env  config.Environment
		op   Op
		want string
	}{
		{config.Environment{Version: config.VersionStandard, WafAuth: "t"}, OpTamperList, "/admin_api/get_web_page_tamper_proof_list"},
		{config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"}, OpTamperCreate, "/admin_api/create_group_web_page_tamper_proof"},
		{config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"}, OpTamperStatus, "/admin_api/edit_sub_account_web_page_tamper_proof_status"},
		{config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"}, OpTamperList, "/user/get_web_page_tamper_proof_list"},
	}
	for _, tc := range cases {
		a, err := New(tc.env)
		if err != nil {
			t.Fatal(err)
		}
		got, err := a.Path(tc.op)
		if err != nil || got != tc.want {
			t.Errorf("tamper %s/%s = %q, %v; want %q", tc.env.Version, tc.op, got, err, tc.want)
		}
	}
}

func TestSslCloudSubMode(t *testing.T) {
	// SSL 证书为云子账号类：standard/professional 为全局模块（无中缀无租户），仅云WAF(admin) 归属子账号
	std, _ := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if got, _ := std.Path(OpSslList); got != "/admin_api/get_ssl_manage_list" {
		t.Errorf("standard ssl = %q", got)
	}
	body := map[string]any{}
	if err := std.InjectTenant(OpSslCreate, body, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Errorf("standard ssl 不应注入租户参数: %v", body)
	}

	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if got, _ := prof.Path(OpSslList); got != "/admin_api/get_ssl_manage_list" {
		t.Errorf("professional ssl = %q（全局模块无 group_ 中缀）", got)
	}
	bodyP := map[string]any{}
	if err := prof.InjectTenant(OpSslCreate, bodyP, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if len(bodyP) != 0 {
		t.Errorf("professional ssl 不应注入 group_name: %v", bodyP)
	}

	cloud, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"})
	if got, _ := cloud.Path(OpSslList); got != "/admin_api/get_sub_account_ssl_manage_list" {
		t.Errorf("cloud admin ssl = %q", got)
	}
	bodyC := map[string]any{}
	if err := cloud.InjectTenant(OpSslCreate, bodyC, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if bodyC["sub_user_name"] != "u1" {
		t.Errorf("cloud admin ssl 应注入 sub_user_name: %v", bodyC)
	}

	user, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"})
	if got, _ := user.Path(OpSslList); got != "/user/get_ssl_manage_list" {
		t.Errorf("cloud user ssl = %q", got)
	}
	bodyU := map[string]any{}
	if err := user.InjectTenant(OpSslCreate, bodyU, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if len(bodyU) != 0 {
		t.Errorf("cloud user ssl 不应注入租户参数: %v", bodyU)
	}
}

func TestDomainGroupVersionCut(t *testing.T) {
	// 域名组仅专业版支持
	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t"})
	if got, _ := prof.Path(OpDomainGroupCreate); got != "/admin_api/create_domain_group" {
		t.Errorf("professional domain group = %q", got)
	}
	for _, env := range []config.Environment{
		{Version: config.VersionStandard, WafAuth: "t"},
		{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"},
		{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"},
	} {
		a, err := New(env)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []Op{OpDomainGroupList, OpDomainGroupGet, OpDomainGroupCreate, OpDomainGroupDelete, OpDomainGroupEdit} {
			if _, err := a.Path(op); err == nil {
				t.Errorf("%s 应拒绝域名组操作 %s（仅专业版支持）", env.Version, op)
			}
		}
	}
}

func TestBackupLoadPaths(t *testing.T) {
	// backup/load 三版本支持（防护类中缀规律），用户模式无对应路由
	std, _ := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if got, _ := std.Path(OpWebRuleBackup); got != "/admin_api/backup_web_rule_protection" {
		t.Errorf("standard backup = %q", got)
	}
	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if got, _ := prof.Path(OpWebRuleBackup); got != "/admin_api/backup_group_web_rule_protection" {
		t.Errorf("professional backup = %q", got)
	}
	cloud, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"})
	if got, _ := cloud.Path(OpWebRuleBackup); got != "/admin_api/backup_sub_account_web_rule_protection" {
		t.Errorf("cloud admin backup = %q", got)
	}
	if got, _ := cloud.Path(OpNameListBackup); got != "/admin_api/backup_global_name_list" {
		t.Errorf("cloud admin namelist backup = %q（全局模块无中缀）", got)
	}
	user, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"})
	for _, op := range []Op{OpWebRuleBackup, OpWebWhiteBackup, OpFlowRuleBackup, OpFlowWhiteBackup,
		OpTamperBackup, OpTamperLoad, OpNameListBackup, OpComponentBackup} {
		if _, err := user.Path(op); err == nil {
			t.Errorf("cloud user 应拒绝 %s（/user 段无 backup/load 路由）", op)
		}
	}
}

func TestEngineRegionPaths(t *testing.T) {
	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if got, _ := prof.Path(OpWebEngineGet); got != "/admin_api/get_group_web_engine_protection" {
		t.Errorf("professional web engine = %q", got)
	}
	if got, _ := prof.Path(OpFlowIPRegionEdit); got != "/admin_api/edit_group_flow_ip_region_block" {
		t.Errorf("professional region = %q", got)
	}
	cloud, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"})
	if got, _ := cloud.Path(OpFlowIPRegionGet); got != "/admin_api/get_sub_account_flow_ip_region_block" {
		t.Errorf("cloud admin region = %q", got)
	}
	user, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"})
	if got, _ := user.Path(OpWebEngineGet); got != "/user/get_web_engine_protection" {
		t.Errorf("cloud user web engine = %q", got)
	}
}

func TestSocStatsPaths(t *testing.T) {
	// SOC 统计：prof/cloud 用 get_soc_*，standard 用 overrides 映射到 get_web_attack_*（ranking），
	// cloudUser 用 overrides 映射到无 soc_ 前缀路径；flow 统计 standard 不支持
	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if got, _ := prof.Path(OpSocWebAttackCountTotal); got != "/admin_api/get_soc_web_attack_count_total" {
		t.Errorf("prof web stats = %q", got)
	}
	if got, _ := prof.Path(OpSocFlowAttackApiTop); got != "/admin_api/get_soc_flow_attack_api_top" {
		t.Errorf("prof flow stats = %q", got)
	}

	std, _ := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	cases := map[Op]string{
		OpSocWebAttackCountTotal:        "/admin_api/get_web_attack_count_total",
		OpSocWebAttackApiCountTotal:     "/admin_api/get_web_attack_api_count",
		OpSocWebAttackIsocodeCountTotal: "/admin_api/get_web_attack_country_count",
		OpSocWebAttackTypeTop:           "/admin_api/get_web_attack_type_ranking",
	}
	for op, want := range cases {
		if got, _ := std.Path(op); got != want {
			t.Errorf("standard %s = %q; want %q", op, got, want)
		}
	}
	if _, err := std.Path(OpSocWebAttackGeoip); err == nil {
		t.Error("standard 应拒绝 geoip（接口集差异）")
	}
	if _, err := std.Path(OpSocFlowAttackCountTotal); err == nil {
		t.Error("standard 应拒绝流量攻击统计")
	}

	user, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"})
	if got, _ := user.Path(OpSocWebAttackCountTotal); got != "/user/get_web_attack_count_total" {
		t.Errorf("user web stats = %q", got)
	}
	if got, _ := user.Path(OpSocFlowAttackCountTotal); got != "/user/get_flow_attack_count_total" {
		t.Errorf("user flow stats = %q", got)
	}
	if got, _ := user.Path(OpSocEventList); got != "/user/get_attack_event_list" {
		t.Errorf("user event = %q", got)
	}
	if got, _ := user.Path(OpSysReportConfGet); got != "/user/get_sys_report_conf_conf" {
		t.Errorf("user report conf = %q", got)
	}
}

func TestCustomCachePaths(t *testing.T) {
	// 自定义配置/缓存策略为防护类：prof 加 group_、cloud admin 加 sub_account_、user 无中缀、std 不支持
	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if got, _ := prof.Path(OpCustomReqHeaderCreate); got != "/admin_api/create_group_custom_request_header" {
		t.Errorf("prof custom = %q", got)
	}
	if got, _ := prof.Path(OpCustomUpstreamList); got != "/admin_api/get_group_custom_upstream_address_list" {
		t.Errorf("prof upstream = %q", got)
	}
	if _, err := prof.Path(OpCachePolicyList); err == nil {
		t.Error("professional 应拒绝缓存策略（仅云WAF）")
	}

	cloud, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"})
	if got, _ := cloud.Path(OpCachePolicyCreate); got != "/admin_api/create_sub_account_cache_policy" {
		t.Errorf("cloud cache = %q", got)
	}
	if got, _ := cloud.Path(OpCustomRespContentDelete); got != "/admin_api/delete_sub_account_custom_response_content" {
		t.Errorf("cloud custom content = %q", got)
	}
	if got, _ := cloud.Path(OpCacheWarmupCreate); got != "/admin_api/create_cache_warmup_task" {
		t.Errorf("cloud cache task = %q", got)
	}
	if _, err := cloud.Path(OpCdnPreheat); err == nil {
		t.Error("cloud admin 应拒绝 CDN 预热（仅子账号模式）")
	}

	user, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"})
	if got, _ := user.Path(OpCustomReqHeaderCreate); got != "/user/create_custom_request_header" {
		t.Errorf("user custom = %q", got)
	}
	if got, _ := user.Path(OpCachePolicyList); got != "/user/get_cache_policy_list" {
		t.Errorf("user cache = %q", got)
	}
	if got, _ := user.Path(OpCdnPreheat); got != "/user/create_cdn_cache_preheat" {
		t.Errorf("user cdn = %q", got)
	}
	for _, op := range []Op{OpCustomReqHeaderBackup, OpCustomReqHeaderLoad, OpCachePolicyHubLoad} {
		if _, err := user.Path(op); err == nil {
			t.Errorf("user 应拒绝 %s（/user 段无 backup/load/hub 路由）", op)
		}
	}

	std, _ := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if _, err := std.Path(OpCustomReqHeaderCreate); err == nil {
		t.Error("standard 应拒绝自定义配置")
	}
}

func TestModuleVersionCut(t *testing.T) {
	// 网络封禁/事件/模型/用量/监控：三版本支持、user 不支持
	std, _ := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if got, _ := std.Path(OpNetworkIpCreate); got != "/admin_api/create_soc_network_ip" {
		t.Errorf("std network = %q", got)
	}
	if got, _ := std.Path(OpSocEventList); got != "/admin_api/get_soc_attack_event_list" {
		t.Errorf("std event = %q", got)
	}
	if got, _ := std.Path(OpUsageStatQpsTrend); got != "/admin_api/get_soc_usage_stat_qps_trend" {
		t.Errorf("std usage = %q", got)
	}
	if got, _ := std.Path(OpNodeMonitorList); got != "/admin_api/get_node_monitor_list" {
		t.Errorf("std monitor = %q", got)
	}

	// 系统配置：prof/cloud 支持，std 不支持
	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if got, _ := prof.Path(OpSysLogConfEdit); got != "/admin_api/edit_sys_log_conf" {
		t.Errorf("prof sysconf = %q", got)
	}
	if got, _ := prof.Path(OpWafConfBackup); got != "/admin_api/waf_conf_backup" {
		t.Errorf("prof backup = %q", got)
	}
	if _, err := prof.Path(OpSubAccountCreate); err == nil {
		t.Error("professional 应拒绝子账号管理")
	}
	if _, err := prof.Path(OpGlobalSslGet); err == nil {
		t.Error("professional 应拒绝全局 SSL 防护")
	}
	stdConf, _ := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if _, err := stdConf.Path(OpSysLogConfEdit); err == nil {
		t.Error("standard 应拒绝系统配置")
	}

	cloud, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"})
	if got, _ := cloud.Path(OpSubAccountCreate); got != "/admin_api/create_sub_account" {
		t.Errorf("cloud subaccount = %q", got)
	}
	if got, _ := cloud.Path(OpGlobalSslEdit); got != "/admin_api/edit_global_ssl_protection" {
		t.Errorf("cloud global ssl = %q", got)
	}

	user, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"})
	if _, err := user.Path(OpNetworkIpList); err == nil {
		t.Error("user 应拒绝网络封禁")
	}
	if _, err := user.Path(OpSubAccountCreate); err == nil {
		t.Error("user 应拒绝子账号管理")
	}
	if _, err := user.Path(OpSysLogConfEdit); err == nil {
		t.Error("user 应拒绝系统配置编辑（仅报表配置只读）")
	}
	// 用量统计 user 支持（同名路径）
	if got, _ := user.Path(OpUsageStatOverview); got != "/user/get_soc_usage_stat_overview" {
		t.Errorf("user usage = %q", got)
	}
}

func TestWebsiteAccExtraPaths(t *testing.T) {
	cloud, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "t", SubUserName: "u1"})
	if got, _ := cloud.Path(OpWebsiteAccConnectTest); got != "/admin_api/website_access_conf_connect_test" {
		t.Errorf("cloud connect-test = %q", got)
	}
	if got, _ := cloud.Path(OpWebsiteAccCnameEdit); got != "/admin_api/domain_cname_edit" {
		t.Errorf("cloud cname edit = %q", got)
	}
	// cname 类为域名租户形态：cloud admin 注入 sub_user_name
	body := map[string]any{"domain": "a.com"}
	if err := cloud.InjectTenant(OpWebsiteAccCnameEdit, body, TenantOpts{}); err != nil {
		t.Fatal(err)
	}
	if body["sub_user_name"] != "u1" {
		t.Errorf("cname edit 应注入 sub_user_name: %v", body)
	}
	if got, _ := cloud.Path(OpResourceQuotaTemplate); got != "/admin_api/get_resource_quota_template" {
		t.Errorf("cloud quota = %q", got)
	}

	std, _ := New(config.Environment{Version: config.VersionStandard, WafAuth: "t"})
	if _, err := std.Path(OpWebsiteAccConnectTest); err == nil {
		t.Error("standard 应拒绝网站接入扩展")
	}
}

func TestPriorityHubSearchPaths(t *testing.T) {
	prof, _ := New(config.Environment{Version: config.VersionProfessional, WafAuth: "t", GroupName: "g1"})
	if got, _ := prof.Path(OpWebRulePriority); got != "/admin_api/exchange_group_web_rule_protection_priority" {
		t.Errorf("prof priority = %q", got)
	}
	if got, _ := prof.Path(OpWebRuleHubLoad); got != "/admin_api/load_group_web_rule_protection_hub_config" {
		t.Errorf("prof hub load = %q", got)
	}
	if got, _ := prof.Path(OpNameListPriority); got != "/admin_api/exchange_global_name_list_priority" {
		t.Errorf("prof namelist priority = %q", got)
	}
	if got, _ := prof.Path(OpDomainSearch); got != "/admin_api/get_domain_search_list" {
		t.Errorf("prof domain search = %q", got)
	}
	if got, _ := prof.Path(OpDomainGroupSearch); got != "/admin_api/get_domain_group_search_list" {
		t.Errorf("prof group search = %q", got)
	}

	user, _ := New(config.Environment{Version: config.VersionCloud, WafAuth: "m", SubWafAuth: "s"})
	if got, _ := user.Path(OpWebRulePriority); got != "/user/exchange_web_rule_protection_priority" {
		t.Errorf("user priority = %q", got)
	}
	if got, _ := user.Path(OpSslRetry); got != "/user/retry_ssl_cert" {
		t.Errorf("user ssl retry = %q", got)
	}
	for _, op := range []Op{OpWebRuleHubLoad, OpNameListPriority, OpComponentPriority, OpNameListItemSearch} {
		if _, err := user.Path(op); err == nil {
			t.Errorf("user 应拒绝 %s", op)
		}
	}
}

func TestNewInvalid(t *testing.T) {
	if _, err := New(config.Environment{Version: "foo", WafAuth: "t"}); err == nil {
		t.Error("非法版本应报错")
	}
	if _, err := New(config.Environment{Version: config.VersionStandard}); err == nil {
		t.Error("缺少 waf_auth 应报错")
	}
}
