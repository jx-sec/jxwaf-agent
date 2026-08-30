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
}

func TestNewInvalid(t *testing.T) {
	if _, err := New(config.Environment{Version: "foo", WafAuth: "t"}); err == nil {
		t.Error("非法版本应报错")
	}
	if _, err := New(config.Environment{Version: config.VersionStandard}); err == nil {
		t.Error("缺少 waf_auth 应报错")
	}
}
