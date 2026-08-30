// Package adapter 屏蔽 JXWAF 三个版本管理 API 的差异：认证头、端点命名与租户修饰。
//
// 三个版本的路由表（jxwaf_admin_server 各版 access.lua）核心路径一致，
// 差异呈现为规律的命名修饰：
//
//	standard      /admin_api/<suffix>
//	professional  /admin_api/group_<suffix>   （仅防护类端点，需 body 带 group_name）
//	cloud(admin)  /admin_api/sub_account_<suffix>（仅防护类端点）
//	cloud(user)   /user/<suffix>              （子账号双 token）
package adapter

import (
	"fmt"
	"strings"

	"github.com/jx-sec/jxwaf-agent/internal/config"
)

// Op 逻辑操作名：命令层使用的、与版本无关的统一操作集合。
type Op string

const (
	OpWebEngineGet     Op = "web_engine_get"
	OpWebEngineEdit    Op = "web_engine_edit"
	OpWebRuleList      Op = "web_rule_list"
	OpWebRuleGet       Op = "web_rule_get"
	OpWebRuleCreate    Op = "web_rule_create"
	OpWebRuleDelete    Op = "web_rule_delete"
	OpWebRuleEdit      Op = "web_rule_edit"
	OpWebRuleStatus    Op = "web_rule_edit_status"
	OpWebRuleLoad      Op = "web_rule_load"
	OpWebWhiteList     Op = "web_white_list"
	OpWebWhiteGet      Op = "web_white_get"
	OpWebWhiteCreate   Op = "web_white_create"
	OpWebWhiteDelete   Op = "web_white_delete"
	OpWebWhiteEdit     Op = "web_white_edit"
	OpWebWhiteStatus   Op = "web_white_edit_status"
	OpWebWhiteLoad     Op = "web_white_load"
	OpFlowEngineGet    Op = "flow_engine_get"
	OpFlowEngineEdit   Op = "flow_engine_edit"
	OpFlowRuleList     Op = "flow_rule_list"
	OpFlowRuleGet      Op = "flow_rule_get"
	OpFlowRuleCreate   Op = "flow_rule_create"
	OpFlowRuleDelete   Op = "flow_rule_delete"
	OpFlowRuleEdit     Op = "flow_rule_edit"
	OpFlowRuleStatus   Op = "flow_rule_edit_status"
	OpFlowRuleLoad     Op = "flow_rule_load"
	OpFlowWhiteList    Op = "flow_white_list"
	OpFlowWhiteGet     Op = "flow_white_get"
	OpFlowWhiteCreate  Op = "flow_white_create"
	OpFlowWhiteDelete  Op = "flow_white_delete"
	OpFlowWhiteEdit    Op = "flow_white_edit"
	OpFlowWhiteStatus  Op = "flow_white_edit_status"
	OpFlowWhiteLoad    Op = "flow_white_load"
	OpFlowIPRegionGet  Op = "flow_ip_region_get"
	OpFlowIPRegionEdit Op = "flow_ip_region_edit"
	OpDomainList       Op = "domain_list"
	OpDomainGet        Op = "domain_get"
	OpDomainCreate     Op = "domain_create"
	OpDomainDelete     Op = "domain_delete"
	OpDomainEdit       Op = "domain_edit"
	OpNameListList     Op = "name_list_list"
	OpNameListGet      Op = "name_list_get"
	OpNameListCreate   Op = "name_list_create"
	OpNameListDelete   Op = "name_list_delete"
	OpNameListEdit     Op = "name_list_edit"
	OpNameListStatus   Op = "name_list_edit_status"
	OpNameListLoad     Op = "name_list_load"
	OpNameListItemList Op = "name_list_item_list"
	OpNameListItemAdd  Op = "name_list_item_add"
	OpNameListItemDel  Op = "name_list_item_delete"
	OpComponentList    Op = "component_list"
	OpComponentGet     Op = "component_get"
	OpComponentCreate  Op = "component_create"
	OpComponentDelete  Op = "component_delete"
	OpComponentEdit    Op = "component_edit"
	OpComponentStatus  Op = "component_edit_status"
	OpComponentLoad    Op = "component_load"
	OpSocLogQuery      Op = "soc_log_query"
	OpWebsiteAccList   Op = "website_access_list"
	OpWebsiteAccGet    Op = "website_access_get"
	OpWebsiteAccCreate Op = "website_access_create"
	OpWebsiteAccDelete Op = "website_access_delete"
	OpWebsiteAccEdit   Op = "website_access_edit"
)

// opSpec 描述一个逻辑操作在各版本中的端点构成。
type opSpec struct {
	suffix  string // 核心路径（不含 /admin_api/、/user/ 前缀与租户中缀）
	grouped bool   // 防护类端点：professional 加 group_，cloud(admin) 加 sub_account_
}

// opSpecs 为统一的端点规格表；suffix 与三版路由表逐条一致。
var opSpecs = map[Op]opSpec{
	OpWebEngineGet:     {"get_web_engine_protection", true},
	OpWebEngineEdit:    {"edit_web_engine_protection", true},
	OpWebRuleList:      {"get_web_rule_protection_list", true},
	OpWebRuleGet:       {"get_web_rule_protection", true},
	OpWebRuleCreate:    {"create_web_rule_protection", true},
	OpWebRuleDelete:    {"delete_web_rule_protection", true},
	OpWebRuleEdit:      {"edit_web_rule_protection", true},
	OpWebRuleStatus:    {"edit_web_rule_protection_status", true},
	OpWebRuleLoad:      {"load_web_rule_protection", true},
	OpWebWhiteList:     {"get_web_white_rule_list", true},
	OpWebWhiteGet:      {"get_web_white_rule", true},
	OpWebWhiteCreate:   {"create_web_white_rule", true},
	OpWebWhiteDelete:   {"delete_web_white_rule", true},
	OpWebWhiteEdit:     {"edit_web_white_rule", true},
	OpWebWhiteStatus:   {"edit_web_white_rule_status", true},
	OpWebWhiteLoad:     {"load_web_white_rule", true},
	OpFlowEngineGet:    {"get_flow_engine_protection", true},
	OpFlowEngineEdit:   {"edit_flow_engine_protection", true},
	OpFlowRuleList:     {"get_flow_rule_protection_list", true},
	OpFlowRuleGet:      {"get_flow_rule_protection", true},
	OpFlowRuleCreate:   {"create_flow_rule_protection", true},
	OpFlowRuleDelete:   {"delete_flow_rule_protection", true},
	OpFlowRuleEdit:     {"edit_flow_rule_protection", true},
	OpFlowRuleStatus:   {"edit_flow_rule_protection_status", true},
	OpFlowRuleLoad:     {"load_flow_rule_protection", true},
	OpFlowWhiteList:    {"get_flow_white_rule_list", true},
	OpFlowWhiteGet:     {"get_flow_white_rule", true},
	OpFlowWhiteCreate:  {"create_flow_white_rule", true},
	OpFlowWhiteDelete:  {"delete_flow_white_rule", true},
	OpFlowWhiteEdit:    {"edit_flow_white_rule", true},
	OpFlowWhiteStatus:  {"edit_flow_white_rule_status", true},
	OpFlowWhiteLoad:    {"load_flow_white_rule", true},
	OpFlowIPRegionGet:  {"get_flow_ip_region_block", true},
	OpFlowIPRegionEdit: {"edit_flow_ip_region_block", true},
	OpDomainList:       {"get_domain_list", false},
	OpDomainGet:        {"get_domain", false},
	OpDomainCreate:     {"create_domain", false},
	OpDomainDelete:     {"delete_domain", false},
	OpDomainEdit:       {"edit_domain", false},
	OpNameListList:     {"get_global_name_list_list", false},
	OpNameListGet:      {"get_global_name_list", false},
	OpNameListCreate:   {"create_global_name_list", false},
	OpNameListDelete:   {"delete_global_name_list", false},
	OpNameListEdit:     {"edit_global_name_list", false},
	OpNameListStatus:   {"edit_global_name_list_status", false},
	OpNameListLoad:     {"load_global_name_list", false},
	OpNameListItemList: {"get_name_list_item_list_list", false},
	OpNameListItemAdd:  {"create_global_name_list_item", false},
	OpNameListItemDel:  {"delete_global_name_list_item", false},
	OpComponentList:    {"get_component_list", false},
	OpComponentGet:     {"get_component", false},
	OpComponentCreate:  {"create_component", false},
	OpComponentDelete:  {"delete_component", false},
	OpComponentEdit:    {"edit_component", false},
	OpComponentStatus:  {"edit_component_status", false},
	OpComponentLoad:    {"load_component", false},
	OpSocLogQuery:      {"get_soc_log_query_list", false},
	OpWebsiteAccList:   {"get_website_access_conf_list", false},
	OpWebsiteAccGet:    {"get_website_access_conf", false},
	OpWebsiteAccCreate: {"create_website_access_conf", false},
	OpWebsiteAccDelete: {"delete_website_access_conf", false},
	OpWebsiteAccEdit:   {"edit_website_access_conf", false},
}

// profile 描述一个版本模式的端点与认证行为。
type profile struct {
	prefix      string          // 路径前缀：/admin_api 或 /user
	tenantInfix string          // 防护类端点动词后的修饰中缀："" / group_ / sub_account_
	authHeader  string          // 主认证头名
	subAuthHead string          // 子账号认证头名（云WAF用户模式）
	overrides   map[Op]string   // 端点覆盖（云WAF用户模式的特殊路径）
	unsupported map[Op]struct{} // 该模式不支持的操作
	needsGroup  bool            // 防护类请求 body 是否必须带 group_name
}

// websiteAccOps 仅云WAF(admin)支持的网站接入操作。
func websiteAccOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpWebsiteAccList: {}, OpWebsiteAccGet: {}, OpWebsiteAccCreate: {},
		OpWebsiteAccDelete: {}, OpWebsiteAccEdit: {},
	}
}

var (
	profileStandard = profile{
		prefix:      "/admin_api",
		tenantInfix: "",
		authHeader:  "jxwaf_waf_auth",
		unsupported: websiteAccOps(),
	}
	profileProfessional = profile{
		prefix:      "/admin_api",
		tenantInfix: "group_",
		authHeader:  "jxwaf_waf_auth",
		needsGroup:  true,
		unsupported: websiteAccOps(),
	}
	profileCloudAdmin = profile{
		prefix:      "/admin_api",
		tenantInfix: "sub_account_",
		authHeader:  "jxwaf-waf-auth",
	}
	profileCloudUser = profile{
		prefix:      "/user",
		authHeader:  "jxwaf-waf-auth",
		subAuthHead: "jxwaf-sub-waf-auth",
		overrides: map[Op]string{
			OpSocLogQuery:     "/user/get_log_query_list",
			OpNameListList:    "/user/api_get_global_name_list_list",
			OpNameListItemAdd: "/user/create_global_name_list_item",
		},
		unsupported: map[Op]struct{}{
			OpNameListGet: {}, OpNameListCreate: {}, OpNameListDelete: {},
			OpNameListEdit: {}, OpNameListStatus: {}, OpNameListLoad: {},
			OpNameListItemList: {}, OpNameListItemDel: {},
			OpComponentList: {}, OpComponentGet: {}, OpComponentCreate: {},
			OpComponentDelete: {}, OpComponentEdit: {}, OpComponentStatus: {}, OpComponentLoad: {},
			OpWebsiteAccList: {}, OpWebsiteAccGet: {}, OpWebsiteAccCreate: {},
			OpWebsiteAccDelete: {}, OpWebsiteAccEdit: {},
		},
	}
)

// Adapter 屏蔽版本差异，提供端点映射与认证头。
type Adapter struct {
	profile profile
	env     config.Environment
}

// New 根据环境配置构造适配器（含模式选择与参数校验）。
func New(env config.Environment) (*Adapter, error) {
	if !env.Version.Valid() {
		return nil, fmt.Errorf("不支持的产品版本: %q", env.Version)
	}
	if env.WafAuth == "" {
		return nil, fmt.Errorf("缺少 waf_auth 凭据")
	}
	var p profile
	switch env.Version {
	case config.VersionStandard:
		p = profileStandard
	case config.VersionProfessional:
		p = profileProfessional
	case config.VersionCloud:
		if env.SubWafAuth != "" {
			p = profileCloudUser
		} else {
			p = profileCloudAdmin
		}
	}
	return &Adapter{profile: p, env: env}, nil
}

// Path 将逻辑操作映射为当前环境的真实请求路径。
func (a *Adapter) Path(op Op) (string, error) {
	if p, ok := a.profile.overrides[op]; ok {
		return p, nil
	}
	spec, ok := opSpecs[op]
	if !ok {
		return "", fmt.Errorf("未知操作: %s", op)
	}
	if _, no := a.profile.unsupported[op]; no {
		return "", fmt.Errorf("当前环境（%s）不支持该操作", a.env.Version)
	}
	if !spec.grouped || a.profile.tenantInfix == "" {
		return a.profile.prefix + "/" + spec.suffix, nil
	}
	// 修饰中缀插在动词后：get_web_rule_protection_list → get_group_web_rule_protection_list
	verb, rest, ok := strings.Cut(spec.suffix, "_")
	if !ok {
		return "", fmt.Errorf("端点规格非法: %s", spec.suffix)
	}
	return a.profile.prefix + "/" + verb + "_" + a.profile.tenantInfix + rest, nil
}

// HeaderMap 返回当前环境的认证请求头。
func (a *Adapter) HeaderMap() map[string]string {
	h := map[string]string{a.profile.authHeader: a.env.WafAuth}
	if a.profile.subAuthHead != "" {
		h[a.profile.subAuthHead] = a.env.SubWafAuth
	}
	return h
}

// NeedsGroup 表示防护类请求 body 必须携带 group_name（专业版）。
func (a *Adapter) NeedsGroup() bool { return a.profile.needsGroup }

// GroupName 返回该环境的默认域名组（专业版）。
func (a *Adapter) GroupName() string { return a.env.GroupName }

// TenantOpts 供命令层指定租户参数。
type TenantOpts struct {
	Group   string // 专业版域名组
	SubUser string // 云WAF(admin)子账号名
}

// InjectTenant 为防护类操作注入租户 body 参数：
// 专业版注入 group_name，云WAF(admin) 注入 sub_user_name；其余操作与版本为空操作。
func (a *Adapter) InjectTenant(op Op, body map[string]any, opts TenantOpts) error {
	spec, ok := opSpecs[op]
	if !ok || !spec.grouped {
		return nil
	}
	switch a.profile.tenantInfix {
	case "group_":
		g := opts.Group
		if g == "" {
			g = a.env.GroupName
		}
		if g == "" {
			return fmt.Errorf("专业版防护操作需要 group_name：请用 --group 指定，或 config set 时提供 --group-name")
		}
		body["group_name"] = g
	case "sub_account_":
		su := opts.SubUser
		if su == "" {
			su = a.env.SubUserName
		}
		if su == "" {
			return fmt.Errorf("云WAF主账号操作需要指定子账号：请用 --sub-user 提供 sub_user_name，或 config set 时提供 --sub-user-name")
		}
		body["sub_user_name"] = su
	}
	return nil
}
