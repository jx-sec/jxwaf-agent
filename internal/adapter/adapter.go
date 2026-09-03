// Package adapter 屏蔽 JXWAF 三个版本管理 API 的差异：认证头、端点命名与租户修饰。
//
// 三个版本的管理 API 路由核心路径一致，
// 差异呈现为规律的命名修饰：
//
//	standard      /admin_api/<suffix>
//	professional  /admin_api/group_<suffix>   （仅防护类端点；域名类路径无中缀但 body 必带 group_name）
//	cloud(admin)  /admin_api/sub_account_<suffix>（仅防护类端点；域名类 body 必带 sub_user_name；
//	                                              SSL 证书等专业版为全局模块、云WAF归属子账号）
//	cloud(user)   /user/<suffix>              （子账号双 token）
//
// Op 常量与端点规格表见 ops.go；各 profile 的能力裁剪（unsupported）与
// 命名差异覆盖（overrides）见本文件。
package adapter

import (
	"fmt"
	"strings"

	"github.com/jx-sec/jxwaf-agent/internal/config"
)

// profile 描述一个版本模式的端点与认证行为。
type profile struct {
	prefix      string          // 路径前缀：/admin_api 或 /user
	tenantInfix string          // 防护类端点动词后的修饰中缀："" / group_ / sub_account_
	authHeader  string          // 主认证头名
	subAuthHead string          // 子账号认证头名（云WAF用户模式）
	overrides   map[Op]string   // 端点覆盖（命名差异：standard/user 模式的特殊路径）
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

// websiteAccExtraOps 仅云WAF(admin)支持的网站接入扩展操作（连通性测试/CNAME 管理/配额模板）。
func websiteAccExtraOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpWebsiteAccConnectTest: {}, OpWebsiteAccCnameIps: {}, OpWebsiteAccCnameEdit: {},
		OpWebsiteAccSync: {}, OpResourceQuotaTemplate: {},
	}
}

// domainGroupOps 域名组管理操作（仅专业版支持：域名组为专业版多租户特性）。
func domainGroupOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpDomainGroupList: {}, OpDomainGroupGet: {}, OpDomainGroupCreate: {},
		OpDomainGroupDelete: {}, OpDomainGroupEdit: {}, OpDomainGroupSearch: {},
	}
}

// backupLoadOps 规则/白名单/防篡改的备份与加载操作（/user 段无对应路由，用户模式不支持）。
func backupLoadOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpWebRuleBackup: {}, OpWebWhiteBackup: {}, OpFlowRuleBackup: {}, OpFlowWhiteBackup: {},
		OpTamperBackup: {},
		OpWebRuleLoad: {}, OpWebWhiteLoad: {}, OpFlowRuleLoad: {}, OpFlowWhiteLoad: {},
		OpTamperLoad: {},
	}
}

// customOps 自定义配置全部操作（standard 无该模块）。
func customOps() map[Op]struct{} {
	out := make(map[Op]struct{}, 44)
	for _, base := range []struct{ list, get, create, delete, edit, status, priority, backup, load, hubLoad, hubExport Op }{
		{OpCustomReqHeaderList, OpCustomReqHeaderGet, OpCustomReqHeaderCreate, OpCustomReqHeaderDelete,
			OpCustomReqHeaderEdit, OpCustomReqHeaderStatus, OpCustomReqHeaderPriority, OpCustomReqHeaderBackup,
			OpCustomReqHeaderLoad, OpCustomReqHeaderHubLoad, OpCustomReqHeaderHubExport},
		{OpCustomRespHeaderList, OpCustomRespHeaderGet, OpCustomRespHeaderCreate, OpCustomRespHeaderDelete,
			OpCustomRespHeaderEdit, OpCustomRespHeaderStatus, OpCustomRespHeaderPriority, OpCustomRespHeaderBackup,
			OpCustomRespHeaderLoad, OpCustomRespHeaderHubLoad, OpCustomRespHeaderHubExport},
		{OpCustomRespContentList, OpCustomRespContentGet, OpCustomRespContentCreate, OpCustomRespContentDelete,
			OpCustomRespContentEdit, OpCustomRespContentStatus, OpCustomRespContentPriority, OpCustomRespContentBackup,
			OpCustomRespContentLoad, OpCustomRespContentHubLoad, OpCustomRespContentHubExport},
		{OpCustomUpstreamList, OpCustomUpstreamGet, OpCustomUpstreamCreate, OpCustomUpstreamDelete,
			OpCustomUpstreamEdit, OpCustomUpstreamStatus, OpCustomUpstreamPriority, OpCustomUpstreamBackup,
			OpCustomUpstreamLoad, OpCustomUpstreamHubLoad, OpCustomUpstreamHubExport},
	} {
		for _, op := range []Op{base.list, base.get, base.create, base.delete, base.edit,
			base.status, base.priority, base.backup, base.load, base.hubLoad, base.hubExport} {
			out[op] = struct{}{}
		}
	}
	return out
}

// backupLoadHubOps 自定义配置/缓存策略的备份/加载/Hub 操作（/user 段无，用户模式不支持）。
func backupLoadHubOps() map[Op]struct{} {
	out := make(map[Op]struct{}, 28)
	for _, g := range [][]Op{
		{OpCustomReqHeaderBackup, OpCustomReqHeaderLoad, OpCustomReqHeaderHubLoad, OpCustomReqHeaderHubExport},
		{OpCustomRespHeaderBackup, OpCustomRespHeaderLoad, OpCustomRespHeaderHubLoad, OpCustomRespHeaderHubExport},
		{OpCustomRespContentBackup, OpCustomRespContentLoad, OpCustomRespContentHubLoad, OpCustomRespContentHubExport},
		{OpCustomUpstreamBackup, OpCustomUpstreamLoad, OpCustomUpstreamHubLoad, OpCustomUpstreamHubExport},
		{OpCachePolicyBackup, OpCachePolicyLoad, OpCachePolicyHubLoad, OpCachePolicyHubExport},
		{OpNoCachePolicyBackup, OpNoCachePolicyLoad, OpNoCachePolicyHubLoad, OpNoCachePolicyHubExport},
		{OpCacheBypassBackup, OpCacheBypassLoad, OpCacheBypassHubLoad, OpCacheBypassHubExport},
	} {
		for _, op := range g {
			out[op] = struct{}{}
		}
	}
	return out
}

// cachePolicyOps 缓存策略全部操作（standard/professional 无该模块，仅云WAF）。
func cachePolicyOps() map[Op]struct{} {
	out := make(map[Op]struct{}, 33)
	for _, g := range [][]Op{
		{OpCachePolicyList, OpCachePolicyGet, OpCachePolicyCreate, OpCachePolicyDelete, OpCachePolicyEdit,
			OpCachePolicyStatus, OpCachePolicyPriority, OpCachePolicyBackup, OpCachePolicyLoad,
			OpCachePolicyHubLoad, OpCachePolicyHubExport},
		{OpNoCachePolicyList, OpNoCachePolicyGet, OpNoCachePolicyCreate, OpNoCachePolicyDelete, OpNoCachePolicyEdit,
			OpNoCachePolicyStatus, OpNoCachePolicyPriority, OpNoCachePolicyBackup, OpNoCachePolicyLoad,
			OpNoCachePolicyHubLoad, OpNoCachePolicyHubExport},
		{OpCacheBypassList, OpCacheBypassGet, OpCacheBypassCreate, OpCacheBypassDelete, OpCacheBypassEdit,
			OpCacheBypassStatus, OpCacheBypassPriority, OpCacheBypassBackup, OpCacheBypassLoad,
			OpCacheBypassHubLoad, OpCacheBypassHubExport},
	} {
		for _, op := range g {
			out[op] = struct{}{}
		}
	}
	return out
}

// cacheCloudOps 云WAF专属缓存能力（缓存任务仅云WAF）。
func cacheCloudOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpCacheWarmupCreate: {}, OpCacheWarmupList: {}, OpCacheWarmupDetail: {}, OpCacheWarmupDelete: {},
		OpCacheRefreshCreate: {}, OpCacheRefreshList: {}, OpCacheRefreshDetail: {}, OpCacheRefreshDelete: {},
	}
}

// userOnlyCacheOps 仅 /user 段存在的缓存操作（缓存开关与 CDN 预热/刷新）。
func userOnlyCacheOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpCacheSwitchGet: {}, OpCacheSwitchEdit: {}, OpCdnPreheat: {}, OpCdnRefresh: {},
	}
}

// subAccountOps 子账号管理操作（仅云WAF admin 模式）。
func subAccountOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpSubAccountList: {}, OpSubAccountSearch: {}, OpSubAccountGet: {}, OpSubAccountCreate: {},
		OpSubAccountDelete: {}, OpSubAccountEdit: {}, OpSubAccountWafAuth: {}, OpSubAccountOtpReset: {},
	}
}

// sysConfOps 系统配置操作（standard 无该模块；/user 段仅报表配置只读）。
func sysConfOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpSysLogConfGet: {}, OpSysLogConfEdit: {},
		OpSysReportConfGet: {}, OpSysReportConfEdit: {}, OpSysReportConfTest: {},
		OpSysCustomPageGet: {}, OpSysCustomPageEdit: {},
		OpSysWebtdsGet: {}, OpSysWebtdsEdit: {},
		OpWafConfBackup: {}, OpWafConfLoad: {},
	}
}

// socModelOps SOC AI 模型操作（/user 段无）。
func socModelOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpSocModelList: {}, OpSocModelDelete: {}, OpSocModelResultEdit: {},
		OpSocModelWhiteList: {}, OpSocModelWhiteCreate: {}, OpSocModelWhiteDelete: {},
	}
}

// networkIpOps SOC 网络封禁 IP 操作（/user 段无）。
func networkIpOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpNetworkIpList: {}, OpNetworkIpSearch: {}, OpNetworkIpGet: {}, OpNetworkIpCreate: {},
		OpNetworkIpEdit: {}, OpNetworkIpStatusGet: {}, OpNetworkIpStatusEdit: {}, OpNetworkIpNodeUpdate: {},
	}
}

// flowStatsOps SOC 流量攻击统计（standard 无该模块）。
func flowStatsOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpSocFlowAttackCountTotal: {}, OpSocFlowAttackApiCountTotal: {}, OpSocFlowAttackIpCountTotal: {},
		OpSocFlowAttackIsocodeCountTotal: {}, OpSocFlowAttackGeoip: {}, OpSocFlowAttackCountTrend: {},
		OpSocFlowAttackApiTop: {}, OpSocFlowAttackTypeTop: {}, OpSocFlowAttackIpTop: {}, OpSocFlowAttackIsocodeTop: {},
	}
}

// globalSslOps 全局 SSL 协议防护（仅云WAF admin）。
func globalSslOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpGlobalSslGet: {}, OpGlobalSslEdit: {}, OpGlobalSslStatus: {},
	}
}

// monitorOps 节点监控操作（/user 段无）。
func monitorOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpNodeMonitorList: {}, OpNodeMonitorDelete: {},
	}
}

// hubOps 规则/白名单/防篡改/名单/组件的 Hub 配置中心操作（/user 段无）。
func hubOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpWebRuleHubLoad: {}, OpWebRuleHubExport: {},
		OpWebWhiteHubLoad: {}, OpWebWhiteHubExport: {},
		OpFlowRuleHubLoad: {}, OpFlowRuleHubExport: {},
		OpFlowWhiteHubLoad: {}, OpFlowWhiteHubExport: {},
		OpTamperHubLoad: {}, OpTamperHubExport: {},
		OpNameListHubLoad: {}, OpNameListHubExport: {},
		OpComponentHubLoad: {}, OpComponentHubExport: {},
	}
}

// userUnavailableOps 用户模式额外不支持的操作集合：
// /user 段无优先级交换（名单/组件）、无网络封禁、无 AI 模型、无节点监控、
// 无子账号管理、无系统配置写、无域名组、无网站接入、无 Hub。
func userUnavailableOps() map[Op]struct{} {
	return unionOps(
		map[Op]struct{}{
			OpNameListPriority: {}, OpComponentPriority: {},
		},
		networkIpOps(), socModelOps(), monitorOps(), subAccountOps(),
		// 系统配置仅保留报表配置只读（overrides 映射到 /user/get_sys_report_conf_conf）
		minusOps(sysConfOps(), map[Op]struct{}{OpSysReportConfGet: {}}),
	)
}

// socWebAttackStandardOverrides Standard 版 SOC Web 攻击统计的命名映射
// （standard 命名为 get_web_attack_* 且用 ranking 而非 top、count 而非 count_total）。
var socWebAttackStandardOverrides = map[Op]string{
	OpSocWebAttackCountTotal:        "/admin_api/get_web_attack_count_total",
	OpSocWebAttackApiCountTotal:     "/admin_api/get_web_attack_api_count",
	OpSocWebAttackIpCountTotal:      "/admin_api/get_web_attack_ip_count",
	OpSocWebAttackIsocodeCountTotal: "/admin_api/get_web_attack_country_count",
	OpSocWebAttackCountTrend:        "/admin_api/get_web_attack_trend",
	OpSocWebAttackApiTop:            "/admin_api/get_web_attack_api_ranking",
	OpSocWebAttackTypeTop:           "/admin_api/get_web_attack_type_ranking",
	OpSocWebAttackIpTop:             "/admin_api/get_web_attack_ip_ranking",
	OpSocWebAttackIsocodeTop:        "/admin_api/get_web_attack_country_ranking",
}

// socStatsUserOverrides 云WAF用户模式 SOC 统计命名映射（/user 段无 soc_ 前缀）。
var socStatsUserOverrides = map[Op]string{
	OpSocWebAttackCountTotal:        "/user/get_web_attack_count_total",
	OpSocWebAttackApiCountTotal:     "/user/get_web_attack_api_count_total",
	OpSocWebAttackIpCountTotal:      "/user/get_web_attack_ip_count_total",
	OpSocWebAttackIsocodeCountTotal: "/user/get_web_attack_isocode_count_total",
	OpSocWebAttackGeoip:             "/user/get_web_attack_geoip",
	OpSocWebAttackCountTrend:        "/user/get_web_attack_count_trend",
	OpSocWebAttackApiTop:            "/user/get_web_attack_api_top",
	OpSocWebAttackTypeTop:           "/user/get_web_attack_type_top",
	OpSocWebAttackIpTop:             "/user/get_web_attack_ip_top",
	OpSocWebAttackIsocodeTop:        "/user/get_web_attack_isocode_top",
	OpSocFlowAttackCountTotal:        "/user/get_flow_attack_count_total",
	OpSocFlowAttackApiCountTotal:     "/user/get_flow_attack_api_count_total",
	OpSocFlowAttackIpCountTotal:      "/user/get_flow_attack_ip_count_total",
	OpSocFlowAttackIsocodeCountTotal: "/user/get_flow_attack_isocode_count_total",
	OpSocFlowAttackGeoip:             "/user/get_flow_attack_geoip",
	OpSocFlowAttackCountTrend:        "/user/get_flow_attack_count_trend",
	OpSocFlowAttackApiTop:            "/user/get_flow_attack_api_top",
	OpSocFlowAttackTypeTop:           "/user/get_flow_attack_type_top",
	OpSocFlowAttackIpTop:             "/user/get_flow_attack_ip_top",
	OpSocFlowAttackIsocodeTop:        "/user/get_flow_attack_isocode_top",
	OpSocEventList:                   "/user/get_attack_event_list",
	OpSocBehaveTrack:                 "/user/get_attack_behave_track",
	OpSysReportConfGet:               "/user/get_sys_report_conf_conf",
}

var (
	profileStandard = profile{
		prefix:      "/admin_api",
		tenantInfix: "",
		// 认证头为中划线：服务端 ngx.var.http_jxwaf_waf_auth 由 nginx 将中划线转下划线映射而来；
		// 若发送下划线头会被 nginx 默认行为丢弃（underscores_in_headers off）
		authHeader: "jxwaf-waf-auth",
		overrides:  socWebAttackStandardOverrides,
		unsupported: unionOps(websiteAccOps(), websiteAccExtraOps(), domainGroupOps(),
			customOps(), cachePolicyOps(), cacheCloudOps(), userOnlyCacheOps(),
			subAccountOps(), sysConfOps(), flowStatsOps(), globalSslOps(),
			map[Op]struct{}{
				// standard 无 geoip 统计（接口集差异）
				OpSocWebAttackGeoip: {},
			}),
	}
	profileProfessional = profile{
		prefix:      "/admin_api",
		tenantInfix: "group_",
		authHeader:  "jxwaf-waf-auth",
		needsGroup:  true,
		unsupported: unionOps(websiteAccOps(), websiteAccExtraOps(), cachePolicyOps(),
			cacheCloudOps(), userOnlyCacheOps(), subAccountOps(), globalSslOps()),
	}
	profileCloudAdmin = profile{
		prefix:      "/admin_api",
		tenantInfix: "sub_account_",
		authHeader:  "jxwaf-waf-auth",
		unsupported: unionOps(domainGroupOps(), userOnlyCacheOps()),
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
		unsupported: unionOps(websiteAccOps(), websiteAccExtraOps(), domainGroupOps(),
			backupLoadOps(), backupLoadHubOps(), hubOps(),
			nameListManageOps(), componentOps(),
			userUnavailableOps()),
	}
)

// 合并 socStatsUserOverrides 到 cloudUser overrides（单独合并避免字面量过长）。
func init() {
	for op, p := range socStatsUserOverrides {
		profileCloudUser.overrides[op] = p
	}
}

// nameListManageOps 用户模式不支持的名单管理操作（仅保留列表查询与条目新增）。
func nameListManageOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpNameListGet: {}, OpNameListCreate: {}, OpNameListDelete: {},
		OpNameListEdit: {}, OpNameListStatus: {}, OpNameListLoad: {}, OpNameListBackup: {},
		OpNameListItemList: {}, OpNameListItemDel: {}, OpNameListItemSearch: {},
	}
}

// componentOps 全部组件管理操作（用户模式不支持）。
func componentOps() map[Op]struct{} {
	return map[Op]struct{}{
		OpComponentList: {}, OpComponentGet: {}, OpComponentCreate: {},
		OpComponentDelete: {}, OpComponentEdit: {}, OpComponentStatus: {}, OpComponentLoad: {},
		OpComponentBackup: {},
	}
}

// unionOps 合并多个操作集合。
func unionOps(sets ...map[Op]struct{}) map[Op]struct{} {
	out := map[Op]struct{}{}
	for _, s := range sets {
		for op := range s {
			out[op] = struct{}{}
		}
	}
	return out
}

// minusOps 从集合中排除指定操作。
func minusOps(set map[Op]struct{}, exclude map[Op]struct{}) map[Op]struct{} {
	out := make(map[Op]struct{}, len(set))
	for op := range set {
		if _, ok := exclude[op]; !ok {
			out[op] = struct{}{}
		}
	}
	return out
}

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
		// 显式模式优先（cloud_mode）；未配置时按是否配置 sub_waf_auth 隐式推断（兼容旧配置）。
		// 注意：显式 admin 模式可携带 sub_waf_auth 但不使用它，避免"配置了子账号凭据就无法用主账号管理"。
		switch env.CloudMode {
		case config.ModeUser:
			if env.SubWafAuth == "" {
				return nil, fmt.Errorf("cloud_mode=user 缺少 sub_waf_auth 凭据（config set 时提供 --sub-waf-auth）")
			}
			p = profileCloudUser
		case config.ModeAdmin:
			p = profileCloudAdmin
		default:
			if env.SubWafAuth != "" {
				p = profileCloudUser
			} else {
				p = profileCloudAdmin
			}
		}
	}
	return &Adapter{profile: p, env: env}, nil
}

// Path 将逻辑操作映射为当前环境的真实请求路径。
// 能力校验（unsupported）先于端点覆盖（overrides），防止覆盖表意外绕过能力限制。
func (a *Adapter) Path(op Op) (string, error) {
	if _, ok := opSpecs[op]; !ok {
		return "", fmt.Errorf("未知操作: %s", op)
	}
	if _, no := a.profile.unsupported[op]; no {
		return "", fmt.Errorf("当前环境（%s）不支持该操作", a.env.Version)
	}
	if p, ok := a.profile.overrides[op]; ok {
		return p, nil
	}
	spec := opSpecs[op]
	if infix := a.infixOf(spec.mode); infix != "" {
		// 修饰中缀插在动词后：get_web_rule_protection_list → get_group_web_rule_protection_list
		verb, rest, ok := strings.Cut(spec.suffix, "_")
		if !ok {
			return "", fmt.Errorf("端点规格非法: %s", spec.suffix)
		}
		return a.profile.prefix + "/" + verb + "_" + infix + rest, nil
	}
	return a.profile.prefix + "/" + spec.suffix, nil
}

// infixOf 计算指定租户形态在当前 profile 下应插入的路径中缀。
func (a *Adapter) infixOf(mode tenantMode) string {
	switch mode {
	case modeProtection:
		return a.profile.tenantInfix
	case modeCloudSub:
		// 云子账号类仅云WAF主账号模式加中缀；standard/professional 为全局模块
		if a.profile.tenantInfix == "sub_account_" {
			return a.profile.tenantInfix
		}
		return ""
	default:
		return ""
	}
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

// EnvName 返回当前环境名（供 dry-run 预览标注目标环境）。
func (a *Adapter) EnvName() string { return a.env.Name }

// GroupName 返回该环境的默认域名组（专业版）。
func (a *Adapter) GroupName() string { return a.env.GroupName }

// TenantOpts 供命令层指定租户参数。
type TenantOpts struct {
	Group   string // 专业版域名组
	SubUser string // 云WAF(admin)子账号名
}

// InjectTenant 为需要租户参数的操作注入 body 字段：
// 专业版注入 group_name，云WAF(admin) 注入 sub_user_name；域名类与防护类必带，
// 云子账号类（SSL）仅云WAF(admin) 必带；其余为空操作。
func (a *Adapter) InjectTenant(op Op, body map[string]any, opts TenantOpts) error {
	spec, ok := opSpecs[op]
	if !ok {
		return fmt.Errorf("未知操作: %s", op)
	}
	if !a.needsTenant(spec.mode) {
		return nil
	}
	switch a.profile.tenantInfix {
	case "group_":
		g := opts.Group
		if g == "" {
			g = a.env.GroupName
		}
		if g == "" {
			return fmt.Errorf("专业版该操作需要 group_name（防护类与域名类）：请用 --group 指定，或 config set 时提供 --group-name")
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

// needsTenant 判断指定租户形态在当前 profile 下 body 是否必带租户参数。
func (a *Adapter) needsTenant(mode tenantMode) bool {
	switch mode {
	case modeBody, modeProtection:
		return a.profile.tenantInfix != ""
	case modeCloudSub:
		return a.profile.tenantInfix == "sub_account_"
	default:
		return false
	}
}
