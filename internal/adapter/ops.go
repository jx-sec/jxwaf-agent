package adapter

// Op 逻辑操作名：命令层使用的、与版本无关的统一操作集合。
// opSpecs 中 suffix 与三版管理 API 路由逐条一致。

type Op string

// ---- 防护规则/白名单/防篡改/引擎/区域封禁（modeProtection：prof 加 group_、cloud admin 加 sub_account_）----

const (
	OpWebEngineGet      Op = "web_engine_get"
	OpWebEngineEdit     Op = "web_engine_edit"
	OpWebRuleBackup     Op = "web_rule_backup"
	OpWebRuleList       Op = "web_rule_list"
	OpWebRuleGet        Op = "web_rule_get"
	OpWebRuleCreate     Op = "web_rule_create"
	OpWebRuleDelete     Op = "web_rule_delete"
	OpWebRuleEdit       Op = "web_rule_edit"
	OpWebRuleStatus     Op = "web_rule_edit_status"
	OpWebRulePriority   Op = "web_rule_priority"
	OpWebRuleLoad       Op = "web_rule_load"
	OpWebRuleHubLoad    Op = "web_rule_hub_load"
	OpWebRuleHubExport  Op = "web_rule_hub_export"
	OpWebWhiteBackup    Op = "web_white_backup"
	OpWebWhiteList      Op = "web_white_list"
	OpWebWhiteGet       Op = "web_white_get"
	OpWebWhiteCreate    Op = "web_white_create"
	OpWebWhiteDelete    Op = "web_white_delete"
	OpWebWhiteEdit      Op = "web_white_edit"
	OpWebWhiteStatus    Op = "web_white_edit_status"
	OpWebWhitePriority  Op = "web_white_priority"
	OpWebWhiteLoad      Op = "web_white_load"
	OpWebWhiteHubLoad   Op = "web_white_hub_load"
	OpWebWhiteHubExport Op = "web_white_hub_export"
	OpFlowEngineGet     Op = "flow_engine_get"
	OpFlowEngineEdit    Op = "flow_engine_edit"
	OpFlowRuleBackup    Op = "flow_rule_backup"
	OpFlowRuleList      Op = "flow_rule_list"
	OpFlowRuleGet       Op = "flow_rule_get"
	OpFlowRuleCreate    Op = "flow_rule_create"
	OpFlowRuleDelete    Op = "flow_rule_delete"
	OpFlowRuleEdit      Op = "flow_rule_edit"
	OpFlowRuleStatus    Op = "flow_rule_edit_status"
	OpFlowRulePriority  Op = "flow_rule_priority"
	OpFlowRuleLoad      Op = "flow_rule_load"
	OpFlowRuleHubLoad   Op = "flow_rule_hub_load"
	OpFlowRuleHubExport Op = "flow_rule_hub_export"
	OpFlowWhiteBackup   Op = "flow_white_backup"
	OpFlowWhiteList     Op = "flow_white_list"
	OpFlowWhiteGet      Op = "flow_white_get"
	OpFlowWhiteCreate   Op = "flow_white_create"
	OpFlowWhiteDelete   Op = "flow_white_delete"
	OpFlowWhiteEdit     Op = "flow_white_edit"
	OpFlowWhiteStatus   Op = "flow_white_edit_status"
	OpFlowWhitePriority Op = "flow_white_priority"
	OpFlowWhiteLoad     Op = "flow_white_load"
	OpFlowWhiteHubLoad  Op = "flow_white_hub_load"
	OpFlowWhiteHubExport Op = "flow_white_hub_export"
	OpFlowIPRegionGet   Op = "flow_ip_region_get"
	OpFlowIPRegionEdit  Op = "flow_ip_region_edit"
	OpTamperList        Op = "web_page_tamper_list"
	OpTamperGet         Op = "web_page_tamper_get"
	OpTamperCreate      Op = "web_page_tamper_create"
	OpTamperDelete      Op = "web_page_tamper_delete"
	OpTamperEdit        Op = "web_page_tamper_edit"
	OpTamperStatus      Op = "web_page_tamper_edit_status"
	OpTamperPriority    Op = "web_page_tamper_priority"
	OpTamperBackup      Op = "web_page_tamper_backup"
	OpTamperLoad        Op = "web_page_tamper_load"
	OpTamperHubLoad     Op = "web_page_tamper_hub_load"
	OpTamperHubExport   Op = "web_page_tamper_hub_export"
)

// ---- 域名 / 域名组 ----

const (
	OpDomainList       Op = "domain_list"
	OpDomainGet        Op = "domain_get"
	OpDomainCreate     Op = "domain_create"
	OpDomainDelete     Op = "domain_delete"
	OpDomainEdit       Op = "domain_edit"
	OpDomainSearch     Op = "domain_search"
	OpDomainGroupList  Op = "domain_group_list"
	OpDomainGroupGet   Op = "domain_group_get"
	OpDomainGroupCreate Op = "domain_group_create"
	OpDomainGroupDelete Op = "domain_group_delete"
	OpDomainGroupEdit  Op = "domain_group_edit"
	OpDomainGroupSearch Op = "domain_group_search"
)

// ---- SSL 证书（modeCloudSub：std/prof 全局、cloud 归属子账号、user /user 段）----

const (
	OpSslList       Op = "ssl_list"
	OpSslGet        Op = "ssl_get"
	OpSslCreate     Op = "ssl_create"
	OpSslDelete     Op = "ssl_delete"
	OpSslEdit       Op = "ssl_edit"
	OpSslSearch     Op = "ssl_search"
	OpSslWildcard   Op = "ssl_wildcard_request"
	OpSslRetry      Op = "ssl_cert_retry"
	OpSslCertConfig Op = "ssl_cert_config_edit"
	// 全局 SSL 协议防护（仅云WAF admin）
	OpGlobalSslGet    Op = "global_ssl_get"
	OpGlobalSslEdit   Op = "global_ssl_edit"
	OpGlobalSslStatus Op = "global_ssl_status"
)

// ---- 全局名单 / 组件 ----

const (
	OpNameListBackup      Op = "name_list_backup"
	OpNameListList        Op = "name_list_list"
	OpNameListGet         Op = "name_list_get"
	OpNameListCreate      Op = "name_list_create"
	OpNameListDelete      Op = "name_list_delete"
	OpNameListEdit        Op = "name_list_edit"
	OpNameListStatus      Op = "name_list_edit_status"
	OpNameListPriority    Op = "name_list_priority"
	OpNameListLoad        Op = "name_list_load"
	OpNameListHubLoad     Op = "name_list_hub_load"
	OpNameListHubExport   Op = "name_list_hub_export"
	OpNameListItemList    Op = "name_list_item_list"
	OpNameListItemAdd     Op = "name_list_item_add"
	OpNameListItemDel     Op = "name_list_item_delete"
	OpNameListItemSearch  Op = "name_list_item_search"
	OpComponentList       Op = "component_list"
	OpComponentGet        Op = "component_get"
	OpComponentCreate     Op = "component_create"
	OpComponentDelete     Op = "component_delete"
	OpComponentEdit       Op = "component_edit"
	OpComponentStatus     Op = "component_edit_status"
	OpComponentPriority   Op = "component_priority"
	OpComponentBackup     Op = "component_backup"
	OpComponentLoad       Op = "component_load"
	OpComponentHubLoad    Op = "component_hub_load"
	OpComponentHubExport  Op = "component_hub_export"
)

// ---- 自定义配置（prof group_ / cloud sub_account_ / user 无中缀；standard 不支持）----

const (
	OpCustomReqHeaderList       Op = "custom_req_header_list"
	OpCustomReqHeaderGet        Op = "custom_req_header_get"
	OpCustomReqHeaderCreate     Op = "custom_req_header_create"
	OpCustomReqHeaderDelete     Op = "custom_req_header_delete"
	OpCustomReqHeaderEdit       Op = "custom_req_header_edit"
	OpCustomReqHeaderStatus     Op = "custom_req_header_edit_status"
	OpCustomReqHeaderPriority   Op = "custom_req_header_priority"
	OpCustomReqHeaderBackup     Op = "custom_req_header_backup"
	OpCustomReqHeaderLoad       Op = "custom_req_header_load"
	OpCustomReqHeaderHubLoad    Op = "custom_req_header_hub_load"
	OpCustomReqHeaderHubExport  Op = "custom_req_header_hub_export"
	OpCustomRespHeaderList      Op = "custom_resp_header_list"
	OpCustomRespHeaderGet       Op = "custom_resp_header_get"
	OpCustomRespHeaderCreate    Op = "custom_resp_header_create"
	OpCustomRespHeaderDelete    Op = "custom_resp_header_delete"
	OpCustomRespHeaderEdit      Op = "custom_resp_header_edit"
	OpCustomRespHeaderStatus    Op = "custom_resp_header_edit_status"
	OpCustomRespHeaderPriority  Op = "custom_resp_header_priority"
	OpCustomRespHeaderBackup    Op = "custom_resp_header_backup"
	OpCustomRespHeaderLoad      Op = "custom_resp_header_load"
	OpCustomRespHeaderHubLoad   Op = "custom_resp_header_hub_load"
	OpCustomRespHeaderHubExport Op = "custom_resp_header_hub_export"
	OpCustomRespContentList     Op = "custom_resp_content_list"
	OpCustomRespContentGet      Op = "custom_resp_content_get"
	OpCustomRespContentCreate   Op = "custom_resp_content_create"
	OpCustomRespContentDelete   Op = "custom_resp_content_delete"
	OpCustomRespContentEdit     Op = "custom_resp_content_edit"
	OpCustomRespContentStatus   Op = "custom_resp_content_edit_status"
	OpCustomRespContentPriority Op = "custom_resp_content_priority"
	OpCustomRespContentBackup   Op = "custom_resp_content_backup"
	OpCustomRespContentLoad     Op = "custom_resp_content_load"
	OpCustomRespContentHubLoad  Op = "custom_resp_content_hub_load"
	OpCustomRespContentHubExport Op = "custom_resp_content_hub_export"
	OpCustomUpstreamList        Op = "custom_upstream_list"
	OpCustomUpstreamGet         Op = "custom_upstream_get"
	OpCustomUpstreamCreate      Op = "custom_upstream_create"
	OpCustomUpstreamDelete      Op = "custom_upstream_delete"
	OpCustomUpstreamEdit        Op = "custom_upstream_edit"
	OpCustomUpstreamStatus      Op = "custom_upstream_edit_status"
	OpCustomUpstreamPriority    Op = "custom_upstream_priority"
	OpCustomUpstreamBackup      Op = "custom_upstream_backup"
	OpCustomUpstreamLoad        Op = "custom_upstream_load"
	OpCustomUpstreamHubLoad     Op = "custom_upstream_hub_load"
	OpCustomUpstreamHubExport   Op = "custom_upstream_hub_export"
)

// ---- 缓存策略（仅云WAF；user 段无 backup/load/hub）----

const (
	OpCachePolicyList       Op = "cache_policy_list"
	OpCachePolicyGet        Op = "cache_policy_get"
	OpCachePolicyCreate     Op = "cache_policy_create"
	OpCachePolicyDelete     Op = "cache_policy_delete"
	OpCachePolicyEdit       Op = "cache_policy_edit"
	OpCachePolicyStatus     Op = "cache_policy_edit_status"
	OpCachePolicyPriority   Op = "cache_policy_priority"
	OpCachePolicyBackup     Op = "cache_policy_backup"
	OpCachePolicyLoad       Op = "cache_policy_load"
	OpCachePolicyHubLoad    Op = "cache_policy_hub_load"
	OpCachePolicyHubExport  Op = "cache_policy_hub_export"
	OpNoCachePolicyList     Op = "no_cache_policy_list"
	OpNoCachePolicyGet      Op = "no_cache_policy_get"
	OpNoCachePolicyCreate   Op = "no_cache_policy_create"
	OpNoCachePolicyDelete   Op = "no_cache_policy_delete"
	OpNoCachePolicyEdit     Op = "no_cache_policy_edit"
	OpNoCachePolicyStatus   Op = "no_cache_policy_edit_status"
	OpNoCachePolicyPriority Op = "no_cache_policy_priority"
	OpNoCachePolicyBackup   Op = "no_cache_policy_backup"
	OpNoCachePolicyLoad     Op = "no_cache_policy_load"
	OpNoCachePolicyHubLoad  Op = "no_cache_policy_hub_load"
	OpNoCachePolicyHubExport Op = "no_cache_policy_hub_export"
	OpCacheBypassList       Op = "cache_bypass_list"
	OpCacheBypassGet        Op = "cache_bypass_get"
	OpCacheBypassCreate     Op = "cache_bypass_create"
	OpCacheBypassDelete     Op = "cache_bypass_delete"
	OpCacheBypassEdit       Op = "cache_bypass_edit"
	OpCacheBypassStatus     Op = "cache_bypass_edit_status"
	OpCacheBypassPriority   Op = "cache_bypass_priority"
	OpCacheBypassBackup     Op = "cache_bypass_backup"
	OpCacheBypassLoad       Op = "cache_bypass_load"
	OpCacheBypassHubLoad    Op = "cache_bypass_hub_load"
	OpCacheBypassHubExport  Op = "cache_bypass_hub_export"
	// 缓存任务（cloud admin 与 user 同路径）
	OpCacheWarmupCreate  Op = "cache_warmup_create"
	OpCacheWarmupList    Op = "cache_warmup_list"
	OpCacheWarmupDetail  Op = "cache_warmup_detail"
	OpCacheWarmupDelete  Op = "cache_warmup_delete"
	OpCacheRefreshCreate Op = "cache_refresh_create"
	OpCacheRefreshList   Op = "cache_refresh_list"
	OpCacheRefreshDetail Op = "cache_refresh_detail"
	OpCacheRefreshDelete Op = "cache_refresh_delete"
	// 缓存开关与 CDN 预热/刷新（仅 /user 段）
	OpCacheSwitchGet  Op = "cache_switch_get"
	OpCacheSwitchEdit Op = "cache_switch_edit"
	OpCdnPreheat      Op = "cdn_cache_preheat"
	OpCdnRefresh      Op = "cdn_cache_refresh"
)

// ---- SOC：日志/统计/事件/模型/用量 ----

const (
	OpSocLogQuery Op = "soc_log_query"
	// Web 攻击统计（standard 命名为 get_web_attack_* 且无 geoip，用 overrides 映射）
	OpSocWebAttackCountTotal        Op = "soc_web_attack_count_total"
	OpSocWebAttackApiCountTotal     Op = "soc_web_attack_api_count_total"
	OpSocWebAttackIpCountTotal      Op = "soc_web_attack_ip_count_total"
	OpSocWebAttackIsocodeCountTotal Op = "soc_web_attack_isocode_count_total"
	OpSocWebAttackGeoip             Op = "soc_web_attack_geoip"
	OpSocWebAttackCountTrend        Op = "soc_web_attack_count_trend"
	OpSocWebAttackApiTop            Op = "soc_web_attack_api_top"
	OpSocWebAttackTypeTop           Op = "soc_web_attack_type_top"
	OpSocWebAttackIpTop             Op = "soc_web_attack_ip_top"
	OpSocWebAttackIsocodeTop        Op = "soc_web_attack_isocode_top"
	// Flow 攻击统计（standard 无；user 段无 soc_ 前缀）
	OpSocFlowAttackCountTotal        Op = "soc_flow_attack_count_total"
	OpSocFlowAttackApiCountTotal     Op = "soc_flow_attack_api_count_total"
	OpSocFlowAttackIpCountTotal      Op = "soc_flow_attack_ip_count_total"
	OpSocFlowAttackIsocodeCountTotal Op = "soc_flow_attack_isocode_count_total"
	OpSocFlowAttackGeoip             Op = "soc_flow_attack_geoip"
	OpSocFlowAttackCountTrend        Op = "soc_flow_attack_count_trend"
	OpSocFlowAttackApiTop            Op = "soc_flow_attack_api_top"
	OpSocFlowAttackTypeTop           Op = "soc_flow_attack_type_top"
	OpSocFlowAttackIpTop             Op = "soc_flow_attack_ip_top"
	OpSocFlowAttackIsocodeTop        Op = "soc_flow_attack_isocode_top"
	// 攻击事件（user 段无 soc_ 前缀）
	OpSocEventList   Op = "soc_attack_event_list"
	OpSocBehaveTrack Op = "soc_attack_behave_track"
	// AI 模型（/user 段无）
	OpSocModelList        Op = "soc_model_list"
	OpSocModelDelete      Op = "soc_model_delete"
	OpSocModelResultEdit  Op = "soc_model_result_edit"
	OpSocModelWhiteList   Op = "soc_model_white_list"
	OpSocModelWhiteCreate Op = "soc_model_white_create"
	OpSocModelWhiteDelete Op = "soc_model_white_delete"
	// 用量统计（三版本 + user 均同名）
	OpUsageStatDomains    Op = "usage_stat_domains"
	OpUsageStatOverview   Op = "usage_stat_overview"
	OpUsageStatQpsTrend   Op = "usage_stat_qps_trend"
	OpUsageStatBandwidth  Op = "usage_stat_bandwidth_trend"
	OpUsageStatStatusDist Op = "usage_stat_status_distribution"
	OpUsageStatLatency    Op = "usage_stat_latency_trend"
	OpUsageStatDetail     Op = "usage_stat_detail"
)

// ---- SOC 网络封禁 IP（/user 段无）----

const (
	OpNetworkIpList       Op = "network_ip_list"
	OpNetworkIpSearch     Op = "network_ip_search"
	OpNetworkIpGet        Op = "network_ip_get"
	OpNetworkIpCreate     Op = "network_ip_create"
	OpNetworkIpEdit       Op = "network_ip_edit"
	OpNetworkIpStatusGet  Op = "network_ip_status_get"
	OpNetworkIpStatusEdit Op = "network_ip_status_edit"
	OpNetworkIpNodeUpdate Op = "network_ip_node_update"
)

// ---- 子账号管理（仅云WAF admin）----

const (
	OpSubAccountList     Op = "sub_account_list"
	OpSubAccountSearch   Op = "sub_account_search"
	OpSubAccountGet      Op = "sub_account_get"
	OpSubAccountCreate   Op = "sub_account_create"
	OpSubAccountDelete   Op = "sub_account_delete"
	OpSubAccountEdit     Op = "sub_account_edit"
	OpSubAccountWafAuth  Op = "sub_account_waf_auth_edit"
	OpSubAccountOtpReset Op = "sub_account_otp_reset"
)

// ---- 系统配置（standard 无；/user 段仅 report get）----

const (
	OpSysLogConfGet     Op = "sys_log_conf_get"
	OpSysLogConfEdit    Op = "sys_log_conf_edit"
	OpSysReportConfGet  Op = "sys_report_conf_get"
	OpSysReportConfEdit Op = "sys_report_conf_edit"
	OpSysReportConfTest Op = "sys_report_conf_test"
	OpSysCustomPageGet  Op = "sys_custom_page_get"
	OpSysCustomPageEdit Op = "sys_custom_page_edit"
	OpSysWebtdsGet      Op = "sys_webtds_check_get"
	OpSysWebtdsEdit     Op = "sys_webtds_check_edit"
	OpWafConfBackup     Op = "waf_conf_backup"
	OpWafConfLoad       Op = "waf_conf_load"
)

// ---- 节点监控（/user 段无）----

const (
	OpNodeMonitorList   Op = "node_monitor_list"
	OpNodeMonitorDelete Op = "node_monitor_delete"
)

// ---- 网站接入配置（仅云WAF；扩展端点仅 admin）----

const (
	OpWebsiteAccList        Op = "website_access_list"
	OpWebsiteAccGet         Op = "website_access_get"
	OpWebsiteAccCreate      Op = "website_access_create"
	OpWebsiteAccDelete      Op = "website_access_delete"
	OpWebsiteAccEdit        Op = "website_access_edit"
	OpWebsiteAccConnectTest Op = "website_access_connect_test"
	OpWebsiteAccCnameIps    Op = "website_access_cname_ips"
	OpWebsiteAccCnameEdit   Op = "website_access_cname_edit"
	OpWebsiteAccSync        Op = "website_access_update_sync"
	OpResourceQuotaTemplate Op = "resource_quota_template"
)

// tenantMode 描述操作所属模块的租户绑定形态，决定端点中缀与 body 租户参数。
type tenantMode uint8

const (
	// modeGlobal 全局模块：所有版本均无中缀、无租户参数（名单/组件/SOC/域名组）。
	modeGlobal tenantMode = iota
	// modeBody 域名类：路径无中缀，但 body 必带租户参数（professional group_name / cloud admin sub_user_name）。
	modeBody
	// modeProtection 防护类：路径加租户中缀（professional group_、cloud admin sub_account_）且 body 必带租户参数；
	// cloud user 无中缀（/user 段自动按子账号会话隔离）。
	modeProtection
	// modeCloudSub 云子账号类：仅云WAF(admin) 加 sub_account_ 中缀并带 sub_user_name；
	// standard/professional 为全局模块（无中缀无租户），如 SSL 证书。
	modeCloudSub
)

// opSpec 描述一个逻辑操作在各版本中的端点构成。
type opSpec struct {
	suffix string     // 核心路径（不含 /admin_api/、/user/ 前缀与租户中缀）
	mode   tenantMode // 租户绑定形态
}

// opSpecs 为统一的端点规格表。
var opSpecs = map[Op]opSpec{
	OpWebEngineGet:      {"get_web_engine_protection", modeProtection},
	OpWebEngineEdit:     {"edit_web_engine_protection", modeProtection},
	OpWebRuleBackup:     {"backup_web_rule_protection", modeProtection},
	OpWebRuleList:       {"get_web_rule_protection_list", modeProtection},
	OpWebRuleGet:        {"get_web_rule_protection", modeProtection},
	OpWebRuleCreate:     {"create_web_rule_protection", modeProtection},
	OpWebRuleDelete:     {"delete_web_rule_protection", modeProtection},
	OpWebRuleEdit:       {"edit_web_rule_protection", modeProtection},
	OpWebRuleStatus:     {"edit_web_rule_protection_status", modeProtection},
	OpWebRulePriority:   {"exchange_web_rule_protection_priority", modeProtection},
	OpWebRuleLoad:       {"load_web_rule_protection", modeProtection},
	OpWebRuleHubLoad:    {"load_web_rule_protection_hub_config", modeProtection},
	OpWebRuleHubExport:  {"export_web_rule_protection_hub_config", modeProtection},
	OpWebWhiteBackup:    {"backup_web_white_rule", modeProtection},
	OpWebWhiteList:      {"get_web_white_rule_list", modeProtection},
	OpWebWhiteGet:       {"get_web_white_rule", modeProtection},
	OpWebWhiteCreate:    {"create_web_white_rule", modeProtection},
	OpWebWhiteDelete:    {"delete_web_white_rule", modeProtection},
	OpWebWhiteEdit:      {"edit_web_white_rule", modeProtection},
	OpWebWhiteStatus:    {"edit_web_white_rule_status", modeProtection},
	OpWebWhitePriority:  {"exchange_web_white_rule_priority", modeProtection},
	OpWebWhiteLoad:      {"load_web_white_rule", modeProtection},
	OpWebWhiteHubLoad:   {"load_web_white_rule_hub_config", modeProtection},
	OpWebWhiteHubExport: {"export_web_white_rule_hub_config", modeProtection},
	OpFlowEngineGet:     {"get_flow_engine_protection", modeProtection},
	OpFlowEngineEdit:    {"edit_flow_engine_protection", modeProtection},
	OpFlowRuleBackup:    {"backup_flow_rule_protection", modeProtection},
	OpFlowRuleList:      {"get_flow_rule_protection_list", modeProtection},
	OpFlowRuleGet:       {"get_flow_rule_protection", modeProtection},
	OpFlowRuleCreate:    {"create_flow_rule_protection", modeProtection},
	OpFlowRuleDelete:    {"delete_flow_rule_protection", modeProtection},
	OpFlowRuleEdit:      {"edit_flow_rule_protection", modeProtection},
	OpFlowRuleStatus:    {"edit_flow_rule_protection_status", modeProtection},
	OpFlowRulePriority:  {"exchange_flow_rule_protection_priority", modeProtection},
	OpFlowRuleLoad:      {"load_flow_rule_protection", modeProtection},
	OpFlowRuleHubLoad:   {"load_flow_rule_protection_hub_config", modeProtection},
	OpFlowRuleHubExport: {"export_flow_rule_protection_hub_config", modeProtection},
	OpFlowWhiteBackup:   {"backup_flow_white_rule", modeProtection},
	OpFlowWhiteList:     {"get_flow_white_rule_list", modeProtection},
	OpFlowWhiteGet:      {"get_flow_white_rule", modeProtection},
	OpFlowWhiteCreate:   {"create_flow_white_rule", modeProtection},
	OpFlowWhiteDelete:   {"delete_flow_white_rule", modeProtection},
	OpFlowWhiteEdit:     {"edit_flow_white_rule", modeProtection},
	OpFlowWhiteStatus:   {"edit_flow_white_rule_status", modeProtection},
	OpFlowWhitePriority: {"exchange_flow_white_rule_priority", modeProtection},
	OpFlowWhiteLoad:     {"load_flow_white_rule", modeProtection},
	OpFlowWhiteHubLoad:  {"load_flow_white_rule_hub_config", modeProtection},
	OpFlowWhiteHubExport: {"export_flow_white_rule_hub_config", modeProtection},
	OpFlowIPRegionGet:   {"get_flow_ip_region_block", modeProtection},
	OpFlowIPRegionEdit:  {"edit_flow_ip_region_block", modeProtection},
	OpTamperList:        {"get_web_page_tamper_proof_list", modeProtection},
	OpTamperGet:         {"get_web_page_tamper_proof", modeProtection},
	OpTamperCreate:      {"create_web_page_tamper_proof", modeProtection},
	OpTamperDelete:      {"delete_web_page_tamper_proof", modeProtection},
	OpTamperEdit:        {"edit_web_page_tamper_proof", modeProtection},
	OpTamperStatus:      {"edit_web_page_tamper_proof_status", modeProtection},
	OpTamperPriority:    {"exchange_web_page_tamper_proof_priority", modeProtection},
	OpTamperBackup:      {"backup_web_page_tamper_proof", modeProtection},
	OpTamperLoad:        {"load_web_page_tamper_proof", modeProtection},
	OpTamperHubLoad:     {"load_web_page_tamper_proof_hub_config", modeProtection},
	OpTamperHubExport:   {"export_web_page_tamper_proof_hub_config", modeProtection},

	OpDomainList:        {"get_domain_list", modeBody},
	OpDomainGet:         {"get_domain", modeBody},
	OpDomainCreate:      {"create_domain", modeBody},
	OpDomainDelete:      {"delete_domain", modeBody},
	OpDomainEdit:        {"edit_domain", modeBody},
	OpDomainSearch:      {"get_domain_search_list", modeBody},
	OpDomainGroupList:   {"get_domain_group_list", modeGlobal},
	OpDomainGroupGet:    {"get_domain_group", modeGlobal},
	OpDomainGroupCreate: {"create_domain_group", modeGlobal},
	OpDomainGroupDelete: {"delete_domain_group", modeGlobal},
	OpDomainGroupEdit:   {"edit_domain_group", modeGlobal},
	OpDomainGroupSearch: {"get_domain_group_search_list", modeGlobal},

	OpSslList:       {"get_ssl_manage_list", modeCloudSub},
	OpSslGet:        {"get_ssl_manage", modeCloudSub},
	OpSslCreate:     {"create_ssl_manage", modeCloudSub},
	OpSslDelete:     {"delete_ssl_manage", modeCloudSub},
	OpSslEdit:       {"edit_ssl_manage", modeCloudSub},
	OpSslSearch:     {"get_ssl_manage_search_list", modeCloudSub},
	OpSslWildcard:   {"request_wildcard_cert", modeCloudSub},
	OpSslRetry:      {"retry_ssl_cert", modeCloudSub},
	OpSslCertConfig: {"edit_ssl_cert_config", modeCloudSub},
	OpGlobalSslGet:    {"get_global_ssl_protection", modeGlobal},
	OpGlobalSslEdit:   {"edit_global_ssl_protection", modeGlobal},
	OpGlobalSslStatus: {"edit_global_ssl_protection_status", modeGlobal},

	OpNameListBackup:     {"backup_global_name_list", modeGlobal},
	OpNameListList:       {"get_global_name_list_list", modeGlobal},
	OpNameListGet:        {"get_global_name_list", modeGlobal},
	OpNameListCreate:     {"create_global_name_list", modeGlobal},
	OpNameListDelete:     {"delete_global_name_list", modeGlobal},
	OpNameListEdit:       {"edit_global_name_list", modeGlobal},
	OpNameListStatus:     {"edit_global_name_list_status", modeGlobal},
	OpNameListPriority:   {"exchange_global_name_list_priority", modeGlobal},
	OpNameListLoad:       {"load_global_name_list", modeGlobal},
	OpNameListHubLoad:    {"load_global_name_list_hub_config", modeGlobal},
	OpNameListHubExport:  {"export_global_name_list_hub_config", modeGlobal},
	OpNameListItemList:   {"get_name_list_item_list_list", modeGlobal},
	OpNameListItemAdd:    {"create_global_name_list_item", modeGlobal},
	OpNameListItemDel:    {"delete_global_name_list_item", modeGlobal},
	OpNameListItemSearch: {"search_global_name_list_item", modeGlobal},

	OpComponentList:      {"get_component_list", modeGlobal},
	OpComponentGet:       {"get_component", modeGlobal},
	OpComponentCreate:    {"create_component", modeGlobal},
	OpComponentDelete:    {"delete_component", modeGlobal},
	OpComponentEdit:      {"edit_component", modeGlobal},
	OpComponentStatus:    {"edit_component_status", modeGlobal},
	OpComponentPriority:  {"exchange_component_priority", modeGlobal},
	OpComponentBackup:    {"backup_component", modeGlobal},
	OpComponentLoad:      {"load_component", modeGlobal},
	OpComponentHubLoad:   {"load_component_hub_config", modeGlobal},
	OpComponentHubExport: {"export_component_hub_config", modeGlobal},

	OpCustomReqHeaderList:       {"get_custom_request_header_list", modeProtection},
	OpCustomReqHeaderGet:        {"get_custom_request_header", modeProtection},
	OpCustomReqHeaderCreate:     {"create_custom_request_header", modeProtection},
	OpCustomReqHeaderDelete:     {"delete_custom_request_header", modeProtection},
	OpCustomReqHeaderEdit:       {"edit_custom_request_header", modeProtection},
	OpCustomReqHeaderStatus:     {"edit_custom_request_header_status", modeProtection},
	OpCustomReqHeaderPriority:   {"exchange_custom_request_header_priority", modeProtection},
	OpCustomReqHeaderBackup:     {"backup_custom_request_header", modeProtection},
	OpCustomReqHeaderLoad:       {"load_custom_request_header", modeProtection},
	OpCustomReqHeaderHubLoad:    {"load_custom_request_header_hub_config", modeProtection},
	OpCustomReqHeaderHubExport:  {"export_custom_request_header_hub_config", modeProtection},
	OpCustomRespHeaderList:      {"get_custom_response_header_list", modeProtection},
	OpCustomRespHeaderGet:       {"get_custom_response_header", modeProtection},
	OpCustomRespHeaderCreate:    {"create_custom_response_header", modeProtection},
	OpCustomRespHeaderDelete:    {"delete_custom_response_header", modeProtection},
	OpCustomRespHeaderEdit:      {"edit_custom_response_header", modeProtection},
	OpCustomRespHeaderStatus:    {"edit_custom_response_header_status", modeProtection},
	OpCustomRespHeaderPriority:  {"exchange_custom_response_header_priority", modeProtection},
	OpCustomRespHeaderBackup:    {"backup_custom_response_header", modeProtection},
	OpCustomRespHeaderLoad:      {"load_custom_response_header", modeProtection},
	OpCustomRespHeaderHubLoad:   {"load_custom_response_header_hub_config", modeProtection},
	OpCustomRespHeaderHubExport: {"export_custom_response_header_hub_config", modeProtection},
	OpCustomRespContentList:     {"get_custom_response_content_list", modeProtection},
	OpCustomRespContentGet:      {"get_custom_response_content", modeProtection},
	OpCustomRespContentCreate:   {"create_custom_response_content", modeProtection},
	OpCustomRespContentDelete:   {"delete_custom_response_content", modeProtection},
	OpCustomRespContentEdit:     {"edit_custom_response_content", modeProtection},
	OpCustomRespContentStatus:   {"edit_custom_response_content_status", modeProtection},
	OpCustomRespContentPriority: {"exchange_custom_response_content_priority", modeProtection},
	OpCustomRespContentBackup:   {"backup_custom_response_content", modeProtection},
	OpCustomRespContentLoad:     {"load_custom_response_content", modeProtection},
	OpCustomRespContentHubLoad:  {"load_custom_response_content_hub_config", modeProtection},
	OpCustomRespContentHubExport: {"export_custom_response_content_hub_config", modeProtection},
	OpCustomUpstreamList:        {"get_custom_upstream_address_list", modeProtection},
	OpCustomUpstreamGet:         {"get_custom_upstream_address", modeProtection},
	OpCustomUpstreamCreate:      {"create_custom_upstream_address", modeProtection},
	OpCustomUpstreamDelete:      {"delete_custom_upstream_address", modeProtection},
	OpCustomUpstreamEdit:        {"edit_custom_upstream_address", modeProtection},
	OpCustomUpstreamStatus:      {"edit_custom_upstream_address_status", modeProtection},
	OpCustomUpstreamPriority:    {"exchange_custom_upstream_address_priority", modeProtection},
	OpCustomUpstreamBackup:      {"backup_custom_upstream_address", modeProtection},
	OpCustomUpstreamLoad:        {"load_custom_upstream_address", modeProtection},
	OpCustomUpstreamHubLoad:     {"load_custom_upstream_address_hub_config", modeProtection},
	OpCustomUpstreamHubExport:   {"export_custom_upstream_address_hub_config", modeProtection},

	OpCachePolicyList:       {"get_cache_policy_list", modeProtection},
	OpCachePolicyGet:        {"get_cache_policy", modeProtection},
	OpCachePolicyCreate:     {"create_cache_policy", modeProtection},
	OpCachePolicyDelete:     {"delete_cache_policy", modeProtection},
	OpCachePolicyEdit:       {"edit_cache_policy", modeProtection},
	OpCachePolicyStatus:     {"edit_cache_policy_status", modeProtection},
	OpCachePolicyPriority:   {"exchange_cache_policy_priority", modeProtection},
	OpCachePolicyBackup:     {"backup_cache_policy", modeProtection},
	OpCachePolicyLoad:       {"load_cache_policy", modeProtection},
	OpCachePolicyHubLoad:    {"load_cache_policy_hub_config", modeProtection},
	OpCachePolicyHubExport:  {"export_cache_policy_hub_config", modeProtection},
	OpNoCachePolicyList:     {"get_no_cache_policy_list", modeProtection},
	OpNoCachePolicyGet:      {"get_no_cache_policy", modeProtection},
	OpNoCachePolicyCreate:   {"create_no_cache_policy", modeProtection},
	OpNoCachePolicyDelete:   {"delete_no_cache_policy", modeProtection},
	OpNoCachePolicyEdit:     {"edit_no_cache_policy", modeProtection},
	OpNoCachePolicyStatus:   {"edit_no_cache_policy_status", modeProtection},
	OpNoCachePolicyPriority: {"exchange_no_cache_policy_priority", modeProtection},
	OpNoCachePolicyBackup:   {"backup_no_cache_policy", modeProtection},
	OpNoCachePolicyLoad:     {"load_no_cache_policy", modeProtection},
	OpNoCachePolicyHubLoad:  {"load_no_cache_policy_hub_config", modeProtection},
	OpNoCachePolicyHubExport: {"export_no_cache_policy_hub_config", modeProtection},
	OpCacheBypassList:       {"get_cache_bypass_policy_list", modeProtection},
	OpCacheBypassGet:        {"get_cache_bypass_policy", modeProtection},
	OpCacheBypassCreate:     {"create_cache_bypass_policy", modeProtection},
	OpCacheBypassDelete:     {"delete_cache_bypass_policy", modeProtection},
	OpCacheBypassEdit:       {"edit_cache_bypass_policy", modeProtection},
	OpCacheBypassStatus:     {"edit_cache_bypass_policy_status", modeProtection},
	OpCacheBypassPriority:   {"exchange_cache_bypass_policy_priority", modeProtection},
	OpCacheBypassBackup:     {"backup_cache_bypass_policy", modeProtection},
	OpCacheBypassLoad:       {"load_cache_bypass_policy", modeProtection},
	OpCacheBypassHubLoad:    {"load_cache_bypass_policy_hub_config", modeProtection},
	OpCacheBypassHubExport:  {"export_cache_bypass_policy_hub_config", modeProtection},
	OpCacheWarmupCreate:     {"create_cache_warmup_task", modeGlobal},
	OpCacheWarmupList:       {"get_cache_warmup_list", modeGlobal},
	OpCacheWarmupDetail:     {"get_cache_warmup_detail", modeGlobal},
	OpCacheWarmupDelete:     {"delete_cache_warmup_task", modeGlobal},
	OpCacheRefreshCreate:    {"create_cache_refresh_task", modeGlobal},
	OpCacheRefreshList:      {"get_cache_refresh_list", modeGlobal},
	OpCacheRefreshDetail:    {"get_cache_refresh_detail", modeGlobal},
	OpCacheRefreshDelete:    {"delete_cache_refresh_task", modeGlobal},
	OpCacheSwitchGet:        {"get_cache_switch", modeGlobal},
	OpCacheSwitchEdit:       {"edit_cache_switch", modeGlobal},
	OpCdnPreheat:            {"create_cdn_cache_preheat", modeGlobal},
	OpCdnRefresh:            {"create_cdn_cache_refresh", modeGlobal},

	OpSocLogQuery:                 {"get_soc_log_query_list", modeGlobal},
	OpSocWebAttackCountTotal:      {"get_soc_web_attack_count_total", modeGlobal},
	OpSocWebAttackApiCountTotal:   {"get_soc_web_attack_api_count_total", modeGlobal},
	OpSocWebAttackIpCountTotal:    {"get_soc_web_attack_ip_count_total", modeGlobal},
	OpSocWebAttackIsocodeCountTotal: {"get_soc_web_attack_isocode_count_total", modeGlobal},
	OpSocWebAttackGeoip:           {"get_soc_web_attack_geoip", modeGlobal},
	OpSocWebAttackCountTrend:      {"get_soc_web_attack_count_trend", modeGlobal},
	OpSocWebAttackApiTop:          {"get_soc_web_attack_api_top", modeGlobal},
	OpSocWebAttackTypeTop:         {"get_soc_web_attack_type_top", modeGlobal},
	OpSocWebAttackIpTop:           {"get_soc_web_attack_ip_top", modeGlobal},
	OpSocWebAttackIsocodeTop:      {"get_soc_web_attack_isocode_top", modeGlobal},
	OpSocFlowAttackCountTotal:      {"get_soc_flow_attack_count_total", modeGlobal},
	OpSocFlowAttackApiCountTotal:   {"get_soc_flow_attack_api_count_total", modeGlobal},
	OpSocFlowAttackIpCountTotal:    {"get_soc_flow_attack_ip_count_total", modeGlobal},
	OpSocFlowAttackIsocodeCountTotal: {"get_soc_flow_attack_isocode_count_total", modeGlobal},
	OpSocFlowAttackGeoip:           {"get_soc_flow_attack_geoip", modeGlobal},
	OpSocFlowAttackCountTrend:      {"get_soc_flow_attack_count_trend", modeGlobal},
	OpSocFlowAttackApiTop:          {"get_soc_flow_attack_api_top", modeGlobal},
	OpSocFlowAttackTypeTop:         {"get_soc_flow_attack_type_top", modeGlobal},
	OpSocFlowAttackIpTop:           {"get_soc_flow_attack_ip_top", modeGlobal},
	OpSocFlowAttackIsocodeTop:      {"get_soc_flow_attack_isocode_top", modeGlobal},
	OpSocEventList:                {"get_soc_attack_event_list", modeGlobal},
	OpSocBehaveTrack:              {"get_soc_attack_behave_track", modeGlobal},
	OpSocModelList:                {"get_soc_web_protection_model_list", modeGlobal},
	OpSocModelDelete:              {"delete_soc_web_protection_model", modeGlobal},
	OpSocModelResultEdit:          {"edit_soc_web_protection_model_result", modeGlobal},
	OpSocModelWhiteList:           {"get_soc_web_protection_model_token_white_list", modeGlobal},
	OpSocModelWhiteCreate:         {"create_soc_web_protection_model_token_white", modeGlobal},
	OpSocModelWhiteDelete:         {"delete_soc_web_protection_model_token_white", modeGlobal},
	OpUsageStatDomains:            {"get_soc_usage_stat_domains", modeGlobal},
	OpUsageStatOverview:           {"get_soc_usage_stat_overview", modeGlobal},
	OpUsageStatQpsTrend:           {"get_soc_usage_stat_qps_trend", modeGlobal},
	OpUsageStatBandwidth:          {"get_soc_usage_stat_bandwidth_trend", modeGlobal},
	OpUsageStatStatusDist:         {"get_soc_usage_stat_status_distribution", modeGlobal},
	OpUsageStatLatency:            {"get_soc_usage_stat_latency_trend", modeGlobal},
	OpUsageStatDetail:             {"get_soc_usage_stat_detail", modeGlobal},

	OpNetworkIpList:       {"get_soc_network_ip_list", modeGlobal},
	OpNetworkIpSearch:     {"get_soc_network_ip_search_list", modeGlobal},
	OpNetworkIpGet:        {"get_soc_network_ip", modeGlobal},
	OpNetworkIpCreate:     {"create_soc_network_ip", modeGlobal},
	OpNetworkIpEdit:       {"edit_soc_network_ip", modeGlobal},
	OpNetworkIpStatusGet:  {"get_soc_network_ip_status", modeGlobal},
	OpNetworkIpStatusEdit: {"edit_soc_network_ip_status", modeGlobal},
	OpNetworkIpNodeUpdate: {"get_soc_network_ip_node_update_list", modeGlobal},

	OpSubAccountList:     {"get_sub_account_list", modeGlobal},
	OpSubAccountSearch:   {"get_sub_account_search_list", modeGlobal},
	OpSubAccountGet:      {"get_sub_account", modeGlobal},
	OpSubAccountCreate:   {"create_sub_account", modeGlobal},
	OpSubAccountDelete:   {"delete_sub_account", modeGlobal},
	OpSubAccountEdit:     {"edit_sub_account", modeGlobal},
	OpSubAccountWafAuth:  {"edit_sub_account_waf_auth", modeGlobal},
	OpSubAccountOtpReset: {"reset_sub_account_otp", modeGlobal},

	OpSysLogConfGet:     {"get_sys_log_conf", modeGlobal},
	OpSysLogConfEdit:    {"edit_sys_log_conf", modeGlobal},
	OpSysReportConfGet:  {"get_sys_report_conf_conf", modeGlobal},
	OpSysReportConfEdit: {"edit_sys_report_conf_conf", modeGlobal},
	OpSysReportConfTest: {"test_sys_report_conf_conf", modeGlobal},
	OpSysCustomPageGet:  {"get_sys_custom_page_conf", modeGlobal},
	OpSysCustomPageEdit: {"edit_sys_custom_page_conf", modeGlobal},
	OpSysWebtdsGet:      {"get_sys_webtds_check_conf", modeGlobal},
	OpSysWebtdsEdit:     {"edit_sys_webtds_check_conf", modeGlobal},
	OpWafConfBackup:     {"waf_conf_backup", modeGlobal},
	OpWafConfLoad:       {"waf_conf_load", modeGlobal},

	OpNodeMonitorList:   {"get_node_monitor_list", modeGlobal},
	OpNodeMonitorDelete: {"delete_node_monitor", modeGlobal},

	OpWebsiteAccList:        {"get_website_access_conf_list", modeGlobal},
	OpWebsiteAccGet:         {"get_website_access_conf", modeGlobal},
	OpWebsiteAccCreate:      {"create_website_access_conf", modeGlobal},
	OpWebsiteAccDelete:      {"delete_website_access_conf", modeGlobal},
	OpWebsiteAccEdit:        {"edit_website_access_conf", modeGlobal},
	OpWebsiteAccConnectTest: {"website_access_conf_connect_test", modeGlobal},
	OpWebsiteAccCnameIps:    {"get_domain_cname_ip_list", modeBody},
	OpWebsiteAccCnameEdit:   {"domain_cname_edit", modeBody},
	OpWebsiteAccSync:        {"website_access_conf_update_sync", modeGlobal},
	OpResourceQuotaTemplate: {"get_resource_quota_template", modeGlobal},
}
