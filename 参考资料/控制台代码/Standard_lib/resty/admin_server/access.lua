local jxwaf_admin_account = require 'resty.admin_server.jxwaf_admin_account'
local jxwaf_waf_domain = require 'resty.admin_server.jxwaf_waf_domain'
local jxwaf_waf_web_engine_protection = require 'resty.admin_server.jxwaf_waf_web_engine_protection'
local jxwaf_waf_web_rule_protection = require 'resty.admin_server.jxwaf_waf_web_rule_protection'
local jxwaf_waf_web_page_tamper_proof = require 'resty.admin_server.jxwaf_waf_web_page_tamper_proof'
local jxwaf_waf_flow_rule_protection = require 'resty.admin_server.jxwaf_waf_flow_rule_protection'
local jxwaf_waf_flow_engine_protection = require 'resty.admin_server.jxwaf_waf_flow_engine_protection'
local jxwaf_waf_flow_ip_region_block = require 'resty.admin_server.jxwaf_waf_flow_ip_region_block'
local jxwaf_waf_flow_white_rule = require 'resty.admin_server.jxwaf_waf_flow_white_rule'
local jxwaf_waf_white_rule = require 'resty.admin_server.jxwaf_waf_white_rule'
local jxwaf_waf_update = require 'resty.admin_server.jxwaf_waf_update'
local jxwaf_node_monitor = require 'resty.admin_server.jxwaf_node_monitor'
local jxwaf_waf_ssl_manage = require 'resty.admin_server.jxwaf_waf_ssl_manage'
local jxwaf_waf_component = require 'resty.admin_server.jxwaf_waf_component'
local jxwaf_waf_global_name_list = require 'resty.admin_server.jxwaf_waf_global_name_list'
local jxwaf_waf_global_name_list_item = require 'resty.admin_server.jxwaf_waf_global_name_list_item'
local jxwaf_soc_attack_statistics = require 'resty.admin_server.jxwaf_soc_attack_statistics'
local jxwaf_soc_attack_event = require 'resty.admin_server.jxwaf_soc_attack_event'
local jxwaf_soc_web_protection_model = require 'resty.admin_server.jxwaf_soc_web_protection_model'
local jxwaf_soc_network_ip = require 'resty.admin_server.jxwaf_soc_network_ip'
local response = require 'resty.admin_server.response'
ngx.req.read_body()
local uri = ngx.var.uri

local uri_route_map = {
    ['/account_init_check'] = jxwaf_admin_account.account_init_check,
    ['/get_otp_qr_url'] = jxwaf_admin_account.get_otp_qr_url,
    ['/account_regist'] = jxwaf_admin_account.account_regist,
    ['/account_login'] = jxwaf_admin_account.account_login,
    ['/account_logout'] = jxwaf_admin_account.account_logout,

    ['/get_node_monitor_list'] = jxwaf_node_monitor.get_node_monitor_list,
    ['/delete_node_monitor'] = jxwaf_node_monitor.delete_node_monitor,


    ['/get_domain_list'] = jxwaf_waf_domain.get_domain_list,
    ['/get_domain_search_list'] = jxwaf_waf_domain.get_domain_search_list,
    ['/get_domain'] = jxwaf_waf_domain.get_domain,
    ['/create_domain'] = jxwaf_waf_domain.create_domain,
    ['/delete_domain'] = jxwaf_waf_domain.delete_domain,
    ['/edit_domain'] = jxwaf_waf_domain.edit_domain,
    ['/api_get_domain_list'] = jxwaf_waf_domain.api_get_domain_list,

    ['/get_web_engine_protection'] = jxwaf_waf_web_engine_protection.get_web_engine_protection,
    ['/edit_web_engine_protection'] = jxwaf_waf_web_engine_protection.edit_web_engine_protection,

    ['/get_web_rule_protection_list'] = jxwaf_waf_web_rule_protection.get_web_rule_protection_list,
    ['/get_web_rule_protection'] = jxwaf_waf_web_rule_protection.get_web_rule_protection,
    ['/create_web_rule_protection'] = jxwaf_waf_web_rule_protection.create_web_rule_protection,
    ['/delete_web_rule_protection'] = jxwaf_waf_web_rule_protection.delete_web_rule_protection,
    ['/edit_web_rule_protection'] = jxwaf_waf_web_rule_protection.edit_web_rule_protection,
    ['/edit_web_rule_protection_status'] = jxwaf_waf_web_rule_protection.edit_web_rule_protection_status,
    ['/api_get_web_rule_protection_list'] = jxwaf_waf_web_rule_protection.api_get_web_rule_protection_list,
    ['/exchange_web_rule_protection_priority'] = jxwaf_waf_web_rule_protection.exchange_web_rule_protection_priority,
    ['/backup_web_rule_protection'] = jxwaf_waf_web_rule_protection.backup_web_rule_protection,
    ['/load_web_rule_protection'] = jxwaf_waf_web_rule_protection.load_web_rule_protection,
    ['/load_web_rule_protection_hub_config'] = jxwaf_waf_web_rule_protection.load_web_rule_protection_hub_config,
    ['/export_web_rule_protection_hub_config'] = jxwaf_waf_web_rule_protection.export_web_rule_protection_hub_config,

    ['/get_web_page_tamper_proof_list'] = jxwaf_waf_web_page_tamper_proof.get_web_page_tamper_proof_list,
    ['/get_web_page_tamper_proof'] = jxwaf_waf_web_page_tamper_proof.get_web_page_tamper_proof,
    ['/create_web_page_tamper_proof'] = jxwaf_waf_web_page_tamper_proof.create_web_page_tamper_proof,
    ['/delete_web_page_tamper_proof'] = jxwaf_waf_web_page_tamper_proof.delete_web_page_tamper_proof,
    ['/edit_web_page_tamper_proof'] = jxwaf_waf_web_page_tamper_proof.edit_web_page_tamper_proof,
    ['/edit_web_page_tamper_proof_status'] = jxwaf_waf_web_page_tamper_proof.edit_web_page_tamper_proof_status,
    ['/exchange_web_page_tamper_proof_priority'] = jxwaf_waf_web_page_tamper_proof.exchange_web_page_tamper_proof_priority,
    ['/backup_web_page_tamper_proof'] = jxwaf_waf_web_page_tamper_proof.backup_web_page_tamper_proof,
    ['/load_web_page_tamper_proof'] = jxwaf_waf_web_page_tamper_proof.load_web_page_tamper_proof,
    ['/load_web_page_tamper_proof_hub_config'] = jxwaf_waf_web_page_tamper_proof.load_web_page_tamper_proof_hub_config,
    ['/export_web_page_tamper_proof_hub_config'] = jxwaf_waf_web_page_tamper_proof.export_web_page_tamper_proof_hub_config,
    ['/waf_get_cache_page_url'] = jxwaf_waf_web_page_tamper_proof.waf_get_cache_page_url,
    ['/waf/waf_get_cache_page_url'] = jxwaf_waf_web_page_tamper_proof.waf_get_cache_page_url,
    
    ['/get_web_white_rule_list'] = jxwaf_waf_white_rule.get_web_white_rule_list,
    ['/get_web_white_rule'] = jxwaf_waf_white_rule.get_web_white_rule,
    ['/create_web_white_rule'] = jxwaf_waf_white_rule.create_web_white_rule,
    ['/delete_web_white_rule'] = jxwaf_waf_white_rule.delete_web_white_rule,
    ['/edit_web_white_rule'] = jxwaf_waf_white_rule.edit_web_white_rule,
    ['/edit_web_white_rule_status'] = jxwaf_waf_white_rule.edit_web_white_rule_status,
    ['/exchange_web_white_rule_priority'] = jxwaf_waf_white_rule.exchange_web_white_rule_priority,
    ['/backup_web_white_rule'] = jxwaf_waf_white_rule.backup_web_white_rule,
    ['/load_web_white_rule'] = jxwaf_waf_white_rule.load_web_white_rule,
    ['/load_web_white_rule_hub_config'] = jxwaf_waf_white_rule.load_web_white_rule_hub_config,
    ['/export_web_white_rule_hub_config'] = jxwaf_waf_white_rule.export_web_white_rule_hub_config,

    ['/get_flow_engine_protection'] = jxwaf_waf_flow_engine_protection.get_flow_engine_protection,
    ['/edit_flow_engine_protection'] = jxwaf_waf_flow_engine_protection.edit_flow_engine_protection,

    ['/get_flow_rule_protection_list'] = jxwaf_waf_flow_rule_protection.get_flow_rule_protection_list,
    ['/get_flow_rule_protection'] = jxwaf_waf_flow_rule_protection.get_flow_rule_protection,
    ['/create_flow_rule_protection'] = jxwaf_waf_flow_rule_protection.create_flow_rule_protection,
    ['/delete_flow_rule_protection'] = jxwaf_waf_flow_rule_protection.delete_flow_rule_protection,
    ['/edit_flow_rule_protection'] = jxwaf_waf_flow_rule_protection.edit_flow_rule_protection,
    ['/edit_flow_rule_protection_status'] = jxwaf_waf_flow_rule_protection.edit_flow_rule_protection_status,
    ['/exchange_flow_rule_protection_priority'] = jxwaf_waf_flow_rule_protection.exchange_flow_rule_protection_priority,
    ['/backup_flow_rule_protection'] = jxwaf_waf_flow_rule_protection.backup_flow_rule_protection,
    ['/load_flow_rule_protection'] = jxwaf_waf_flow_rule_protection.load_flow_rule_protection,
    ['/load_flow_rule_protection_hub_config'] = jxwaf_waf_flow_rule_protection.load_flow_rule_protection_hub_config,
    ['/export_flow_rule_protection_hub_config'] = jxwaf_waf_flow_rule_protection.export_flow_rule_protection_hub_config,

    ['/get_flow_white_rule_list'] = jxwaf_waf_flow_white_rule.get_flow_white_rule_list,
    ['/get_flow_white_rule'] = jxwaf_waf_flow_white_rule.get_flow_white_rule,
    ['/create_flow_white_rule'] = jxwaf_waf_flow_white_rule.create_flow_white_rule,
    ['/delete_flow_white_rule'] = jxwaf_waf_flow_white_rule.delete_flow_white_rule,
    ['/edit_flow_white_rule'] = jxwaf_waf_flow_white_rule.edit_flow_white_rule,
    ['/edit_flow_white_rule_status'] = jxwaf_waf_flow_white_rule.edit_flow_white_rule_status,
    ['/exchange_flow_white_rule_priority'] = jxwaf_waf_flow_white_rule.exchange_flow_white_rule_priority,
    ['/backup_flow_white_rule'] = jxwaf_waf_flow_white_rule.backup_flow_white_rule,
    ['/load_flow_white_rule'] = jxwaf_waf_flow_white_rule.load_flow_white_rule,
    ['/load_flow_white_rule_hub_config'] = jxwaf_waf_flow_white_rule.load_flow_white_rule_hub_config,
    ['/export_flow_white_rule_hub_config'] = jxwaf_waf_flow_white_rule.export_flow_white_rule_hub_config,

    ['/get_flow_ip_region_block'] = jxwaf_waf_flow_ip_region_block.get_flow_ip_region_block,
    ['/edit_flow_ip_region_block'] = jxwaf_waf_flow_ip_region_block.edit_flow_ip_region_block,

    ['/waf_monitor'] = jxwaf_node_monitor.waf_monitor,
    ['/waf_update'] = jxwaf_waf_update.waf_update,
    ['/model_update'] = jxwaf_waf_update.model_update,
    ['/token_ai_analysis'] = jxwaf_waf_update.token_ai_analysis,

    ['/get_ssl_manage_list'] = jxwaf_waf_ssl_manage.get_ssl_manage_list,
    ['/api_get_ssl_manage_list'] = jxwaf_waf_ssl_manage.api_get_ssl_manage_list,
    ['/get_ssl_manage_search_list'] = jxwaf_waf_ssl_manage.get_ssl_manage_search_list,
    ['/get_ssl_manage'] = jxwaf_waf_ssl_manage.get_ssl_manage,
    ['/create_ssl_manage'] = jxwaf_waf_ssl_manage.create_ssl_manage,
    ['/delete_ssl_manage'] = jxwaf_waf_ssl_manage.delete_ssl_manage,
    ['/edit_ssl_manage'] = jxwaf_waf_ssl_manage.edit_ssl_manage,

    ['/get_component_list'] = jxwaf_waf_component.get_component_list,
    ['/get_component'] = jxwaf_waf_component.get_component,
    ['/create_component'] = jxwaf_waf_component.create_component,
    ['/delete_component'] = jxwaf_waf_component.delete_component,
    ['/edit_component'] = jxwaf_waf_component.edit_component,
    ['/edit_component_status'] = jxwaf_waf_component.edit_component_status,
    ['/exchange_component_priority'] = jxwaf_waf_component.exchange_component_priority,
    ['/backup_component'] = jxwaf_waf_component.backup_component,
    ['/load_component'] = jxwaf_waf_component.load_component,
    ['/load_component_hub_config'] = jxwaf_waf_component.load_component_hub_config,
    ['/export_component_hub_config'] = jxwaf_waf_component.export_component_hub_config,

    ['/get_global_name_list_list'] = jxwaf_waf_global_name_list.get_global_name_list_list,
    ['/api_get_global_name_list_list'] = jxwaf_waf_global_name_list.api_get_global_name_list_list,
    ['/get_global_name_list'] = jxwaf_waf_global_name_list.get_global_name_list,
    ['/create_global_name_list'] = jxwaf_waf_global_name_list.create_global_name_list,
    ['/delete_global_name_list'] = jxwaf_waf_global_name_list.delete_global_name_list,
    ['/edit_global_name_list'] = jxwaf_waf_global_name_list.edit_global_name_list,
    ['/edit_global_name_list_status'] = jxwaf_waf_global_name_list.edit_global_name_list_status,
    ['/exchange_global_name_list_priority'] = jxwaf_waf_global_name_list.exchange_global_name_list_priority,
    ['/backup_global_name_list'] = jxwaf_waf_global_name_list.backup_global_name_list,
    ['/load_global_name_list'] = jxwaf_waf_global_name_list.load_global_name_list,
    ['/load_global_name_list_hub_config'] = jxwaf_waf_global_name_list.load_global_name_list_hub_config,
    ['/export_global_name_list_hub_config'] = jxwaf_waf_global_name_list.export_global_name_list_hub_config,

    ['/get_name_list_item_list_list'] = jxwaf_waf_global_name_list_item.get_name_list_item_list_list,
    ['/create_global_name_list_item'] = jxwaf_waf_global_name_list_item.create_global_name_list_item,
    ['/delete_global_name_list_item'] = jxwaf_waf_global_name_list_item.delete_global_name_list_item,
    ['/search_global_name_list_item'] = jxwaf_waf_global_name_list_item.search_global_name_list_item,
    ['/api_get_name_list_item_list_list'] = jxwaf_waf_global_name_list_item.api_get_name_list_item_list_list,
    ['/api_create_global_name_list_item'] = jxwaf_waf_global_name_list_item.api_create_global_name_list_item,
    ['/api_delete_global_name_list_item'] = jxwaf_waf_global_name_list_item.api_delete_global_name_list_item,
    ['/api_search_global_name_list_item'] = jxwaf_waf_global_name_list_item.api_search_global_name_list_item,

    ['/get_web_attack_count_total'] = jxwaf_soc_attack_statistics.get_web_attack_count_total,
    ['/get_web_attack_api_count'] = jxwaf_soc_attack_statistics.get_web_attack_api_count,
    ['/get_web_attack_ip_count'] = jxwaf_soc_attack_statistics.get_web_attack_ip_count,
    ['/get_web_attack_country_count'] = jxwaf_soc_attack_statistics.get_web_attack_country_count,
    ['/get_web_attack_type_ranking'] = jxwaf_soc_attack_statistics.get_web_attack_type_ranking,
    ['/get_web_attack_api_ranking'] = jxwaf_soc_attack_statistics.get_web_attack_api_ranking,
    ['/get_web_attack_ip_ranking'] = jxwaf_soc_attack_statistics.get_web_attack_ip_ranking,
    ['/get_web_attack_country_ranking'] = jxwaf_soc_attack_statistics.get_web_attack_country_ranking,
    ['/get_web_attack_trend'] = jxwaf_soc_attack_statistics.get_web_attack_trend,
    ['/get_soc_log_query_list'] = jxwaf_soc_attack_statistics.get_soc_log_query_list,
    ['/get_soc_attack_event_list'] = jxwaf_soc_attack_event.get_soc_attack_event_list,
    ['/get_soc_attack_behave_track'] = jxwaf_soc_attack_event.get_soc_attack_behave_track,
    ['/get_soc_web_protection_model_list'] = jxwaf_soc_web_protection_model.get_soc_web_protection_model_list,
    ['/delete_soc_web_protection_model'] = jxwaf_soc_web_protection_model.delete_soc_web_protection_model,
    ['/edit_soc_web_protection_model_result'] = jxwaf_soc_web_protection_model.edit_soc_web_protection_model_result,

    ['/get_soc_network_ip_list'] = jxwaf_soc_network_ip.get_soc_network_ip_list,
    ['/get_soc_network_ip_search_list'] = jxwaf_soc_network_ip.get_soc_network_ip_search_list,
    ['/create_soc_network_ip'] = jxwaf_soc_network_ip.create_soc_network_ip,
    ['/get_soc_network_ip'] = jxwaf_soc_network_ip.get_soc_network_ip,
    ['/edit_soc_network_ip'] = jxwaf_soc_network_ip.edit_soc_network_ip,
    ['/network_block'] = jxwaf_soc_network_ip.network_block,
    ['/sync_network_ip'] = jxwaf_soc_network_ip.sync_network_ip,
    ['/get_soc_network_ip_status'] = jxwaf_soc_network_ip.get_soc_network_ip_status,
    ['/edit_soc_network_ip_status'] = jxwaf_soc_network_ip.edit_soc_network_ip_status,
    ['/get_soc_network_ip_node_update_list'] = jxwaf_soc_network_ip.get_soc_network_ip_node_update_list,
}

local handler = uri_route_map[uri]

if handler then
    handler()
end