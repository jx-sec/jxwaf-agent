local jxwaf_admin_account = require 'resty.admin_server.jxwaf_admin_account'
local jxwaf_waf_domain_group = require 'resty.admin_server.jxwaf_waf_domain_group'
local jxwaf_waf_group_web_engine_protection = require 'resty.admin_server.jxwaf_waf_group_web_engine_protection'
local jxwaf_waf_group_web_rule_protection = require 'resty.admin_server.jxwaf_waf_group_web_rule_protection'
local jxwaf_waf_group_web_white_rule = require 'resty.admin_server.jxwaf_waf_group_web_white_rule'
local jxwaf_waf_group_web_page_tamper_proof = require 'resty.admin_server.jxwaf_waf_group_web_page_tamper_proof'
local jxwaf_waf_group_flow_engine_protection = require 'resty.admin_server.jxwaf_waf_group_flow_engine_protection'
local jxwaf_waf_group_flow_rule_protection = require 'resty.admin_server.jxwaf_waf_group_flow_rule_protection'
local jxwaf_waf_group_flow_white_rule = require 'resty.admin_server.jxwaf_waf_group_flow_white_rule'
local jxwaf_waf_group_flow_ip_region_block = require 'resty.admin_server.jxwaf_waf_group_flow_ip_region_block'
local jxwaf_waf_domain = require 'resty.admin_server.jxwaf_waf_domain'
local jxwaf_waf_update = require 'resty.admin_server.jxwaf_waf_update'
local jxwaf_sys_conf = require 'resty.admin_server.jxwaf_sys_conf'
local jxwaf_node_monitor = require 'resty.admin_server.jxwaf_node_monitor'
local jxwaf_waf_ssl_manage = require 'resty.admin_server.jxwaf_waf_ssl_manage'
local jxwaf_waf_component = require 'resty.admin_server.jxwaf_waf_component'
local jxwaf_waf_group_custom_request_header = require 'resty.admin_server.jxwaf_waf_group_custom_request_header'
local jxwaf_waf_group_custom_response_header = require 'resty.admin_server.jxwaf_waf_group_custom_response_header'
local jxwaf_waf_group_custom_response_content = require 'resty.admin_server.jxwaf_waf_group_custom_response_content'
local jxwaf_waf_group_custom_upstream_address = require 'resty.admin_server.jxwaf_waf_group_custom_upstream_address'

local jxwaf_waf_global_name_list =  require 'resty.admin_server.jxwaf_waf_global_name_list'
local jxwaf_waf_global_name_list_item = require 'resty.admin_server.jxwaf_waf_global_name_list_item'
local jxwaf_soc_network_ip = require 'resty.admin_server.jxwaf_soc_network_ip'

local jxwaf_soc_web_attack = require 'resty.admin_server.jxwaf_soc_web_attack'
local jxwaf_soc_flow_attack = require 'resty.admin_server.jxwaf_soc_flow_attack'
local jxwaf_soc_attack_event = require 'resty.admin_server.jxwaf_soc_attack_event'
local jxwaf_soc_log_query = require 'resty.admin_server.jxwaf_soc_log_query'
local jxwaf_soc_web_protection_model = require 'resty.admin_server.jxwaf_soc_web_protection_model'

ngx.req.read_body()
local uri = ngx.var.uri

local uri_route_map = {
    ['/account_init_check'] = jxwaf_admin_account.account_init_check,
    ['/get_otp_qr_url'] = jxwaf_admin_account.get_otp_qr_url,
    ['/account_regist'] = jxwaf_admin_account.account_regist,
    ['/account_login'] = jxwaf_admin_account.account_login,
    ['/account_logout'] = jxwaf_admin_account.account_logout,
    ['/get_waf_auth'] = jxwaf_admin_account.get_waf_auth,
    ['/edit_waf_auth'] = jxwaf_admin_account.edit_waf_auth,

    ['/get_domain_group_list'] = jxwaf_waf_domain_group.get_domain_group_list,
    ['/get_domain_group_search_list'] = jxwaf_waf_domain_group.get_domain_group_search_list,
    ['/get_domain_group'] = jxwaf_waf_domain_group.get_domain_group,
    ['/create_domain_group'] = jxwaf_waf_domain_group.create_domain_group,
    ['/delete_domain_group'] = jxwaf_waf_domain_group.delete_domain_group,
    ['/edit_domain_group'] = jxwaf_waf_domain_group.edit_domain_group,
    ['/api_get_domain_group_list'] = jxwaf_waf_domain_group.api_get_domain_group_list,

    ['/get_group_web_engine_protection'] = jxwaf_waf_group_web_engine_protection.get_group_web_engine_protection,
    ['/edit_group_web_engine_protection'] = jxwaf_waf_group_web_engine_protection.edit_group_web_engine_protection,
    
    ['/get_group_web_rule_protection_list'] = jxwaf_waf_group_web_rule_protection.get_group_web_rule_protection_list,
    ['/get_group_web_rule_protection'] = jxwaf_waf_group_web_rule_protection.get_group_web_rule_protection,
    ['/create_group_web_rule_protection'] = jxwaf_waf_group_web_rule_protection.create_group_web_rule_protection,
    ['/delete_group_web_rule_protection'] = jxwaf_waf_group_web_rule_protection.delete_group_web_rule_protection,
    ['/edit_group_web_rule_protection'] = jxwaf_waf_group_web_rule_protection.edit_group_web_rule_protection,
    ['/edit_group_web_rule_protection_status'] = jxwaf_waf_group_web_rule_protection.edit_group_web_rule_protection_status,
  ['/exchange_group_web_rule_protection_priority'] = jxwaf_waf_group_web_rule_protection.exchange_group_web_rule_protection_priority,
    ['/backup_group_web_rule_protection'] = jxwaf_waf_group_web_rule_protection.backup_group_web_rule_protection,
    ['/load_group_web_rule_protection'] = jxwaf_waf_group_web_rule_protection.load_group_web_rule_protection,
    ['/api_get_group_web_rule_protection_list'] = jxwaf_waf_group_web_rule_protection.api_get_group_web_rule_protection_list,
    ['/load_group_web_rule_protection_hub_config'] = jxwaf_waf_group_web_rule_protection.load_group_web_rule_protection_hub_config,
    ['/export_group_web_rule_protection_hub_config'] = jxwaf_waf_group_web_rule_protection.export_group_web_rule_protection_hub_config,

    ['/get_group_web_white_rule_list'] = jxwaf_waf_group_web_white_rule.get_group_web_white_rule_list,
    ['/get_group_web_white_rule'] = jxwaf_waf_group_web_white_rule.get_group_web_white_rule,
    ['/create_group_web_white_rule'] = jxwaf_waf_group_web_white_rule.create_group_web_white_rule,
    ['/delete_group_web_white_rule'] = jxwaf_waf_group_web_white_rule.delete_group_web_white_rule,
    ['/edit_group_web_white_rule'] = jxwaf_waf_group_web_white_rule.edit_group_web_white_rule,
    ['/edit_group_web_white_rule_status'] = jxwaf_waf_group_web_white_rule.edit_group_web_white_rule_status,
    ['/exchange_group_web_white_rule_priority'] = jxwaf_waf_group_web_white_rule.exchange_group_web_white_rule_priority,
    ['/backup_group_web_white_rule'] = jxwaf_waf_group_web_white_rule.backup_group_web_white_rule,
    ['/load_group_web_white_rule'] = jxwaf_waf_group_web_white_rule.load_group_web_white_rule,
    ['/load_group_web_white_rule_hub_config'] = jxwaf_waf_group_web_white_rule.load_group_web_white_rule_hub_config,
    ['/export_group_web_white_rule_hub_config'] = jxwaf_waf_group_web_white_rule.export_group_web_white_rule_hub_config,

    ['/get_group_web_page_tamper_proof_list'] = jxwaf_waf_group_web_page_tamper_proof.get_group_web_page_tamper_proof_list,
    ['/get_group_web_page_tamper_proof'] = jxwaf_waf_group_web_page_tamper_proof.get_group_web_page_tamper_proof,
    ['/create_group_web_page_tamper_proof'] = jxwaf_waf_group_web_page_tamper_proof.create_group_web_page_tamper_proof,
    ['/delete_group_web_page_tamper_proof'] = jxwaf_waf_group_web_page_tamper_proof.delete_group_web_page_tamper_proof,
    ['/edit_group_web_page_tamper_proof'] = jxwaf_waf_group_web_page_tamper_proof.edit_group_web_page_tamper_proof,
    ['/edit_group_web_page_tamper_proof_status'] = jxwaf_waf_group_web_page_tamper_proof.edit_group_web_page_tamper_proof_status,
    ['/exchange_group_web_page_tamper_proof_priority'] = jxwaf_waf_group_web_page_tamper_proof.exchange_group_web_page_tamper_proof_priority,
    ['/backup_group_web_page_tamper_proof'] = jxwaf_waf_group_web_page_tamper_proof.backup_group_web_page_tamper_proof,
    ['/load_group_web_page_tamper_proof'] = jxwaf_waf_group_web_page_tamper_proof.load_group_web_page_tamper_proof,
    ['/load_group_web_page_tamper_proof_hub_config'] = jxwaf_waf_group_web_page_tamper_proof.load_group_web_page_tamper_proof_hub_config,
    ['/export_group_web_page_tamper_proof_hub_config'] = jxwaf_waf_group_web_page_tamper_proof.export_group_web_page_tamper_proof_hub_config,
    ['/waf_get_cache_page_url'] = jxwaf_waf_group_web_page_tamper_proof.waf_get_cache_page_url,
    ['/waf/waf_get_cache_page_url'] = jxwaf_waf_group_web_page_tamper_proof.waf_get_cache_page_url,
    
    ['/get_group_flow_engine_protection'] = jxwaf_waf_group_flow_engine_protection.get_group_flow_engine_protection,
    ['/edit_group_flow_engine_protection'] = jxwaf_waf_group_flow_engine_protection.edit_group_flow_engine_protection,

    ['/get_group_flow_rule_protection_list'] = jxwaf_waf_group_flow_rule_protection.get_group_flow_rule_protection_list,
    ['/get_group_flow_rule_protection'] = jxwaf_waf_group_flow_rule_protection.get_group_flow_rule_protection,
    ['/create_group_flow_rule_protection'] = jxwaf_waf_group_flow_rule_protection.create_group_flow_rule_protection,
    ['/delete_group_flow_rule_protection'] = jxwaf_waf_group_flow_rule_protection.delete_group_flow_rule_protection,
    ['/edit_group_flow_rule_protection'] = jxwaf_waf_group_flow_rule_protection.edit_group_flow_rule_protection,
    ['/edit_group_flow_rule_protection_status'] = jxwaf_waf_group_flow_rule_protection.edit_group_flow_rule_protection_status,
['/exchange_group_flow_rule_protection_priority'] =jxwaf_waf_group_flow_rule_protection.exchange_group_flow_rule_protection_priority,
    ['/backup_group_flow_rule_protection'] = jxwaf_waf_group_flow_rule_protection.backup_group_flow_rule_protection,
    ['/load_group_flow_rule_protection'] = jxwaf_waf_group_flow_rule_protection.load_group_flow_rule_protection,
    ['/load_group_flow_rule_protection_hub_config'] =  jxwaf_waf_group_flow_rule_protection.load_group_flow_rule_protection_hub_config,
    ['/export_group_flow_rule_protection_hub_config'] = jxwaf_waf_group_flow_rule_protection.export_group_flow_rule_protection_hub_config,

    ['/get_group_flow_white_rule_list'] = jxwaf_waf_group_flow_white_rule.get_group_flow_white_rule_list,
    ['/get_group_flow_white_rule'] = jxwaf_waf_group_flow_white_rule.get_group_flow_white_rule,
    ['/create_group_flow_white_rule'] = jxwaf_waf_group_flow_white_rule.create_group_flow_white_rule,
    ['/delete_group_flow_white_rule'] = jxwaf_waf_group_flow_white_rule.delete_group_flow_white_rule,
    ['/edit_group_flow_white_rule'] = jxwaf_waf_group_flow_white_rule.edit_group_flow_white_rule,
    ['/edit_group_flow_white_rule_status'] = jxwaf_waf_group_flow_white_rule.edit_group_flow_white_rule_status,
    ['/exchange_group_flow_white_rule_priority'] = jxwaf_waf_group_flow_white_rule.exchange_group_flow_white_rule_priority,
    ['/backup_group_flow_white_rule'] = jxwaf_waf_group_flow_white_rule.backup_group_flow_white_rule,
    ['/load_group_flow_white_rule'] = jxwaf_waf_group_flow_white_rule.load_group_flow_white_rule,
    ['/load_group_flow_white_rule_hub_config'] = jxwaf_waf_group_flow_white_rule.load_group_flow_white_rule_hub_config,
    ['/export_group_flow_white_rule_hub_config'] = jxwaf_waf_group_flow_white_rule.export_group_flow_white_rule_hub_config,

    ['/get_group_flow_ip_region_block'] = jxwaf_waf_group_flow_ip_region_block.get_group_flow_ip_region_block,
    ['/edit_group_flow_ip_region_block'] = jxwaf_waf_group_flow_ip_region_block.edit_group_flow_ip_region_block,

    ['/get_domain_list'] = jxwaf_waf_domain.get_domain_list,
    ['/get_domain_search_list'] = jxwaf_waf_domain.get_domain_search_list,
    ['/get_domain'] = jxwaf_waf_domain.get_domain,
    ['/create_domain'] = jxwaf_waf_domain.create_domain,
    ['/delete_domain'] = jxwaf_waf_domain.delete_domain,
    ['/edit_domain'] = jxwaf_waf_domain.edit_domain,
    ['/api_get_domain_list'] = jxwaf_waf_domain.api_get_domain_list,

    ['/get_sys_log_conf'] = jxwaf_sys_conf.get_sys_log_conf,
    ['/edit_sys_log_conf'] = jxwaf_sys_conf.edit_sys_log_conf,

    ['/get_sys_report_conf_conf'] = jxwaf_sys_conf.get_sys_report_conf_conf,
    ['/edit_sys_report_conf_conf'] = jxwaf_sys_conf.edit_sys_report_conf_conf,
    ['/test_sys_report_conf_conf'] = jxwaf_sys_conf.test_sys_report_conf_conf,

    ['/get_sys_custom_page_conf'] = jxwaf_sys_conf.get_sys_custom_page_conf,
    ['/edit_sys_custom_page_conf'] = jxwaf_sys_conf.edit_sys_custom_page_conf,

    ['/get_sys_webtds_check_conf'] = jxwaf_sys_conf.get_sys_webtds_check_conf,
    ['/edit_sys_webtds_check_conf'] = jxwaf_sys_conf.edit_sys_webtds_check_conf,

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

    ['/get_group_custom_request_header_list'] = jxwaf_waf_group_custom_request_header.get_group_custom_request_header_list,
    ['/get_group_custom_request_header'] = jxwaf_waf_group_custom_request_header.get_group_custom_request_header,
    ['/create_group_custom_request_header'] = jxwaf_waf_group_custom_request_header.create_group_custom_request_header,
    ['/delete_group_custom_request_header'] = jxwaf_waf_group_custom_request_header.delete_group_custom_request_header,
    ['/edit_group_custom_request_header'] = jxwaf_waf_group_custom_request_header.edit_group_custom_request_header,
    ['/edit_group_custom_request_header_status'] = jxwaf_waf_group_custom_request_header.edit_group_custom_request_header_status,
    ['/exchange_group_custom_request_header_priority'] = jxwaf_waf_group_custom_request_header.exchange_group_custom_request_header_priority,
    ['/backup_group_custom_request_header'] = jxwaf_waf_group_custom_request_header.backup_group_custom_request_header,
    ['/load_group_custom_request_header'] = jxwaf_waf_group_custom_request_header.load_group_custom_request_header,
    ['/load_group_custom_request_header_hub_config'] = jxwaf_waf_group_custom_request_header.load_group_custom_request_header_hub_config,
    ['/export_group_custom_request_header_hub_config'] = jxwaf_waf_group_custom_request_header.export_group_custom_request_header_hub_config,

    ['/get_group_custom_response_header_list'] = jxwaf_waf_group_custom_response_header.get_group_custom_response_header_list,
    ['/get_group_custom_response_header'] = jxwaf_waf_group_custom_response_header.get_group_custom_response_header,
    ['/create_group_custom_response_header'] = jxwaf_waf_group_custom_response_header.create_group_custom_response_header,
    ['/delete_group_custom_response_header'] = jxwaf_waf_group_custom_response_header.delete_group_custom_response_header,
    ['/edit_group_custom_response_header'] = jxwaf_waf_group_custom_response_header.edit_group_custom_response_header,
    ['/edit_group_custom_response_header_status'] = jxwaf_waf_group_custom_response_header.edit_group_custom_response_header_status,
    ['/exchange_group_custom_response_header_priority'] = jxwaf_waf_group_custom_response_header.exchange_group_custom_response_header_priority,
    ['/backup_group_custom_response_header'] = jxwaf_waf_group_custom_response_header.backup_group_custom_response_header,
    ['/load_group_custom_response_header'] = jxwaf_waf_group_custom_response_header.load_group_custom_response_header,
    ['/load_group_custom_response_header_hub_config'] = jxwaf_waf_group_custom_response_header.load_group_custom_response_header_hub_config,
    ['/export_group_custom_response_header_hub_config'] = jxwaf_waf_group_custom_response_header.export_group_custom_response_header_hub_config,

    ['/get_group_custom_response_content_list'] = jxwaf_waf_group_custom_response_content.get_group_custom_response_content_list,
    ['/get_group_custom_response_content'] = jxwaf_waf_group_custom_response_content.get_group_custom_response_content,
    ['/create_group_custom_response_content'] = jxwaf_waf_group_custom_response_content.create_group_custom_response_content,
    ['/delete_group_custom_response_content'] = jxwaf_waf_group_custom_response_content.delete_group_custom_response_content,
    ['/edit_group_custom_response_content'] = jxwaf_waf_group_custom_response_content.edit_group_custom_response_content,
    ['/edit_group_custom_response_content_status'] = jxwaf_waf_group_custom_response_content.edit_group_custom_response_content_status,
    ['/exchange_group_custom_response_content_priority'] = jxwaf_waf_group_custom_response_content.exchange_group_custom_response_content_priority,
    ['/backup_group_custom_response_content'] = jxwaf_waf_group_custom_response_content.backup_group_custom_response_content,
    ['/load_group_custom_response_content'] = jxwaf_waf_group_custom_response_content.load_group_custom_response_content,
    ['/load_group_custom_response_content_hub_config'] = jxwaf_waf_group_custom_response_content.load_group_custom_response_content_hub_config,
    ['/export_group_custom_response_content_hub_config'] = jxwaf_waf_group_custom_response_content.export_group_custom_response_content_hub_config,

    ['/get_group_custom_upstream_address_list'] = jxwaf_waf_group_custom_upstream_address.get_group_custom_upstream_address_list,
    ['/get_group_custom_upstream_address'] = jxwaf_waf_group_custom_upstream_address.get_group_custom_upstream_address,
    ['/create_group_custom_upstream_address'] = jxwaf_waf_group_custom_upstream_address.create_group_custom_upstream_address,
    ['/delete_group_custom_upstream_address'] = jxwaf_waf_group_custom_upstream_address.delete_group_custom_upstream_address,
    ['/edit_group_custom_upstream_address'] = jxwaf_waf_group_custom_upstream_address.edit_group_custom_upstream_address,
    ['/edit_group_custom_upstream_address_status'] = jxwaf_waf_group_custom_upstream_address.edit_group_custom_upstream_address_status,
    ['/exchange_group_custom_upstream_address_priority'] = jxwaf_waf_group_custom_upstream_address.exchange_group_custom_upstream_address_priority,
    ['/backup_group_custom_upstream_address'] = jxwaf_waf_group_custom_upstream_address.backup_group_custom_upstream_address,
    ['/load_group_custom_upstream_address'] = jxwaf_waf_group_custom_upstream_address.load_group_custom_upstream_address,
    ['/load_group_custom_upstream_address_hub_config'] = jxwaf_waf_group_custom_upstream_address.load_group_custom_upstream_address_hub_config,
    ['/export_group_custom_upstream_address_hub_config'] = jxwaf_waf_group_custom_upstream_address.export_group_custom_upstream_address_hub_config,

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


    ['/get_soc_network_ip_list'] = jxwaf_soc_network_ip.get_soc_network_ip_list,
    ['/get_soc_network_ip_search_list'] = jxwaf_soc_network_ip.get_soc_network_ip_search_list,
    ['/create_soc_network_ip'] = jxwaf_soc_network_ip.create_soc_network_ip,
    ['/edit_soc_network_block_ip'] = jxwaf_soc_network_ip.edit_soc_network_block_ip,
    ['/get_soc_network_block_ip'] = jxwaf_soc_network_ip.get_soc_network_block_ip,
    ['/get_soc_network_ip'] = jxwaf_soc_network_ip.get_soc_network_ip,
    ['/edit_soc_network_ip'] = jxwaf_soc_network_ip.edit_soc_network_ip,
    ['/network_block'] = jxwaf_soc_network_ip.network_block,
    ['/sync_network_ip'] = jxwaf_soc_network_ip.sync_network_ip,
    ['/get_soc_network_ip_status'] = jxwaf_soc_network_ip.get_soc_network_ip_status,
    ['/edit_soc_network_ip_status'] = jxwaf_soc_network_ip.edit_soc_network_ip_status,
    ['/get_soc_network_ip_node_update_list'] = jxwaf_soc_network_ip.get_soc_network_ip_node_update_list,

    ['/get_soc_web_attack_count_total'] = jxwaf_soc_web_attack.get_soc_web_attack_count_total,
    ['/get_soc_web_attack_api_count_total'] = jxwaf_soc_web_attack.get_soc_web_attack_api_count_total,
    ['/get_soc_web_attack_ip_count_total'] = jxwaf_soc_web_attack.get_soc_web_attack_ip_count_total,
    ['/get_soc_web_attack_isocode_count_total'] = jxwaf_soc_web_attack.get_soc_web_attack_isocode_count_total,
    ['/get_soc_web_attack_geoip'] = jxwaf_soc_web_attack.get_soc_web_attack_geoip,
    ['/get_soc_web_attack_count_trend'] = jxwaf_soc_web_attack.get_soc_web_attack_count_trend,
    ['/get_soc_web_attack_api_top'] = jxwaf_soc_web_attack.get_soc_web_attack_api_top,
    ['/get_soc_web_attack_type_top'] = jxwaf_soc_web_attack.get_soc_web_attack_type_top,
    ['/get_soc_web_attack_ip_top'] = jxwaf_soc_web_attack.get_soc_web_attack_ip_top,
    ['/get_soc_web_attack_isocode_top'] = jxwaf_soc_web_attack.get_soc_web_attack_isocode_top,


    ['/get_soc_flow_attack_count_total'] = jxwaf_soc_flow_attack.get_soc_flow_attack_count_total,
    ['/get_soc_flow_attack_api_count_total'] = jxwaf_soc_flow_attack.get_soc_flow_attack_api_count_total,
    ['/get_soc_flow_attack_ip_count_total'] = jxwaf_soc_flow_attack.get_soc_flow_attack_ip_count_total,
    ['/get_soc_flow_attack_isocode_count_total'] = jxwaf_soc_flow_attack.get_soc_flow_attack_isocode_count_total,
    ['/get_soc_flow_attack_geoip'] = jxwaf_soc_flow_attack.get_soc_flow_attack_geoip,
    ['/get_soc_flow_attack_count_trend'] = jxwaf_soc_flow_attack.get_soc_flow_attack_count_trend,
    ['/get_soc_flow_attack_api_top'] = jxwaf_soc_flow_attack.get_soc_flow_attack_api_top,
    ['/get_soc_flow_attack_type_top'] = jxwaf_soc_flow_attack.get_soc_flow_attack_type_top,
    ['/get_soc_flow_attack_ip_top'] = jxwaf_soc_flow_attack.get_soc_flow_attack_ip_top,
    ['/get_soc_flow_attack_isocode_top'] = jxwaf_soc_flow_attack.get_soc_flow_attack_isocode_top,

    ['/get_soc_attack_event_list'] = jxwaf_soc_attack_event.get_soc_attack_event_list,
    ['/get_soc_attack_behave_track'] = jxwaf_soc_attack_event.get_soc_attack_behave_track,

    ['/get_soc_log_query_list'] = jxwaf_soc_log_query.get_soc_log_query_list,

    ['/get_node_monitor_list'] = jxwaf_node_monitor.get_node_monitor_list,
    ['/delete_node_monitor'] = jxwaf_node_monitor.delete_node_monitor,

    ['/waf_conf_backup'] = jxwaf_sys_conf.waf_conf_backup,
    ['/waf_conf_load'] = jxwaf_sys_conf.waf_conf_load,
    ['/get_soc_web_protection_model_list'] = jxwaf_soc_web_protection_model.get_soc_web_protection_model_list,
    ['/delete_soc_web_protection_model'] = jxwaf_soc_web_protection_model.delete_soc_web_protection_model,
    ['/edit_soc_web_protection_model_result'] = jxwaf_soc_web_protection_model.edit_soc_web_protection_model_result,
}

local handler = uri_route_map[uri]

if handler then
    handler()
end


