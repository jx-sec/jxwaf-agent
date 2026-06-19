local waf = require "resty.jxwaf.waf"
local unify_action = require "resty.jxwaf.unify_action"

local access_init_result,access_init_error = pcall(waf.access_init)
if not access_init_result then
  ngx.log(ngx.ERR,access_init_error)
end

local component_result,component_error = pcall(waf.base_component)
if not component_result then
  ngx.log(ngx.ERR,component_error)
end

local name_list_result,name_list_error = pcall(waf.global_name_list)
if not name_list_result then
  ngx.log(ngx.ERR,name_list_error)
end

local domain_check_result,domain_check_error = pcall(waf.domain_check)
if not domain_check_result then
  ngx.log(ngx.ERR,domain_check_error)
end

local bot_commit_auth_result,bot_commit_auth_error = pcall(unify_action.bot_commit_auth)
if not bot_commit_auth_result then
  ngx.log(ngx.ERR,bot_commit_auth_error)
end

local flow_white_rule_result,flow_white_rule_error = pcall(waf.flow_white_rule)
if not flow_white_rule_result then
  ngx.log(ngx.ERR,flow_white_rule_error)
end

local flow_ip_region_block_result,flow_ip_region_block_error = pcall(waf.flow_ip_region_block)
if not flow_ip_region_block_result then
  ngx.log(ngx.ERR,flow_ip_region_block_error)
end

local flow_rule_protection_result,flow_rule_protection_error = pcall(waf.flow_rule_protection)
if not flow_rule_protection_result then
  ngx.log(ngx.ERR,flow_rule_protection_error)
end

local flow_engine_protection_result,flow_engine_protection_error = pcall(waf.flow_engine_protection)
if not flow_engine_protection_result then
  ngx.log(ngx.ERR,flow_engine_protection_error)
end

local web_white_rule_result,web_white_rule_error = pcall(waf.web_white_rule)
if not web_white_rule_result then
  ngx.log(ngx.ERR,web_white_rule_error)
end

local web_rule_protection_result,web_rule_protection_error = pcall(waf.web_rule_protection)
if not web_rule_protection_result then
  ngx.log(ngx.ERR,web_rule_protection_error)
end


local web_engine_protection_result,web_engine_protection_error = pcall(waf.web_engine_protection)
if not web_engine_protection_result then
  ngx.log(ngx.ERR,web_engine_protection_error)
end

local web_page_tamper_proof_result,web_page_tamper_proof_error = pcall(waf.web_page_tamper_proof)
if not web_page_tamper_proof_result then
  ngx.log(ngx.ERR,web_page_tamper_proof_error)
end

local custom_request_header_result,custom_request_header_error = pcall(waf.custom_request_header)
if not custom_request_header_result then
  ngx.log(ngx.ERR,custom_request_header_error)
end

local custom_response_header_result,custom_response_header_error = pcall(waf.custom_response_header)
if not custom_response_header_result then
  ngx.log(ngx.ERR,custom_response_header_error)
end

local custom_response_content_result,custom_response_content_error = pcall(waf.custom_response_content)
if not custom_response_content_result then
  ngx.log(ngx.ERR,custom_response_content_error)
end

local custom_upstream_address_result,custom_upstream_address_error = pcall(waf.custom_upstream_address)
if not custom_upstream_address_result then
  ngx.log(ngx.ERR,custom_upstream_address_error)
end

local init_jxwaf_devid_result,init_jxwaf_devid_error = pcall(waf.init_jxwaf_devid)
if not init_jxwaf_devid_result then
  ngx.log(ngx.ERR,init_jxwaf_devid_error)
end






