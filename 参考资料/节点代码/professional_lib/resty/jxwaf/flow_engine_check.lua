local table_insert = table.insert
local table_concat = table.concat
local request = require "resty.jxwaf.request" 
local cjson = require "cjson.safe"
local unify_action = require "resty.jxwaf.unify_action"

local _M = {}
_M.version = ""

function _M.ip_access_limit_check(conf_data,sys_conf_data,config_info)
    local stat_time = tonumber(conf_data['ip_access_limit_stat_time'])
    local threshold = tonumber(conf_data['ip_access_limit_threshold'])
    local ip_access_limit_action =  conf_data['ip_access_limit_action']
    local ip_access_limit_action_extra_parameter = conf_data['ip_access_limit_action_extra_parameter']
    local duration = tonumber(conf_data['ip_access_limit_duration'])
    local ip_access_limit_block = ngx.shared.ip_access_limit_block
    local src_ip =  request.get_args("http_args","src_ip")
    local block_result = ip_access_limit_block:get(src_ip)
    if block_result then
      local block_action = cjson.decode(block_result)
      local waf_action = block_action['waf_action']
      local waf_extra = block_action['waf_extra']
      local waf_log = {}
      waf_log['waf_module'] = "flow_engine_protection"
      waf_log['waf_policy'] = "IP访问限制"
      waf_log['waf_action'] = waf_action
      waf_log['waf_extra'] = waf_extra
      ngx.ctx.waf_log = waf_log
      if waf_action == "block" then
        local page_conf = {}
        if sys_conf_data['custom_deny_page'] == 'true' then
          page_conf['code'] = sys_conf_data['waf_deny_code']
          page_conf['html'] = sys_conf_data['waf_deny_html']
        end
        unify_action.block(page_conf)
      elseif waf_action == "reject_response" then
        unify_action.reject_response()
      elseif waf_action == "bot_check" then
        unify_action.bot_commit_auth()
        unify_action.bot_check_ip(waf_extra)
      elseif waf_action == "network_block" then
        unify_action.network_block(config_info,src_ip,waf_extra)
      end
      return
    end
  local ip_access_limit_stat = ngx.shared.ip_access_limit_stat
  local request_count = ip_access_limit_stat:incr(src_ip,1,0,stat_time)
  if request_count  > threshold then
     local block_action = {}
     block_action['waf_action'] = ip_access_limit_action
     block_action['waf_extra'] = ip_access_limit_action_extra_parameter
     ip_access_limit_block:set(src_ip,cjson.encode(block_action),duration)
  end
  return
end

function _M.ip_count_limit_check(conf_data,sys_conf_data,config_info)
    local stat_time = tonumber(conf_data['ip_count_limit_stat_time'])
    local threshold = tonumber(conf_data['ip_count_limit_threshold'])
    local waf_action = conf_data['ip_count_limit_action']
    local waf_extra = conf_data['ip_count_limit_action_extra_parameter']

    local domain_key =  request.get_args("http_args","host")
    local src_ip =  request.get_args("http_args","src_ip")
    local ip_count_limit_log = ngx.shared.ip_count_limit_log
    local exist_ip = ip_count_limit_log:get(src_ip)
    if not exist_ip then
        local ip_count_limit_stat = ngx.shared.ip_count_limit_stat
        local request_ip_count = ip_count_limit_stat:incr(domain_key,1,0,stat_time)
        if request_ip_count > threshold then
          local waf_log = {}
          waf_log['waf_module'] = "flow_engine_protection"
          waf_log['waf_policy'] = "IP数量限制"
          waf_log['waf_action'] = waf_action
          waf_log['waf_extra'] = waf_extra
          ngx.ctx.waf_log = waf_log
          if waf_action == "block" then
            local page_conf = {}
            if sys_conf_data['custom_deny_page'] == 'true' then
              page_conf['code'] = sys_conf_data['waf_deny_code']
              page_conf['html'] = sys_conf_data['waf_deny_html']
            end
            unify_action.block(page_conf)
          elseif waf_action == "reject_response" then
            unify_action.reject_response()
          elseif waf_action == "bot_check" then
            unify_action.bot_commit_auth()
            unify_action.bot_check_ip(waf_extra)
          elseif waf_action == "network_block" then
            unify_action.network_block(config_info,src_ip,waf_extra)
          end
          return 
        end
        ip_count_limit_log:set(src_ip,true,stat_time)
    end
end


function _M.domain_access_limit_check(conf_data,sys_conf_data,config_info)
    local stat_time = tonumber(conf_data['domain_access_limit_stat_time'])
    local threshold =  tonumber(conf_data['domain_access_limit_threshold'])
    local waf_action = conf_data['domain_access_limit_action']
    local waf_extra = conf_data['domain_access_limit_action_extra_parameter']
    local domain_key =  request.get_args("http_args","host")
    local src_ip =  request.get_args("http_args","src_ip")
    local domain_access_limit_stat = ngx.shared.domain_access_limit_stat
    local request_count = domain_access_limit_stat:incr(domain_key,1,0,stat_time)
    if request_count  > threshold then
        local waf_log = {}
        waf_log['waf_module'] = "flow_engine_protection"
        waf_log['waf_policy'] = "域名访问限制"
        waf_log['waf_action'] = waf_action
        waf_log['waf_extra'] = waf_extra
        ngx.ctx.waf_log = waf_log
        if waf_action == "block" then
          local page_conf = {}
          if sys_conf_data['custom_deny_page'] == 'true' then
            page_conf['code'] = sys_conf_data['waf_deny_code']
            page_conf['html'] = sys_conf_data['waf_deny_html']
          end
          unify_action.block(page_conf)
        elseif waf_action == "reject_response" then
          unify_action.reject_response()
        elseif waf_action == "bot_check" then
          unify_action.bot_commit_auth()
          unify_action.bot_check_ip(waf_extra)
        elseif waf_action == "network_block" then
          unify_action.network_block(config_info,src_ip,waf_extra)
        end
        return 
    end
end

function _M.ssl_fingerprint_protection_check(conf_data,sys_conf_data,config_info)
    local scheme = ngx.var.scheme
    if scheme ~= 'https' then
      return
    end
    local waf_action = conf_data['ssl_fingerprint_protection_action']
    local waf_extra = conf_data['ssl_fingerprint_protection_action_extra_parameter']
    local src_ip =  request.get_args("http_args","src_ip")
    local check_result = true
    local ssl_client_hello_signature_algorithms_has_grease = ngx.ctx.ssl_client_hello_signature_algorithms_has_grease
    local ssl_client_hello_supported_groups_has_grease = ngx.ctx.ssl_client_hello_supported_groups_has_grease
    local ssl_ciphers = ngx.var.ssl_ciphers or ''
    local ssl_ciphers_has_grease = ngx.re.find(ssl_ciphers, [[0x([0-9A-Fa-f]{2})\1]], "jo")
    if ssl_ciphers_has_grease and (ssl_client_hello_signature_algorithms_has_grease or ssl_client_hello_supported_groups_has_grease) then
      check_result = false
    end
    if check_result then
        local waf_log = {}
        waf_log['waf_module'] = "flow_engine_protection"
        waf_log['waf_policy'] = "SSL指纹防护"
        waf_log['waf_action'] = waf_action
        waf_log['waf_extra'] = waf_extra
        ngx.ctx.waf_log = waf_log
        if waf_action == "block" then
          local page_conf = {}
          if sys_conf_data['custom_deny_page'] == 'true' then
            page_conf['code'] = sys_conf_data['waf_deny_code']
            page_conf['html'] = sys_conf_data['waf_deny_html']
          end
          unify_action.block(page_conf)
        elseif waf_action == "reject_response" then
          unify_action.reject_response()
        elseif waf_action == "bot_check" then
          unify_action.bot_commit_auth()
          unify_action.bot_check_ip(waf_extra)
        elseif waf_action == "network_block" then
          unify_action.network_block(config_info,src_ip,waf_extra)
        end
        return 
    end
end


function _M.emergency_protection_check(conf_data,sys_conf_data,config_info)
  local waf_action = conf_data['emergency_protection_action']
  local waf_extra = conf_data['emergency_protection_action_extra_parameter']
  local src_ip =  request.get_args("http_args","src_ip")
  local waf_log = {}
  waf_log['waf_module'] = "flow_engine_protection"
  waf_log['waf_policy'] = "无差别紧急防护"
  waf_log['waf_action'] = waf_action
  waf_log['waf_extra'] = waf_extra
  ngx.ctx.waf_log = waf_log
  if waf_action == "block" then
    local page_conf = {}
    if sys_conf_data['custom_deny_page'] == 'true' then
      page_conf['code'] = sys_conf_data['waf_deny_code']
      page_conf['html'] = sys_conf_data['waf_deny_html']
    end
    unify_action.block(page_conf)
  elseif waf_action == "reject_response" then
    unify_action.reject_response()
  elseif waf_action == "bot_check" then
    unify_action.bot_commit_auth()
    unify_action.bot_check_ip(waf_extra)
  elseif waf_action == "network_block" then
    unify_action.network_block(config_info,src_ip,waf_extra)
  end
  return
end


return _M
