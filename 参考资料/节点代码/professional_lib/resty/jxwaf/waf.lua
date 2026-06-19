local cjson = require "cjson.safe"
local request = require "resty.jxwaf.request"
local preprocess = require "resty.jxwaf.preprocess"
local operator = require "resty.jxwaf.operator"
local resty_random = require "resty.random"
local pairs = pairs
local ipairs = ipairs
local table_insert = table.insert
local table_sort = table.sort
local table_concat = table.concat
local http = require "resty.jxwaf.http"
local upload = require "resty.upload"
local unify_action = require "resty.jxwaf.unify_action"
local uuid = require "resty.jxwaf.uuid"
local ngx_md5 = ngx.md5
local string_find = string.find
local string_sub = string.sub
local loadstring = loadstring
local tonumber = tonumber
local type = type
local string_lower = string.lower
local process = require "ngx.process"
local ngx_decode_base64 = ngx.decode_base64
local geo = require 'resty.jxwaf.maxminddb'
local iputils = require 'resty.jxwaf.iputils'
local ssl = require "ngx.ssl"
local flow_engine_check = require "resty.jxwaf.flow_engine_check"
local resty_string = require "resty.string"


local _M = {}
_M.version = ""
local _config_geo_path = "/opt/jxwaf/nginx/conf/jxwaf/GeoLite2.mmdb"

_config_info = {}
local _waf_conf_md5 = ""
local _name_list_item_conf_md5 = ""
local _fail_update_period = 60
local _auto_update_period = 3
local _waf_node_monitor_period = 60
local _waf_domain_data = {}
local _waf_domain_conf_data = {}
local _waf_global_name_list_data = {}
local _waf_global_name_list_item_data = {}
local _waf_component_data = {}
local _waf_component_code = {}
local _waf_analysis_component_data = {}
local _waf_analysis_component_code = {}
local _waf_ssl_manage_data = {}
local _sys_conf_data = {}
local _jxwaf_engine

local _model_data = {}
local _model_update_time = ""

function _M.get_config_info()
	return _config_info
end

function _M.get_waf_domain_data()
	return _waf_domain_data
end

function _M.get_waf_domain_conf_data()
	return _waf_domain_conf_data
end

function _M.get_waf_ssl_manage_data()
	return _waf_ssl_manage_data
end

function _M.get_sys_conf_data()
	return _sys_conf_data
end

local function _update_at(auto_update_period,global_update_rule)
  local global_ok, global_err = ngx.timer.at(tonumber(auto_update_period),global_update_rule)
  if not global_ok then
    if global_err ~= "process exiting" then
      ngx.log(ngx.ERR, "failed to create the cycle timer: ", global_err)
    end
  end
end

local function _monitor_update()
    local _update_website  =  _config_info.jxwaf_server.."/waf_monitor"
    local httpc = http.new()
    local post_data = {}
    post_data['waf_auth'] = _config_info.waf_auth
    post_data['waf_node_uuid'] = _config_info.waf_node_uuid
    post_data['waf_node_hostname'] = _config_info.waf_node_hostname
    local res, err = httpc:request_uri( _update_website , {
        method = "POST",
        body = cjson.encode(post_data),
        headers = {
        ["Content-Type"] = "application/json",
        }
    })
    if not res then
      ngx.log(ngx.ERR,"failed to request: ", err)
      return _update_at(tonumber(_fail_update_period),_monitor_update)
    end
		local res_body = cjson.decode(res.body)
		if not res_body then
      ngx.log(ngx.ERR,"init fail,failed to decode resp body " )
      return _update_at(tonumber(_fail_update_period),_monitor_update)
		end
    if  res_body['result'] == false then
      ngx.log(ngx.ERR,"init fail,failed to request, ",res_body['message'])
      return _update_at(tonumber(_fail_update_period),_monitor_update)
    end
    local global_ok, global_err = ngx.timer.at(tonumber(_waf_node_monitor_period),_monitor_update)
    if not global_ok then
      if global_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the cycle timer: ", global_err)
      end
    end
end


local function _global_update_rule()
    local _update_website  =  _config_info.jxwaf_server.."/waf_update"
    local httpc = http.new()
    httpc:set_timeouts(5000, 5000, 30000)
    local post_data = {}
    post_data['waf_auth'] = _config_info.waf_auth
    post_data['waf_conf_md5'] = _waf_conf_md5
    post_data['waf_node_uuid'] = _config_info.waf_node_uuid
    local res, err = httpc:request_uri( _update_website , {
        method = "POST",
        body = cjson.encode(post_data)
    })

    if not res then
      ngx.log(ngx.ERR,"failed to request: ", err)
      ngx.log(ngx.ERR,"60 seconds and try again ")
      return _update_at(tonumber(_fail_update_period),_global_update_rule)
    end

		local res_body = cjson.decode(res.body)
		if not res_body then
      ngx.log(ngx.ERR,"init fail,failed to decode resp body " )
      ngx.log(ngx.ERR,"60 seconds and try again ")
      return _update_at(tonumber(_fail_update_period),_global_update_rule)
		end

    if  res_body['result'] ~= true  then
      ngx.log(ngx.ERR,"init fail,failed to request, ",res_body['message'])
      ngx.log(ngx.ERR,"60 seconds and try again ")
      return _update_at(tonumber(_fail_update_period),_global_update_rule)
    end

    if not res_body['configure_without_change'] then
      local waf_conf_data = ngx.shared.waf_conf_data
      local conf_data = res_body['waf_conf_data']
      local waf_domain_data = conf_data['waf_domain_data']
      if waf_domain_data == nil then
        ngx.log(ngx.ERR,"waf_domain_data update fail")
        ngx.log(ngx.ERR,"60 seconds and try again ")
        return _update_at(tonumber(_fail_update_period),_global_update_rule)
      end

      local waf_domain_conf_data = conf_data['waf_domain_conf_data']
      if waf_domain_conf_data == nil   then
        ngx.log(ngx.ERR,"waf_domain_conf_data update fail")
        ngx.log(ngx.ERR,"60 seconds and try again ")
        return _update_at(tonumber(_fail_update_period),_global_update_rule)
      end

      local waf_global_name_list_data = conf_data['waf_global_name_list_data']
      if waf_global_name_list_data == nil then
        ngx.log(ngx.ERR,"waf_global_name_list_data update fail")
        ngx.log(ngx.ERR,"60 seconds and try again ")
        return _update_at(tonumber(_fail_update_period),_global_update_rule)
      end


      local waf_global_name_list_item_data = conf_data['waf_global_name_list_item_data']
      if waf_global_name_list_item_data == nil then
        ngx.log(ngx.ERR,"waf_global_name_list_item_data update fail")
        ngx.log(ngx.ERR,"60 seconds and try again ")
        return _update_at(tonumber(_fail_update_period),_global_update_rule)
      end

      local waf_component_data = conf_data['waf_component_data']
      if waf_component_data == nil then
        ngx.log(ngx.ERR,"waf_component_data update fail")
        ngx.log(ngx.ERR,"60 seconds and try again ")
        return _update_at(tonumber(_fail_update_period),_global_update_rule)
      end

      for _,v in ipairs(waf_component_data) do
        local name = v['name']
        local code = v['code']
        if ngx.decode_base64(code) and loadstring(ngx.decode_base64(code)) then
          local load_component_data = loadstring(ngx.decode_base64(code))()
          if load_component_data then
            _waf_component_code[name] = load_component_data
          else
            ngx.log(ngx.ERR,"init fail,can not decode component_data,name is "..name)
          end
        else
          ngx.log(ngx.ERR,"init fail,can not decode component_data,name is "..name)
        end
      end

      local waf_ssl_manage_data = conf_data['waf_ssl_manage_data']
      if waf_ssl_manage_data == nil then
        ngx.log(ngx.ERR,"waf_ssl_manage_data update fail")
        ngx.log(ngx.ERR,"60 seconds and try again ")
        return _update_at(tonumber(_fail_update_period),_global_update_rule)
      end

      local sys_conf_data = conf_data['sys_conf_data']
      if sys_conf_data == nil then
        ngx.log(ngx.ERR,"sys_conf_data update fail")
        ngx.log(ngx.ERR,"60 seconds and try again ")
        return _update_at(tonumber(_fail_update_period),_global_update_rule)
      end

      local res_body_succ, res_body_err = waf_conf_data:set("res_body",res.body)
      if res_body_err then
        ngx.log(ngx.ERR,"init fail,can not set res_body")
        return _update_at(_auto_update_period,_global_update_rule)
      end

      local md5_succ, md5_err = waf_conf_data:set("waf_conf_md5",res_body['waf_conf_md5'])
      if md5_err then
        ngx.log(ngx.ERR,"init fail,can not set waf_conf_data md5")
        return _update_at(_auto_update_period,_global_update_rule)
      end

      _waf_conf_md5 = res_body['waf_conf_md5']
      ngx.log(ngx.ALERT,"update config info success,global config info md5 is ".._waf_conf_md5..",")
    end

    local global_ok, global_err = ngx.timer.at(_auto_update_period,_global_update_rule)
    if not global_ok then
      if global_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the cycle timer: ", global_err)
      end
    end
end

local function _worker_update_rule()
  local waf_conf_data = ngx.shared.waf_conf_data
  local waf_conf_md5 = waf_conf_data:get("waf_conf_md5")

  if waf_conf_md5 and waf_conf_md5 ~= _waf_conf_md5 then
    local tmp_res_body = waf_conf_data:get("res_body")

    if not tmp_res_body then
      ngx.log(ngx.ERR,"worker error,init fail,failed to get resp body " )
    end
    local res_body = cjson.decode(tmp_res_body)
		if not res_body then
      ngx.log(ngx.ERR,"worker error,init fail,failed to decode resp body " )
		end
    local conf_data = res_body['waf_conf_data']

    local waf_domain_data = conf_data['waf_domain_data']
    if waf_domain_data == nil  then
      ngx.log(ngx.ERR,"init fail,can not decode waf_domain_data")
    else
      _waf_domain_data = waf_domain_data
    end

    local waf_domain_conf_data = conf_data['waf_domain_conf_data']
    if waf_domain_conf_data == nil  then
      ngx.log(ngx.ERR,"init fail,can not decode waf_domain_conf_data")
    else
      _waf_domain_conf_data = waf_domain_conf_data
    end

    local waf_global_name_list_data = conf_data['waf_global_name_list_data']
    if waf_global_name_list_data == nil  then
      ngx.log(ngx.ERR,"init fail,can not decode waf_global_name_list_data")
    else
      _waf_global_name_list_data = waf_global_name_list_data
    end

    local waf_global_name_list_item_data = conf_data['waf_global_name_list_item_data']
    if waf_global_name_list_item_data == nil  then
      ngx.log(ngx.ERR,"init fail,can not decode waf_global_name_list_item_data")
    else
      _waf_global_name_list_item_data = waf_global_name_list_item_data
    end

    local waf_component_data = conf_data['waf_component_data']
    if waf_component_data == nil  then
      ngx.log(ngx.ERR,"init fail,can not decode waf_component_data")
    else
      _waf_component_data = waf_component_data
      for _,v in ipairs(waf_component_data) do
        local name = v['name']
        local code = v['code']
        if ngx.decode_base64(code) and loadstring(ngx.decode_base64(code)) then
          local load_component_data = loadstring(ngx.decode_base64(code))()
          if load_component_data then
            _waf_component_code[name] = load_component_data
          else
            ngx.log(ngx.ERR,"init fail,can not decode component_data,name is "..name)
          end
        else
          ngx.log(ngx.ERR,"init fail,can not decode component_data,name is "..name)
        end
      end
    end

    
    local waf_ssl_manage_data = conf_data['waf_ssl_manage_data']
    if waf_ssl_manage_data == nil then
        ngx.log(ngx.ERR, "init fail,can not decode waf_ssl_manage_data")
    else
        -- 遍历所有证书配置，预先进行 PEM 转 DER 计算
        for domain, data in pairs(waf_ssl_manage_data) do
            -- 转换公钥证书
            local pub_key = data["public_key"]
            if pub_key then
                local der_cert, err = ssl.cert_pem_to_der(pub_key)
                if der_cert then
                    data["der_public_key"] = der_cert
                else
                    ngx.log(ngx.ERR, "failed to convert cert PEM to DER in init_worker for ", domain, ": ", err)
                end
            end

            -- 转换私钥
            local priv_key = data["private_key"]
            if priv_key then
                local der_key, err = ssl.priv_key_pem_to_der(priv_key)
                if der_key then
                    data["der_private_key"] = der_key
                else
                    ngx.log(ngx.ERR, "failed to convert key PEM to DER in init_worker for ", domain, ": ", err)
                end
            end
        end

        _waf_ssl_manage_data = waf_ssl_manage_data
    end


    local sys_conf_data = conf_data['sys_conf_data']
    if sys_conf_data == nil then
      ngx.log(ngx.ERR,"init fail,can not decode sys_conf_data")
    else
      _sys_conf_data = sys_conf_data
    end

    _waf_conf_md5 = res_body['waf_conf_md5']
  end
end


local function _global_update_model()
    local _update_website  =  _config_info.jxwaf_server.."/model_update"
    local httpc = http.new()
    httpc:set_timeouts(5000, 5000, 30000)
    local post_data = {}
    post_data['waf_auth'] = _config_info.waf_auth
    post_data['model_update_time'] = _model_update_time

    local res, err = httpc:request_uri( _update_website , {
        method = "POST",
        body = cjson.encode(post_data)
    })

    if not res then
      ngx.log(ngx.ERR,"failed to request: ", err)
      ngx.log(ngx.ERR,"60 seconds and try again ")
      return _update_at(tonumber(_fail_update_period),_global_update_model)
    end

		local res_body = cjson.decode(res.body)
		if not res_body then
      ngx.log(ngx.ERR,"init fail,failed to decode resp body " )
      ngx.log(ngx.ERR,"60 seconds and try again ")
      return _update_at(tonumber(_fail_update_period),_global_update_model)
		end

    if  res_body['result'] ~= true  then
      ngx.log(ngx.ERR,"init fail,failed to request, ",res_body['message'])
      ngx.log(ngx.ERR,"60 seconds and try again ")
      return _update_at(tonumber(_fail_update_period),_global_update_model)
    end


    local waf_conf_data = ngx.shared.waf_conf_data

    if res_body['model_update'] == 'true' then
        local model_data = res_body['model_data']
        local model_update_time = res_body['model_update_time']
        if model_data == nil then
          ngx.log(ngx.ERR,"model_data update fail")
          ngx.log(ngx.ERR,"60 seconds and try again ")
          return _update_at(tonumber(_fail_update_period),_global_update_model)
        end

        if model_update_time == nil then
          ngx.log(ngx.ERR,"model_update_time update fail")
          ngx.log(ngx.ERR,"60 seconds and try again ")
          return _update_at(tonumber(_fail_update_period),_global_update_model)
        end
        waf_conf_data:set("model_data",cjson.encode(model_data))
        waf_conf_data:set("model_update_time",model_update_time)
        _model_update_time = model_update_time
        ngx.log(ngx.ALERT,"update model success,model_update_time is "..model_update_time)
    end

    local global_ok, global_err = ngx.timer.at(_auto_update_period,_global_update_model)
    if not global_ok then
      if global_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the cycle timer: ", global_err)
      end
    end

end

local function _worker_update_model()
  local waf_conf_data = ngx.shared.waf_conf_data
  local model_update_time = waf_conf_data:get("model_update_time")
  if model_update_time and model_update_time > _model_update_time then
      local tmp_model_data = waf_conf_data:get("model_data")
      if not tmp_model_data then
        ngx.log(ngx.ERR,"worker error,init fail,failed to get tmp_model_data " )
      end
      local model_data = cjson.decode(tmp_model_data)
      if model_data then
          for k,v in pairs(model_data) do
            _model_data[k] = v
          end
          _model_update_time = model_update_time
          ngx.log(ngx.ALERT,"worker update model success,model_update_time is "..model_update_time)
      else
         ngx.log(ngx.ERR,"init fail,can not decode model_data")
      end
  end
end

function _M.init_worker()
  if not _jxwaf_engine then
    return
  end
  if process.type() == "privileged agent" then
    local monitor_ok,monitor_err = ngx.timer.at(0,_monitor_update)
    if not monitor_ok then
      if monitor_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the init timer: ", monitor_err)
      end
    end

    local init_ok,init_err = ngx.timer.at(3,_global_update_rule)
    if not init_ok then
      if init_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the init global timer: ", init_err)
      end
    end

    local model_init_ok,model_init_err = ngx.timer.at(3,_global_update_model)
    if not model_init_ok then
      if model_init_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the init global timer: ", model_init_err)
      end
    end
  else
    local worker_init_ok,worker_init_err = ngx.timer.at(0,_worker_update_rule)
    if not worker_init_ok then
      if worker_init_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the init worker timer: ", worker_init_err)
      end
    end
    local worker_init_hdl, worker_init_err = ngx.timer.every(3,_worker_update_rule)
    if worker_init_err then
      ngx.log(ngx.ERR, "failed to create the worker update timer: ", worker_init_err)
    end

    local model_worker_init_ok,model_worker_init_err = ngx.timer.at(0,_worker_update_model)
    if not model_worker_init_ok then
      if model_worker_init_err ~= "process exiting" then
        ngx.log(ngx.ERR, "failed to create the init worker timer: ", model_worker_init_err)
      end
    end
    local model_worker_init_hdl, model_worker_init_err = ngx.timer.every(3,_worker_update_model)
    if model_worker_init_err then
      ngx.log(ngx.ERR, "failed to create the model worker update timer: ", model_worker_init_err)
    end

  end
end

function _M.init(config_path,jxcore_path)
	local init_config_path = config_path
	local read_config = assert(io.open(init_config_path,'r+'))
	local raw_config_info = read_config:read('*all')
    read_config:close()
	local config_info = cjson.decode(raw_config_info)
	if config_info == nil then
     error("init fail,can not decode config file")
	end
  if not config_info['waf_node_uuid'] then
    local waf_node_uuid = uuid.generate_random()
    config_info['waf_node_uuid'] = waf_node_uuid
    local new_config_info = cjson.encode(config_info)
    local write_config = assert(io.open(init_config_path,'w+'))
    write_config:write(new_config_info)
    write_config:close()
  end
  _config_info = config_info
  local init_jxcore_path = jxcore_path
  local jxcore_read = assert(io.open(init_jxcore_path,'r+'))
	local raw_jxcore = jxcore_read:read('*all')
  jxcore_read:close()
	if raw_jxcore == nil then
    error("init fail,can not read jxcore")
	end
  local decoded_jxcore = ngx.decode_base64(raw_jxcore) 
  if not decoded_jxcore then
    error("init fail,can not read jxcore")
  end
  local pre_jxwaf_engine = loadstring(decoded_jxcore)()
  if not pre_jxwaf_engine then
    error("init fail,can not read jxcore")
  end
  local init_jxwaf_engine = pre_jxwaf_engine.init()
  if init_jxwaf_engine then
      _jxwaf_engine = init_jxwaf_engine
  else
    error("init fail,can not read jxcore")
  end

  if not geo.initted() then
    geo.init(_config_geo_path)
  end
  if not geo.initted() then
    ngx.log(ngx.ERR,"init geoip fail")
  end

  local ok, err = process.enable_privileged_agent()
  if not ok then
    ngx.log(ngx.ERR, "enables privileged agent failed error:", err)
  end
  ngx.log(ngx.ALERT,"jxwaf init success,waf_node_uuid is ".._config_info['waf_node_uuid'])

  iputils.enable_lrucache()
end

local function is_valid_ip(ip)
    if not ip or type(ip) ~= "string" then
        return false
    end

    -- IPv4验证
    local ipv4_match = ngx.re.match(ip, "^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$", "jo")
    if ipv4_match then
        for i = 1, 4 do
            local num = tonumber(ipv4_match[i])
            if not num or num < 0 or num > 255 then
                return false
            end
        end
        return true
    end

    -- IPv6基础格式验证
    if ngx.re.match(ip, "^[a-fA-F0-9:]+$", "jo") or
       ngx.re.match(ip, "^[a-fA-F0-9:]+\\.\\d+\\.\\d+\\.\\d+\\.\\d+$", "jo") then
        return true
    end

    return false
end

function _M.access_init()
  local host = ngx.var.http_host or ngx.var.host
  local req_host
  local domain_conf_data
  if _waf_domain_data[host] then
    req_host = _waf_domain_data[host]
    domain_conf_data = _waf_domain_conf_data[host]
  else
    local wildcard_host = nil
    local dot_pos = string_find(host,".",1,true)
    if dot_pos then
      wildcard_host = "*"..string_sub(host,dot_pos)
    end
    if wildcard_host and _waf_domain_data[wildcard_host] then
      req_host = _waf_domain_data[wildcard_host]
      domain_conf_data = _waf_domain_conf_data[wildcard_host]
    end
 end

  ngx.ctx.req_host = req_host
  ngx.ctx.domain_conf_data = domain_conf_data

  local request_uuid = uuid.generate_random()
  ngx.ctx.request_uuid = request_uuid

    if req_host  and req_host['pre_proxy'] == 'true' then
         local src_ip = ngx.var.remote_addr
         if req_host['real_ip_conf'] == 'XRI' then
             local xri_ip = ngx.req.get_headers()['X-REAL-IP']
             if xri_ip and type(xri_ip) == 'string' then
                 if is_valid_ip(xri_ip) then
                    ngx.ctx.src_ip = xri_ip
                 end
             elseif xri_ip and type(xri_ip) == 'table' then
                 if is_valid_ip(xri_ip[1]) then
                    ngx.ctx.src_ip = xri_ip[1]
                 end
             end
         elseif req_host['real_ip_conf'] == 'XFF' then
            local xff = ngx.req.get_headers()['X-Forwarded-For']
            if xff and type(xff) == 'string' then
                local first_ip_match = ngx.re.match(xff, "^[^,]*", "jo")
                if first_ip_match and is_valid_ip(first_ip_match[0]) then
                    ngx.ctx.src_ip = first_ip_match[0]
                end
            elseif xff and type(xff) == 'table' then
                local first_ip_match = ngx.re.match(xff[1], "^[^,]*", "jo")
                if first_ip_match and is_valid_ip(first_ip_match[0]) then
                    ngx.ctx.src_ip = first_ip_match[0]
                end
            end
         end
    end

  local iso_code = ""
  if not geo.initted() then
     geo.init(_config_geo_path)
  end
  local src_ip =  request.get_args("http_args","src_ip")
  local res = geo.lookup(src_ip)

  if res and res['country'] then
     iso_code = res['country']['iso_code']
  end

  ngx.ctx.iso_code = iso_code
  -- 提供分组名称，供后续匹配
  ngx.ctx.group_name = req_host['group_name']
end


function _M.base_component()
  for _,web_component_conf in ipairs(_waf_component_data) do
    local component_conf = web_component_conf['conf']
    local component_name = web_component_conf['name']
    if _waf_component_code[component_name] then
      local function_result,return_result = pcall(_waf_component_code[component_name].check,component_conf)
      if not function_result then
        ngx.log(ngx.ERR,"component_protection error name: "..component_name.." ,error_message: "..return_result)
      end
    end
  end
end


function _M.global_name_list()
  for _,name_list_conf in ipairs(_waf_global_name_list_data) do
    local name_list_name = name_list_conf['name_list_name']
    local name_list_rule = name_list_conf['name_list_rule']
    local name_list_action = name_list_conf['name_list_action']
    local action_value = name_list_conf['action_value']
    local name_list_item_data = _waf_global_name_list_item_data[name_list_name]
    if name_list_item_data then
      local item_value_table = {}
      local nil_exist
      for _,rule in ipairs(name_list_rule) do
        local key = rule['key']
        local value = rule['value']
        local return_value = request.get_args(key,value)
        if type(return_value) == "string" or type(return_value) == "number" or type(return_value) == "boolean" then
          table.insert(item_value_table,return_value)
        else
          nil_exist = true
          break
        end
      end
      if not nil_exist then
        local item_value = table.concat(item_value_table)
        if name_list_item_data[item_value] then
          local waf_log = {}
          waf_log['waf_module'] = "name_list"
          waf_log['waf_policy'] = "名单防护-"..name_list_name
          waf_log['waf_action'] = name_list_action
          waf_log['waf_extra'] = item_value
          ngx.ctx.waf_log = waf_log
          if name_list_action == "block"  then
            local page_conf = {}
            if _sys_conf_data['custom_deny_page'] == 'true' then
              page_conf['code'] = _sys_conf_data['waf_deny_code']
              page_conf['html'] = _sys_conf_data['waf_deny_html']
            end
            unify_action.block(page_conf)
          elseif name_list_action == "reject_response"  then
            unify_action.reject_response()
          elseif name_list_action == "network_block"  then
            local src_ip = request.get_args("http_args","src_ip")
            unify_action.network_block(_config_info,src_ip,action_value)
          elseif  name_list_action == "bot_check" then
            unify_action.bot_commit_auth()
            unify_action.bot_check_ip(action_value)
          elseif name_list_action == "all_bypass" then
            ngx.ctx.web_bypass = true
            ngx.ctx.flow_bypass = true
          elseif name_list_action == "web_bypass" then
            ngx.ctx.web_bypass = true
          elseif name_list_action == "flow_bypass" then
            ngx.ctx.flow_bypass = true
          end
        end
      end
    end
  end
end

function _M.domain_check()
  local req_host = ngx.ctx.req_host
  local scheme = ngx.var.scheme
  if (not req_host) or (  req_host[scheme] == "false") then
    local page_conf = {}
    if _sys_conf_data['custom_not_find_page'] == 'true' then
        page_conf['code'] = _sys_conf_data['not_find_code']
        page_conf['html'] = _sys_conf_data['not_find_html']
    else
        page_conf['code'] = "404"
        page_conf['html'] = "domain_is_not_exist"
    end
     return unify_action.not_find(page_conf)
  end
end

function _M.flow_white_rule()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local flow_white_rule_data = domain_conf_data['flow_white_rule_data']
  if not flow_white_rule_data then
    return
  end
  for _,rule_conf in ipairs(flow_white_rule_data) do
    local rule_name = rule_conf['rule_name']
    local rule_matchs = rule_conf['rule_matchs']
    local rule_action = rule_conf['rule_action']
    local action_value = rule_conf['action_value']
    local matchs_result = true
    for _,rule_match in ipairs(rule_matchs) do
        local match_args = rule_match['match_args']
        local args_prepocess = rule_match['args_prepocess']
        local match_operator = rule_match['match_operator']
        local match_value = rule_match['match_value']
        local operator_result = false
        for _,match_arg in ipairs(match_args) do
          local arg = request.get_args(match_arg.key,match_arg.value)
          for _,arg_prepocess in ipairs(args_prepocess) do
                 arg = preprocess.process_args(arg_prepocess,arg)
          end
          if arg or match_operator == 'status_check' then
            local operator_match_result = operator.match(match_operator,arg,match_value)
            if  operator_match_result then
                operator_result =  true
                break
            end
          end
        end
        if (not operator_result) then
          matchs_result = false
          break
        end
    end
    if matchs_result then
      local waf_log = {}
      waf_log['waf_module'] = "flow_white_rule"
      waf_log['waf_policy'] = "流量白名单规则-"..rule_name
      waf_log['waf_action'] = rule_action
      waf_log['waf_extra'] = action_value
      ngx.ctx.waf_log = waf_log
      if rule_action == "flow_bypass" then
        ngx.ctx.flow_bypass = true
      end
    end
  end
end

function _M.flow_ip_region_block()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local flow_ip_region_block_data = domain_conf_data['flow_ip_region_block_data']
  if not flow_ip_region_block_data  or ngx.ctx.flow_bypass then
    return
  end
  local ip_region_block = flow_ip_region_block_data['ip_region_block']
  local check_model = flow_ip_region_block_data['check_model']
  local country_list = flow_ip_region_block_data['country_list']
  local block_action = flow_ip_region_block_data['block_action']
  local action_value = flow_ip_region_block_data['action_value']
  if not (ip_region_block and check_model and country_list and block_action and action_value) then
      return
  end

  if ip_region_block == 'true' then
    local iso_code = ngx.ctx.iso_code
    if not iso_code then
       return
    end
    local check_result
    if check_model == 'black' then
        if country_list[iso_code] then
            check_result = true
        end
    elseif check_model == 'white' then
        if not country_list[iso_code] then
            check_result = true
        end
    end

    if check_result == true then
          local waf_log = {}
          waf_log['waf_module'] = "flow_ip_region_block"
          waf_log['waf_policy'] = "流量防护-IP区域封禁"
          waf_log['waf_action'] = block_action
          waf_log['waf_extra'] = iso_code
          ngx.ctx.waf_log = waf_log
          if block_action == "block"  then
            local page_conf = {}
            if _sys_conf_data['custom_deny_page'] == 'true' then
              page_conf['code'] = _sys_conf_data['waf_deny_code']
              page_conf['html'] = _sys_conf_data['waf_deny_html']
            end
            unify_action.block(page_conf)
          elseif block_action == "reject_response"  then
            unify_action.reject_response()
          elseif block_action == "network_block"  then
            local src_ip = request.get_args("http_args","src_ip")
            unify_action.network_block(_config_info,src_ip,action_value)
          elseif  block_action == "bot_check" then
            unify_action.bot_commit_auth()
            unify_action.bot_check_ip(action_value)
          end
    end
  end
end

function _M.flow_rule_protection()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local flow_rule_protection_data = domain_conf_data['flow_rule_protection_data']
  if  not flow_rule_protection_data  or ngx.ctx.flow_bypass then
    return
  end
  local jxwaf_inner = ngx.shared.jxwaf_inner
  local src_ip =  request.get_args("http_args","src_ip")
  local block_result = jxwaf_inner:get("flow_rule_block"..src_ip)
  if block_result then
    local block_action = cjson.decode(block_result)
    local rule_name = block_action['rule_name']
    local rule_action = block_action['rule_action']
    local action_value = block_action['action_value']
    local waf_log = {}
    waf_log['waf_module'] = "flow_rule_protection"
    waf_log['waf_policy'] = "流量防护规则-"..rule_name
    waf_log['waf_action'] = rule_action
    waf_log['waf_extra'] = action_value
    ngx.ctx.waf_log = waf_log
    if rule_action == "block"  then
      local page_conf = {}
      if _sys_conf_data['custom_deny_page'] == 'true' then
        page_conf['code'] = _sys_conf_data['waf_deny_code']
        page_conf['html'] = _sys_conf_data['waf_deny_html']
      end
      unify_action.block(page_conf)
    elseif rule_action == "reject_response"  then
      unify_action.reject_response()
    elseif  rule_action == "bot_check" then
      unify_action.bot_commit_auth()
      unify_action.bot_check_ip(action_value)
    end
  end

  for _,rule_conf in ipairs(flow_rule_protection_data) do
    local rule_name = rule_conf['rule_name']
    local filter = rule_conf['filter']
    local rule_matchs = rule_conf['rule_matchs']
    local entity = rule_conf['entity']
    local stat_time = tonumber(rule_conf['stat_time'])
    local exceed_count = tonumber(rule_conf['exceed_count'])
    local rule_action = rule_conf['rule_action']
    local action_value = rule_conf['action_value']
    local block_time = tonumber(rule_conf['block_time'])
    local matchs_result = true
    if filter == "true" then
        for _,rule_match in ipairs(rule_matchs) do
            local match_args = rule_match['match_args']
            local args_prepocess = rule_match['args_prepocess']
            local match_operator = rule_match['match_operator']
            local match_value = rule_match['match_value']
            local operator_result = false
            for _,match_arg in ipairs(match_args) do
              local arg = request.get_args(match_arg.key,match_arg.value)
              for _,arg_prepocess in ipairs(args_prepocess) do
                     arg = preprocess.process_args(arg_prepocess,arg)
              end
              if arg or match_operator == 'status_check' then
                local operator_match_result = operator.match(match_operator,arg,match_value)
                if  operator_match_result then
                    operator_result =  true
                    break
                end
              end
            end
            if (not operator_result) then
              matchs_result = false
              break
            end
        end
    end
    if matchs_result then
        local statics_object_table = {}
        statics_object_table[1] = "flow_rule_stat"
        local nil_exist
        for _,v in ipairs(entity) do
          local return_value = request.get_args(v.key,v.value)
          if type(return_value) == "string" then
            table.insert(statics_object_table,return_value)
          elseif type(return_value) == "table" and type(return_value[1]) == "string" then
            table.insert(statics_object_table,return_value[1])
          else
            nil_exist = true
            break
          end
        end
        if not nil_exist then
          local statics_object_key = table.concat(statics_object_table)
          local statics_object_result = jxwaf_inner:incr(statics_object_key,1,0,stat_time)
          if statics_object_result > exceed_count then
            if rule_action == "network_block"  then
                local waf_log = {}
                waf_log['waf_module'] = "flow_rule_protection"
                waf_log['waf_policy'] = "流量防护规则-"..rule_name
                waf_log['waf_action'] = rule_action
                waf_log['waf_extra'] = action_value
                ngx.ctx.waf_log = waf_log
                unify_action.network_block(_config_info,src_ip,action_value)
            end
	        local block_action = {}
	        block_action['rule_name'] = rule_name
	        block_action['rule_action'] = rule_action
	        block_action['action_value'] = action_value
            jxwaf_inner:set("flow_rule_block"..src_ip,cjson.encode(block_action),block_time)
          end
        end
    end
  end
end

function _M.flow_engine_protection()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local flow_engine_protection_data = domain_conf_data['flow_engine_protection_data']
  if  not flow_engine_protection_data  or ngx.ctx.flow_bypass then
    return
  end
  local engine_status = flow_engine_protection_data['engine_status']
  if  engine_status ~= "true" then
    return
  end
  local ip_access_limit_status = flow_engine_protection_data['ip_access_limit_status']
  if  ip_access_limit_status == "true" then
    flow_engine_check.ip_access_limit_check(flow_engine_protection_data,_sys_conf_data,_config_info)
  end

  local ip_count_limit_status = flow_engine_protection_data['ip_count_limit_status']
  if  ip_count_limit_status == "true" then
    flow_engine_check.ip_count_limit_check(flow_engine_protection_data,_sys_conf_data,_config_info)
  end

  local domain_access_limit_status = flow_engine_protection_data['domain_access_limit_status']
  if  domain_access_limit_status == "true" then
    flow_engine_check.domain_access_limit_check(flow_engine_protection_data,_sys_conf_data,_config_info)
  end


  local ssl_fingerprint_protection_status = flow_engine_protection_data['ssl_fingerprint_protection_status']
  if  ssl_fingerprint_protection_status == "true" then
    flow_engine_check.ssl_fingerprint_protection_check(flow_engine_protection_data,_sys_conf_data,_config_info)
  end

  local emergency_protection_status = flow_engine_protection_data['emergency_protection_status']
  if  emergency_protection_status == "true" then
    flow_engine_check.emergency_protection_check(flow_engine_protection_data,_sys_conf_data,_config_info)
  end

end


function _M.web_white_rule()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local web_white_rule_data = domain_conf_data['web_white_rule_data']
  if  not web_white_rule_data  then
    return
  end
  for _,rule_conf in ipairs(web_white_rule_data) do
    local rule_name = rule_conf['rule_name']
    local rule_matchs = rule_conf['rule_matchs']
    local rule_action = rule_conf['rule_action']
    local action_value = rule_conf['action_value']
    local matchs_result = true
    for _,rule_match in ipairs(rule_matchs) do
        local match_args = rule_match['match_args']
        local args_prepocess = rule_match['args_prepocess']
        local match_operator = rule_match['match_operator']
        local match_value = rule_match['match_value']
        local operator_result = false
        for _,match_arg in ipairs(match_args) do
          local arg = request.get_args(match_arg.key,match_arg.value)
          for _,arg_prepocess in ipairs(args_prepocess) do
                 arg = preprocess.process_args(arg_prepocess,arg)
          end
          if arg or match_operator == 'status_check' then
            local operator_match_result = operator.match(match_operator,arg,match_value)
            if  operator_match_result then
                operator_result =  true
                break
            end
          end
        end
        if (not operator_result) then
          matchs_result = false
          break
        end
    end
    if matchs_result then
      local waf_log = {}
      waf_log['waf_module'] = "web_white_rule"
      waf_log['waf_policy'] = "Web白名单规则-"..rule_name
      waf_log['waf_action'] = rule_action
      waf_log['waf_extra'] = action_value
      ngx.ctx.waf_log = waf_log
      if rule_action == "web_bypass" then
        ngx.ctx.web_bypass = true
      end
    end
  end
end

function _M.web_rule_protection()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local web_rule_protection_data = domain_conf_data['web_rule_protection_data']
  if not web_rule_protection_data or ngx.ctx.web_bypass then
    return
  end
  for _,rule_conf in ipairs(web_rule_protection_data) do
    local rule_name = rule_conf['rule_name']
    local rule_matchs = rule_conf['rule_matchs']
    local rule_action = rule_conf['rule_action']
    local action_value = rule_conf['action_value']
    local matchs_result = true
    for _,rule_match in ipairs(rule_matchs) do
        local match_args = rule_match['match_args']
        local args_prepocess = rule_match['args_prepocess']
        local match_operator = rule_match['match_operator']
        local match_value = rule_match['match_value']
        local operator_result = false
        for _,match_arg in ipairs(match_args) do
          local arg = request.get_args(match_arg.key,match_arg.value)
          for _,arg_prepocess in ipairs(args_prepocess) do
                 arg = preprocess.process_args(arg_prepocess,arg)
          end
          if arg or match_operator == 'status_check' then
            local operator_match_result = operator.match(match_operator,arg,match_value)
            if  operator_match_result then
                operator_result =  true
                break
            end
          end
        end
        if (not operator_result) then
          matchs_result = false
          break
        end
    end
    if matchs_result then
      local waf_log = {}
      waf_log['waf_module'] = "web_rule_protection"
      waf_log['waf_policy'] = "Web防护规则-"..rule_name
      waf_log['waf_action'] = rule_action
      waf_log['waf_extra'] = action_value
      ngx.ctx.waf_log = waf_log
      if rule_action == "block"  or rule_action == "reject_response" then
          local page_conf = {}
          if _sys_conf_data['custom_deny_page'] == 'true' then
            page_conf['code'] = _sys_conf_data['waf_deny_code']
            page_conf['html'] = _sys_conf_data['waf_deny_html']
          end
          unify_action.block(page_conf)
      end
    end
  end
end

local function _uni_decode(value)
    if not value or type(value) ~= "string" then
        return value
    end

    -- 性能优化：如果没有 \u 转义符，直接返回
    if not string.find(value, "\\u", 1, true) then
        return value
    end

    -- 校验格式：确保是 \u 后跟4个十六进制字符
    if not value:find("\\u%x%x%x%x") then
        return value
    end

    return value:gsub("\\u(%x%x%x%x)", function(hex)
        local codepoint = tonumber(hex, 16)
        -- 安全检查：确保 tonumber 成功，且符合设计范围 (0-255)
        if not codepoint or codepoint > 255 then
            return nil
        end

        -- 此时 codepoint 在 0-255 之间，string.char 是安全的
        return string.char(codepoint)
    end)
end

local NAMED_ENTITIES = {
    ["&lt;"]   = "<",
    ["&gt;"]   = ">",
    ["&quot;"] = "\"",
    ["&amp;"]  = "&",
    ["&apos;"] = "'",
}

local LOOSE_ENTITIES = {
    ["&lt"]   = "<",
    ["&gt"]   = ">",
    ["&quot"] = "\"",
    ["&amp"]  = "&",
}

local function _html_decode(str)
    if not str or type(str) ~= "string" or str == "" then
        return str
    end

    if not string.find(str, "&", 1, true) then
        return str
    end

    local result = str

    -- ① 十进制实体 &#NNN;
    if string.find(result, "&#%d", 1) then
        result = string.gsub(result, "&#(%d+);", function(n)
            local num = tonumber(n)
            if num and num <= 255 then
                return string.char(num)
            end
            return nil
        end)
    end

    -- ② 十六进制实体 &#xNN;
    if string.find(result, "&#[xX]", 1) then
        result = string.gsub(result, "&#[xX](%x+);", function(h)
            local num = tonumber(h, 16)
            if num and num <= 255 then
                return string.char(num)
            end
            return nil
        end)
    end

    -- ③ 严格命名实体 &lt; &gt; 等
    if string.find(result, "&%a+;", 1) then
        result = string.gsub(result, "&(%a+);", function(name)
            return NAMED_ENTITIES["&" .. name .. ";"]
        end)
    end

    -- ④ 宽松命名实体 &lt &gt 等
    if string.find(result, "&%a", 1) then
        result = string.gsub(result, "&(%a+)", function(name)
            return LOOSE_ENTITIES["&" .. name]
        end)
    end

    return result
end

local function process_token(token, raw_value, raw_original, model_provider, model_api_key, model_data, mode, host, uri, src_ip)
    if not token or token == "" then
        return false
    end

    local token_hash = token
    if mode == 'learn' then
        if model_data[token_hash] == nil then
            ngx.timer.at(0, unify_action.token_ai_analysis, _config_info, token_hash, raw_original, model_provider, model_api_key, host, uri, src_ip)
        elseif type(model_data[token_hash]) == "table" then
            return false, model_data[token_hash]
        end
        return false

    elseif mode == 'business_priority' then
        if type(model_data[token_hash]) == "table" then
            return true, model_data[token_hash]
        elseif model_data[token_hash] == nil then
            ngx.timer.at(0, unify_action.token_ai_analysis, _config_info, token_hash, raw_original, model_provider, model_api_key, host, uri, src_ip)
            return nil
        end
        return false

    elseif mode == 'security_priority' then
        if model_data[token_hash] == nil then
            ngx.timer.at(0, unify_action.token_ai_analysis, _config_info, token_hash, raw_original, model_provider, model_api_key, host, uri, src_ip)
            return true, {}
        elseif type(model_data[token_hash]) == "table" then
            return true, model_data[token_hash]
        else
            return false
        end

    elseif mode == 'offline' then
        if model_data[token_hash] == nil then
            return true, {}
        elseif type(model_data[token_hash]) == "table" then
            return true, model_data[token_hash]
        else
            return false
        end
    end

    return false
end


local function _get_attack_type(model_attack_types, sql_result, xss_result, rce_result, code_exec_result, path_traversal_result, use_semantic_fallback)
    local model_set = {}
    if type(model_attack_types) == "table" then
        for _, mt in ipairs(model_attack_types) do
            model_set[mt] = true
        end
    end

    if model_set["sql"] then
        return "AI模型检测-SQL注入"
    elseif model_set["xss"] then
        return "AI模型检测-XSS"
    elseif model_set["rce"] then
        return "AI模型检测-RCE"
    elseif model_set["code_exec"] then
        return "AI模型检测-代码执行"
    elseif model_set["path_traversal"] then
        return "AI模型检测-路径穿越"
    elseif model_set["xxe"] then
        return "AI模型检测-XXE"
    elseif model_set["other"] then
        return "AI模型检测-其他攻击"
    elseif type(model_attack_types) == "table" and #model_attack_types > 0 then
        return "AI模型检测-" .. table_concat(model_attack_types, ", ")
    end

    if use_semantic_fallback then
        if sql_result then
            return "语义分析-SQL注入"
        elseif xss_result then
            return "语义分析-XSS"
        elseif rce_result then
            return "语义分析-RCE"
        elseif code_exec_result then
            return "语义分析-代码执行"
        elseif path_traversal_result then
            return "语义分析-路径穿越"
        end
    end

    return "AI模型检测-未知请求"
end


local function _web_engine_check(raw_value, raw_original, engine_block, model_provider, model_api_key, protection_mode, engine_protection, host, uri, src_ip)
    local sql_result, sql_token = _jxwaf_engine.jxwaf_sql_check(raw_value)
    local xss_result, xss_token = _jxwaf_engine.jxwaf_xss_check(_html_decode(raw_value))
    local rce_result, rce_token = _jxwaf_engine.jxwaf_rce_check(raw_value)
    local code_exec_result, code_exec_token = _jxwaf_engine.jxwaf_code_exec_check(raw_value)
    local path_traversal_result, path_traversal_token = _jxwaf_engine.jxwaf_path_traversal_check(raw_value)

    local should_block = nil
    local model_attack_types = nil

    local valid_tokens = {}
    if sql_token and sql_token ~= "" then valid_tokens[#valid_tokens + 1] = sql_token end
    if xss_token and xss_token ~= "" then valid_tokens[#valid_tokens + 1] = xss_token end 
    if rce_token and rce_token ~= "" then valid_tokens[#valid_tokens + 1] = rce_token end
    if code_exec_token and code_exec_token ~= "" then valid_tokens[#valid_tokens + 1] = code_exec_token end
    if path_traversal_token and path_traversal_token ~= "" then valid_tokens[#valid_tokens + 1] = path_traversal_token end

    local combined_token 
    if #valid_tokens > 0 then
        combined_token = resty_string.to_hex(ngx.hmac_sha1('jxwaf', table_concat(valid_tokens, ',')))
        should_block, model_attack_types = process_token(combined_token, raw_value, raw_original, model_provider, model_api_key, _model_data, protection_mode, host, uri, src_ip)
    end

    local has_ai_attack = (should_block == true) or (type(model_attack_types) == "table")

    if should_block == nil and engine_block and (sql_result or xss_result or rce_result or code_exec_result or path_traversal_result) then
        should_block = true
    end

    local has_semantic_attack = sql_result or xss_result or rce_result or code_exec_result or path_traversal_result
    local attack_detected = has_ai_attack or (protection_mode == 'business_priority' and engine_protection ~= 'close' and has_semantic_attack)

    if attack_detected then
        local use_semantic_fallback = (protection_mode == 'business_priority' and engine_protection ~= 'close')
        local attack_type = _get_attack_type(model_attack_types, sql_result, xss_result, rce_result, code_exec_result, path_traversal_result, use_semantic_fallback)
        local waf_log = { waf_module = "web_engine_protection", waf_policy = attack_type, waf_extra = combined_token }

        if should_block then
            waf_log['waf_action'] = 'block'
            ngx.ctx.waf_log = waf_log
            local page_conf = {}
            if _sys_conf_data['custom_deny_page'] == 'true' then
                page_conf['code'] = _sys_conf_data['waf_deny_code']
                page_conf['html'] = _sys_conf_data['waf_deny_html']
            end
            unify_action.block(page_conf)
        else
            waf_log['waf_action'] = 'watch'
            ngx.ctx.waf_log = waf_log
        end
        return false
    end

    return false
end


function _M.web_engine_protection()
    local domain_conf_data = ngx.ctx.domain_conf_data
    local web_engine_protection_data = domain_conf_data['web_engine_protection_data']
    if not web_engine_protection_data or ngx.ctx.web_bypass then
        return
    end
    local ai_protection = web_engine_protection_data['ai_protection']
    local protection_mode = web_engine_protection_data['protection_mode']
    local engine_protection = web_engine_protection_data['engine_protection']
    local model_provider = web_engine_protection_data['model_provider']
    local model_api_key = web_engine_protection_data['model_api_key']

    if ai_protection ~= 'true' then
        return
    end

    local raw_request_uri = request.get_args("http_args","request_uri")
    local raw_http_body = request.get_args("http_args","raw_body")
    local raw_high_risk_headers = request.get_args("http_args","high_risk_header")

    local request_uri = _uni_decode(ngx.unescape_uri(ngx.unescape_uri(raw_request_uri)))
    local http_body = _uni_decode(ngx.unescape_uri(ngx.unescape_uri(raw_http_body)))

    local host = request.get_args("http_args", "host")
    local src_ip = request.get_args("http_args", "src_ip")

    local engine_block = (protection_mode == 'business_priority' and engine_protection == 'block')

    if _web_engine_check(request_uri, raw_request_uri, engine_block, model_provider, model_api_key, protection_mode, engine_protection, host, raw_request_uri, src_ip) then return end
    if _web_engine_check(http_body, raw_http_body, engine_block, model_provider, model_api_key, protection_mode, engine_protection, host, raw_request_uri, src_ip) then return end

    -- 对每个高风险 header value 单独检测
    if raw_high_risk_headers and type(raw_high_risk_headers) == "table" then
        for _, header_value in pairs(raw_high_risk_headers) do
            local value_to_check = header_value
            if type(value_to_check) == "table" then
                value_to_check = table_concat(value_to_check, ", ")
            end
            if type(value_to_check) == "string" then
                local decoded_header_value = _uni_decode(ngx.unescape_uri(ngx.unescape_uri(value_to_check)))
                if _web_engine_check(decoded_header_value, value_to_check, engine_block, model_provider, model_api_key, protection_mode, engine_protection, host, raw_request_uri, src_ip) then
                    return
                end
            end
        end
    end
end


function _M.web_page_tamper_proof()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local web_page_tamper_proof_data = domain_conf_data['web_page_tamper_proof_data']
  if  not web_page_tamper_proof_data or ngx.ctx.web_bypass then
    return
  end

  for _,rule_conf in ipairs(web_page_tamper_proof_data) do
    local rule_name = rule_conf['rule_name']
    local rule_matchs = rule_conf['rule_matchs']
    local cache_page_url = rule_conf['cache_page_url']
    local cache_content_type = rule_conf['cache_content_type']
    local cache_page_content = rule_conf['cache_page_content']
    local matchs_result = true
    for _,rule_match in ipairs(rule_matchs) do
        local match_args = rule_match['match_args']
        local args_prepocess = rule_match['args_prepocess']
        local match_operator = rule_match['match_operator']
        local match_value = rule_match['match_value']
        local operator_result = false
        for _,match_arg in ipairs(match_args) do
          local arg = request.get_args(match_arg.key,match_arg.value)
          for _,arg_prepocess in ipairs(args_prepocess) do
                 arg = preprocess.process_args(arg_prepocess,arg)
          end
          if arg or match_operator == 'status_check' then
            local operator_match_result = operator.match(match_operator,arg,match_value)
            if  operator_match_result then
                operator_result =  true
                break
            end
          end
        end
        if (not operator_result) then
          matchs_result = false
          break
        end
    end
    if matchs_result then
      
      local waf_log = {}
      waf_log['waf_module'] = "web_page_tamper_proof"
      waf_log['waf_policy'] = "网页防篡改-"..rule_name
      waf_log['waf_action'] = "page_tamper_proof"
      waf_log['waf_extra'] = cache_page_url
      ngx.ctx.waf_log = waf_log
      
      unify_action.page_tamper_proof(cache_content_type,cache_page_content)
    end
  end
end

function _M.custom_request_header()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local custom_request_header_data = domain_conf_data['custom_request_header_data']

  if not custom_request_header_data then
    return
  end

  for _,rule_conf in ipairs(custom_request_header_data) do
    local rule_name = rule_conf['rule_name']
    local filter = rule_conf['filter']
    local rule_matchs = rule_conf['rule_matchs']
    local header_name = rule_conf['header_name']
    local header_value = rule_conf['header_value']
    if filter == "true" then
      local matchs_result = true
      for _,rule_match in ipairs(rule_matchs) do
          local match_args = rule_match['match_args']
          local args_prepocess = rule_match['args_prepocess']
          local match_operator = rule_match['match_operator']
          local match_value = rule_match['match_value']
          local operator_result = false
          for _,match_arg in ipairs(match_args) do
            local arg = request.get_args(match_arg.key,match_arg.value)
            for _,arg_prepocess in ipairs(args_prepocess) do
                   arg = preprocess.process_args(arg_prepocess,arg)
            end
          if arg or match_operator == 'status_check' then
              local operator_match_result = operator.match(match_operator,arg,match_value)
              if  operator_match_result then
                  operator_result =  true
                  break
              end
            end
          end
          if (not operator_result) then
            matchs_result = false
            break
          end
      end
      if matchs_result then
        ngx.req.set_header(header_name, header_value)
      end
    else
      ngx.req.set_header(header_name, header_value)
    end
  end
end


function _M.custom_response_header()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local custom_response_header_data = domain_conf_data['custom_response_header_data']

  if  not custom_response_header_data   then
    return
  end

  for _,rule_conf in ipairs(custom_response_header_data) do
    local rule_name = rule_conf['rule_name']
    local filter = rule_conf['filter']
    local rule_matchs = rule_conf['rule_matchs']
    local header_name = rule_conf['header_name']
    local header_value = rule_conf['header_value']
    if filter == "true" then
      local matchs_result = true
      for _,rule_match in ipairs(rule_matchs) do
          local match_args = rule_match['match_args']
          local args_prepocess = rule_match['args_prepocess']
          local match_operator = rule_match['match_operator']
          local match_value = rule_match['match_value']
          local operator_result = false
          for _,match_arg in ipairs(match_args) do
            local arg = request.get_args(match_arg.key,match_arg.value)
            for _,arg_prepocess in ipairs(args_prepocess) do
                   arg = preprocess.process_args(arg_prepocess,arg)
            end
          if arg or match_operator == 'status_check' then
              local operator_match_result = operator.match(match_operator,arg,match_value)
              if  operator_match_result then
                  operator_result =  true
                  break
              end
            end
          end
          if (not operator_result) then
            matchs_result = false
            break
          end
      end
      if matchs_result then
        ngx.header[header_name] = header_value
      end
    else
      ngx.header[header_name] = header_value
    end
  end
end

function _M.custom_response_content()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local custom_response_content_data = domain_conf_data['custom_response_content_data']

  if  not custom_response_content_data  then
    return
  end

  for _,rule_conf in ipairs(custom_response_content_data) do
    local rule_name = rule_conf['rule_name']
    local filter = rule_conf['filter']
    local rule_matchs = rule_conf['rule_matchs']
    local content_type = rule_conf['content_type']
    local return_code = rule_conf['return_code']
    local return_content = rule_conf['return_content']
    if filter == "true" then
      local matchs_result = true
      for _,rule_match in ipairs(rule_matchs) do
          local match_args = rule_match['match_args']
          local args_prepocess = rule_match['args_prepocess']
          local match_operator = rule_match['match_operator']
          local match_value = rule_match['match_value']
          local operator_result = false
          for _,match_arg in ipairs(match_args) do
            local arg = request.get_args(match_arg.key,match_arg.value)
            for _,arg_prepocess in ipairs(args_prepocess) do
                   arg = preprocess.process_args(arg_prepocess,arg)
            end
          if arg or match_operator == 'status_check' then
              local operator_match_result = operator.match(match_operator,arg,match_value)
              if  operator_match_result then
                  operator_result =  true
                  break
              end
            end
          end
          if (not operator_result) then
            matchs_result = false
            break
          end
      end
      if matchs_result then
        ngx.header.content_type = content_type
        ngx.status = tonumber(return_code)
        ngx.say(return_content)
        return ngx.exit(tonumber(return_code))
      end
    else
        ngx.header.content_type = content_type
        ngx.status = tonumber(return_code)
        ngx.say(return_content)
        return ngx.exit(tonumber(return_code))
    end
  end
end

function _M.custom_upstream_address()
  local domain_conf_data = ngx.ctx.domain_conf_data
  local custom_upstream_address_data = domain_conf_data['custom_upstream_address_data']

  if  not custom_upstream_address_data   then
    return
  end

  for _,rule_conf in ipairs(custom_upstream_address_data) do
    local rule_name = rule_conf['rule_name']
    local filter = rule_conf['filter']
    local rule_matchs = rule_conf['rule_matchs']
    local source_ip = rule_conf['source_ip']
    local source_http_port = rule_conf['source_http_port']
    local source_https_port = rule_conf['source_https_port']
    if filter == "true" then
      local matchs_result = true
      for _,rule_match in ipairs(rule_matchs) do
          local match_args = rule_match['match_args']
          local args_prepocess = rule_match['args_prepocess']
          local match_operator = rule_match['match_operator']
          local match_value = rule_match['match_value']
          local operator_result = false
          for _,match_arg in ipairs(match_args) do
            local arg = request.get_args(match_arg.key,match_arg.value)
            for _,arg_prepocess in ipairs(args_prepocess) do
                   arg = preprocess.process_args(arg_prepocess,arg)
            end
          if arg or match_operator == 'status_check' then
              local operator_match_result = operator.match(match_operator,arg,match_value)
              if  operator_match_result then
                  operator_result =  true
                  break
              end
            end
          end
          if (not operator_result) then
            matchs_result = false
            break
          end
      end 
        if matchs_result then
            ngx.ctx.component_source_ip = source_ip
            ngx.ctx.component_source_http_port = source_http_port 
            ngx.ctx.component_source_https_port = source_https_port 
        end
    else
            ngx.ctx.component_source_ip = source_ip
            ngx.ctx.component_source_http_port = source_http_port 
            ngx.ctx.component_source_https_port = source_https_port 
    end
  end
end


function _M.init_jxwaf_devid()
    if  ngx.ctx.jxwaf_devid == false then
        return
    end
    local cookie_jxwaf_devid = request.get_args("cookie_args","jxwaf_devid")
    if cookie_jxwaf_devid then
        return
    end
    _jxwaf_engine.init_jxwaf_devid(_config_info.waf_auth)
end


return _M