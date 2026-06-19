local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local tools = require 'resty.admin_server.tools'

local _M = {}


local function update_waf_conf_update_time(waf_node_uuid)
    local now_time = ngx.time()
    local count_sql = "SELECT COUNT(*) as count FROM jxwaf_node_monitor WHERE node_uuid = ? ;"
    local count_sql_params = {waf_node_uuid}
    local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
    if not count_sql_result then
        ngx.log(ngx.ERR,count_error)
        return
    end
    if tonumber(count_sql_result[1].count) == 1 then
        local update_sql = "UPDATE jxwaf_node_monitor  SET  waf_conf_update_time = ? WHERE   node_uuid = ?  ;"
        local update_sql_params = {now_time,waf_node_uuid}
        local update_sql_result,update_sql_error = db_query.query_mysql(update_sql,update_sql_params)
        if not update_sql_result then
            ngx.log(ngx.ERR,update_sql_error)
          return
        end
    end
end

function _M.waf_update()
  local check_param = {"waf_auth"}
  local body_data = request_data.get_body_data(check_param)
  local waf_auth = body_data['waf_auth']
  local conf_md5 = body_data['waf_conf_md5'] or ""
  local waf_node_uuid = body_data['waf_node_uuid']

  local  init_waf_auth =  init_config['waf_auth']
  if waf_auth ~= init_waf_auth then
      response.fail_response("waf_auth error")
  end

  local waf_update_conf_data = ngx.shared.waf_update_conf_data
  local waf_conf_md5 = waf_update_conf_data:get("waf_conf_md5")
  if waf_conf_md5 and waf_conf_md5 == conf_md5 then
    local return_data = {}
    return_data['result'] = true
    return_data['configure_without_change'] = true
    ngx.status = 200
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode(return_data))
    return ngx.exit(200)
  end
  local waf_conf_data = waf_update_conf_data:get("waf_conf_data")
  if waf_conf_data and waf_conf_md5 then
    local return_data = {}
    return_data['result'] = true
    return_data['waf_conf_md5'] = waf_conf_md5
    local waf_conf_decode_data = cjson.decode(waf_conf_data)
    if not waf_conf_decode_data then
        response.fail_response("waf_conf_data json decode error")
    end
    return_data['waf_conf_data'] = waf_conf_decode_data
    update_waf_conf_update_time(waf_node_uuid)
    ngx.status = 200
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode(return_data))
    return ngx.exit(200)
  end
  if not waf_conf_md5 then
    response.fail_response("waf_conf_md5 is nil ")
  end
  if not waf_conf_data then
    response.fail_response("waf_conf_data is nil ")
  end
end


function _M.model_update()
  local check_param = {"waf_auth"}
  local body_data = request_data.get_body_data(check_param)
  local waf_auth = body_data['waf_auth']
  local node_model_update_time = body_data['model_update_time']

  local  init_waf_auth =  init_config['waf_auth']
  if waf_auth ~= init_waf_auth then
      response.fail_response("waf_auth error")
  end

  local return_data = {}
  return_data['model_update'] = 'false'

  local waf_update_conf_data = ngx.shared.waf_update_conf_data
  local model_data = waf_update_conf_data:get("model_data")
  local model_update_time = waf_update_conf_data:get("model_update_time")
  if model_data and model_update_time then
      if not node_model_update_time or model_update_time > node_model_update_time then
          return_data['model_data'] = cjson.decode(model_data)
          return_data['model_update_time'] = model_update_time
          return_data['model_update'] = 'true'
      end
  end

  return_data['result'] = true
  ngx.status = 200
  ngx.header.content_type = "application/json"
  ngx.say(cjson.encode(return_data))
  return ngx.exit(200)
end



function _M.token_ai_analysis()
  local check_param = {"waf_auth","token","raw_string","host","uri","request_time","src_ip"}
  local body_data = request_data.get_body_data(check_param)
  local waf_auth = body_data['waf_auth']
  local token = body_data['token']
  local raw_string = body_data['raw_string']
  local host = body_data['host']
  local uri = body_data['uri']
  local request_time = body_data['request_time']
  local src_ip = body_data['src_ip']
  local model_provider = body_data['model_provider'] or "jxwaf"
  local model_api_key = body_data['model_api_key'] or ""

  local model_data = {}
  model_data['raw_string'] = raw_string
  model_data['token'] = token

  local  init_waf_auth =  init_config['waf_auth']
  if waf_auth ~= init_waf_auth then
      response.fail_response("waf_auth error")
  end

  local conf_data = ngx.shared.conf_data
  local check_key = "ai_analysis"..token
  local check_key_result = conf_data:get(check_key)
  if check_key_result then
    response.fail_response('ai_analysis is exist')
  end

  conf_data:set(check_key,true,60)

  local query_account_sql = "SELECT user_name FROM jxwaf_admin_account LIMIT 1;"
  local query_account_result = db_query.query_mysql(query_account_sql)
  if not query_account_result or #query_account_result == 0 then
    response.fail_response("no user found")
  end
  local user_name = query_account_result[1]['user_name']

  if  model_provider == "jxwaf" and init_config['jxwaf_model_server_host'] and init_config['jxwaf_model_server_port']  then
      local model_result = tools.jxwaf_model_query(model_data,init_config['jxwaf_model_server_host'],init_config['jxwaf_model_server_port'])
      if model_result and model_result.status == 'ok' then
        local attack_type = model_result.attack_type
        if attack_type == cjson.null then
          attack_type = {}
        end
        local attack_type_json = cjson.encode(attack_type or {})
        local ai_model = model_result.ai_model or ''
        local ai_analysis_result = model_result.result
        if ai_analysis_result == "none" then
          ai_analysis_result = ''
        end
        local create_sql = "INSERT INTO jxwaf_soc_web_protection_model (user_name,token,raw_string,attack_type,ai_analysis_result,ai_model,host,uri,request_time,src_ip) VALUES (?,?,?,?,?,?,?,?,?,?);"
        local create_sql_params = {user_name,token,raw_string,attack_type_json,ai_analysis_result,ai_model,host,uri,request_time,src_ip}
        local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
        if not create_result then
          response.fail_response(create_err)
        end
        response.success_response(model_result)
      end
  end

    local create_sql = "INSERT INTO jxwaf_soc_web_protection_model (user_name,token,raw_string,attack_type,ai_analysis_result,ai_model,host,uri,request_time,src_ip,model_api_key) VALUES (?,?,?,?,?,?,?,?,?,?,?);"
    local create_sql_params = {user_name,token,raw_string,'','',model_provider,host,uri,request_time,src_ip,model_api_key}
    local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
    if not create_result then
        response.fail_response(create_err)
    end
    response.success_response('ai analysis error')
end

return _M 