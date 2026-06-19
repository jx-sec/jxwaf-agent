local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'

local _M = {}

local function get_user_name(waf_auth)
    local query_account_sql = [[SELECT * FROM `jxwaf_admin_account` where `waf_auth` = ?;]]
    local query_account_sql_params = {waf_auth}
    local query_account_result,err = db_query.query_mysql(query_account_sql,query_account_sql_params)
    if (not query_account_result) or (query_account_result and #query_account_result == 0) then
      response.fail_response("waf_auth fail")
    end
    local user_name = query_account_result[1]['user_name']
    if not user_name then
      response.fail_response("user_name error")
    end
   return user_name
end

function _M.get_session()
  local conf_data = ngx.shared.conf_data
  local jxwaf_session = ngx.var.cookie_jxwaf_session
  if jxwaf_session then
    local user_name = conf_data:get(jxwaf_session)
    if user_name then
      conf_data:set(jxwaf_session,user_name,86400)
      return user_name
    end
  end
  local return_data = {}
  return_data['result'] = false
  return_data['message'] = "redirect_to_login"
  ngx.status = 200
  ngx.header.content_type = "application/json"
  ngx.say(cjson.encode(return_data))
  return ngx.exit(200)
end


return _M 