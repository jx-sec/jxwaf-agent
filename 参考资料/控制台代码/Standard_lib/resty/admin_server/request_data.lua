local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'

local _M = {}

local function param_check(input_param)
    if not input_param then
       local data_result = {}
       data_result['result'] = false
       data_result['message'] = "param is null"
       ngx.status = 200
       ngx.header.content_type = "application/json"
       ngx.log(ngx.ERR,cjson.encode(data_result))
       ngx.say(cjson.encode(data_result))
       return ngx.exit(200)
    end
    return input_param
end


function _M.get_body_data(check_param)
     local body_data = ngx.req.get_body_data()
     local decode_body_data = cjson.decode(body_data)
     if not decode_body_data then
       local return_data = {}
       return_data['result'] = false
       return_data['message'] = "decode_body_data error"
       return_data['body_data'] = body_data
       ngx.log(ngx.ERR,cjson.encode(return_data))
       ngx.status = 200
       ngx.header.content_type = "application/json"
       ngx.say(cjson.encode(return_data))
       return ngx.exit(200)
     end
     for _,v in ipairs(check_param) do
       param_check(decode_body_data[v])
     end
     return decode_body_data
end

function _M.get_user_name(waf_auth)
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

return _M 
