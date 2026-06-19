local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}


function _M.waf_monitor()
  local check_param = {"waf_auth","waf_node_uuid","waf_node_hostname"}
  local body_data = request_data.get_body_data(check_param)
  local waf_auth = body_data['waf_auth']
  local waf_node_uuid = body_data['waf_node_uuid']
  local waf_node_hostname = body_data['waf_node_hostname']
  local waf_node_ip  =  ngx.var.remote_addr
  local now_time = ngx.time()
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

  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_node_monitor WHERE node_uuid = ? AND user_name = ?;"
  local count_sql_params = {waf_node_uuid,user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) == 0 then
    local create_sql = "INSERT INTO jxwaf_node_monitor (user_name,node_uuid,node_hostname,node_ip,node_status_update_time) VALUES (?,?,?,?,?);"
    local create_sql_params = {user_name,waf_node_uuid,waf_node_hostname,waf_node_ip,now_time}
    local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
    if not create_result then
      response.fail_response(create_err)
    end
  else
    local update_sql = "UPDATE jxwaf_node_monitor  SET  node_hostname = ?,node_ip = ?,node_status_update_time = ? WHERE  user_name = ? and node_uuid = ?  ;"
    local update_sql_params = {waf_node_hostname,waf_node_ip,now_time,user_name,waf_node_uuid}
    local update_sql_result,update_sql_error = db_query.query_mysql(update_sql,update_sql_params)
    if not update_sql_result then
      response.fail_response(update_sql_error)
    end
  end
  response.success_response("update success")
end



function _M.get_node_monitor_list()
  local user_name = login_check.get_session()
  local now_time = ngx.time()
  local sql = "SELECT * FROM jxwaf_node_monitor  WHERE `user_name` = ? ;"
  local sql_params = {user_name}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
  end
  local result = {}
  for _,v in ipairs(query_result) do
    local node_status = "true"
    if  ngx.time()  - tonumber(v['node_status_update_time'])  > 600 then
        node_status = "false"
    end
    table.insert(result,{
        node_status = node_status,
        node_uuid = v['node_uuid'],
        node_hostname = v['node_hostname'],
        node_ip = v['node_ip'],
        node_status_update_time = v['node_status_update_time'],
        waf_conf_update_time = v['waf_conf_update_time']
    })
  end
  cjson.encode_empty_table_as_object(false)
  response.success_response(result)
end

function _M.delete_node_monitor()
  local user_name = login_check.get_session()
  local check_param = {"node_uuid"}
  local body_data = request_data.get_body_data(check_param)
  local node_uuid = body_data['node_uuid']
  local sql = "DELETE FROM jxwaf_node_monitor WHERE node_uuid = ? AND user_name = ?;"
  local sql_params = {node_uuid,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("delete success")
end


return _M





