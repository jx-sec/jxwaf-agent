local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}


function _M.get_group_flow_ip_region_block()
  local user_name = login_check.get_session()
  local check_param = {"group_name"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_group_flow_ip_region_block WHERE group_name = ? AND user_name = ?;"
  local count_sql_params = {group_name,user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) ~= 1 then
    local del_sql = "DELETE FROM jxwaf_waf_group_flow_ip_region_block WHERE group_name = ? AND user_name = ?;"
    local del_sql_params = {group_name,user_name}
    local del_sql_result,del_sql_error = db_query.query_mysql(del_sql,del_sql_params)
    if not del_sql_result then
      response.fail_response(del_sql_error)
    end
    local create_sql = "INSERT INTO jxwaf_waf_group_flow_ip_region_block (user_name,group_name) VALUES (?,?);"
    local create_sql_params = {user_name,group_name}
    local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
    if not create_result then
      response.fail_response(create_err)
    end
  end
  local sql = "SELECT * FROM jxwaf_waf_group_flow_ip_region_block  WHERE `user_name` = ? AND `group_name` = ?;"
  local sql_params = {user_name, group_name}   
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response(query_error)
  end
end

function _M.edit_group_flow_ip_region_block()
  local user_name = login_check.get_session()
  local check_param = {"group_name","ip_region_block","check_model","country_list","block_action","action_value"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local ip_region_block = body_data['ip_region_block']
  local check_model = body_data['check_model']
  local country_list = body_data['country_list']
  local block_action = body_data['block_action']
  local action_value = body_data['action_value']
  local sql = "UPDATE jxwaf_waf_group_flow_ip_region_block  SET  ip_region_block = ?,check_model = ?,country_list = ? ,block_action = ? ,action_value = ? WHERE group_name = ? AND user_name = ?;"
  local sql_params = {ip_region_block,check_model,country_list,block_action,action_value,group_name,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

return _M 