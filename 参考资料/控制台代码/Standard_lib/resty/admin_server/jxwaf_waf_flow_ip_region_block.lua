local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}

function _M.get_flow_ip_region_block()
  local user_name = login_check.get_session()

  -- 根据新表结构，只需要用户名为查询条件
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_flow_ip_region_block WHERE user_name = ?;"
  local count_sql_params = {user_name}
  local count_sql_result, count_error = db_query.query_mysql(count_sql, count_sql_params)

  if not count_sql_result then
    response.fail_response(count_error)
  end

  -- 如果用户没有记录，则创建默认记录
  if tonumber(count_sql_result[1].count) == 0 then
    local create_sql = "INSERT INTO jxwaf_waf_flow_ip_region_block (user_name, ip_region_block, check_model, country_list, block_action,action_value) VALUES (?, 'false','white', '[]', 'block', '');"
    local create_sql_params = {user_name}
    local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)

    if not create_result then
      response.fail_response(create_err)
    end
  end

  -- 查询用户配置
  local sql = "SELECT * FROM jxwaf_waf_flow_ip_region_block WHERE user_name = ?;"
  local sql_params = {user_name}
  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response(query_error)
  end
end

function _M.edit_flow_ip_region_block()
  local user_name = login_check.get_session()

  -- 根据新表结构调整参数检查
  local check_param = {"ip_region_block", "check_model", "country_list", "block_action","action_value"}
  local body_data = request_data.get_body_data(check_param)

  local ip_region_block = body_data['ip_region_block']
  local check_model = body_data['check_model']
  local country_list = body_data['country_list']
  local block_action = body_data['block_action']
  local action_value = body_data['action_value']
  -- 更新用户配置
  local sql = "UPDATE jxwaf_waf_flow_ip_region_block SET ip_region_block = ?, check_model = ?, country_list = ?, block_action = ?, action_value = ? WHERE user_name = ?;"
  local sql_params = {ip_region_block, check_model, country_list, block_action,action_value, user_name}
  local sql_result, sql_error = db_query.query_mysql(sql, sql_params)

  if not sql_result then
    response.fail_response(sql_error)
  end

  response.success_response("edit success")
end

return _M
