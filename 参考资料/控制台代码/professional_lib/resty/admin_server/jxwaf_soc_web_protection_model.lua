local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local tools = require 'resty.admin_server.tools'

local _M = {}



function _M.get_soc_web_protection_model_list()
  local user_name = login_check.get_session()
  local check_param = {"page"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local search = body_data['search']
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql, count_sql_params, sql, sql_params
  if search then
    count_sql = "SELECT COUNT(*) AS total FROM jxwaf_soc_web_protection_model WHERE `user_name` = ? AND (`raw_string` LIKE CONCAT('%', ?, '%') OR `host` LIKE CONCAT('%', ?, '%') OR `uri` LIKE CONCAT('%', ?, '%') OR `token` LIKE CONCAT('%', ?, '%'));"
    count_sql_params = {user_name, search, search, search, search}
  else
    count_sql = "SELECT COUNT(*) AS total FROM jxwaf_soc_web_protection_model WHERE `user_name` = ? ;"
    count_sql_params = {user_name}
  end
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  if search then
    sql = "SELECT * FROM jxwaf_soc_web_protection_model  WHERE `user_name` = ? AND (`raw_string` LIKE CONCAT('%', ?, '%') OR `host` LIKE CONCAT('%', ?, '%') OR `uri` LIKE CONCAT('%', ?, '%') OR `token` LIKE CONCAT('%', ?, '%')) order by request_time desc LIMIT ? OFFSET ?;"
    sql_params = {user_name, search, search, search, search, pageSize, offset}
  else
    sql = "SELECT * FROM jxwaf_soc_web_protection_model  WHERE `user_name` = ?  order by request_time desc LIMIT ? OFFSET ?;"
    sql_params = {user_name, pageSize, offset}
  end
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)
  local response_message = {
      records = query_result,
      page = page,
      total_pages = total_pages,
      total_records = total,
      result = true
  }
  response.raw_success_response(response_message)
end

function _M.delete_soc_web_protection_model()
  local user_name = login_check.get_session()
  local check_param = {"token"}
  local body_data = request_data.get_body_data(check_param)
  local token = body_data['token']
  local sql = "DELETE FROM jxwaf_soc_web_protection_model WHERE token = ? AND user_name = ? ;"
  local sql_params = {token, user_name}
  local sql_result, sql_error = db_query.query_mysql(sql, sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("delete success")
end

function _M.edit_soc_web_protection_model_result()
  local user_name = login_check.get_session()
  local check_param = {"token", "ai_analysis_result"}
  local body_data = request_data.get_body_data(check_param)
  local token = body_data['token']
  local ai_analysis_result = body_data['ai_analysis_result']
  local request_time = ngx.localtime()
  local sql = "UPDATE jxwaf_soc_web_protection_model SET ai_analysis_result = ?, request_time = ? WHERE token = ? AND user_name = ? ;"
  local sql_params = {ai_analysis_result, request_time, token, user_name}
  local sql_result, sql_error = db_query.query_mysql(sql, sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("update success")
end


return _M