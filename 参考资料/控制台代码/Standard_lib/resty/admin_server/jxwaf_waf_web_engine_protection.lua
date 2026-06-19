local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}

function _M.get_web_engine_protection()
  local user_name = login_check.get_session()
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_web_engine_protection WHERE user_name = ?;"
  local count_sql_params = {user_name}
  local count_sql_result, count_error = db_query.query_mysql(count_sql, count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) ~= 1 then
    local del_sql = "DELETE FROM jxwaf_waf_web_engine_protection WHERE user_name = ?;"
    local del_sql_params = {user_name}
    local del_sql_result, del_sql_error = db_query.query_mysql(del_sql, del_sql_params)
    if not del_sql_result then
      response.fail_response(del_sql_error)
    end
    local create_sql = "INSERT INTO jxwaf_waf_web_engine_protection (user_name) VALUES (?);"
    local create_sql_params = {user_name}
    local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)
    if not create_result then
      response.fail_response(create_err)
    end
  end
  local sql = "SELECT * FROM jxwaf_waf_web_engine_protection WHERE user_name = ?;"
  local sql_params = {user_name}
  local query_result, query_error = db_query.query_mysql(sql, sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response(query_error)
  end
end

function _M.edit_web_engine_protection()
  local user_name = login_check.get_session()
  local check_param = {"ai_protection", "protection_mode", "model_provider", "model_api_key", "engine_protection"}
  local body_data = request_data.get_body_data(check_param)

  local ai_protection = body_data['ai_protection']
  local protection_mode = body_data['protection_mode']
  local model_provider = body_data['model_provider']
  local model_api_key = body_data['model_api_key']
  local engine_protection = body_data['engine_protection']

  local sql = "UPDATE jxwaf_waf_web_engine_protection SET ai_protection = ?, protection_mode = ?, model_provider = ?, model_api_key = ?, engine_protection = ? WHERE user_name = ?;"
  local sql_params = {ai_protection, protection_mode, model_provider, model_api_key, engine_protection, user_name}
  local sql_result, sql_error = db_query.query_mysql(sql, sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

return _M
