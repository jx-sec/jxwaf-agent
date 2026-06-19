local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local tools = require 'resty.admin_server.tools'

local _M = {}

function _M.get_soc_log_query_list()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time", "page", "sql_rules"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local page = tonumber(body_data['page']) or 1
  local pageSize = 20
  local offset = (page - 1) * pageSize
  local sql_rules = body_data['sql_rules'] or {}

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end

  local report_conf_ch_host = sys_query_result[1]['report_conf_ch_host']
  local report_conf_ch_port = sys_query_result[1]['report_conf_ch_port']
  local report_conf_ch_user = sys_query_result[1]['report_conf_ch_user']
  local report_conf_ch_password = sys_query_result[1]['report_conf_ch_password']
  local report_conf_ch_database = sys_query_result[1]['report_conf_ch_database']
  local report_conf_ch_table = sys_query_result[1]['report_conf_ch_table']
  local clickhouse_db_config = {
    host = report_conf_ch_host,
    port = report_conf_ch_port,
    user = report_conf_ch_user,
    database = report_conf_ch_database,
    password = report_conf_ch_password,
    charset = "utf8mb4"
  }

  local where_conditions = {}
  local sql_params = {}
  for _, rule in ipairs(sql_rules) do
    local field_name = rule['field']
    local operation = rule['operation']
    local value = rule['value']
    if operation == "contains" then
      table.insert(where_conditions, field_name .. " LIKE ?")
      table.insert(sql_params, "%" .. value .. "%")
    elseif operation == "prefix" then
      table.insert(where_conditions, field_name .. " LIKE ?")
      table.insert(sql_params, value .. "%")
    elseif operation == "suffix" then
      table.insert(where_conditions, field_name .. " LIKE ?")
      table.insert(sql_params, "%" .. value)
    elseif operation == "equals" then
      table.insert(where_conditions, field_name .. " = ?")
      table.insert(sql_params, value)
    elseif operation == "not_equals" then
      table.insert(where_conditions, field_name .. " <> ?")
      table.insert(sql_params, value)
    end
  end

  local parse_sql_rule = table.concat(where_conditions, " AND ")
  local additional_where = ""
  if #where_conditions > 0 then
    additional_where = " AND " .. parse_sql_rule
  end

  local count_sql = [[
    SELECT COUNT(*) AS total
    FROM ]] .. report_conf_ch_table .. [[
    WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?)]] .. additional_where .. [[;
  ]]

  local count_params = {from_time, to_time}
  for _, param in ipairs(sql_params) do
    table.insert(count_params, param)
  end

  local count_result, count_err = db_query.clickhouse_query_mysql(count_sql, clickhouse_db_config, count_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  local sql = [[
    SELECT *
    FROM ]] .. report_conf_ch_table .. [[
    WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?)]] .. additional_where .. [[
    ORDER BY request_time DESC
    LIMIT ? OFFSET ?;
  ]]
  
  local query_params = {from_time, to_time}
  for _, param in ipairs(sql_params) do
    table.insert(query_params, param)
  end
  table.insert(query_params, pageSize)
  table.insert(query_params, offset)
  
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, query_params)
  if not query_result or query_error then
    response.fail_response(query_error)
  end

  local return_result = {
    result = true,
    message = query_result,
    total_count = total,
    total_pages = total_pages,
    now_page = page
  }
  response.raw_success_response(return_result)
end

return _M
