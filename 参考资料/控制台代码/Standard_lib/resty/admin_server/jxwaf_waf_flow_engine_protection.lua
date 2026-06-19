local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}

local DEFAULT_PLAN_CONFIG = {
  ip_access_limit_status = "true",
  ip_access_limit_stat_time = "60",
  ip_access_limit_threshold = "100",
  ip_access_limit_action = "block",
  ip_access_limit_action_extra_parameter = "auto",
  ip_access_limit_duration = "300",
  ip_count_limit_status = "true",
  ip_count_limit_stat_time = "60",
  ip_count_limit_threshold = "200",
  ip_count_limit_action = "bot_check",
  ip_count_limit_action_extra_parameter = "auto",
  domain_access_limit_status = "false",
  domain_access_limit_stat_time = "60",
  domain_access_limit_threshold = "10000",
  domain_access_limit_action = "bot_check",
  domain_access_limit_action_extra_parameter = "auto",
  ssl_fingerprint_protection_status = "false",
  ssl_fingerprint_protection_action = "bot_check",
  ssl_fingerprint_protection_action_extra_parameter = "auto",
  emergency_protection_status = "false",
  emergency_protection_action = "block",
  emergency_protection_action_extra_parameter = "auto"
}

local function create_default_flow_engine_protection(user_name)
  local plan_config_json = cjson.encode(DEFAULT_PLAN_CONFIG)
  local create_sql = [[INSERT INTO jxwaf_waf_flow_engine_protection
    (user_name, engine_status, plans_config)
    VALUES (?,?,?);]]
  local create_sql_params = {user_name, "false", plan_config_json}
  local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)
  if not create_result then
    ngx.log(ngx.ERR, "create default flow engine protection failed: ", create_err)
    return false
  end
  return true
end

function _M.get_flow_engine_protection()
  local user_name = login_check.get_session()
  local check_param = {}
  local body_data = request_data.get_body_data(check_param)

  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_flow_engine_protection WHERE user_name = ?;"
  local count_sql_params = {user_name}
  local count_sql_result, count_error = db_query.query_mysql(count_sql, count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
    return
  end

  if tonumber(count_sql_result[1].count) == 0 then
    local success = create_default_flow_engine_protection(user_name)
    if not success then
      response.fail_response("create default protection failed")
      return
    end
  end

  local sql = "SELECT * FROM jxwaf_waf_flow_engine_protection WHERE user_name = ?;"
  local sql_params = {user_name}

  local query_result, query_error = db_query.query_mysql(sql, sql_params)
  if query_result and #query_result > 0 then
    local result = query_result[1]
    local plan_config = {}

    if result.plans_config and result.plans_config ~= ngx.null then
      plan_config = cjson.decode(result.plans_config) or {}
    end

    local response_data = {
      user_name = result.user_name,
      engine_status = result.engine_status
    }

    for k, v in pairs(plan_config) do
      response_data[k] = v
    end

    response.success_response(response_data)
  else
    response.fail_response(query_error or "protection config not found")
  end
end

function _M.edit_flow_engine_protection()
  local user_name = login_check.get_session()
  local check_param = {}
  local body_data = request_data.get_body_data(check_param)

  local sql = "SELECT plans_config FROM jxwaf_waf_flow_engine_protection WHERE user_name = ?;"
  local sql_params = {user_name}
  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or #query_result == 0 then
    response.fail_response(query_error or "protection config not found")
    return
  end

  local plan_config = {}
  if query_result[1].plans_config and query_result[1].plans_config ~= ngx.null then
    plan_config = cjson.decode(query_result[1].plans_config) or {}
  end

  local plan_config_fields = {
    "ip_access_limit_status", "ip_access_limit_stat_time", "ip_access_limit_threshold",
    "ip_access_limit_action", "ip_access_limit_action_extra_parameter", "ip_access_limit_duration",
    "ip_count_limit_status", "ip_count_limit_stat_time", "ip_count_limit_threshold",
    "ip_count_limit_action", "ip_count_limit_action_extra_parameter",
    "domain_access_limit_status", "domain_access_limit_stat_time", "domain_access_limit_threshold",
    "domain_access_limit_action", "domain_access_limit_action_extra_parameter",
    "ssl_fingerprint_protection_status", "ssl_fingerprint_protection_action", "ssl_fingerprint_protection_action_extra_parameter",
    "emergency_protection_status", "emergency_protection_action", "emergency_protection_action_extra_parameter"
  }

  for _, field in ipairs(plan_config_fields) do
    if body_data[field] then
      plan_config[field] = body_data[field]
    end
  end

  local update_fields = {}
  local update_params = {}

  if body_data['engine_status'] then
    table.insert(update_fields, "engine_status = ?")
    table.insert(update_params, body_data['engine_status'])
  end

  table.insert(update_fields, "plans_config = ?")
  table.insert(update_params, cjson.encode(plan_config))

  table.insert(update_params, user_name)

  local update_sql = "UPDATE jxwaf_waf_flow_engine_protection SET " .. table.concat(update_fields, ", ") .. " WHERE user_name = ?;"

  local update_result, update_error = db_query.query_mysql(update_sql, update_params)
  if not update_result then
    response.fail_response(update_error)
    return
  end

  response.success_response("edit success")
end

return _M
