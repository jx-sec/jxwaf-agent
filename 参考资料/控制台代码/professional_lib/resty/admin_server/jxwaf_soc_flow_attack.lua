local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local os = require("os")
local _M = {}

local function calculate_previous_period(from_time, to_time)
  local from_ts = os.time({
    year  = tonumber(string.sub(from_time, 1, 4)),
    month = tonumber(string.sub(from_time, 6, 7)),
    day   = tonumber(string.sub(from_time, 9, 10)),
    hour  = tonumber(string.sub(from_time, 12, 13)),
    min   = tonumber(string.sub(from_time, 15, 16)),
    sec   = tonumber(string.sub(from_time, 18, 19))
  })
  local to_ts = os.time({
    year  = tonumber(string.sub(to_time, 1, 4)),
    month = tonumber(string.sub(to_time, 6, 7)),
    day   = tonumber(string.sub(to_time, 9, 10)),
    hour  = tonumber(string.sub(to_time, 12, 13)),
    min   = tonumber(string.sub(to_time, 15, 16)),
    sec   = tonumber(string.sub(to_time, 18, 19))
  })

  local duration = os.difftime(to_ts, from_ts)

  local prev_to_ts   = from_ts
  local prev_from_ts = from_ts - duration

  local prev_from = os.date("%Y-%m-%d %H:%M:%S", prev_from_ts)
  local prev_to   = os.date("%Y-%m-%d %H:%M:%S", prev_to_ts)

  return prev_from, prev_to
end

function _M.get_soc_flow_attack_count_total()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local prev_from, prev_to = calculate_previous_period(from_time, to_time)

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT COUNT(*) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT COUNT(*) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ?
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT COUNT(*) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  local current_count = tonumber(query_result[1]['count']) or 0

  local prev_sql_params = {prev_from, prev_to}
  if group_name then
    table.insert(prev_sql_params, group_name)
    if domain then
      local dv
      if string.sub(domain, 1, 1) == '*' then
        dv = "%" .. string.sub(domain, 2)
      else
        dv = domain
      end
      table.insert(prev_sql_params, dv)
    end
  end
  local prev_result, prev_err = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, prev_sql_params)

  if not prev_result or prev_err then
    response.fail_response(prev_err)
  end
  local previous_count = tonumber(prev_result[1]['count']) or 0

  local trend = "flat"
  if previous_count > 0 and current_count > previous_count then
    trend = "up"
  elseif previous_count > 0 and current_count < previous_count then
    trend = "down"
  end

  response.success_response({
    current = current_count,
    previous = previous_count,
    trend = trend
  })
end

function _M.get_soc_flow_attack_api_count_total()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local prev_from, prev_to = calculate_previous_period(from_time, to_time)

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT uniqExact(host, uri) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT uniqExact(host, uri) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ?
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT uniqExact(host, uri) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  local current_count = tonumber(query_result[1]['count']) or 0

  local prev_sql_params = {prev_from, prev_to}
  if group_name then
    table.insert(prev_sql_params, group_name)
    if domain then
      local dv
      if string.sub(domain, 1, 1) == '*' then
        dv = "%" .. string.sub(domain, 2)
      else
        dv = domain
      end
      table.insert(prev_sql_params, dv)
    end
  end
  local prev_result, prev_err = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, prev_sql_params)

  if not prev_result or prev_err then
    response.fail_response(prev_err)
  end
  local previous_count = tonumber(prev_result[1]['count']) or 0

  local trend = "flat"
  if previous_count > 0 and current_count > previous_count then
    trend = "up"
  elseif previous_count > 0 and current_count < previous_count then
    trend = "down"
  end

  response.success_response({
    current = current_count,
    previous = previous_count,
    trend = trend
  })
end

function _M.get_soc_flow_attack_ip_count_total()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local prev_from, prev_to = calculate_previous_period(from_time, to_time)

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT COUNT(DISTINCT src_ip) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT COUNT(DISTINCT src_ip) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ?
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT COUNT(DISTINCT src_ip) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  local current_count = tonumber(query_result[1]['count']) or 0

  local prev_sql_params = {prev_from, prev_to}
  if group_name then
    table.insert(prev_sql_params, group_name)
    if domain then
      local dv
      if string.sub(domain, 1, 1) == '*' then
        dv = "%" .. string.sub(domain, 2)
      else
        dv = domain
      end
      table.insert(prev_sql_params, dv)
    end
  end
  local prev_result, prev_err = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, prev_sql_params)

  if not prev_result or prev_err then
    response.fail_response(prev_err)
  end
  local previous_count = tonumber(prev_result[1]['count']) or 0

  local trend = "flat"
  if previous_count > 0 and current_count > previous_count then
    trend = "up"
  elseif previous_count > 0 and current_count < previous_count then
    trend = "down"
  end

  response.success_response({
    current = current_count,
    previous = previous_count,
    trend = trend
  })
end


function _M.get_soc_flow_attack_isocode_count_total()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local prev_from, prev_to = calculate_previous_period(from_time, to_time)

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT COUNT(DISTINCT iso_code) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT COUNT(DISTINCT iso_code) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ?
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT COUNT(DISTINCT iso_code) as count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  local current_count = tonumber(query_result[1]['count']) or 0

  local prev_sql_params = {prev_from, prev_to}
  if group_name then
    table.insert(prev_sql_params, group_name)
    if domain then
      local dv
      if string.sub(domain, 1, 1) == '*' then
        dv = "%" .. string.sub(domain, 2)
      else
        dv = domain
      end
      table.insert(prev_sql_params, dv)
    end
  end
  local prev_result, prev_err = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, prev_sql_params)

  if not prev_result or prev_err then
    response.fail_response(prev_err)
  end
  local previous_count = tonumber(prev_result[1]['count']) or 0

  local trend = "flat"
  if previous_count > 0 and current_count > previous_count then
    trend = "up"
  elseif previous_count > 0 and current_count < previous_count then
    trend = "down"
  end

  response.success_response({
    current = current_count,
    previous = previous_count,
    trend = trend
  })
end


function _M.get_soc_flow_attack_geoip()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT iso_code,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND notEmpty(iso_code)
      GROUP BY iso_code  ORDER BY attack_count DESC
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT iso_code,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND notEmpty(iso_code)
      AND group_name = ? GROUP BY iso_code  ORDER BY attack_count DESC
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT iso_code,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND notEmpty(iso_code)  AND
      group_name = ? AND host ]=] .. domain_condition .. [=[ GROUP BY iso_code  ORDER BY attack_count DESC
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  response.success_response(query_result)
end



local function calculate_time_slot(from_time, to_time)
  local time_format = "%Y-%m-%d %H:%M:%S"

  local from_time_parsed = os.time({
    year = tonumber(string.sub(from_time, 1, 4)),
    month = tonumber(string.sub(from_time, 6, 7)),
    day = tonumber(string.sub(from_time, 9, 10)),
    hour = tonumber(string.sub(from_time, 12, 13)),
    min = tonumber(string.sub(from_time, 15, 16)),
    sec = tonumber(string.sub(from_time, 18, 19))
  })
  local to_time_parsed = os.time({
    year = tonumber(string.sub(to_time, 1, 4)),
    month = tonumber(string.sub(to_time, 6, 7)),
    day = tonumber(string.sub(to_time, 9, 10)),
    hour = tonumber(string.sub(to_time, 12, 13)),
    min = tonumber(string.sub(to_time, 15, 16)),
    sec = tonumber(string.sub(to_time, 18, 19))
  })

  local diff_seconds = os.difftime(to_time_parsed, from_time_parsed)
  local diff_days = diff_seconds / (24 * 3600)

  if diff_days <= 1 then
    return "toStartOfHour(request_time)"
  elseif diff_days <= 7 then
    return "toDate(request_time)"
  elseif diff_days <= 30 then
    return "toMonday(request_time)"
  else
    return "toStartOfMonth(request_time)"
  end
end

function _M.get_soc_flow_attack_count_trend()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
  end


  local clickhouse_db_config = {
    host = sys_query_result[1]['report_conf_ch_host'],
    port = sys_query_result[1]['report_conf_ch_port'],
    user = sys_query_result[1]['report_conf_ch_user'],
    database = sys_query_result[1]['report_conf_ch_database'],
    password = sys_query_result[1]['report_conf_ch_password'],
    charset = "utf8mb4"
  }
  local report_conf_ch_table = sys_query_result[1]['report_conf_ch_table']

  local group_by_func = calculate_time_slot(from_time, to_time)

  local sql
  local sql_params = {from_time, to_time}

  local domain_condition = ""
  if domain then
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "AND host LIKE ? "
      table.insert(sql_params, "%" .. string.sub(domain, 2))
    else
      domain_condition = "AND host = ? "
      table.insert(sql_params, domain)
    end
  end

  if group_name then
    sql = "SELECT " .. group_by_func .. " AS TimeSlot, COUNT(*) AS AttackCount " ..
          "FROM " .. report_conf_ch_table .. " " ..
          "WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND " ..
          "waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') " ..
          "AND group_name = ? " .. domain_condition ..
          "GROUP BY TimeSlot " ..
          "ORDER BY TimeSlot"
    table.insert(sql_params, 3, group_name)
  else
    sql = "SELECT " .. group_by_func .. " AS TimeSlot, COUNT(*) AS AttackCount " ..
          "FROM " .. report_conf_ch_table .. " " ..
          "WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND " ..
          "waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') " .. domain_condition ..
          "GROUP BY TimeSlot " ..
          "ORDER BY TimeSlot"
  end

  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end

  response.success_response(query_result)
end



function _M.get_soc_flow_attack_api_top()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT concat(host, uri) AS api,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      GROUP BY api  ORDER BY attack_count DESC LIMIT 5
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT concat(host, uri) AS api,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      AND group_name = ? GROUP BY api  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT concat(host, uri) AS api,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[ GROUP BY api  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  response.success_response(query_result)
end



function _M.get_soc_flow_attack_type_top()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT waf_policy,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      GROUP BY waf_policy  ORDER BY attack_count DESC LIMIT 5
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT waf_policy,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      AND group_name = ? GROUP BY waf_policy  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT waf_policy,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[ GROUP BY waf_policy  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  response.success_response(query_result)
end


function _M.get_soc_flow_attack_ip_top()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT src_ip,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      GROUP BY src_ip  ORDER BY attack_count DESC LIMIT 5
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT src_ip,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      AND group_name = ? GROUP BY src_ip  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT src_ip,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[ GROUP BY src_ip  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  response.success_response(query_result)
end


function _M.get_soc_flow_attack_isocode_top()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

  local sys_sql = "SELECT * FROM jxwaf_sys_conf WHERE `user_name` = ?;"
  local sys_sql_params = {user_name}
  local sys_query_result, sys_query_error = db_query.query_mysql(sys_sql, sys_sql_params)
  if not sys_query_result or sys_query_error then
    response.fail_response(sys_query_error)
  end
  local report_conf = sys_query_result[1]['report_conf']
  local log_conf_remote = sys_query_result[1]['log_conf_remote']

  if report_conf == "false" then
    response.fail_response("ClickHouse connect is not configured")
  end
  if log_conf_remote == "false" then
    response.fail_response("remote log is not configured")
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

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [=[
      SELECT iso_code,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      GROUP BY iso_code  ORDER BY attack_count DESC LIMIT 5
    ]=]
  elseif group_name and not domain then
    sql = [=[
      SELECT iso_code,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block')
      AND group_name = ? GROUP BY iso_code  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
  elseif group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [=[
      SELECT iso_code,COUNT(*) AS attack_count
      FROM ]=] .. report_conf_ch_table .. [=[
      WHERE request_time BETWEEN toDateTime(?) AND toDateTime(?) AND
      waf_module IN ('flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block') AND
      group_name = ? AND host ]=] .. domain_condition .. [=[ GROUP BY iso_code  ORDER BY attack_count DESC LIMIT 5
    ]=]
    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  response.success_response(query_result)
end


return _M
