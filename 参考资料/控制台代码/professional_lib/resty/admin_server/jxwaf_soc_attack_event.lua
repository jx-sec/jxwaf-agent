local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local tools = require 'resty.admin_server.tools'

local _M = {}


function _M.get_soc_attack_event_list()
  local user_name = login_check.get_session()
  local check_param = {"from_time","to_time","page"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local group_name = body_data['group_name']
  local domain = body_data['domain']
  local page = tonumber(body_data['page']) or 1
  local pageSize = 50
  local offset = (page - 1) * pageSize

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

  local attack_module_condition = "(waf_module IN ('web_engine_protection', 'web_rule_protection', 'flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block', 'name_list', 'web_page_tamper_proof') AND waf_action NOT IN ('all_bypass', 'web_bypass', 'flow_bypass'))"

  local count_sql_conditions = {"request_time BETWEEN toDateTime(?) AND toDateTime(?)", attack_module_condition}
  local count_sql_params = {from_time, to_time}

  if group_name then
    table.insert(count_sql_conditions, "group_name = ?")
    table.insert(count_sql_params, group_name)
  end

  if domain then
    if string.sub(domain, 1, 1) == '*' then
      table.insert(count_sql_conditions, "host LIKE ?")
      table.insert(count_sql_params, "%" .. string.sub(domain, 2))
    else
      table.insert(count_sql_conditions, "host = ?")
      table.insert(count_sql_params, domain)
    end
  end

  local count_sql = "SELECT COUNT(DISTINCT src_ip) as total FROM " .. report_conf_ch_table ..
  " WHERE " .. table.concat(count_sql_conditions, " AND ")
  local count_result, count_err = db_query.clickhouse_query_mysql(count_sql, clickhouse_db_config, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  local sql
  local sql_params = {from_time, to_time}

  if not group_name and not domain then
    sql = [[
            SELECT
                src_ip AS AttackIP,
                COUNT(*) AS AttackCount,
                countIf(waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof')) AS BlockCount,
                uniqExact(host, uri) AS UniqueAttackInterfaces,
                COUNT(DISTINCT CASE WHEN waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof') THEN uri END) AS UniqueBlockedInterfaces,
                MIN(request_time) AS StartTime,
                MAX(request_time) AS LatestTime,
                groupUniqArray(waf_policy) AS AttackTypes
            FROM
                ]] .. report_conf_ch_table .. [[
            WHERE
                request_time BETWEEN toDateTime(?) AND toDateTime(?)
                AND ]] .. attack_module_condition .. [[
            GROUP BY
                src_ip
            ORDER BY
                LatestTime DESC
            LIMIT ]] ..pageSize ..[[  OFFSET  ]] ..offset
  elseif not group_name and domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end

    sql = [[
            SELECT
                src_ip AS AttackIP,
                COUNT(*) AS AttackCount,
                countIf(waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof')) AS BlockCount,
                uniqExact(host, uri) AS UniqueAttackInterfaces,
                COUNT(DISTINCT CASE WHEN waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof') THEN uri END) AS UniqueBlockedInterfaces,
                MIN(request_time) AS StartTime,
                MAX(request_time) AS LatestTime,
                groupUniqArray(waf_policy) AS AttackTypes
            FROM
                ]] .. report_conf_ch_table .. [[
            WHERE
                request_time BETWEEN toDateTime(?) AND toDateTime(?)
                AND ]] .. attack_module_condition .. [[ AND host ]]..domain_condition..[[
            GROUP BY
                src_ip
            ORDER BY
                LatestTime DESC
            LIMIT ]] ..pageSize ..[[  OFFSET  ]] ..offset

    table.insert(sql_params, domain_value)
  elseif group_name and not domain then
     sql = [[
            SELECT
                src_ip AS AttackIP,
                COUNT(*) AS AttackCount,
                countIf(waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof')) AS BlockCount,
                uniqExact(host, uri) AS UniqueAttackInterfaces,
                COUNT(DISTINCT CASE WHEN waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof') THEN uri END) AS UniqueBlockedInterfaces,
                MIN(request_time) AS StartTime,
                MAX(request_time) AS LatestTime,
                groupUniqArray(waf_policy) AS AttackTypes
            FROM
                ]] .. report_conf_ch_table .. [[
            WHERE
                request_time BETWEEN toDateTime(?) AND toDateTime(?) AND group_name = ?
                AND ]] .. attack_module_condition .. [[
            GROUP BY
                src_ip
            ORDER BY
                LatestTime DESC
            LIMIT ]] ..pageSize ..[[  OFFSET  ]] ..offset
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

         sql = [[
            SELECT
                src_ip AS AttackIP,
                COUNT(*) AS AttackCount,
                countIf(waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof')) AS BlockCount,
                uniqExact(host, uri) AS UniqueAttackInterfaces,
                COUNT(DISTINCT CASE WHEN waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof') THEN uri END) AS UniqueBlockedInterfaces,
                MIN(request_time) AS StartTime,
                MAX(request_time) AS LatestTime,
                groupUniqArray(waf_policy) AS AttackTypes
            FROM
                ]] .. report_conf_ch_table .. [[
            WHERE
                request_time BETWEEN toDateTime(?) AND toDateTime(?) AND group_name = ?
                AND ]] .. attack_module_condition .. [[ AND host ]]..domain_condition..[[
            GROUP BY
                src_ip
            ORDER BY
                LatestTime DESC
            LIMIT ]] ..pageSize ..[[  OFFSET  ]] ..offset

    table.insert(sql_params, group_name)
    table.insert(sql_params, domain_value)
  end
  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end

 for _, row in ipairs(query_result) do
    local attack_types_str = row["AttackTypes"]
    local attack_types = {}

    for type in string.gmatch(attack_types_str, "'([^']*)'") do
      table.insert(attack_types, type)
    end

    row["AttackTypes"] = attack_types
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



function _M.get_soc_attack_behave_track()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time", "attack_ip"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local attack_ip = body_data['attack_ip']
  local group_name = body_data['group_name']
  local domain = body_data['domain']

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

  local attack_module_condition = "(waf_module IN ('web_engine_protection', 'web_rule_protection', 'flow_engine_protection', 'flow_rule_protection', 'flow_ip_region_block', 'name_list', 'web_page_tamper_proof') AND waf_action NOT IN ('all_bypass', 'web_bypass', 'flow_bypass'))"

  local sql_conditions = {}
  local sql_params = {}

  table.insert(sql_conditions, "src_ip = ?")
  table.insert(sql_params, attack_ip)

  if group_name then
    table.insert(sql_conditions, "group_name = ?")
    table.insert(sql_params, group_name)
  end

  if domain then
    local domain_condition, domain_value
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      domain_value = "%" .. string.sub(domain, 2)
    else
      domain_condition = "= ?"
      domain_value = domain
    end
    table.insert(sql_conditions, "host " .. domain_condition)
    table.insert(sql_params, domain_value)
  end

  table.insert(sql_conditions, "request_time BETWEEN ? AND ?")
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  table.insert(sql_conditions, attack_module_condition)

  local sql = [[
        SELECT
            MIN(request_time) AS FirstRequestTime,
            MIN(request_time) AS StartAttackTime,
            MAX(request_time) AS LatestAttackTime,
            CONCAT(host, uri) AS URL,
            groupUniqArray(IF(notEmpty(waf_policy), waf_policy, NULL)) AS AttackTypes,
            COUNT(*) AS AttackCount,
            SUM(IF(waf_action IN ('block', 'reject_response', 'bot_check', 'network_block', 'page_tamper_proof'), 1, 0)) AS BlockCount,
            COUNT(*) AS TotalRequestCount,
            host AS Host,
            uri AS URI
        FROM
            ]] .. report_conf_ch_table .. [[
        WHERE ]] .. table.concat(sql_conditions, " AND ") .. [[
        GROUP BY
            host,uri
        ORDER BY
            FirstRequestTime]]

  local query_result, query_error = db_query.clickhouse_query_mysql(sql, clickhouse_db_config, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end

  for _, row in ipairs(query_result) do
    local attack_types_str = row["AttackTypes"]
    local attack_types = {}

    for type in string.gmatch(attack_types_str, "'([^']*)'") do
      table.insert(attack_types, type)
    end

    row["AttackTypes"] = attack_types
  end


  response.success_response(query_result)
end


return _M
