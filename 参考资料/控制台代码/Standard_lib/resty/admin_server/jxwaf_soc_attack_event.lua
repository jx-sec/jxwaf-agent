local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local tools = require 'resty.admin_server.tools'

local _M = {}

function _M.get_soc_attack_event_list()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time", "page"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']
  local page = tonumber(body_data['page']) or 1
  local pageSize = 50
  local offset = (page - 1) * pageSize

  -- 修复：删除多余的右括号
  local count_sql = [[
    SELECT COUNT(DISTINCT src_ip) as total
    FROM jxwaf_waf_attack_log
    WHERE request_time >= ? AND request_time <= ?
  ]]

  local count_sql_params = {from_time, to_time}

  -- 添加域名条件
  if domain and domain ~= '' then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(count_sql_params, domain_value)
      count_sql = count_sql .. " AND host " .. domain_condition
    else
      domain_condition = "= ?"
      table.insert(count_sql_params, domain)
      count_sql = count_sql .. " AND host " .. domain_condition
    end
  end

  count_sql = count_sql .. ";"

  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end

  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  -- 构建主查询
  local sql = [[
    SELECT
      src_ip AS AttackIP,
      COUNT(*) AS AttackCount,
      COUNT(CASE WHEN waf_action IN ('block', 'reject_response', 'bot_check') THEN 1 END) AS BlockCount,
      COUNT(DISTINCT CONCAT(host, uri)) AS UniqueAttackInterfaces,
      COUNT(DISTINCT CASE WHEN waf_action IN ('block', 'reject_response', 'bot_check') THEN uri END) AS UniqueBlockedInterfaces,
      MIN(request_time) AS StartTime,
      MAX(request_time) AS LatestTime,
      GROUP_CONCAT(DISTINCT waf_policy ORDER BY waf_policy) AS AttackTypes
    FROM
      jxwaf_waf_attack_log
    WHERE
      request_time >= ? AND request_time <= ?
  ]]

  local sql_params = {from_time, to_time}

  -- 添加域名条件
  if domain and domain ~= '' then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
      sql = sql .. " AND host " .. domain_condition
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
      sql = sql .. " AND host " .. domain_condition
    end
  end

  -- 添加分组和分页
  sql = sql .. [[
    GROUP BY
      src_ip
    ORDER BY
      StartTime DESC
    LIMIT ? OFFSET ?
  ]]

  table.insert(sql_params, pageSize)
  table.insert(sql_params, offset)

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end

  -- 处理AttackTypes字段（从逗号分隔的字符串转换为数组）
  for _, row in ipairs(query_result) do
    local attack_types_str = row["AttackTypes"]
    local attack_types = {}

    if attack_types_str and attack_types_str ~= '' then
      -- 分割字符串
      for type in string.gmatch(attack_types_str, "([^,]+)") do
        table.insert(attack_types, type)
      end
    end

    row["AttackTypes"] = attack_types
  end
  cjson.encode_empty_table_as_object(false)
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
  local domain = body_data['domain']

  local sql_conditions = {}
  local sql_params = {}

  -- 添加基础条件
  table.insert(sql_conditions, "src_ip = ?")
  table.insert(sql_params, attack_ip)

  table.insert(sql_conditions, "request_time >= ? AND request_time <= ?")
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
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

  -- 构建查询
  local sql = [[
    SELECT
      MIN(request_time) AS FirstRequestTime,
      MIN(CASE WHEN waf_module NOT IN ('web_white_rule', 'flow_white_rule', '') THEN request_time ELSE NULL END) AS StartAttackTime,
      MAX(CASE WHEN waf_module NOT IN ('web_white_rule', 'flow_white_rule', '') THEN request_time ELSE NULL END) AS LatestAttackTime,
      CONCAT(host, uri) AS URL,
      GROUP_CONCAT(DISTINCT CASE WHEN waf_policy != '' THEN waf_policy ELSE NULL END ORDER BY waf_policy) AS AttackTypes,
      SUM(CASE WHEN waf_module NOT IN ('web_white_rule', 'flow_white_rule', '') THEN 1 ELSE 0 END) AS AttackCount,
      SUM(CASE WHEN waf_action IN ('block', 'reject_response', 'bot_check') THEN 1 ELSE 0 END) AS BlockCount,
      COUNT(*) AS TotalRequestCount,
      host AS Host,
      uri AS URI
    FROM
      jxwaf_waf_attack_log
    WHERE ]] .. table.concat(sql_conditions, " AND ") .. [[
    GROUP BY
      host, uri
    HAVING
      AttackCount > 0
    ORDER BY
      StartAttackTime DESC
  ]]

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end

  -- 处理AttackTypes字段（从逗号分隔的字符串转换为数组）
  for _, row in ipairs(query_result) do
    local attack_types_str = row["AttackTypes"]
    local attack_types = {}

    if attack_types_str and attack_types_str ~= '' then
      -- 分割字符串
      for type in string.gmatch(attack_types_str, "([^,]+)") do
        table.insert(attack_types, type)
      end
    end

    row["AttackTypes"] = attack_types
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result)
end

return _M
