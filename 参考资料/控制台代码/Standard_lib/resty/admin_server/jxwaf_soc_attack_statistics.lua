local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local os = require("os")
local _M = {}

-- 获取总攻击次数
function _M.get_web_attack_count_total()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT COUNT(*) as count FROM jxwaf_waf_attack_log" .. where_clause .. ";"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result[1]['count'])
end

-- 获取攻击接口数量（去重） - 使用host+uri
function _M.get_web_attack_api_count()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT COUNT(DISTINCT CONCAT(host, uri)) as count FROM jxwaf_waf_attack_log" .. where_clause .. ";"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result[1]['count'])
end

-- 获取攻击IP数量（去重）
function _M.get_web_attack_ip_count()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT COUNT(DISTINCT src_ip) as count FROM jxwaf_waf_attack_log" .. where_clause .. ";"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result[1]['count'])
end

-- 获取攻击国家数量（去重）
function _M.get_web_attack_country_count()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ? AND iso_code != ''"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT COUNT(DISTINCT iso_code) as count FROM jxwaf_waf_attack_log" .. where_clause .. ";"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result[1]['count'])
end

-- 获取攻击类型排名（TOP 10）
function _M.get_web_attack_type_ranking()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT waf_policy as attack_type, COUNT(*) as attack_count " ..
              "FROM jxwaf_waf_attack_log" .. where_clause .. " " ..
              "GROUP BY waf_policy ORDER BY attack_count DESC LIMIT 5;"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result)
end

-- 获取攻击接口排名（TOP 10） - 修正为host+uri
function _M.get_web_attack_api_ranking()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT CONCAT(host, uri) as api, COUNT(*) as attack_count " ..
              "FROM jxwaf_waf_attack_log" .. where_clause .. " " ..
              "GROUP BY CONCAT(host, uri) ORDER BY attack_count DESC LIMIT 5;"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result)
end

-- 获取攻击IP排名（TOP 10）
function _M.get_web_attack_ip_ranking()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT src_ip as attack_ip, COUNT(*) as attack_count " ..
              "FROM jxwaf_waf_attack_log" .. where_clause .. " " ..
              "GROUP BY src_ip ORDER BY attack_count DESC LIMIT 5;"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result)
end

-- 获取攻击国家排名（TOP 10）
function _M.get_web_attack_country_ranking()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local sql_params = {}
  local where_clause = " WHERE request_time >= ? AND request_time <= ? AND iso_code != ''"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = "SELECT iso_code as country, COUNT(*) as attack_count " ..
              "FROM jxwaf_waf_attack_log" .. where_clause .. " " ..
              "GROUP BY iso_code ORDER BY attack_count DESC LIMIT 5;"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result)
end

-- 辅助函数：计算时间粒度
local function calculate_time_slot(from_time, to_time)
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
    return "DATE_FORMAT(request_time, '%Y-%m-%d %H:00:00')"  -- 按小时分组
  elseif diff_days <= 7 then
    return "DATE(request_time)"  -- 按天分组
  elseif diff_days <= 30 then
    return "DATE_FORMAT(request_time, '%Y-%u')"  -- 按周分组（年-周数）
  else
    return "DATE_FORMAT(request_time, '%Y-%m')"  -- 按月分组
  end
end

-- 获取攻击趋势分析
function _M.get_web_attack_trend()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local domain = body_data['domain']

  local time_func = calculate_time_slot(from_time, to_time)
  local sql_params = {}

  local where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(sql_params, from_time)
  table.insert(sql_params, to_time)

  -- 添加域名条件
  if domain then
    local domain_condition
    if string.sub(domain, 1, 1) == '*' then
      domain_condition = "LIKE ?"
      local domain_value = "%" .. string.sub(domain, 2)
      table.insert(sql_params, domain_value)
    else
      domain_condition = "= ?"
      table.insert(sql_params, domain)
    end
    where_clause = where_clause .. " AND host " .. domain_condition
  end

  local sql = string.format("SELECT %s AS TimeSlot, COUNT(*) AS AttackCount ", time_func) ..
              "FROM jxwaf_waf_attack_log" .. where_clause .. " " ..
              "GROUP BY TimeSlot ORDER BY TimeSlot;"

  local query_result, query_error = db_query.query_mysql(sql, sql_params)

  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)

  response.success_response(query_result)
end


function _M.get_soc_log_query_list()
  local user_name = login_check.get_session()
  local check_param = {"from_time", "to_time", "page"}
  local body_data = request_data.get_body_data(check_param)
  local from_time = body_data['from_time']
  local to_time = body_data['to_time']
  local page = tonumber(body_data['page']) or 1
  local pageSize = 20
  local offset = (page - 1) * pageSize
  local sql_rules = body_data['sql_rules'] or {}

  -- 先获取总数
  local count_sql_params = {}
  local count_where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(count_sql_params, from_time)
  table.insert(count_sql_params, to_time)

  -- 构建动态条件
  for _, rule in ipairs(sql_rules) do
    local field_name = rule['field']
    local operation = rule['operation']
    local value = rule['value']

    if operation == "contains" then
      count_where_clause = count_where_clause .. " AND " .. field_name .. " LIKE ?"
      table.insert(count_sql_params, "%" .. value .. "%")
    elseif operation == "prefix" then
      count_where_clause = count_where_clause .. " AND " .. field_name .. " LIKE ?"
      table.insert(count_sql_params, value .. "%")
    elseif operation == "suffix" then
      count_where_clause = count_where_clause .. " AND " .. field_name .. " LIKE ?"
      table.insert(count_sql_params, "%" .. value)
    elseif operation == "equals" then
      count_where_clause = count_where_clause .. " AND " .. field_name .. " = ?"
      table.insert(count_sql_params, value)
    elseif operation == "not_equals" then
      count_where_clause = count_where_clause .. " AND " .. field_name .. " <> ?"
      table.insert(count_sql_params, value)
    end
  end

  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_attack_log" .. count_where_clause .. ";"
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)

  if not count_result or count_err then
    response.fail_response(count_err)
  end

  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  -- 获取分页数据
  local query_sql_params = {}
  local query_where_clause = " WHERE request_time >= ? AND request_time <= ?"
  table.insert(query_sql_params, from_time)
  table.insert(query_sql_params, to_time)

  -- 构建动态条件（与总数查询相同）
  for _, rule in ipairs(sql_rules) do
    local field_name = rule['field']
    local operation = rule['operation']
    local value = rule['value']

    if operation == "contains" then
      query_where_clause = query_where_clause .. " AND " .. field_name .. " LIKE ?"
      table.insert(query_sql_params, "%" .. value .. "%")
    elseif operation == "prefix" then
      query_where_clause = query_where_clause .. " AND " .. field_name .. " LIKE ?"
      table.insert(query_sql_params, value .. "%")
    elseif operation == "suffix" then
      query_where_clause = query_where_clause .. " AND " .. field_name .. " LIKE ?"
      table.insert(query_sql_params, "%" .. value)
    elseif operation == "equals" then
      query_where_clause = query_where_clause .. " AND " .. field_name .. " = ?"
      table.insert(query_sql_params, value)
    elseif operation == "not_equals" then
      query_where_clause = query_where_clause .. " AND " .. field_name .. " <> ?"
      table.insert(query_sql_params, value)
    end
  end

  -- 添加分页参数
  table.insert(query_sql_params, pageSize)
  table.insert(query_sql_params, offset)

  local query_sql = "SELECT * " ..
                    "FROM jxwaf_waf_attack_log" .. query_where_clause .. " " ..
                    "ORDER BY request_time DESC LIMIT ? OFFSET ?;"

  local query_result, query_error = db_query.query_mysql(query_sql, query_sql_params)

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

  cjson.encode_empty_table_as_object(false)
  response.raw_success_response(return_result)
end



return _M
