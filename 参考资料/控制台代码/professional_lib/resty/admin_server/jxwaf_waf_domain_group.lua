local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}

--日 PV 级别	单 IP 请求限制 /60s	独立 IP 数限制 /60s	域名总请求限制 /60s	阻断时长
--~1 万（个人/小企业）	50 ~ 100 次	50 ~ 100 个	1,000 ~ 3,000 次	600 秒
--~10 万（中型站）	200 ~ 500 次	200 ~ 500 个	5,000 ~ 10,000 次	600 秒
--~100 万（中大型站）	600 ~ 1,500 次	1,500 ~ 3,000 个	30,000 ~ 60,000 次	300 ~ 600 秒
--~1000 万（大型平台）	2,000 ~ 5,000 次	10,000 ~ 20,000 个	200,000 ~ 400,000 次	120 ~ 300 秒

local DEFAULT_PLANS_CONFIG = {
  daily_observe = {
    ip_access_limit_status = "true",
    ip_access_limit_stat_time = "60",
    ip_access_limit_threshold = "1000",
    ip_access_limit_action = "watch",
    ip_access_limit_action_extra_parameter = "auto",
    ip_access_limit_duration = "300",
    ip_count_limit_status = "true",
    ip_count_limit_stat_time = "60",
    ip_count_limit_threshold = "1000",
    ip_count_limit_action = "watch",
    ip_count_limit_action_extra_parameter = "auto",
    domain_access_limit_status = "true",
    domain_access_limit_stat_time = "60",
    domain_access_limit_threshold = "100000",
    domain_access_limit_action = "watch",
    domain_access_limit_action_extra_parameter = "auto",
    ssl_fingerprint_protection_status = "false",
    ssl_fingerprint_protection_action = "watch",
    ssl_fingerprint_protection_action_extra_parameter = "auto",
    emergency_protection_status = "false",
    emergency_protection_action = "watch",
    emergency_protection_action_extra_parameter = "auto"
  },
  daily_protect = {
    ip_access_limit_status = "true",
    ip_access_limit_stat_time = "60",
    ip_access_limit_threshold = "1000",
    ip_access_limit_action = "bot_check",
    ip_access_limit_action_extra_parameter = "auto",
    ip_access_limit_duration = "300",
    ip_count_limit_status = "true",
    ip_count_limit_stat_time = "60",
    ip_count_limit_threshold = "1000",
    ip_count_limit_action = "bot_check",
    ip_count_limit_action_extra_parameter = "auto",
    domain_access_limit_status = "true",
    domain_access_limit_stat_time = "60",
    domain_access_limit_threshold = "100000",
    domain_access_limit_action = "bot_check",
    domain_access_limit_action_extra_parameter = "auto",
    ssl_fingerprint_protection_status = "false",
    ssl_fingerprint_protection_action = "bot_check",
    ssl_fingerprint_protection_action_extra_parameter = "auto",
    emergency_protection_status = "false",
    emergency_protection_action = "bot_check",
    emergency_protection_action_extra_parameter = "auto"
  },
  attack_protect = {
    ip_access_limit_status = "true",
    ip_access_limit_stat_time = "60",
    ip_access_limit_threshold = "500",
    ip_access_limit_action = "bot_check",
    ip_access_limit_action_extra_parameter = "slipper",
    ip_access_limit_duration = "600",
    ip_count_limit_status = "true",
    ip_count_limit_stat_time = "60",
    ip_count_limit_threshold = "500",
    ip_count_limit_action = "bot_check",
    ip_count_limit_action_extra_parameter = "slipper",
    domain_access_limit_status = "true",
    domain_access_limit_stat_time = "60",
    domain_access_limit_threshold = "50000",
    domain_access_limit_action = "bot_check",
    domain_access_limit_action_extra_parameter = "slipper",
    ssl_fingerprint_protection_status = "true",
    ssl_fingerprint_protection_action = "bot_check",
    ssl_fingerprint_protection_action_extra_parameter = "slipper",
    emergency_protection_status = "false",
    emergency_protection_action = "bot_check",
    emergency_protection_action_extra_parameter = "slipper"
  },
  emergency_protect = {
    ip_access_limit_status = "true",
    ip_access_limit_stat_time = "60",
    ip_access_limit_threshold = "100",
    ip_access_limit_action = "bot_check",
    ip_access_limit_action_extra_parameter = "words",
    ip_access_limit_duration = "900",
    ip_count_limit_status = "true",
    ip_count_limit_stat_time = "60",
    ip_count_limit_threshold = "100",
    ip_count_limit_action = "bot_check",
    ip_count_limit_action_extra_parameter = "words",
    domain_access_limit_status = "true",
    domain_access_limit_stat_time = "60",
    domain_access_limit_threshold = "10000",
    domain_access_limit_action = "bot_check",
    domain_access_limit_action_extra_parameter = "words",
    ssl_fingerprint_protection_status = "true",
    ssl_fingerprint_protection_action = "bot_check",
    ssl_fingerprint_protection_action_extra_parameter = "words",
    emergency_protection_status = "true",
    emergency_protection_action = "bot_check",
    emergency_protection_action_extra_parameter = "words"
  }
}

function _M.get_domain_group_list()
  local user_name = login_check.get_session()
  local check_param = {"page"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_domain_group WHERE `user_name` = ?;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name})
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_domain_group  WHERE `user_name` = ?  LIMIT ? OFFSET ?;"
  local sql_params = {user_name,pageSize,offset}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
  end
  local domain_count_sql = "SELECT group_name, COUNT(*) AS domain_count FROM jxwaf_waf_domain WHERE `user_name` = ? GROUP BY group_name;"
  local domain_count_result, domain_count_err = db_query.query_mysql(domain_count_sql, {user_name})
  if not domain_count_result or domain_count_err then
    response.fail_response(domain_count_err)
  end
  local domain_count_map = {}
  for _, item in ipairs(domain_count_result) do
    domain_count_map[item.group_name] = tonumber(item.domain_count) or 0
  end
  local web_engine_sql = "SELECT group_name, ai_protection FROM jxwaf_waf_group_web_engine_protection WHERE `user_name` = ?;"
  local web_engine_result, web_engine_err = db_query.query_mysql(web_engine_sql, {user_name})
  if not web_engine_result or web_engine_err then
    response.fail_response(web_engine_err)
  end
  local web_engine_map = {}
  for _, item in ipairs(web_engine_result) do
    web_engine_map[item.group_name] = item.ai_protection
  end
  local flow_engine_sql = "SELECT group_name, engine_status FROM jxwaf_waf_group_flow_engine_protection WHERE `user_name` = ?;"
  local flow_engine_result, flow_engine_err = db_query.query_mysql(flow_engine_sql, {user_name})
  if not flow_engine_result or flow_engine_err then
    response.fail_response(flow_engine_err)
  end
  local flow_engine_map = {}
  for _, item in ipairs(flow_engine_result) do
    flow_engine_map[item.group_name] = item.engine_status
  end
  for _, record in ipairs(query_result) do
    record.domain_count = domain_count_map[record.group_name] or 0
    record.web_engine_status = web_engine_map[record.group_name] or ""
    record.flow_engine_status = flow_engine_map[record.group_name] or ""
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

function _M.api_get_domain_group_list()
  local user_name = login_check.get_session()
  local sql = "SELECT * FROM jxwaf_waf_domain_group  WHERE `user_name` = ? ;"
  local sql_params = {user_name}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
  end
  cjson.encode_empty_table_as_object(false)
  local response_message = {
      records = query_result,
      result = true
  }
  response.raw_success_response(response_message)
end


function _M.get_domain_group_search_list()
  local user_name = login_check.get_session()
  local check_param = {"page","search"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local search = body_data['search']
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_domain_group WHERE `user_name` = ? AND `group_name` LIKE CONCAT('%', ?, '%');"
  local count_sql_params = {user_name,search}
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_domain_group  WHERE `user_name` = ? AND `group_name` LIKE CONCAT('%', ?, '%') LIMIT ? OFFSET ?;"
  local sql_params = {user_name,search,pageSize,offset}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
  end
  local domain_count_sql = "SELECT group_name, COUNT(*) AS domain_count FROM jxwaf_waf_domain WHERE `user_name` = ? GROUP BY group_name;"
  local domain_count_result, domain_count_err = db_query.query_mysql(domain_count_sql, {user_name})
  if not domain_count_result or domain_count_err then
    response.fail_response(domain_count_err)
  end
  local domain_count_map = {}
  for _, item in ipairs(domain_count_result) do
    domain_count_map[item.group_name] = tonumber(item.domain_count) or 0
  end
  local web_engine_sql = "SELECT group_name, ai_protection FROM jxwaf_waf_group_web_engine_protection WHERE `user_name` = ?;"
  local web_engine_result, web_engine_err = db_query.query_mysql(web_engine_sql, {user_name})
  if not web_engine_result or web_engine_err then
    response.fail_response(web_engine_err)
  end
  local web_engine_map = {}
  for _, item in ipairs(web_engine_result) do
    web_engine_map[item.group_name] = item.ai_protection
  end
  local flow_engine_sql = "SELECT group_name, engine_status FROM jxwaf_waf_group_flow_engine_protection WHERE `user_name` = ?;"
  local flow_engine_result, flow_engine_err = db_query.query_mysql(flow_engine_sql, {user_name})
  if not flow_engine_result or flow_engine_err then
    response.fail_response(flow_engine_err)
  end
  local flow_engine_map = {}
  for _, item in ipairs(flow_engine_result) do
    flow_engine_map[item.group_name] = item.engine_status
  end
  for _, record in ipairs(query_result) do
    record.domain_count = domain_count_map[record.group_name] or 0
    record.web_engine_status = web_engine_map[record.group_name] or ""
    record.flow_engine_status = flow_engine_map[record.group_name] or ""
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

function _M.get_domain_group()
  local user_name = login_check.get_session()
  local check_param = {"group_name"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local sql = "SELECT * FROM jxwaf_waf_domain_group  WHERE `user_name` = ? AND `group_name` = ?;"
  local sql_params = {user_name, group_name}   
  local query_result = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response("group_name is not exist")
  end
end


function _M.create_domain_group()
  local user_name = login_check.get_session()
  local check_param = {"group_name","group_detail"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local group_detail = body_data['group_detail']
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_domain_group WHERE group_name = ? AND user_name = ?;"
  local count_sql_params = {group_name,user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) > 0 then
    response.fail_response("group_name is exist")
  end
  local web_engine_protection_del_sql = "DELETE FROM jxwaf_waf_group_web_engine_protection WHERE group_name = ? AND user_name = ?;"
  local web_engine_protection_del_sql_params = {group_name,user_name}
  local web_engine_protection_del_sql_result,web_engine_protection_del_sql_error = db_query.query_mysql(web_engine_protection_del_sql,web_engine_protection_del_sql_params)
  if not web_engine_protection_del_sql_result then
    response.fail_response(web_engine_protection_del_sql_error)
  end
  local web_engine_protection_create_sql = "INSERT INTO jxwaf_waf_group_web_engine_protection (user_name,group_name) VALUES (?,?);"
  local web_engine_protection_create_sql_params = {user_name,group_name}
  local web_engine_protection_create_result,web_engine_protection_create_err = db_query.query_mysql(web_engine_protection_create_sql,web_engine_protection_create_sql_params)
  if not web_engine_protection_create_result then
    response.fail_response(web_engine_protection_create_err)
  end
  local flow_ip_region_block_del_sql = "DELETE FROM jxwaf_waf_group_flow_ip_region_block WHERE group_name = ? AND user_name = ?;"
  local flow_ip_region_block_del_sql_params = {group_name,user_name}
  local flow_ip_region_block_del_sql_result,flow_ip_region_block_del_sql_error = db_query.query_mysql(flow_ip_region_block_del_sql,flow_ip_region_block_del_sql_params)
  if not flow_ip_region_block_del_sql_result then
    response.fail_response(flow_ip_region_block_del_sql_error)
  end
  local flow_ip_region_block_create_sql = "INSERT INTO jxwaf_waf_group_flow_ip_region_block (user_name,group_name) VALUES (?,?);"
  local flow_ip_region_block_create_sql_params = {user_name,group_name}
  local flow_ip_region_block_create_result,flow_ip_region_block_create_err = db_query.query_mysql(flow_ip_region_block_create_sql,flow_ip_region_block_create_sql_params)
  if not flow_ip_region_block_create_result then
    response.fail_response(flow_ip_region_block_create_err)
  end
  local flow_engine_protection_del_sql = "DELETE FROM jxwaf_waf_group_flow_engine_protection WHERE group_name = ? AND user_name = ?;"
  local flow_engine_protection_del_sql_params = {group_name,user_name}
  local flow_engine_protection_del_sql_result,flow_engine_protection_del_sql_error = db_query.query_mysql(flow_engine_protection_del_sql,flow_engine_protection_del_sql_params)
  if not flow_engine_protection_del_sql_result then
    response.fail_response(flow_engine_protection_del_sql_error)
  end
  local plans_config_json = cjson.encode(DEFAULT_PLANS_CONFIG)
  local flow_engine_protection_create_sql = [[INSERT INTO jxwaf_waf_group_flow_engine_protection 
    (user_name, group_name, engine_status, protection_plan, plans_config)
    VALUES (?,?,?,?,?);]]
  local flow_engine_protection_create_sql_params = {user_name, group_name, "false", "daily_observe", plans_config_json}
  local flow_engine_protection_create_result,flow_engine_protection_create_err = db_query.query_mysql(flow_engine_protection_create_sql,flow_engine_protection_create_sql_params)
  if not flow_engine_protection_create_result then
    response.fail_response(flow_engine_protection_create_err)
  end
  local create_sql = "INSERT INTO jxwaf_waf_domain_group (user_name,group_name, group_detail) VALUES (?,?,?);"
  local create_sql_params = {user_name,group_name,group_detail}
  local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
  if not create_result then
    response.fail_response(create_err)
  else
    response.success_response("create success")
  end
end

function _M.delete_domain_group()
  local user_name = login_check.get_session()
  local check_param = {"group_name"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local waf_module = {}
    waf_module[1] = "jxwaf_waf_group_web_engine_protection"
    waf_module[2] = "jxwaf_waf_group_web_rule_protection"
    waf_module[3] = "jxwaf_waf_group_web_page_tamper_proof"
    waf_module[4] = "jxwaf_waf_group_web_white_rule"
    waf_module[5] = "jxwaf_waf_group_flow_engine_protection"
    waf_module[6] = "jxwaf_waf_group_flow_rule_protection"
    waf_module[7] = "jxwaf_waf_group_flow_ip_region_block"
    waf_module[8] = "jxwaf_waf_group_flow_white_rule"
    waf_module[9] = "jxwaf_waf_group_custom_request_header"
    waf_module[10] = "jxwaf_waf_group_custom_response_header"
    waf_module[11] = "jxwaf_waf_group_custom_upstream_address"
    waf_module[12] = "jxwaf_waf_domain"
  for _,v in ipairs(waf_module) do
     local del_sql = "DELETE FROM ? WHERE group_name = ? AND user_name = ?;"
     local del_sql_params = {v,group_name,user_name}
     local build_del_sql = db_query.table_build_query(del_sql,del_sql_params)
     local del_sql_result,del_sql_error = db_query.query_mysql(build_del_sql)
     if not del_sql_result then
        response.fail_response(del_sql_error)
      end
  end
  local sql = "DELETE FROM jxwaf_waf_domain_group WHERE group_name = ? AND user_name = ?;"
  local sql_params = {group_name,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("delete success")
end

function _M.edit_domain_group()
  local user_name = login_check.get_session()
  local check_param = {"group_name","group_detail"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local group_detail = body_data['group_detail']
  local sql = "UPDATE jxwaf_waf_domain_group  SET  group_detail = ? WHERE group_name = ? AND user_name = ?;"
  local sql_params = {group_detail,group_name,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

return _M 
