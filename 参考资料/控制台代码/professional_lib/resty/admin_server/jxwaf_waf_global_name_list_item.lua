local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}

function _M.get_name_list_item_list_list()
  local user_name = login_check.get_session()
  local check_param = {"page","name_list_name"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local name_list_name = body_data['name_list_name']
  local pageSize = 50
  local offset = (page - 1) * pageSize

  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND name_list_name = ? ;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name, name_list_name})
  if not count_result or count_err then
    response.fail_response(count_err)
    return
  end

  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  local sql = "SELECT * FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND name_list_name = ? LIMIT ? OFFSET ?;"
  local sql_params = {user_name, name_list_name, pageSize, offset}
  local query_result, query_error = db_query.query_mysql(sql, sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
    return
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

function _M.create_global_name_list_item()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name", "name_list_item"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local name_list_item = body_data['name_list_item']

  local sql = "SELECT * FROM jxwaf_waf_global_name_list WHERE `user_name` = ? AND `name_list_name` = ? ;"
  local sql_params = {user_name, name_list_name}
  local query_result, query_err = db_query.query_mysql(sql, sql_params)
  if not query_result or query_err then
    response.fail_response("name_list_name 不存在")
    return
  end

  local name_list_expire_time
  if query_result[1]['name_list_expire'] == "false" then
    name_list_expire_time = 0
  else
    name_list_expire_time = ngx.time() + tonumber(query_result[1]['name_list_expire_time'])
  end

  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_global_name_list_item WHERE user_name = ? AND name_list_name = ? AND name_list_item = ?;"
  local count_sql_params = {user_name, name_list_name, name_list_item}
  local count_sql_result, count_error = db_query.query_mysql(count_sql, count_sql_params)
  if not count_sql_result or count_error then
    response.fail_response(count_error or "计数查询失败")
    return
  end

  if tonumber(count_sql_result[1].count) > 0 then
    local update_sql = "UPDATE jxwaf_waf_global_name_list_item SET name_list_item_expire_time = ? WHERE user_name = ? AND name_list_name = ? AND name_list_item = ? ;"
    local update_sql_params = {name_list_expire_time, user_name, name_list_name, name_list_item}
    local update_sql_result, update_sql_error = db_query.query_mysql(update_sql, update_sql_params)
    if not update_sql_result or update_sql_error then
      response.fail_response(update_sql_error or "更新查询失败")
      return
    end
    response.success_response("edit_success")
  else
    local create_sql = "INSERT INTO jxwaf_waf_global_name_list_item (user_name, name_list_name, name_list_item, name_list_expire, name_list_item_expire_time) VALUES (?, ?, ?, ?, ?);"
    local create_sql_params = {user_name, name_list_name, name_list_item, query_result[1]['name_list_expire'], name_list_expire_time}
    local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)
    if not create_result or create_err then
      response.fail_response(create_err or "创建查询失败")
      return
    end
    response.success_response("create_success")
  end
end

function _M.delete_global_name_list_item()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name", "name_list_item"}  -- 确保包含 "name_list_item"
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local name_list_item = body_data['name_list_item']

  local sql = "DELETE FROM jxwaf_waf_global_name_list_item WHERE user_name = ? AND name_list_name = ? AND name_list_item = ? ;"
  local sql_params = {user_name, name_list_name, name_list_item}
  local sql_result, sql_error = db_query.query_mysql(sql, sql_params)
  if not sql_result or sql_error then
    response.fail_response(sql_error or "删除查询失败")
    return
  end
  response.success_response("删除成功")
end

function _M.search_global_name_list_item()
  local user_name = login_check.get_session()
  local check_param = {"page", "name_list_name", "search_value"}  -- 确保参数名称一致
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local name_list_name = body_data['name_list_name']
  local search_value = body_data['search_value']
  local pageSize = 50
  local offset = (page - 1) * pageSize

  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND `name_list_name` = ? AND `name_list_item` LIKE CONCAT('%', ?, '%');"
  local count_sql_params = {user_name, name_list_name, search_value}
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err or "计数查询失败")
    return
  end

  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  local sql = "SELECT * FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND `name_list_name` = ? AND `name_list_item` LIKE CONCAT('%', ?, '%') LIMIT ? OFFSET ?;"
  local sql_params = {user_name, name_list_name, search_value, pageSize, offset}
  local query_result, query_error = db_query.query_mysql(sql, sql_params)
  if not query_result or query_error then
    response.fail_response(query_error or "搜索查询失败")
    return
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

function _M.api_get_name_list_item_list_list()
  local check_param = {"page","name_list_name","waf_auth"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local name_list_name = body_data['name_list_name']
  local waf_auth = body_data['waf_auth']
  local user_name = request_data.get_user_name(waf_auth)
  local pageSize = 50
  local offset = (page - 1) * pageSize

  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND name_list_name = ? ;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name, name_list_name})
  if not count_result or count_err then
    response.fail_response(count_err)
    return
  end

  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  local sql = "SELECT * FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND name_list_name = ? LIMIT ? OFFSET ?;"
  local sql_params = {user_name, name_list_name, pageSize, offset}
  local query_result, query_error = db_query.query_mysql(sql, sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
    return
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

function _M.api_create_global_name_list_item()
  local check_param = {"name_list_name", "name_list_item","waf_auth"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local name_list_item = body_data['name_list_item']
  local waf_auth = body_data['waf_auth']
  local user_name = request_data.get_user_name(waf_auth)

  local sql = "SELECT * FROM jxwaf_waf_global_name_list WHERE `user_name` = ? AND `name_list_name` = ? ;"
  local sql_params = {user_name, name_list_name}
  local query_result, query_err = db_query.query_mysql(sql, sql_params)
  if not query_result or query_err then
    response.fail_response("name_list_name not exist")
    return
  end

  local name_list_expire_time
  if query_result[1]['name_list_expire'] == "false" then
    name_list_expire_time = 0
  else
    name_list_expire_time = ngx.time() + tonumber(query_result[1]['name_list_expire_time'])
  end

  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_global_name_list_item WHERE user_name = ? AND name_list_name = ? AND name_list_item = ?;"
  local count_sql_params = {user_name, name_list_name, name_list_item}
  local count_sql_result, count_error = db_query.query_mysql(count_sql, count_sql_params)
  if not count_sql_result or count_error then
    response.fail_response(count_error)
    return
  end

  if tonumber(count_sql_result[1].count) > 0 then
    local update_sql = "UPDATE jxwaf_waf_global_name_list_item SET name_list_item_expire_time = ? WHERE user_name = ? AND name_list_name = ? AND name_list_item = ? ;"
    local update_sql_params = {name_list_expire_time, user_name, name_list_name, name_list_item}
    local update_sql_result, update_sql_error = db_query.query_mysql(update_sql, update_sql_params)
    if not update_sql_result or update_sql_error then
      response.fail_response(update_sql_error)
      return
    end
    response.success_response("edit_success")
  else
    local create_sql = "INSERT INTO jxwaf_waf_global_name_list_item (user_name, name_list_name, name_list_item, name_list_expire, name_list_item_expire_time) VALUES (?, ?, ?, ?, ?);"
    local create_sql_params = {user_name, name_list_name, name_list_item, query_result[1]['name_list_expire'], name_list_expire_time}
    local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)
    if not create_result or create_err then
      response.fail_response(create_err)
      return
    end
    response.success_response("create_success")
  end
end

function _M.api_delete_global_name_list_item()
  local check_param = {"name_list_name", "name_list_item","waf_auth"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local name_list_item = body_data['name_list_item']
  local waf_auth = body_data['waf_auth']
  local user_name = request_data.get_user_name(waf_auth)

  local sql = "DELETE FROM jxwaf_waf_global_name_list_item WHERE user_name = ? AND name_list_name = ? AND name_list_item = ? ;"
  local sql_params = {user_name, name_list_name, name_list_item}
  local sql_result, sql_error = db_query.query_mysql(sql, sql_params)
  if not sql_result or sql_error then
    response.fail_response(sql_error)
    return
  end
  response.success_response("delete_success")
end

function _M.api_search_global_name_list_item()
  local check_param = {"page", "name_list_name", "search_value","waf_auth"}  -- 确保参数名称一致
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local name_list_name = body_data['name_list_name']
  local search_value = body_data['search_value']
  local waf_auth = body_data['waf_auth']
  local user_name = request_data.get_user_name(waf_auth)

  local pageSize = 50
  local offset = (page - 1) * pageSize

  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND `name_list_name` = ? AND `name_list_item` LIKE CONCAT('%', ?, '%');"
  local count_sql_params = {user_name, name_list_name, search_value}
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
    return
  end

  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  local sql = "SELECT * FROM jxwaf_waf_global_name_list_item WHERE `user_name` = ? AND `name_list_name` = ? AND `name_list_item` LIKE CONCAT('%', ?, '%') LIMIT ? OFFSET ?;"
  local sql_params = {user_name, name_list_name, search_value, pageSize, offset}
  local query_result, query_error = db_query.query_mysql(sql, sql_params)
  if not query_result or query_error then
    response.fail_response(query_error)
    return
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




return _M
