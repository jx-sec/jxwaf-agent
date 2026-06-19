local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local ngx_re = require "ngx.re"
local _M = {}

local function getIPType(ip)
	local parts = ngx_re.split(ip, [[\.]])
	if #parts == 4 then
        for _, part in ipairs(parts) do
            local num = tonumber(part)
	        if not num or num < 0 or num > 255 or tostring(num) ~= part then
                return nil
	        end
        end
        return "IPv4"
	end
	local ipv6_pattern = [[^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$]]
	local ipv6_abbr_pattern = [[^(([0-9a-fA-F]{1,4}:){0,6}::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$|^(::([0-9a-fA-F]{1,4}:){1,7})$|^([0-9a-fA-F]{1,4}:){1,7}:$]]
    local ipv6_hex4dec_pattern = [[^::[fF]{4}:(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$]]
	if ngx_re.match(ip, ipv6_pattern) or ngx_re.match(ip, ipv6_abbr_pattern) or ngx_re.match(ip, ipv6_hex4dec_pattern) then
        return "IPv6"
	end
    return nil
end

function _M.get_soc_network_ip_list()
  local user_name = login_check.get_session()
  local check_param = {"page"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_soc_network_ip WHERE `user_name` = ? ;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name})
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_soc_network_ip  WHERE `user_name` = ?  order by operator_time desc LIMIT ? OFFSET ?;"
  local sql_params = {user_name,pageSize,offset}
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

function _M.get_soc_network_ip_search_list()
  local user_name = login_check.get_session()
  local check_param = {"page","search_ip"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local search_ip = body_data['search_ip']
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_soc_network_ip WHERE `user_name` = ? AND `ip` LIKE CONCAT('%', ?, '%');"
  local count_sql_params = {user_name,search_ip}
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_soc_network_ip  WHERE `user_name` = ?  AND `ip` LIKE CONCAT('%', ?, '%') LIMIT ? OFFSET ?;"
  local sql_params = {user_name,search_ip,pageSize,offset}
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

function _M.create_soc_network_ip()
    local user_name = login_check.get_session()
	local check_param = {"ip", "status", "expire_time"}
	local body_data = request_data.get_body_data(check_param)
	local ip = body_data['ip']
	local ip_check = getIPType(ip)
    if not ip_check then
        return response.fail_response("ip is not ipv4 or ipv6 type")
    end
	local status = body_data['status']
	local expire_time = body_data['expire_time']
	local operator_type = 'user_create'
	local operator_time = ngx.time()
    local sql = [[INSERT INTO jxwaf_soc_network_ip
                     (user_name, ip, status, expire_time, operator_type,operator_time)
                     VALUES (?,?,?,?,?,?)
                     ON DUPLICATE KEY UPDATE
                     status = VALUES(status),
                     expire_time = VALUES(expire_time),
                     operator_type = VALUES(operator_type),
                     operator_time = VALUES(operator_time);]]
	local res, err = db_query.query_mysql(sql, {user_name, ip, status, expire_time, operator_type, operator_time})
	if not res then
        response.fail_response(err)
	else
        response.success_response("create success")
	end
end

function _M.get_soc_network_ip()
  local user_name = login_check.get_session()
  local check_param = {"ip"}
  local body_data = request_data.get_body_data(check_param)
  local ip = body_data['ip']
  local sql = "SELECT * FROM jxwaf_soc_network_ip  WHERE `user_name` = ? AND `ip` = ? ;"
  local sql_params = {user_name,ip}
  local query_result = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response("ip is not exist")
  end
end

function _M.edit_soc_network_ip()
    local user_name = login_check.get_session()
    local check_param = {"ip", "expire_time", "status"}
    local body_data = request_data.get_body_data(check_param)
    local ip = body_data['ip']
    local ip_check = getIPType(ip)
    if not ip_check then
        response.fail_response("ip is not ipv4 or ipv6 type")
    end
    local status = body_data['status']
    local expire_time = body_data['expire_time']
    local operator_type = 'user_create'
    local operator_time = ngx.time()

    local sql = [[UPDATE jxwaf_soc_network_ip
                  SET status = ?,
                      expire_time = ?,
                      operator_type = ?,
                      operator_time = ?
                  WHERE user_name = ? AND ip = ?;]]
    local sql_params = {status, expire_time, operator_type, operator_time, user_name, ip}

    local res, err = db_query.query_mysql(sql, sql_params)

    if not res then
        response.fail_response(err)
    else
        response.success_response("edit success")
    end
end

function _M.network_block()
  local check_param = {"waf_auth", "ip", "expire_time", "operator_type"}
	local body_data = request_data.get_body_data(check_param)
	local waf_auth = body_data['waf_auth']
	local init_waf_auth = init_config['waf_auth']
	if waf_auth ~= init_waf_auth then
	    response.fail_response("waf_auth fail")
	end
	local query_account_sql = [[SELECT user_name FROM `jxwaf_admin_account` LIMIT 1;]]
	local query_account_result = db_query.query_mysql(query_account_sql)
	if not query_account_result or #query_account_result == 0 then
        response.fail_response("no user found")
	end
    local user_name = query_account_result[1]['user_name']
	local ip = body_data['ip']
	local expire_time = tonumber(body_data['expire_time'])
  if not expire_time then
    response.fail_response("expire_time error")
  end
	local operator_type = body_data['operator_type']
	local operator_time = ngx.time()
	local query_sql = [[SELECT status FROM jxwaf_soc_network_ip WHERE user_name = ? AND ip = ?;]]
	local query_result = db_query.query_mysql(query_sql, {user_name, ip})
	if not query_result then
		response.fail_response("query fail")
	end
	if #query_result > 0 and tonumber(query_result[1]['status']) == 2 then
		response.success_response("block success")
	end
	local sql = [[INSERT INTO jxwaf_soc_network_ip (user_name, ip, status, expire_time, operator_time, operator_type) VALUES (?,?,1,?,?,?) ON DUPLICATE KEY UPDATE expire_time = VALUES(expire_time), operator_time = VALUES(operator_time), operator_type = VALUES(operator_type);]]
	local sql_params = {user_name, ip, expire_time, operator_time, operator_type}
	local res, err = db_query.query_mysql(sql, sql_params)
	if not res then
        response.fail_response(err)
	else
        response.success_response("block success")
	end
end

function _M.sync_network_ip()
    local check_param = {"waf_auth", "last_sync_time"}
    local body_data = request_data.get_body_data(check_param)
    local waf_auth = body_data['waf_auth']
    local last_sync_time = tonumber(body_data['last_sync_time']) or 0
    local ip = ngx.var.remote_addr

    local init_waf_auth = init_config['waf_auth']
    if waf_auth ~= init_waf_auth then
        response.fail_response("waf_auth fail")
    end

    local query_account_sql = [[SELECT user_name FROM `jxwaf_admin_account` LIMIT 1;]]
    local query_account_result = db_query.query_mysql(query_account_sql)
    if not query_account_result or #query_account_result == 0 then
        response.fail_response("no user found")
    end
    local user_name = query_account_result[1]['user_name']

    local sql = [[SELECT ip, status, expire_time, operator_time FROM jxwaf_soc_network_ip
                    WHERE user_name = ? AND operator_time > ? ORDER BY operator_time ASC LIMIT 10000;]]
    local sql_result, sql_error = db_query.query_mysql(sql, {user_name, last_sync_time})
    if not sql_result then
        response.fail_response(sql_error)
    end

    cjson.encode_empty_table_as_object(false)

    local actions = {}
    local newest_operator_time = last_sync_time

    if sql_result and #sql_result > 0 then
        for _, row in ipairs(sql_result) do
            table.insert(actions, {
                ip = row['ip'],
                status = row['status'],
                expire_time = row['expire_time']
            })
        end
        newest_operator_time = sql_result[#sql_result]['operator_time']
    end

    local update_time = ngx.time()
    local node_update_sql = [[INSERT INTO jxwaf_soc_network_ip_node_update (user_name, ip, update_time) VALUES (?,?,?) ON DUPLICATE KEY UPDATE update_time = VALUES(update_time);]]
    local node_update_result, node_update_error = db_query.query_mysql(node_update_sql, {user_name, ip, update_time})
    if not node_update_result then
        ngx.log(ngx.ERR, node_update_error)
    end

    local conf_data = ngx.shared.conf_data
    local network_ip_status = conf_data:get("network_ip_status")
    if not network_ip_status then
        network_ip_status = "block"
    end
    response.raw_success_response({
        actions = actions,
        newest_operator_time = newest_operator_time,
        network_ip_status = network_ip_status,
        result = true
    })
end

function _M.get_soc_network_ip_status()
  local user_name = login_check.get_session()
  local conf_data = ngx.shared.conf_data
  local network_ip_status = conf_data:get("network_ip_status")
  if network_ip_status then
    response.success_response(network_ip_status)
  else
    conf_data:set("network_ip_status","block")
    response.success_response("block")
  end
end

function _M.edit_soc_network_ip_status()
  local user_name = login_check.get_session()
  local check_param = {"network_ip_status"}
  local body_data = request_data.get_body_data(check_param)
  local network_ip_status = body_data['network_ip_status']
  local conf_data = ngx.shared.conf_data
  conf_data:set("network_ip_status",network_ip_status)
  response.success_response("edit success")
end

function _M.get_soc_network_ip_node_update_list()
  local user_name = login_check.get_session()
  local sql = [[SELECT ip, update_time FROM jxwaf_soc_network_ip_node_update WHERE user_name = ? ORDER BY update_time DESC;]]
  local sql_result, sql_error = db_query.query_mysql(sql, {user_name})
  if not sql_result then
    response.fail_response(sql_error)
  end
  cjson.encode_empty_table_as_object(false)
  response.raw_success_response({
    records = sql_result,
    result = true
  })
end


return _M
