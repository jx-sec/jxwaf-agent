local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local tools = require 'resty.admin_server.tools'

local _M = {}

local function isIPv4(str)
    local pattern = [[^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$]]
    local match, err = ngx.re.match(str, pattern)
    return match ~= nil
end

local function isIPv6(str)
    local pattern = [[^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$]]
    local match, err = ngx.re.match(str, pattern)
    return match ~= nil
end

local function isIP(str)
    return isIPv4(str) or isIPv6(str)
end

function _M.get_domain_list()
  local user_name = login_check.get_session()
  local check_param = {"page","group_name"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local group_name = body_data['group_name']
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_domain WHERE `user_name` = ? AND `group_name` = ?;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name, group_name})
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_domain  WHERE `user_name` = ? AND `group_name` = ? LIMIT ? OFFSET ?;"
  local sql_params = {user_name,group_name,pageSize,offset}
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

function _M.api_get_domain_list()
  local user_name = login_check.get_session()
  local check_param = {"group_name"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local sql = "SELECT * FROM jxwaf_waf_domain  WHERE `user_name` = ? AND `group_name` = ? ;"
  local sql_params = {user_name,group_name}
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

function _M.get_domain_search_list()
  local user_name = login_check.get_session()
  local check_param = {"page","group_name","search_domain"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local group_name = body_data['group_name']
  local search_domain = body_data['search_domain']
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_domain WHERE `user_name` = ? AND `group_name` = ? AND `domain` LIKE CONCAT('%', ?, '%');"
  local count_sql_params = {user_name, group_name,search_domain}
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_domain  WHERE `user_name` = ? AND `group_name` = ? AND `domain` LIKE CONCAT('%', ?, '%') LIMIT ? OFFSET ?;"
  local sql_params = {user_name,group_name,search_domain,pageSize,offset}
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

function _M.get_domain()
  local user_name = login_check.get_session()
  local check_param = {"group_name","domain"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local domain = body_data['domain']
  local sql = "SELECT * FROM jxwaf_waf_domain  WHERE `user_name` = ? AND `group_name` = ? AND `domain` = ?;"
  local sql_params = {user_name, group_name, domain}
  local query_result = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response("group_name is not exist")
  end
end


function _M.create_domain()
  local user_name = login_check.get_session()
  local check_param = {"group_name","domain","http","https","ssl_domain","source_ip","source_http_port","source_https_port","origin_protocol","balance_type","pre_proxy","real_ip_conf","connect_timeout","send_timeout","read_timeout","detail"}
  local body_data = request_data.get_body_data(check_param)

  local group_name = body_data['group_name']
  local domain = body_data['domain']
  local http = body_data['http']
  local https = body_data['https']
  local ssl_domain = body_data['ssl_domain']
  local source_ip = body_data['source_ip']
  local source_http_port = body_data['source_http_port']
  local source_https_port = body_data['source_https_port']
  local origin_protocol = body_data['origin_protocol']
  local balance_type = body_data['balance_type']
  local pre_proxy = body_data['pre_proxy']
  local real_ip_conf = body_data['real_ip_conf']
  local connect_timeout = body_data['connect_timeout']
  local send_timeout = body_data['send_timeout']
  local read_timeout = body_data['read_timeout']
  local detail = body_data['detail']

  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_domain WHERE  user_name = ? AND domain = ?;"
  local count_sql_params = {user_name,domain}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result or  count_error then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) > 0 then
    response.fail_response("domain is exist")
  end

  local source_ip_result = cjson.decode(source_ip)
  if not source_ip_result then
    response.fail_response("source_ip json decode error")
  end

  local waf_update_source_ip_table = {}
  for _,source_ip_item in ipairs(source_ip_result) do
    local check_ip_result = isIP(source_ip_item)
    if not check_ip_result then
       local ip_list = tools.get_dns_resolver_ip(source_ip_item)
       if ip_list then
          for _,ip in ipairs(ip_list) do
              table.insert(waf_update_source_ip_table,ip)
          end
       else
          response.fail_response("domain resolver error")
       end
     else
       table.insert(waf_update_source_ip_table,source_ip_item)
     end
  end

  if #waf_update_source_ip_table == 0 then
    response.fail_response("domain resolver ip count is 0")
  end
  local waf_update_source_ip = cjson.encode(waf_update_source_ip_table)


  local create_sql = "INSERT INTO jxwaf_waf_domain (user_name,group_name, domain, detail, http, https, ssl_domain, source_ip, waf_update_source_ip, source_http_port, source_https_port, origin_protocol, balance_type, pre_proxy, real_ip_conf, connect_timeout, send_timeout, read_timeout) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);"
  local create_sql_params = {user_name,group_name,domain,detail,http,https,ssl_domain,source_ip,waf_update_source_ip,source_http_port,source_https_port,origin_protocol,balance_type,pre_proxy,real_ip_conf,connect_timeout,send_timeout,read_timeout}

  local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
  if not create_result then
    response.fail_response(create_err)
  end

  response.success_response("create success")
end

function _M.delete_domain()
  local user_name = login_check.get_session()
  local check_param = {"group_name","domain"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local domain = body_data['domain']
  local sql = "DELETE FROM jxwaf_waf_domain WHERE group_name = ? AND user_name = ? AND domain = ?;"
  local sql_params = {group_name,user_name,domain}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("delete success")
end

function _M.edit_domain()
  local user_name = login_check.get_session()
  local check_param = {"group_name","domain","http","https","ssl_domain","source_ip","source_http_port","source_https_port","origin_protocol","balance_type","pre_proxy","real_ip_conf","connect_timeout","send_timeout","read_timeout","detail"}
  local body_data = request_data.get_body_data(check_param)

  local group_name = body_data['group_name']
  local domain = body_data['domain']
  local http = body_data['http']
  local https = body_data['https']
  local ssl_domain = body_data['ssl_domain']
  local source_ip = body_data['source_ip']
  local source_http_port = body_data['source_http_port']
  local source_https_port = body_data['source_https_port']
  local origin_protocol = body_data['origin_protocol']
  local balance_type = body_data['balance_type']
  local pre_proxy = body_data['pre_proxy']
  local real_ip_conf = body_data['real_ip_conf']
  local connect_timeout = body_data['connect_timeout']
  local send_timeout = body_data['send_timeout']
  local read_timeout = body_data['read_timeout']
  local detail = body_data['detail']

  local source_ip_result = cjson.decode(source_ip)
  if not source_ip_result then
    response.fail_response("source_ip json decode error")
  end
  local waf_update_source_ip_table = {}
  for _,source_ip_item in ipairs(source_ip_result) do
    local check_ip_result = isIP(source_ip_item)
    if not check_ip_result then
       local ip_list = tools.get_dns_resolver_ip(source_ip_item)
       if ip_list then
          for _,ip in ipairs(ip_list) do
              table.insert(waf_update_source_ip_table,ip)
          end
       else
          response.fail_response("domain resolver error")
        end
     else
       table.insert(waf_update_source_ip_table,source_ip_item)
     end
  end
  if #waf_update_source_ip_table == 0 then
    response.fail_response("domain resolver ip  count is 0")
  end
  local waf_update_source_ip = cjson.encode(waf_update_source_ip_table)

  local sql = "UPDATE jxwaf_waf_domain SET detail = ?, http = ?, https = ?, ssl_domain = ?, source_ip = ?, source_http_port = ?, source_https_port = ?, origin_protocol = ?, balance_type = ?, pre_proxy = ?, real_ip_conf = ?, connect_timeout = ?, send_timeout = ?, read_timeout = ?, waf_update_source_ip = ? WHERE group_name = ? AND user_name = ? AND domain = ?;"

  local sql_params = {detail, http, https, ssl_domain, source_ip, source_http_port, source_https_port, origin_protocol, balance_type, pre_proxy, real_ip_conf, connect_timeout, send_timeout, read_timeout, waf_update_source_ip, group_name, user_name, domain}

  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

return _M