local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local tools = require 'resty.admin_server.tools'
local http = require "resty.admin_server.http"
local ssl = require "ngx.ssl"

local _M = {}

function _M.get_ssl_manage_list()
  local user_name = login_check.get_session()
  local check_param = {"page"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_ssl_manage WHERE `user_name` = ?;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name})
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_ssl_manage  WHERE `user_name` = ?  LIMIT ? OFFSET ?;"
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

function _M.api_get_ssl_manage_list()
  local user_name = login_check.get_session()
  local sql = "SELECT * FROM jxwaf_waf_ssl_manage  WHERE `user_name` = ?;"
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

function _M.get_ssl_manage_search_list()
  local user_name = login_check.get_session()
  local check_param = {"page","search"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local search = body_data['search']
  local pageSize = 50
  local offset = (page - 1) * pageSize
  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_ssl_manage WHERE `user_name` = ? AND `ssl_domain` LIKE CONCAT('%', ?, '%');"
  local count_sql_params = {user_name,search}
  local count_result, count_err = db_query.query_mysql(count_sql, count_sql_params)
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_ssl_manage  WHERE `user_name` = ? AND `ssl_domain` LIKE CONCAT('%', ?, '%') LIMIT ? OFFSET ?;"
  local sql_params = {user_name,search,pageSize,offset}
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


function _M.get_ssl_manage()
  local user_name = login_check.get_session()
  local check_param = {"ssl_domain"}
  local body_data = request_data.get_body_data(check_param)
  local ssl_domain = body_data['ssl_domain']
  local sql = "SELECT * FROM jxwaf_waf_ssl_manage  WHERE `user_name` = ? AND `ssl_domain` = ?;"
  local sql_params = {user_name, ssl_domain}
  local query_result = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response("ssl_domain is not exist")
  end
end

function _M.create_ssl_manage()
  local user_name = login_check.get_session()
  local check_param = {"ssl_domain","detail","private_key","public_key"}
  local body_data = request_data.get_body_data(check_param)
  local ssl_domain = body_data['ssl_domain']
  local detail = body_data['detail']
  local private_key = body_data['private_key']
  local public_key = body_data['public_key']
  local der_cert, cert_err = ssl.cert_pem_to_der(public_key)
  if not der_cert then
    response.fail_response("public_key invalid: " .. (cert_err or "unknown error"))
  end
  local der_key, key_err = ssl.priv_key_pem_to_der(private_key)
  if not der_key then
    response.fail_response("private_key invalid: " .. (key_err or "unknown error"))
  end
  local update_time =  ngx.time()
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_ssl_manage WHERE ssl_domain = ? AND user_name = ?;"
  local count_sql_params = {ssl_domain,user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) > 0 then
    response.fail_response("ssl_domain is exist")
  end

  local create_sql = "INSERT INTO jxwaf_waf_ssl_manage (user_name,ssl_domain, detail, private_key,public_key,update_time) VALUES (?,?,?,?,?,?);"
  local create_sql_params = {user_name,ssl_domain,detail,private_key,public_key,update_time}
  local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
  if not create_result then
    response.fail_response(create_err)
  else
    response.success_response("create success")
  end
end

function _M.delete_ssl_manage()
  local user_name = login_check.get_session()
  local check_param = {"ssl_domain"}
  local body_data = request_data.get_body_data(check_param)
  local ssl_domain = body_data['ssl_domain']
  local sql = "DELETE FROM jxwaf_waf_ssl_manage WHERE ssl_domain = ? AND user_name = ?;"
  local sql_params = {ssl_domain,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("delete success")
end

function _M.edit_ssl_manage()
  local user_name = login_check.get_session()
  local check_param = {"ssl_domain","detail","private_key","public_key"}
  local body_data = request_data.get_body_data(check_param)
  local ssl_domain = body_data['ssl_domain']
  local detail = body_data['detail']
  local private_key = body_data['private_key']
  local public_key = body_data['public_key']
  local der_cert, cert_err = ssl.cert_pem_to_der(public_key)
  if not der_cert then
    response.fail_response("public_key invalid: " .. (cert_err or "unknown error"))
  end
  local der_key, key_err = ssl.priv_key_pem_to_der(private_key)
  if not der_key then
    response.fail_response("private_key invalid: " .. (key_err or "unknown error"))
  end
  local update_time =  ngx.time()

  local query_sql = "SELECT * FROM jxwaf_waf_ssl_manage  WHERE `user_name` = ? AND `ssl_domain` = ? AND private_key = ? AND public_key = ?;"
  local query_sql_params = {user_name, ssl_domain,private_key,public_key}
  local query_result,query_error = db_query.query_mysql(query_sql,query_sql_params)
  if not query_result then
      response.fail_response(query_error)
  end
  if #query_result == 1 then
      update_time =  query_result[1]['update_time']
  end

  local sql = "UPDATE jxwaf_waf_ssl_manage  SET  detail = ?,private_key = ?,public_key = ?,update_time = ? WHERE ssl_domain = ? AND user_name = ?;"
  local sql_params = {detail,private_key,public_key,update_time,ssl_domain,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end


return _M