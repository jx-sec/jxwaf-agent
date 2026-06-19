local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'

local _M = {}

local waf_backup_tables = {
  "jxwaf_waf_domain_group",
  "jxwaf_waf_group_web_engine_protection",
  "jxwaf_waf_group_web_rule_protection",
  "jxwaf_waf_group_web_page_tamper_proof",
  "jxwaf_waf_group_web_white_rule",
  "jxwaf_waf_group_flow_engine_protection",
  "jxwaf_waf_group_flow_rule_protection",
  "jxwaf_waf_group_flow_ip_region_block",
  "jxwaf_waf_group_flow_white_rule",
  "jxwaf_waf_domain",
  "jxwaf_waf_group_custom_request_header",
  "jxwaf_waf_group_custom_response_header",
  "jxwaf_waf_group_custom_response_content",
  "jxwaf_waf_group_custom_upstream_address",
  "jxwaf_waf_global_name_list",
  "jxwaf_waf_global_name_list_item",
  "jxwaf_waf_component",
  "jxwaf_waf_ssl_manage",
  "jxwaf_sys_conf"
}

local waf_backup_table_set = {}
for _, t in ipairs(waf_backup_tables) do
  waf_backup_table_set[t] = true
end


function _M.get_sys_log_conf()
  local user_name = login_check.get_session()
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_sys_conf WHERE  user_name = ?;"
  local count_sql_params = {user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) ~= 1 then
    local del_sql = "DELETE FROM jxwaf_sys_conf WHERE  user_name = ?;"
    local del_sql_params = {user_name}
    local del_sql_result,del_sql_error = db_query.query_mysql(del_sql,del_sql_params)
    if not del_sql_result then
      response.fail_response(del_sql_error)
    end
    local create_sql = "INSERT INTO jxwaf_sys_conf (user_name) VALUES (?);"
    local create_sql_params = {user_name}
    local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
    if not create_result then
      response.fail_response(create_err)
    end
  end
  local sql = "SELECT * FROM jxwaf_sys_conf  WHERE `user_name` = ?;"
  local sql_params = {user_name}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response(query_error)
  end
end

function _M.edit_sys_log_conf()
  local user_name = login_check.get_session()
  local check_param = {"log_conf_local_debug","log_conf_remote","log_ip","log_port","log_response","log_all"}
  local body_data = request_data.get_body_data(check_param)
  local log_conf_local_debug = body_data['log_conf_local_debug']
  local log_conf_remote = body_data['log_conf_remote']
  local log_ip = body_data['log_ip']
  local log_port = body_data['log_port']
  local log_response = body_data['log_response']
  local log_all = body_data['log_all']
  local sql = "UPDATE jxwaf_sys_conf  SET  log_conf_local_debug = ?,log_conf_remote = ? ,log_ip = ? ,log_port = ? ,log_response = ?,log_all = ?  WHERE user_name = ?;"
  local sql_params = {log_conf_local_debug,log_conf_remote,log_ip,log_port,log_response,log_all,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

function _M.get_sys_report_conf_conf()
  local user_name = login_check.get_session()
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_sys_conf WHERE  user_name = ?;"
  local count_sql_params = {user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) ~= 1 then
    local del_sql = "DELETE FROM jxwaf_sys_conf WHERE  user_name = ?;"
    local del_sql_params = {user_name}
    local del_sql_result,del_sql_error = db_query.query_mysql(del_sql,del_sql_params)
    if not del_sql_result then
      response.fail_response(del_sql_error)
    end
    local create_sql = "INSERT INTO jxwaf_sys_conf (user_name) VALUES (?);"
    local create_sql_params = {user_name}
    local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
    if not create_result then
      response.fail_response(create_err)
    end
  end
  local sql = "SELECT * FROM jxwaf_sys_conf  WHERE `user_name` = ?;"
  local sql_params = {user_name}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response(query_error)
  end
end

function _M.edit_sys_report_conf_conf()
  local user_name = login_check.get_session()
  local check_param = {"report_conf","report_conf_ch_host","report_conf_ch_port","report_conf_ch_user","report_conf_ch_password","report_conf_ch_database","report_conf_ch_table"}
  local body_data = request_data.get_body_data(check_param)
  local report_conf = body_data['report_conf']
  local report_conf_ch_host = body_data['report_conf_ch_host']
  local report_conf_ch_port = body_data['report_conf_ch_port']
  local report_conf_ch_user = body_data['report_conf_ch_user']
  local report_conf_ch_password = body_data['report_conf_ch_password']
  local report_conf_ch_database = body_data['report_conf_ch_database']
  local report_conf_ch_table = body_data['report_conf_ch_table']
  local sql = "UPDATE jxwaf_sys_conf  SET  report_conf = ?,report_conf_ch_host = ?,report_conf_ch_port = ? ,report_conf_ch_user = ? ,report_conf_ch_password = ?,report_conf_ch_database = ?,report_conf_ch_table = ? WHERE user_name = ?;"
  local sql_params = {report_conf,report_conf_ch_host,report_conf_ch_port,report_conf_ch_user,report_conf_ch_password,report_conf_ch_database,report_conf_ch_table,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

function _M.test_sys_report_conf_conf()
  local check_param = {"report_conf_ch_host","report_conf_ch_port","report_conf_ch_user","report_conf_ch_password","report_conf_ch_database","report_conf_ch_table"}
  local body_data = request_data.get_body_data(check_param)
  local report_conf_ch_host = body_data['report_conf_ch_host']
  local report_conf_ch_port = body_data['report_conf_ch_port']
  local report_conf_ch_user = body_data['report_conf_ch_user']
  local report_conf_ch_password = body_data['report_conf_ch_password']
  local report_conf_ch_database = body_data['report_conf_ch_database']
  local report_conf_ch_table = body_data['report_conf_ch_table']
  local clickhouse_db_config = {
    host = report_conf_ch_host,
    port = report_conf_ch_port,
    user = report_conf_ch_user,
    database = report_conf_ch_database,
    password = report_conf_ch_password,
    charset = "utf8mb4"
  }
  local test_sql = "SELECT 1"
  local test_result, test_err = db_query.clickhouse_query_mysql(test_sql, clickhouse_db_config, {})
  if not test_result or test_err then
    response.fail_response(test_err)
  end
  local check_table_sql = "EXISTS TABLE " .. report_conf_ch_database .. "." .. report_conf_ch_table
  local check_table_result, check_table_err = db_query.clickhouse_query_mysql(check_table_sql, clickhouse_db_config, {})
  if not check_table_result or check_table_err then
    response.fail_response(check_table_err)
  end
  if tonumber(check_table_result[1]["result"]) ~= 1 then
    response.fail_response("table " .. report_conf_ch_database .. "." .. report_conf_ch_table .. " does not exist")
  end
  response.success_response("connection success")
end

function _M.get_sys_custom_page_conf()
  local user_name = login_check.get_session()
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_sys_conf WHERE  user_name = ?;"
  local count_sql_params = {user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) ~= 1 then
    local del_sql = "DELETE FROM jxwaf_sys_conf WHERE  user_name = ?;"
    local del_sql_params = {user_name}
    local del_sql_result,del_sql_error = db_query.query_mysql(del_sql,del_sql_params)
    if not del_sql_result then
      response.fail_response(del_sql_error)
    end
    local create_sql = "INSERT INTO jxwaf_sys_conf (user_name) VALUES (?);"
    local create_sql_params = {user_name}
    local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
    if not create_result then
      response.fail_response(create_err)
    end
  end
  local sql = "SELECT * FROM jxwaf_sys_conf  WHERE `user_name` = ?;"
  local sql_params = {user_name}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response(query_error)
  end
end

function _M.edit_sys_custom_page_conf()
  local user_name = login_check.get_session()
  local check_param = {"custom_deny_page","waf_deny_code","waf_deny_html","custom_not_find_page","not_find_code","not_find_html"}
  local body_data = request_data.get_body_data(check_param)
  local custom_deny_page = body_data['custom_deny_page']
  local waf_deny_code = body_data['waf_deny_code']
  local waf_deny_html = body_data['waf_deny_html']
  local custom_not_find_page = body_data['custom_not_find_page']
  local not_find_code = body_data['not_find_code']
  local not_find_html = body_data['not_find_html']
  local sql = "UPDATE jxwaf_sys_conf  SET  custom_deny_page = ?,waf_deny_code = ?,waf_deny_html = ? ,custom_not_find_page = ? ,not_find_code = ?,not_find_html = ? WHERE user_name = ?;"
  local sql_params = {custom_deny_page,waf_deny_code,waf_deny_html,custom_not_find_page,not_find_code,not_find_html,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

function _M.get_sys_webtds_check_conf()
  local user_name = login_check.get_session()
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_sys_conf WHERE  user_name = ?;"
  local count_sql_params = {user_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) ~= 1 then
    local del_sql = "DELETE FROM jxwaf_sys_conf WHERE  user_name = ?;"
    local del_sql_params = {user_name}
    local del_sql_result,del_sql_error = db_query.query_mysql(del_sql,del_sql_params)
    if not del_sql_result then
      response.fail_response(del_sql_error)
    end
    local create_sql = "INSERT INTO jxwaf_sys_conf (user_name) VALUES (?);"
    local create_sql_params = {user_name}
    local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
    if not create_result then
      response.fail_response(create_err)
    end
  end
  local sql = "SELECT * FROM jxwaf_sys_conf  WHERE `user_name` = ?;"
  local sql_params = {user_name}
  local query_result,query_error = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response(query_error)
  end
end

function _M.edit_sys_webtds_check_conf()
  local user_name = login_check.get_session()
  local check_param = {"webtds_check","webtds_node_ip","webtds_node_port"}
  local body_data = request_data.get_body_data(check_param)
  local webtds_check = body_data['webtds_check']
  local webtds_node_ip = body_data['webtds_node_ip']
  local webtds_node_port = body_data['webtds_node_port']
  local sql = "UPDATE jxwaf_sys_conf  SET  webtds_check = ?,webtds_node_ip = ?,webtds_node_port = ? WHERE user_name = ?;"
  local sql_params = {webtds_check,webtds_node_ip,webtds_node_port,user_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end



function _M.waf_conf_backup()
  local user_name = login_check.get_session()
  local response_message = {}
    for _,v in ipairs(waf_backup_tables) do
         local sql = "SELECT * FROM ?  WHERE `user_name` = ?;"
         local sql_params = {v,user_name}
         local build_sql = db_query.table_build_query(sql,sql_params)
         local sql_result,sql_error = db_query.query_mysql(build_sql)
         response_message[v] = sql_result
         if not sql_result then
            response.fail_response(sql_error)
          end
      end

  cjson.encode_empty_table_as_object(false)
  ngx.status = 200
  ngx.header.content_type = "application/json"
  ngx.header.content_disposition = [=[attachment; filename="backup_data.json"]=]
  ngx.say(cjson.encode(response_message))
  return ngx.exit(200)
end

function _M.waf_conf_load()
    local user_name = login_check.get_session()
    local check_param = {}
    local body_data = request_data.get_body_data(check_param)

    for table_name, records in pairs(body_data) do
        if not waf_backup_table_set[table_name] then
            ngx.log(ngx.ERR, "非法表名: " .. tostring(table_name))
            goto continue
        end
        if type(records) ~= "table" then
            ngx.log(ngx.WARN, "备份数据中表 '" .. table_name .. "' 的数据格式不正确。")
            goto continue
        end
        local del_sql = "DELETE FROM `" .. table_name .. "` WHERE `user_name` = ?;"
        local del_sql_params = {user_name}
        local del_sql_result, del_sql_error = db_query.query_mysql(del_sql, del_sql_params)
        if not del_sql_result then
            response.fail_response("删除表 '" .. table_name .. "' 时出错: " .. (del_sql_error or ""))
        end
        if #records > 0 then
            for _, record in ipairs(records) do
                local columns = {}
                local placeholders = {}
                local params = {}

                for key, value in pairs(record) do
                    if type(key) ~= "string" or key:find("`") then
                        ngx.log(ngx.ERR, "非法列名: " .. tostring(key))
                        goto skip_column
                    end
                    table.insert(columns, "`" .. key .. "`")
                    table.insert(placeholders, "?")
                    table.insert(params, value)
                    ::skip_column::
                end

                if #columns > 0 then
                    local insert_sql = "INSERT INTO `" .. table_name .. "` (" .. table.concat(columns, ", ") .. ") VALUES (" .. table.concat(placeholders, ", ") .. ");"
                    local create_result, create_err = db_query.query_mysql(insert_sql, params)
                    if not create_result then
                        ngx.log(ngx.ERR,"插入表 '" .. table_name .. "' 时出错: " .. (create_err or ""))
                    end
                end
            end
        end
        ::continue::
    end
    response.success_response("加载成功。")
end



return _M