local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local http = require "resty.admin_server.http"
local aes = require "resty.aes"
local _M = {}
  
function _M.get_group_custom_response_header_list()
  local user_name = login_check.get_session()
  local check_param = {"page","group_name"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local group_name = body_data['group_name']
  local pageSize = 50
  local offset = (page - 1) * pageSize
local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_group_custom_response_header WHERE `user_name` = ? AND `group_name` = ?  ;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name, group_name})
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_group_custom_response_header  WHERE `user_name` = ? AND `group_name` = ? ORDER BY rule_order_time ASC LIMIT ? OFFSET ?;"
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

function _M.get_group_custom_response_header()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rule_name"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rule_name = body_data['rule_name']
  local sql = "SELECT * FROM jxwaf_waf_group_custom_response_header  WHERE `user_name` = ? AND `group_name` = ? AND `rule_name` = ?;"
  local sql_params = {user_name,group_name,rule_name}   
  local query_result = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response("rule_name is not exist")
  end
end

function _M.create_group_custom_response_header()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rule_name","rule_detail","rule_matchs","filter","header_name","header_value"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rule_name = body_data['rule_name']
  local rule_detail = body_data['rule_detail']
  local rule_matchs = body_data['rule_matchs']
  local filter = body_data['filter']
  local header_name = body_data['header_name']
  local header_value = body_data['header_value']
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_group_custom_response_header WHERE group_name = ? AND user_name = ?  AND rule_name = ?;"
  local count_sql_params = {group_name,user_name,rule_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) > 0 then
    response.fail_response("rule_name is exist")
  end
  local rule_order_time = math.floor(ngx.now())
  local create_sql = "INSERT INTO jxwaf_waf_group_custom_response_header (user_name,group_name,rule_name, rule_detail,rule_matchs,filter,header_name,header_value,rule_order_time) VALUES (?,?,?,?,?,?,?,?,?);"
  local create_sql_params = {user_name,group_name,rule_name,rule_detail,rule_matchs,filter,header_name,header_value,rule_order_time}
  local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
  if not create_result then
    response.fail_response(create_err)
  else
    response.success_response("create success")
  end
end

function _M.delete_group_custom_response_header()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rule_name"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rule_name = body_data['rule_name']
  local sql = "DELETE FROM jxwaf_waf_group_custom_response_header WHERE group_name = ? AND user_name = ? AND rule_name = ?;"
  local sql_params = {group_name,user_name,rule_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("delete success")
end

function _M.edit_group_custom_response_header()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rule_name","rule_detail","rule_matchs","filter","header_name","header_value"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rule_name = body_data['rule_name']
  local rule_detail = body_data['rule_detail']
  local rule_matchs = body_data['rule_matchs']
  local filter = body_data['filter']
  local header_name = body_data['header_name']
  local header_value = body_data['header_value']
  local sql = "UPDATE jxwaf_waf_group_custom_response_header  SET  rule_detail = ?,rule_matchs = ?,filter = ? ,header_name = ? ,header_value = ? WHERE group_name = ? AND user_name = ? AND rule_name = ?;"
  local sql_params = {rule_detail,rule_matchs,filter,header_name,header_value,group_name,user_name,rule_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

function _M.edit_group_custom_response_header_status()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rule_name","status"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rule_name = body_data['rule_name']
  local status = body_data['status']
  local sql = "UPDATE jxwaf_waf_group_custom_response_header  SET  status = ? WHERE group_name = ? AND user_name = ? AND rule_name = ?;"
  local sql_params = {status,group_name,user_name,rule_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

local function param_check(input_param)
    if not input_param then
       local data_result = {}
       data_result['result'] = false
       data_result['error'] = "param is null"
       ngx.status = 200
       ngx.header.content_type = "application/json"
       ngx.log(ngx.ERR,cjson.encode(data_result))
       ngx.say(cjson.encode(data_result))
       return ngx.exit(200)
    end
    return input_param
end

function _M.exchange_group_custom_response_header_priority()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rule_name","type"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rule_name = body_data['rule_name']
  local exchange_type = body_data['type']
  if exchange_type == "top" then
    local sql = "SELECT rule_order_time FROM jxwaf_waf_group_custom_response_header  WHERE `user_name` = ? AND `group_name` = ?  ORDER BY `rule_order_time` ASC limit 1;"
    local sql_params = {user_name,group_name}
    local query_result = db_query.query_mysql(sql,sql_params)
    if not query_result then
      response.fail_response("exchange priority error")
    end
    local rule_order_time = tonumber(query_result[1].rule_order_time) - 1
    local exchange_sql = "UPDATE jxwaf_waf_group_custom_response_header  SET  rule_order_time = ? WHERE group_name = ? AND user_name = ? AND rule_name = ? ;"
    local exchange_sql_params = {rule_order_time,group_name,user_name,rule_name}
    local exchange_sql_result,exchange_sql_error = db_query.query_mysql(exchange_sql,exchange_sql_params)
    if not exchange_sql_result then
      response.fail_response(exchange_sql_error)
    end
  elseif exchange_type == "exchange" then
    local exchange_rule_name = param_check(body_data['exchange_rule_name'])
    -- get rule_query_rule_order_time
    local rule_query_sql = "SELECT rule_order_time FROM jxwaf_waf_group_custom_response_header  WHERE `user_name` = ? AND `group_name` = ? AND `rule_name` = ? ;"
    local rule_query_sql_params = {user_name,group_name,rule_name}
    local rule_query_sql_result,rule_query_sql_error = db_query.query_mysql(rule_query_sql,rule_query_sql_params)
    if not rule_query_sql_result then
      response.fail_response(rule_query_sql_error)
    end
    local rule_query_rule_order_time = tonumber(rule_query_sql_result[1].rule_order_time)
    -- get exchange_query_rule_order_time
    local exchange_query_sql = "SELECT rule_order_time FROM jxwaf_waf_group_custom_response_header  WHERE `user_name` = ? AND `group_name` = ? AND `rule_name` = ?;"
    local exchange_query_sql_params = {user_name,group_name,exchange_rule_name}
    local exchange_query_sql_result,exchange_query_sql_error = db_query.query_mysql(exchange_query_sql,exchange_query_sql_params)
    if not exchange_query_sql_result then
      response.fail_response(exchange_query_sql_error)
    end
    local exchange_query_rule_order_time = tonumber(exchange_query_sql_result[1].rule_order_time)
    -- exchange rule_order_time
    local rule_update_sql = "UPDATE jxwaf_waf_group_custom_response_header  SET  rule_order_time = ? WHERE group_name = ? AND user_name = ? AND rule_name = ?  ;"
    local rule_update_sql_params = {exchange_query_rule_order_time,group_name,user_name,rule_name}
    local rule_update_sql_result,rule_update_sql_error = db_query.query_mysql(rule_update_sql,rule_update_sql_params)
    if not rule_update_sql_result then
      response.fail_response(rule_update_sql_error)
    end
    local exchange_update_sql = "UPDATE jxwaf_waf_group_custom_response_header  SET  rule_order_time = ? WHERE group_name = ? AND user_name = ? AND rule_name = ?;"
    local exchange_update_sql_params = {rule_query_rule_order_time,group_name,user_name,exchange_rule_name}
    local exchange_update_sql_result,exchange_update_sql_error = db_query.query_mysql(exchange_update_sql,exchange_update_sql_params)
    if not exchange_update_sql_result then
      response.fail_response(exchange_update_sql_error)
    end
  end
  response.success_response("exchange priority success")
end

function _M.backup_group_custom_response_header()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rule_name_list"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rule_name_list = body_data['rule_name_list']
  local rules = {}
  for _,rule_name in ipairs(rule_name_list) do 
    local sql = "SELECT * FROM jxwaf_waf_group_custom_response_header  WHERE `user_name` = ? AND `group_name` = ? AND `rule_name` = ? ;"
    local sql_params = {user_name,group_name,rule_name}   
    local query_result = db_query.query_mysql(sql,sql_params)
    if not query_result then
      response.fail_response("rule_name is not exist")
    end
    local rule_name_result = query_result[1]
    local rule_conf = {
      rule_name = rule_name_result['rule_name'],
      rule_detail = rule_name_result['rule_detail'],
      rule_matchs = rule_name_result['rule_matchs'],
      filter = rule_name_result['filter'],
      header_name = rule_name_result['header_name'],
      header_value = rule_name_result['header_value']
      }
    table.insert(rules,rule_conf)
  end
  ngx.status = 200
  ngx.header.content_type = 'application/json'
  ngx.header['Content-Disposition'] = 'attachment; filename="custom_response_header_data.json"'
  ngx.say(cjson.encode(rules))
  return ngx.exit(200)
end

function _M.load_group_custom_response_header()
  local user_name = login_check.get_session()
  local check_param = {"group_name","rules"}
  local body_data = request_data.get_body_data(check_param)
  local group_name = body_data['group_name']
  local rules = body_data['rules']
  for _,rule in ipairs(rules) do 
    local rule_name = rule['rule_name']
    local rule_detail = rule['rule_detail']
    local rule_matchs = rule['rule_matchs']
    local filter = rule['filter']
    local header_name = rule['header_name']
    local header_value = rule['header_value']
    local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_group_custom_response_header WHERE group_name = ? AND user_name = ? AND rule_name = ? ;"
    local count_sql_params = {group_name,user_name,rule_name}
    local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
    if not count_sql_result then
      response.fail_response(count_error)
    end
    if tonumber(count_sql_result[1].count) == 0 then
      local rule_order_time = math.floor(ngx.now())
      local create_sql = "INSERT INTO jxwaf_waf_group_custom_response_header (user_name,group_name,rule_name,rule_detail,rule_matchs,filter,header_name,header_value) VALUES (?,?,?,?,?,?,?,?);"
      local create_sql_params = {user_name,group_name,rule_name,rule_detail,rule_matchs,filter,header_name,header_value}
      local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
       if not create_result then
          response.fail_response(create_err)
      end
    end
  end
  response.success_response("load success")
end

local function load_custom_response_header_data(user_name,group_name,custom_response_header_data)
    for k,v in pairs(custom_response_header_data) do
        local rule_name = v['rule_name']
        local rule_detail = v['rule_detail']
        local rule_matchs = v['rule_matchs']
        local filter = v['filter']
        local header_name = v['header_name']
        local header_value = v['header_value']
        local status = v['status']
        local rule_order_time = v['rule_order_time']
        local sql = "DELETE FROM jxwaf_waf_group_custom_response_header WHERE user_name = ? AND group_name = ? AND rule_name = ? ;"
        local sql_params = {user_name,group_name,rule_name}
        local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
        if not sql_result then
          response.fail_response(sql_error)
        end
        local create_sql = "INSERT INTO jxwaf_waf_group_custom_response_header (user_name,group_name, rule_name, rule_detail,rule_matchs,filter,header_name,header_value,rule_order_time,status) VALUES (?,?,?,?,?,?,?,?,?,?);"
        local create_sql_params = {user_name,group_name,rule_name,rule_detail,rule_matchs,filter,header_name,header_value,rule_order_time,status}
        local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
        if not create_result then
          response.fail_response(create_err)
        end
    end
end

function _M.load_group_custom_response_header_hub_config()
    local user_name = login_check.get_session()
    local check_param = {"hub_repo","force_load"}
    local body_data = request_data.get_body_data(check_param)
    local hub_repo = body_data['hub_repo']
    local force_load = body_data['force_load']
    local group_name = body_data['group_name']
    local auth_code = body_data['auth_code']
    local hub_website  =  'https://user.jxwaf.com/waf/repo?uuid='..hub_repo
    local httpc = http.new()
    local res, err = httpc:request_uri( hub_website , {
        method = "GET"
    })
    if not res then
        response.fail_response(err)
    end
    local status_code = res.status
    if status_code ~= 200 then
        response.fail_response("hub_repo not find")
    end
    local res_body = cjson.decode(res.body)
    if not res_body then
        response.fail_response("res body json decode error")
    end
    if  res_body['result'] == false then
        response.fail_response("res body result is false")
    end
    if res_body['enc_data'] and not auth_code then
        response.fail_response("auth_code is nil")
    end
    if auth_code and #auth_code ~= 0 then
        local aes_256_cbc_md5 = aes:new(
            auth_code,
            nil,
            aes.cipher(256, "cbc"),
            aes.hash.sha512,
            5
        )
        if not res_body['enc_data'] then
            response.fail_response("enc_data is nil")
        end
        local enc_data = ngx.decode_base64(res_body['enc_data'])
        if not enc_data then
            response.fail_response("invalid base64 data")
        end
        local decrypted = aes_256_cbc_md5:decrypt(enc_data)
        if not decrypted then
            response.fail_response("auth_code is error")
        end
        local decrypted_res_body = cjson.decode(decrypted)
        if not decrypted_res_body then
            response.fail_response("enc_data json decode is nil")
        end
        res_body = decrypted_res_body
    end
    local custom_response_header_data = res_body['custom_response_header_data']
    if not custom_response_header_data then
        if auth_code and #auth_code ~= 0 then
            response.fail_response("auth_code is error")
        else
            response.fail_response("custom_response_header_data is nil")
        end
    end
    if force_load == "false" then
        for k, v in pairs(custom_response_header_data) do
            local sql = "SELECT COUNT(*) as count FROM jxwaf_waf_group_custom_response_header WHERE user_name = ? AND group_name = ?  AND rule_name = ?;"
            local count_sql_result,count_sql_error = db_query.query_mysql(sql,{user_name,group_name,k})
            if not count_sql_result then
              response.fail_response(count_sql_error)
            end
            if tonumber(count_sql_result[1].count) > 0  then
              response.fail_response("rule_name name is exist "..k)
            end
        end
    end
    load_custom_response_header_data(user_name,group_name,custom_response_header_data)
    response.success_response("load success")
end

function _M.export_group_custom_response_header_hub_config()
  local user_name = login_check.get_session()
  local check_param = {"custom_response_header","group_name"}
  local body_data = request_data.get_body_data(check_param)
  local custom_response_header = body_data['custom_response_header']
  local group_name = body_data['group_name']
  local custom_response_header_data = {}
  for _,rule_name in ipairs(custom_response_header) do
      local sql = "SELECT * FROM jxwaf_waf_group_custom_response_header  WHERE `user_name` = ? AND `group_name` = ? AND `rule_name` = ?;"
      local sql_params = {user_name,group_name,rule_name}
      local result = db_query.query_mysql(sql,sql_params)
      if not result or #result == 0 then
          response.fail_response("rule_name is not exist: "..rule_name)
      end
      custom_response_header_data[rule_name] = {
        rule_name = result[1]['rule_name'],
        rule_detail = result[1]['rule_detail'],
        rule_matchs = result[1]['rule_matchs'],
        filter = result[1]['filter'],
        header_name = result[1]['header_name'],
        header_value = result[1]['header_value'],
        status = result[1]['status'],
        rule_order_time = result[1]['rule_order_time']
      }
  end
    cjson.encode_empty_table_as_object(false)
    local response_message = {
        custom_response_header_data = custom_response_header_data,
        result = true
    }
    response.raw_success_response(response_message)
end


return _M 