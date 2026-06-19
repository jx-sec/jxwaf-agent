local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local http = require "resty.admin_server.http"
local aes = require "resty.aes"
local _M = {}

function _M.get_global_name_list_list()
  local user_name = login_check.get_session()
  local check_param = {"page"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local pageSize = 50
  local offset = (page - 1) * pageSize
local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_global_name_list WHERE `user_name` = ?  ;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name})
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)
  local sql = "SELECT * FROM jxwaf_waf_global_name_list  WHERE `user_name` = ?  ORDER BY rule_order_time ASC LIMIT ? OFFSET ?;"
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

function _M.api_get_global_name_list_list()
  local user_name = login_check.get_session()
  local sql = "SELECT * FROM jxwaf_waf_global_name_list  WHERE `user_name` = ? ;"
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


function _M.get_global_name_list()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local sql = "SELECT * FROM jxwaf_waf_global_name_list  WHERE `user_name` = ? AND `name_list_name` = ? ;"
  local sql_params = {user_name,name_list_name}
  local query_result = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response("rule_name is not exist")
  end
end

function _M.create_global_name_list()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name","name_list_detail","name_list_rule","name_list_action","action_value","name_list_expire","name_list_expire_time"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local name_list_detail = body_data['name_list_detail']
  local name_list_rule = body_data['name_list_rule']
  local name_list_action = body_data['name_list_action']
  local action_value = body_data['action_value']
  local name_list_expire = body_data['name_list_expire']
  local name_list_expire_time = body_data['name_list_expire_time']
  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_global_name_list WHERE  user_name = ? AND name_list_name = ?;"
  local count_sql_params = {user_name,name_list_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) > 0 then
    response.fail_response("rule_name is exist")
  end
  local rule_order_time = ngx.time()

  local create_sql = "INSERT INTO jxwaf_waf_global_name_list (user_name,name_list_name,name_list_detail, name_list_rule,name_list_action, action_value,name_list_expire,name_list_expire_time) VALUES (?,?,?,?,?,?,?,?);"
  local create_sql_params = {user_name,name_list_name,name_list_detail,name_list_rule,name_list_action,action_value,name_list_expire,name_list_expire_time}
  local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
  if not create_result then
    response.fail_response(create_err)
  else
    response.success_response("create success")
  end
end

function _M.delete_global_name_list()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local sql = "DELETE FROM jxwaf_waf_global_name_list WHERE  user_name = ? AND name_list_name = ? ;"
  local sql_params = {user_name,name_list_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end

  local item_sql = "DELETE FROM jxwaf_waf_global_name_list_item WHERE user_name = ? AND name_list_name = ? ;"
  local item_sql_params = {user_name, name_list_name}
  local item_sql_result, item_sql_error = db_query.query_mysql(item_sql, item_sql_params)
  if not item_sql_result or item_sql_error then
    response.fail_response(item_sql_error)
  end
  response.success_response("delete success")
end

function _M.edit_global_name_list()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name","name_list_detail","name_list_rule","name_list_action","action_value","name_list_expire","name_list_expire_time"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local name_list_detail = body_data['name_list_detail']
  local name_list_rule = body_data['name_list_rule']
  local name_list_action = body_data['name_list_action']
  local action_value = body_data['action_value']
  local name_list_expire = body_data['name_list_expire']
  local name_list_expire_time = body_data['name_list_expire_time']
  local sql = "UPDATE jxwaf_waf_global_name_list  SET  name_list_detail = ?,name_list_rule = ?,name_list_action = ? ,action_value = ? ,name_list_expire = ? ,name_list_expire_time = ?  WHERE user_name = ? AND name_list_name = ? ;"
  local sql_params = {name_list_detail,name_list_rule,name_list_action,action_value,name_list_expire,name_list_expire_time,user_name,name_list_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

function _M.edit_global_name_list_status()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name","status"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local status = body_data['status']
  local sql = "UPDATE jxwaf_waf_global_name_list  SET  status = ? WHERE  user_name = ? AND name_list_name = ? ;"
  local sql_params = {status,user_name,name_list_name}
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

function _M.exchange_global_name_list_priority()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name","type"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name = body_data['name_list_name']
  local exchange_type = body_data['type']
  if exchange_type == "top" then
    local sql = "SELECT MIN(rule_order_time) as rule_order_time FROM jxwaf_waf_global_name_list WHERE `user_name` = ? ;"
    local sql_params = {user_name}
    local query_result = db_query.query_mysql(sql,sql_params)
    if not query_result then
      response.fail_response("exchange priority error")
    end
    local min_rule_order_time = tonumber(query_result[1].rule_order_time)
    local rule_order_time = min_rule_order_time - 1
    local exchange_sql = "UPDATE jxwaf_waf_global_name_list  SET  rule_order_time = ? WHERE  user_name = ? AND name_list_name = ? ;"
    local exchange_sql_params = {rule_order_time,user_name,name_list_name}
    local exchange_sql_result,exchange_sql_error = db_query.query_mysql(exchange_sql,exchange_sql_params)
    if not exchange_sql_result then
      response.fail_response(exchange_sql_error)
    end
  elseif exchange_type == "exchange" then
    local exchange_name_list_name = param_check(body_data['exchange_name_list_name'])
    -- get rule_query_rule_order_time
    local rule_query_sql = "SELECT rule_order_time FROM jxwaf_waf_global_name_list  WHERE `user_name` = ?  AND `name_list_name` = ? ;"
    local rule_query_sql_params = {user_name,name_list_name}
    local rule_query_sql_result,rule_query_sql_error = db_query.query_mysql(rule_query_sql,rule_query_sql_params)
    if not rule_query_sql_result then
      response.fail_response(rule_query_sql_error)
    end
    local rule_query_rule_order_time = tonumber(rule_query_sql_result[1].rule_order_time)
    -- get exchange_query_rule_order_time
    local exchange_query_sql = "SELECT rule_order_time FROM jxwaf_waf_global_name_list  WHERE `user_name` = ? AND `name_list_name` = ? ;"
    local exchange_query_sql_params = {user_name,exchange_name_list_name}
    local exchange_query_sql_result,exchange_query_sql_error = db_query.query_mysql(exchange_query_sql,exchange_query_sql_params)
    if not exchange_query_sql_result then
      response.fail_response(exchange_query_sql_error)
    end
    local exchange_query_rule_order_time = tonumber(exchange_query_sql_result[1].rule_order_time)
    -- exchange rule_order_time
    local rule_update_sql = "UPDATE jxwaf_waf_global_name_list  SET  rule_order_time = ? WHERE  user_name = ? AND name_list_name = ? ;"
    local rule_update_sql_params = {exchange_query_rule_order_time,user_name,name_list_name}
    local rule_update_sql_result,rule_update_sql_error = db_query.query_mysql(rule_update_sql,rule_update_sql_params)
    if not rule_update_sql_result then
      response.fail_response(rule_update_sql_error)
    end
    local exchange_update_sql = "UPDATE jxwaf_waf_global_name_list  SET  rule_order_time = ? WHERE  user_name = ? AND name_list_name = ? ;"
    local exchange_update_sql_params = {rule_query_rule_order_time,user_name,exchange_name_list_name}
    local exchange_update_sql_result,exchange_update_sql_error = db_query.query_mysql(exchange_update_sql,exchange_update_sql_params)
    if not exchange_update_sql_result then
      response.fail_response(exchange_update_sql_error)
    end
  end
  response.success_response("exchange priority success")
end

function _M.backup_global_name_list()
  local user_name = login_check.get_session()
  local check_param = {"name_list_name_list"}
  local body_data = request_data.get_body_data(check_param)
  local name_list_name_list = body_data['name_list_name_list']
  local rules = {}
  for _,name_list_name in ipairs(name_list_name_list) do
    local sql = "SELECT * FROM jxwaf_waf_global_name_list  WHERE `user_name` = ? AND `name_list_name` = ?;"
    local sql_params = {user_name,name_list_name}
    local query_result = db_query.query_mysql(sql,sql_params)
    if not query_result or #query_result == 0 then
      response.fail_response("name_list_name is not exist")
    end
    local rule_conf = {
      name_list_name = query_result[1]['name_list_name'],
      name_list_detail = query_result[1]['name_list_detail'],
      name_list_rule = query_result[1]['name_list_rule'],
      name_list_action = query_result[1]['name_list_action'],
      action_value = query_result[1]['action_value'],
      name_list_expire = query_result[1]['name_list_expire'],
      name_list_expire_time = query_result[1]['name_list_expire_time']
    }
    table.insert(rules,rule_conf)
  end
  ngx.status = 200
  ngx.header.content_type = 'application/json'
  ngx.header['Content-Disposition'] = 'attachment; filename="global_name_list_data.json"'
  ngx.say(cjson.encode(rules))
  return ngx.exit(200)
end

function _M.load_global_name_list()
  local user_name = login_check.get_session()
  local check_param = {"rules"}
  local body_data = request_data.get_body_data(check_param)
  local rules = body_data['rules']
  for _,rule in ipairs(rules) do
    local name_list_name = rule['name_list_name']
    local name_list_detail = rule['name_list_detail']
    local name_list_rule = rule['name_list_rule']
    local name_list_action = rule['name_list_action']
    local action_value = rule['action_value']
    local name_list_expire = rule['name_list_expire']
    local name_list_expire_time = rule['name_list_expire_time']
    local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_global_name_list WHERE user_name = ? AND name_list_name = ?;"
    local count_sql_params = {user_name,name_list_name}
    local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
    if not count_sql_result then
      response.fail_response(count_error)
    end
    if tonumber(count_sql_result[1].count) == 0 then
      local rule_order_time = ngx.time()
      local create_sql = "INSERT INTO jxwaf_waf_global_name_list (user_name,name_list_name,name_list_detail,name_list_rule,name_list_action,action_value,name_list_expire,name_list_expire_time,rule_order_time) VALUES (?,?,?,?,?,?,?,?,?);"
      local create_sql_params = {user_name,name_list_name,name_list_detail,name_list_rule,name_list_action,action_value,name_list_expire,name_list_expire_time,rule_order_time}
      local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
      if not create_result then
        response.fail_response(create_err)
      end
    end
  end
  response.success_response("load success")
end

local function load_global_name_list_data(user_name,global_name_list_data)
    for k,v in pairs(global_name_list_data) do
        local name_list_name = v['name_list_name']
        local name_list_detail = v['name_list_detail']
        local name_list_rule = v['name_list_rule']
        local name_list_action = v['name_list_action']
        local action_value = v['action_value']
        local name_list_expire = v['name_list_expire']
        local name_list_expire_time = v['name_list_expire_time']
        local status = v['status']
        local rule_order_time = v['rule_order_time']
        local sql = "DELETE FROM jxwaf_waf_global_name_list WHERE name_list_name = ? AND user_name = ? ;"
        local sql_params = {name_list_name,user_name}
        local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
        if not sql_result then
          response.fail_response(sql_error)
        end
        local create_sql = "INSERT INTO jxwaf_waf_global_name_list (user_name,name_list_name,name_list_detail, name_list_rule,name_list_action, action_value,name_list_expire,name_list_expire_time,status,rule_order_time) VALUES (?,?,?,?,?,?,?,?,?,?);"
        local create_sql_params = {user_name,name_list_name,name_list_detail,name_list_rule,name_list_action,action_value,name_list_expire,name_list_expire_time,status,rule_order_time}
        local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
        if not create_result then
          response.fail_response(create_err)
        end
    end
end

function _M.load_global_name_list_hub_config()
    local user_name = login_check.get_session()
    local check_param = {"hub_repo","force_load"}
    local body_data = request_data.get_body_data(check_param)
    local hub_repo = body_data['hub_repo']
    local force_load = body_data['force_load']
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
    local global_name_list_data = res_body['global_name_list_data']
    if not global_name_list_data then
        if auth_code and #auth_code ~= 0 then
            response.fail_response("auth_code is error")
        else
            response.fail_response("global_name_list_data is nil")
        end
    end
    if force_load == "false" then
        for k, v in pairs(global_name_list_data) do
            local sql = "SELECT COUNT(*) as count FROM jxwaf_waf_global_name_list WHERE name_list_name = ? AND user_name = ? ;"
            local count_sql_result,count_sql_error = db_query.query_mysql(sql,{k,user_name})
            if not count_sql_result then
              response.fail_response(count_sql_error)
            end
            if tonumber(count_sql_result[1].count) > 0  then
              response.fail_response("name_list_name is exist "..k)
            end
        end
    end
    load_global_name_list_data(user_name,global_name_list_data)
    response.success_response("load success")
end

function _M.export_global_name_list_hub_config()
  local user_name = login_check.get_session()
  local check_param = {"global_name_list"}
  local body_data = request_data.get_body_data(check_param)
  local global_name_list = body_data['global_name_list']
  local global_name_list_data = {}
  for _,name_list_name in ipairs(global_name_list) do
      local sql = "SELECT * FROM jxwaf_waf_global_name_list  WHERE `user_name` = ? AND `name_list_name` = ?;"
      local sql_params = {user_name,name_list_name}
      local result = db_query.query_mysql(sql,sql_params)
      if not result or #result == 0 then
          response.fail_response("name_list_name is not exist: "..name_list_name)
      end
      global_name_list_data[name_list_name] = {
          name_list_name = result[1]['name_list_name'],
          name_list_detail = result[1]['name_list_detail'],
          name_list_rule = result[1]['name_list_rule'],
          name_list_action = result[1]['name_list_action'],
          action_value = result[1]['action_value'],
          name_list_expire = result[1]['name_list_expire'],
          name_list_expire_time = result[1]['name_list_expire_time'],
          status = result[1]['status'],
          rule_order_time = result[1]['rule_order_time']
      }
  end
    cjson.encode_empty_table_as_object(false)
    local response_message = {
        global_name_list_data = global_name_list_data,
        result = true
    }
    response.raw_success_response(response_message)
end

return _M