local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local request_data = require 'resty.admin_server.request_data'
local login_check = require 'resty.admin_server.login_check'
local http = require "resty.admin_server.http"
local aes = require "resty.aes"

local _M = {}

function _M.get_flow_rule_protection_list()
  local user_name = login_check.get_session()
  local check_param = {"page"}
  local body_data = request_data.get_body_data(check_param)
  local page = tonumber(body_data['page']) or 1
  local pageSize = 50
  local offset = (page - 1) * pageSize

  local count_sql = "SELECT COUNT(*) AS total FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ?;"
  local count_result, count_err = db_query.query_mysql(count_sql, {user_name})
  if not count_result or count_err then
    response.fail_response(count_err)
  end
  local total = count_result[1]["total"]
  local total_pages = math.ceil(total / pageSize)

  local sql = "SELECT * FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ? ORDER BY rule_order_time ASC LIMIT ? OFFSET ?;"
  local sql_params = {user_name, pageSize, offset}
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

function _M.get_flow_rule_protection()
  local user_name = login_check.get_session()
  local check_param = {"rule_name"}
  local body_data = request_data.get_body_data(check_param)
  local rule_name = body_data['rule_name']

  local sql = "SELECT * FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ? AND `rule_name` = ?;"
  local sql_params = {user_name, rule_name}
  local query_result = db_query.query_mysql(sql,sql_params)
  if query_result and #query_result > 0 then
    response.success_response(query_result[1])
  else
    response.fail_response("rule_name is not exist")
  end
end

function _M.create_flow_rule_protection()
  local user_name = login_check.get_session()
  local check_param = {"rule_name","rule_detail","rule_matchs","rule_action","action_value","filter","entity","stat_time","exceed_count","block_time"}
  local body_data = request_data.get_body_data(check_param)
  local rule_name = body_data['rule_name']
  local rule_detail = body_data['rule_detail']
  local rule_matchs = body_data['rule_matchs']
  local rule_action = body_data['rule_action']
  local action_value = body_data['action_value']
  local filter = body_data['filter']
  local entity = body_data['entity']
  local stat_time = body_data['stat_time']
  local exceed_count = body_data['exceed_count']
  local block_time = body_data['block_time']

  local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_flow_rule_protection WHERE user_name = ? AND rule_name = ?;"
  local count_sql_params = {user_name, rule_name}
  local count_sql_result,count_error = db_query.query_mysql(count_sql,count_sql_params)
  if not count_sql_result then
    response.fail_response(count_error)
  end
  if tonumber(count_sql_result[1].count) > 0 then
    response.fail_response("rule_name is exist")
  end

  local rule_order_time = ngx.time()

  local create_sql = "INSERT INTO jxwaf_waf_flow_rule_protection (user_name, rule_name, rule_detail, rule_matchs, rule_action, action_value, rule_order_time, filter, entity, stat_time, exceed_count, block_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);"
  local create_sql_params = {user_name, rule_name, rule_detail, rule_matchs, rule_action, action_value, rule_order_time, filter, entity, stat_time, exceed_count, block_time}
  local create_result,create_err = db_query.query_mysql(create_sql,create_sql_params)
  if not create_result then
    response.fail_response(create_err)
  else
    response.success_response("create success")
  end
end

function _M.delete_flow_rule_protection()
  local user_name = login_check.get_session()
  local check_param = {"rule_name"}
  local body_data = request_data.get_body_data(check_param)
  local rule_name = body_data['rule_name']

  local sql = "DELETE FROM jxwaf_waf_flow_rule_protection WHERE user_name = ? AND rule_name = ?;"
  local sql_params = {user_name, rule_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("delete success")
end

function _M.edit_flow_rule_protection()
  local user_name = login_check.get_session()
  local check_param = {"rule_name", "rule_detail", "rule_matchs", "rule_action", "action_value", "filter", "entity", "stat_time", "exceed_count", "block_time"}
  local body_data = request_data.get_body_data(check_param)
  local rule_name = body_data['rule_name']
  local rule_detail = body_data['rule_detail']
  local rule_matchs = body_data['rule_matchs']
  local rule_action = body_data['rule_action']
  local action_value = body_data['action_value']
  local filter = body_data['filter']
  local entity = body_data['entity']
  local stat_time = body_data['stat_time']
  local exceed_count = body_data['exceed_count']
  local block_time = body_data['block_time']

  local sql = "UPDATE jxwaf_waf_flow_rule_protection SET rule_detail = ?, rule_matchs = ?, rule_action = ?, action_value = ?, filter = ?, entity = ?, stat_time = ?, exceed_count = ?, block_time = ? WHERE user_name = ? AND rule_name = ?;"
  local sql_params = {rule_detail, rule_matchs, rule_action, action_value, filter, entity, stat_time, exceed_count, block_time, user_name, rule_name}
  local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
  if not sql_result then
    response.fail_response(sql_error)
  end
  response.success_response("edit success")
end

function _M.edit_flow_rule_protection_status()
  local user_name = login_check.get_session()
  local check_param = {"rule_name","status"}
  local body_data = request_data.get_body_data(check_param)
  local rule_name = body_data['rule_name']
  local status = body_data['status']

  local sql = "UPDATE jxwaf_waf_flow_rule_protection SET status = ? WHERE user_name = ? AND rule_name = ?;"
  local sql_params = {status, user_name, rule_name}
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
       ngx.log(ngx.ERR, cjson.encode(data_result))
       ngx.say(cjson.encode(data_result))
       return ngx.exit(200)
    end
    return input_param
end

function _M.exchange_flow_rule_protection_priority()
  local user_name = login_check.get_session()
  local check_param = {"rule_name","type"}
  local body_data = request_data.get_body_data(check_param)
  local rule_name = body_data['rule_name']
  local exchange_type = body_data['type']
  if exchange_type == "top" then
    local sql = "SELECT rule_order_time FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ? ORDER BY `rule_order_time` ASC limit 1;"
    local sql_params = {user_name}
    local query_result = db_query.query_mysql(sql,sql_params)
    if not query_result then
      response.fail_response("exchange priority error")
    end
    local rule_order_time = tonumber(query_result[1].rule_order_time) - 1
    local exchange_sql = "UPDATE jxwaf_waf_flow_rule_protection SET rule_order_time = ? WHERE user_name = ? AND rule_name = ?;"
    local exchange_sql_params = {rule_order_time, user_name, rule_name}
    local exchange_sql_result,exchange_sql_error = db_query.query_mysql(exchange_sql,exchange_sql_params)
    if not exchange_sql_result then
      response.fail_response(exchange_sql_error)
    end
  elseif exchange_type == "exchange" then
    local exchange_rule_name = param_check(body_data['exchange_rule_name'])
    local rule_query_sql = "SELECT rule_order_time FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ? AND `rule_name` = ?;"
    local rule_query_sql_params = {user_name, rule_name}
    local rule_query_sql_result,rule_query_sql_error = db_query.query_mysql(rule_query_sql, rule_query_sql_params)
    if not rule_query_sql_result then
      response.fail_response(rule_query_sql_error)
    end
    local rule_query_rule_order_time = tonumber(rule_query_sql_result[1].rule_order_time)
    local exchange_query_sql = "SELECT rule_order_time FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ? AND `rule_name` = ?;"
    local exchange_query_sql_params = {user_name, exchange_rule_name}
    local exchange_query_sql_result,exchange_query_sql_error = db_query.query_mysql(exchange_query_sql, exchange_query_sql_params)
    if not exchange_query_sql_result then
      response.fail_response(exchange_query_sql_error)
    end
    local exchange_query_rule_order_time = tonumber(exchange_query_sql_result[1].rule_order_time)
    local rule_update_sql = "UPDATE jxwaf_waf_flow_rule_protection SET rule_order_time = ? WHERE user_name = ? AND rule_name = ?;"
    local rule_update_sql_params = {exchange_query_rule_order_time, user_name, rule_name}
    local rule_update_sql_result,rule_update_sql_error = db_query.query_mysql(rule_update_sql, rule_update_sql_params)
    if not rule_update_sql_result then
      response.fail_response(rule_update_sql_error)
    end
    local exchange_update_sql = "UPDATE jxwaf_waf_flow_rule_protection SET rule_order_time = ? WHERE user_name = ? AND rule_name = ?;"
    local exchange_update_sql_params = {rule_query_rule_order_time, user_name, exchange_rule_name}
    local exchange_update_sql_result,exchange_update_sql_error = db_query.query_mysql(exchange_update_sql, exchange_update_sql_params)
    if not exchange_update_sql_result then
      response.fail_response(exchange_update_sql_error)
    end
  end
  response.success_response("exchange priority success")
end

function _M.backup_flow_rule_protection()
  local user_name = login_check.get_session()
  local check_param = {"rule_name_list"}
  local body_data = request_data.get_body_data(check_param)
  local rule_name_list = body_data['rule_name_list']
  local rules = {}
  for _,rule_name in ipairs(rule_name_list) do
    local sql = "SELECT * FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ? AND `rule_name` = ?;"
    local sql_params = {user_name, rule_name}
    local query_result = db_query.query_mysql(sql,sql_params)
    if not query_result then
      response.fail_response("rule_name is not exist")
    end
    local rule_name_result = query_result[1]
    local rule_conf = {
      rule_name = rule_name_result['rule_name'],
      rule_detail = rule_name_result['rule_detail'],
      rule_matchs = rule_name_result['rule_matchs'],
      rule_action = rule_name_result['rule_action'],
      action_value = rule_name_result['action_value'],
      filter = rule_name_result['filter'],
      entity = rule_name_result['entity'],
      stat_time = rule_name_result['stat_time'],
      exceed_count = rule_name_result['exceed_count'],
      block_time = rule_name_result['block_time']
    }
    table.insert(rules, rule_conf)
  end
  ngx.status = 200
  ngx.header.content_type = 'application/json'
  ngx.header['Content-Disposition'] = 'attachment; filename="flow_rule_protection_data.json"'
  ngx.say(cjson.encode(rules))
  return ngx.exit(200)
end

function _M.load_flow_rule_protection()
  local user_name = login_check.get_session()
  local check_param = {"rules"}
  local body_data = request_data.get_body_data(check_param)
  local rules = body_data['rules']
  for _,rule in ipairs(rules) do
    local rule_name = rule['rule_name']
    local rule_detail = rule['rule_detail']
    local rule_matchs = rule['rule_matchs']
    local rule_action = rule['rule_action']
    local action_value = rule['action_value']
    local filter = rule['filter']
    local entity = rule['entity']
    local stat_time = rule['stat_time']
    local exceed_count = rule['exceed_count']
    local block_time = rule['block_time']
    local count_sql = "SELECT COUNT(*) as count FROM jxwaf_waf_flow_rule_protection WHERE user_name = ? AND rule_name = ?;"
    local count_sql_params = {user_name, rule_name}
    local count_sql_result, count_error = db_query.query_mysql(count_sql, count_sql_params)
    if not count_sql_result then
      response.fail_response(count_error)
    end
    if tonumber(count_sql_result[1].count) == 0 then
      local rule_order_time = math.floor(ngx.now())
      local create_sql = "INSERT INTO jxwaf_waf_flow_rule_protection (user_name, rule_name, rule_detail, rule_matchs, rule_action, action_value, rule_order_time, filter, entity, stat_time, exceed_count, block_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);"
      local create_sql_params = {user_name, rule_name, rule_detail, rule_matchs, rule_action, action_value, rule_order_time, filter, entity, stat_time, exceed_count, block_time}
      local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)
      if not create_result then
        response.fail_response(create_err)
      end
    end
  end
  response.success_response("load success")
end

local function load_flow_rule_protection_data(user_name, flow_rule_protection_data)
    for k,v in pairs(flow_rule_protection_data) do
        local rule_name = v['rule_name']
        local rule_detail = v['rule_detail']
        local filter = v['filter']
        local rule_matchs = v['rule_matchs']
        local entity = v['entity']
        local stat_time = v['stat_time']
        local exceed_count = v['exceed_count']
        local rule_action = v['rule_action']
        local action_value = v['action_value']
        local block_time = v['block_time']
        local status = v['status']
        local rule_order_time = v['rule_order_time']
        local sql = "DELETE FROM jxwaf_waf_flow_rule_protection WHERE user_name = ? AND rule_name = ? ;"
        local sql_params = {user_name, rule_name}
        local sql_result,sql_error = db_query.query_mysql(sql,sql_params)
        if not sql_result then
          response.fail_response(sql_error)
        end
        local create_sql = "INSERT INTO jxwaf_waf_flow_rule_protection (user_name, rule_name, rule_detail, rule_matchs, rule_action, action_value, rule_order_time, filter, entity, stat_time, exceed_count, block_time, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);"
        local create_sql_params = {user_name, rule_name, rule_detail, rule_matchs, rule_action, action_value, rule_order_time, filter, entity, stat_time, exceed_count, block_time, status}
        local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)
        if not create_result then
          response.fail_response(create_err)
        end
    end
end

function _M.load_flow_rule_protection_hub_config()
    local user_name = login_check.get_session()
    local check_param = {"hub_repo","force_load"}
    local body_data = request_data.get_body_data(check_param)
    local hub_repo = body_data['hub_repo']
    local force_load = body_data['force_load']
    local auth_code = body_data['auth_code']
    local hub_website = 'https://user.jxwaf.com/waf/repo?uuid=' .. hub_repo
    local httpc = http.new()
    local res, err = httpc:request_uri(hub_website, {
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
    if res_body['result'] == false then
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
    local flow_rule_protection_data = res_body['flow_rule_protection_data']
    if not flow_rule_protection_data then
        if auth_code and #auth_code ~= 0 then
            response.fail_response("auth_code is error")
        else
            response.fail_response("flow_rule_protection_data is nil")
        end
    end
    if force_load == "false" then
        for k, v in pairs(flow_rule_protection_data) do
            local sql = "SELECT COUNT(*) as count FROM jxwaf_waf_flow_rule_protection WHERE user_name = ? AND rule_name = ?;"
            local count_sql_result, count_sql_error = db_query.query_mysql(sql, {user_name, k})
            if not count_sql_result then
              response.fail_response(count_sql_error)
            end
            if tonumber(count_sql_result[1].count) > 0 then
              response.fail_response("rule_name name is exist " .. k)
            end
        end
    end
    load_flow_rule_protection_data(user_name, flow_rule_protection_data)
    response.success_response("load success")
end

function _M.export_flow_rule_protection_hub_config()
  local user_name = login_check.get_session()
  local check_param = {"flow_rule_protection"}
  local body_data = request_data.get_body_data(check_param)
  local flow_rule_protection = body_data['flow_rule_protection']
  local flow_rule_protection_data = {}
  for _,rule_name in ipairs(flow_rule_protection) do
      local sql = "SELECT * FROM jxwaf_waf_flow_rule_protection WHERE `user_name` = ? AND `rule_name` = ?;"
      local sql_params = {user_name, rule_name}
      local result = db_query.query_mysql(sql, sql_params)
      if not result or #result == 0 then
          response.fail_response("rule_name is not exist: " .. rule_name)
      end
      flow_rule_protection_data[rule_name] = {
        rule_name = result[1]['rule_name'],
        rule_detail = result[1]['rule_detail'],
        filter = result[1]['filter'],
        rule_matchs = result[1]['rule_matchs'],
        entity = result[1]['entity'],
        stat_time = result[1]['stat_time'],
        exceed_count = result[1]['exceed_count'],
        rule_action = result[1]['rule_action'],
        action_value = result[1]['action_value'],
        block_time = result[1]['block_time'],
        status = result[1]['status'],
        rule_order_time = result[1]['rule_order_time']
      }
  end
    cjson.encode_empty_table_as_object(false)
    local response_message = {
        flow_rule_protection_data = flow_rule_protection_data,
        result = true
    }
    response.raw_success_response(response_message)
end

return _M
