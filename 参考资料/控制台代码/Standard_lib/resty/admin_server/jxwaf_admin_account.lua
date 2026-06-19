local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'
local response = require 'resty.admin_server.response'
local otp = require 'resty.admin_server.otp'
local request_data = require 'resty.admin_server.request_data'
local tools = require 'resty.admin_server.tools'
local uuid = require "resty.admin_server.uuid"
local login_check = require 'resty.admin_server.login_check'
local bit = require("bit")
local band = bit.band
local lshift = bit.lshift
local rshift = bit.rshift
local _M = {}

local Base32_Hash = {
    [0 ] = 65, [1 ] = 66, [2 ] = 67, [3 ] = 68, [4 ] = 69, [5 ] = 70,
    [6 ] = 71, [7 ] = 72, [8 ] = 73, [9 ] = 74, [10] = 75, [11] = 76,
    [12] = 77, [13] = 78, [14] = 79, [15] = 80, [16] = 81, [17] = 82,
    [18] = 83, [19] = 84, [20] = 85, [21] = 86, [22] = 87, [23] = 88,
    [24] = 89, [25] = 90,
    [26] = 50, [27] = 51, [28] = 52, [29] = 53, [30] = 54, [31] = 55,

    [50] = 26, [51] = 27, [52] = 28, [53] = 29, [54] = 30, [55] = 31,
    [65] = 0,  [66] = 1,  [67] = 2,  [68] = 3,  [69] = 4,  [70] = 5,
    [71] = 6,  [72] = 7,  [73] = 8,  [74] = 9,  [75] = 10, [76] = 11,
    [77] = 12, [78] = 13, [79] = 14, [80] = 15, [81] = 16, [82] = 17,
    [83] = 18, [84] = 19, [85] = 20, [86] = 21, [87] = 22, [88] = 23,
    [89] = 24, [90] = 25,
}

local function encode_base32(serect_str)
    local Serect_Token = {serect_str:byte(1, -1)}
    local Serect_Token_Base32 = {}
    local Tmp_cahr = 0

    local c = 0
    local n = 0
    local tmp_n = 0
    local bs =0

    for i, v in ipairs(Serect_Token) do
        n = lshift(n, 8)
        n = n + v
        c = c + 8
        bs = c % 5
        tmp_n = rshift(n, bs)

        for j = c - bs - 5, 0, -5 do
            Tmp_cahr = rshift(band(tmp_n, lshift(0x1F, j)), j)
            Serect_Token_Base32[#Serect_Token_Base32+1] = Base32_Hash[Tmp_cahr]
        end

        c = bs
        n = band(n, rshift(0xFF, 8 - bs))
    end

    return string.char(table.unpack(Serect_Token_Base32))
end

local function totp_new_key()
    local tmp_k = ""
    math.randomseed(ngx.time())
    for i = 1, 10 do
        tmp_k = tmp_k .. string.char(math.random(0, 255))
    end
    return encode_base32(tmp_k)
end



function _M.account_init_check()
  local account_count_sql = 'SELECT COUNT(*) AS count FROM jxwaf_admin_account;'
  local account_count_sql_result = db_query.query_mysql(account_count_sql)
  if not account_count_sql_result then
    ngx.log(ngx.ERR,"account_init_check error,account_count_sql query failed")
    response.fail_response("account_init_check error,account_count_sql query failed")
  end
  local account_count = tonumber(account_count_sql_result[1]["count"])
  local return_data = {}
  return_data['result'] = true
  if account_count == 0 then
    return_data['message'] = "account_init_fail"
    response.raw_success_response(return_data)
  else
      return_data['message'] = "account_init_success"
      response.raw_success_response(return_data)
  end
end

function _M.get_otp_qr_url()
  local account_count_sql = 'SELECT COUNT(*) AS count FROM jxwaf_admin_account;'
  local account_count_sql_result = db_query.query_mysql(account_count_sql)
  if not account_count_sql_result then
    ngx.log(ngx.ERR,"get_otp_qr error,account_count_sql query failed")
    response.fail_response("get_otp_qr error,account_count_sql query failed")
  end
  local account_count = tonumber(account_count_sql_result[1]["count"])
  if account_count == 0 then
    local otp_secret_key =  totp_new_key()
    local session_uuid = uuid.generate_random()
    local tmp_data = ngx.shared.conf_data
    tmp_data:set(session_uuid.."otp",otp_secret_key,86400)
    response.set_regist_session(session_uuid)
    local otp_init = otp.totp_init(otp_secret_key)
    local url = otp_init:get_qr_url('jxwaf', 'jxwaf-admin-server')
    response.success_response(url)
  else
    response.success_response("account_has_been_registered")
  end
end

local function init_waf_conf(user_name)
    local create_ai_sql = "INSERT INTO jxwaf_ai_web_protection (user_name) VALUES (?);"
    local create_ai_sql_params = {user_name}
    local create_ai_result,create_ai_err = db_query.query_mysql(create_ai_sql,create_ai_sql_params)
    if not create_ai_result then
      response.fail_response(create_ai_err)
    end
end


function _M.account_regist()
  local account_count_sql = 'SELECT COUNT(*) AS count FROM jxwaf_admin_account;'
  local account_count_sql_result = db_query.query_mysql(account_count_sql)
  if not account_count_sql_result then
    response.fail_response("account_count_sql query failed")
  end
  local account_count = tonumber(account_count_sql_result[1]["count"])
  if account_count == 0 then
     local check_param = {"user_name","user_password","otp_auth"}
     local body_data = request_data.get_body_data(check_param)
     local user_name = body_data['user_name']
     local user_password = body_data['user_password']
     local user_password_md5 = tools.get_md5(user_password)
     local otp_auth = body_data['otp_auth']
     if otp_auth == 'true' then
        local otp_auth_code = body_data['otp_auth_code']
        local tmp_data = ngx.shared.conf_data
        local account_regist_session = ngx.var.cookie_account_regist_session
        if not account_regist_session then
            response.fail_response("otp not init")
        end
        local otp_secret_key =  tmp_data:get(account_regist_session.."otp")
        if not otp_secret_key then
            response.fail_response("otp not init fail,session is null")
        end
         local otp_init = otp.totp_init(otp_secret_key)
         if otp_init:verify_token(otp_auth_code) then
            --init_waf_conf(user_name)
            local create_account_sql = [[INSERT INTO `jxwaf_admin_account` (`user_name`, `user_password`,`otp_auth`,`otp_secret_key`) VALUES ( ?,?,?,? );]]
            local create_account_sql_params = {user_name,user_password_md5,otp_auth,otp_secret_key}
            local create_account_result,err = db_query.query_mysql(create_account_sql,create_account_sql_params)
            if not create_account_result then
              response.fail_response(err)
            else
              response.success_response("create success")
            end
         else
            response.fail_response("otp fail")
         end
     else
            --init_waf_conf(user_name)
            local create_account_sql = [[INSERT INTO `jxwaf_admin_account` (`user_name`, `user_password`,`otp_auth`,`otp_secret_key`) VALUES ( ?,?,?,? );]]
            local create_account_sql_params = {user_name,user_password_md5,otp_auth,''}
            local create_account_result,err = db_query.query_mysql(create_account_sql,create_account_sql_params)
            if not create_account_result then
              response.fail_response(err)
            else
              response.success_response("create success")
            end
     end
  else
      response.fail_response("account_has_been_registered")
  end
end

function _M.account_login()
  local check_param = {"user_name","user_password"}
  local body_data = request_data.get_body_data(check_param)
  local user_name = body_data['user_name']
  local user_password = body_data['user_password']
  local otp_auth_code = body_data['otp_auth_code']
  local user_password_md5 =   tools.get_md5(user_password)
  local query_account_sql = [[SELECT * FROM `jxwaf_admin_account` where `user_name` = ? and  `user_password` = ? ;]]
  local query_account_sql_params = {user_name,user_password_md5}   
  local query_account_result,err = db_query.query_mysql(query_account_sql,query_account_sql_params)
  if (not query_account_result) or (query_account_result and #query_account_result == 0) then
    response.fail_response("username or password auth fail")
  end

  local otp_auth = query_account_result[1]['otp_auth']
  if not otp_auth then
    response.fail_response("otp_auth error")
  end
  if otp_auth == 'true' then
      local otp_secret_key = query_account_result[1]['otp_secret_key']
      local otp_init = otp.totp_init(otp_secret_key)
      if otp_init:verify_token(otp_auth_code) then
        local session_uuid = uuid.generate_random()
        local conf_data = ngx.shared.conf_data
        conf_data:set(session_uuid,user_name,86400)
        response.set_auth_session(session_uuid)
        response.success_response(user_name)
      else
        response.fail_response("otp auth fail")
      end
  else
        local session_uuid = uuid.generate_random()
        local conf_data = ngx.shared.conf_data
        conf_data:set(session_uuid,user_name,86400)
        response.set_auth_session(session_uuid)
        response.success_response(user_name)
  end
end

function _M.account_logout()
  local conf_data = ngx.shared.conf_data
  local jxwaf_session = ngx.var.cookie_jxwaf_session
  if jxwaf_session then
    conf_data:delete(jxwaf_session)
  end
  return ngx.redirect("/#/login")
end

return _M 
