local cjson = require "cjson.safe"
local _M = {}

function _M.fail_response(error_message)
  local return_data = {}
  return_data['result'] = false
  return_data['message'] = error_message
  ngx.status = 200
  ngx.header.content_type = "application/json"
  ngx.say(cjson.encode(return_data))
  return ngx.exit(200)
end

function _M.success_response(success_message)
  local return_data = {}
  return_data['result'] = true
  return_data['message'] = success_message
  ngx.status = 200
  ngx.header.content_type = "application/json"
  ngx.say(cjson.encode(return_data))
  return ngx.exit(200)
end

function _M.raw_success_response(success_message)
  ngx.status = 200
  ngx.header.content_type = "application/json"
  ngx.say(cjson.encode(success_message))
  return ngx.exit(200)
end

function _M.set_auth_session(value)
  local name = "jxwaf_session"
  local max_age = 86400
  local expires = ngx.cookie_time(ngx.time() + max_age)
  local cookie = string.format("%s=%s; Expires=%s; Path=/; HttpOnly", name, value, expires)
  if ngx.var.scheme == "https" then
    cookie = cookie .. "; Secure"
  end
  ngx.header['Set-Cookie'] = cookie
end

function _M.set_regist_session(value)
  local name = "account_regist_session"
  local max_age = 86400
  local expires = ngx.cookie_time(ngx.time() + max_age)
  local cookie = string.format("%s=%s; Expires=%s; Path=/; HttpOnly", name, value, expires)
  if ngx.var.scheme == "https" then
    cookie = cookie .. "; Secure"
  end
  ngx.header['Set-Cookie'] = cookie
end

return _M 