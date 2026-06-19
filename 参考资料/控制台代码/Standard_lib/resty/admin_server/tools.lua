local resty_md5 = require "resty.md5"
local str = require "resty.string"
local resolver = require "resty.dns.resolver"
local http = require "resty.admin_server.http"
local cjson = require "cjson.safe"
local db_query = require 'resty.admin_server.db_query'


local _M = {}

function _M.get_md5(input)
  local md5 = resty_md5:new()
  local ok = md5:update(input)
  local digest = md5:final()
  local hex = str.to_hex(digest)
  return hex
end

local function get_resolver_nameservers()
    local resolver_ips = init_config['resolver_ips'] or "223.5.5.5 119.29.29.29 114.114.114.114 1.1.1.1"
    local nameservers = {}
    for ip in string.gmatch(resolver_ips, "%S+") do
        table.insert(nameservers, ip)
    end
    return nameservers
end

function _M.get_dns_resolver_ip(domain)
  local r, err = resolver:new{
      nameservers = get_resolver_nameservers(),
      retrans = 5,
      timeout = 2000
  }
  if not r then
      ngx.log(ngx.ERR,"failed to instantiate the resolver: ", err)
      return
  end

  local ip_list = {}
  
  local a_answers, a_err = r:query(domain, {qtype = r.TYPE_A})
  if a_answers and not a_answers.errcode then
    for _, ans in ipairs(a_answers) do
      if ans.address then
        table.insert(ip_list, ans.address)
      end
    end
  end
  
  local aaaa_answers, aaaa_err = r:query(domain, {qtype = r.TYPE_AAAA})
  if aaaa_answers and not aaaa_answers.errcode then
    for _, ans in ipairs(aaaa_answers) do
      if ans.address then
        table.insert(ip_list, ans.address)
      end
    end
  end
  
  if #ip_list == 0 then
    ngx.log(ngx.ERR,"DNS resolution failed: no IP addresses found for domain: ", domain)
    return
  end
  
  return ip_list
end

function _M.get_dns_resolver_cname(domain)
  local r, err = resolver:new{
      nameservers = get_resolver_nameservers(),
      retrans = 5,
      timeout = 2000
  }
  if not r then
      ngx.log(ngx.ERR,"failed to instantiate the resolver: ", err)
      return
  end

  local query_answers, query_err = r:query(domain, {qtype = r.TYPE_CNAME})
  if not query_answers then
     ngx.log(ngx.ERR,"DNS resolution failed: ", query_err)
     return
  end

  if query_answers.errcode then
    return
  end

  local cname_list = {}
  for _, ans in ipairs(query_answers) do
    if ans.cname then
       table.insert(cname_list, ans.cname)
    end
  end

  if #cname_list == 0 then
      return
  else
      return cname_list
  end
end


function _M.waf_get_cache_page_url(cache_page_url)
    local httpc = http.new()
    httpc:set_timeout(5000)
    local res, err = httpc:request_uri(cache_page_url)
    if not res then
       ngx.log(ngx.ERR, "failed to request: ", cache_page_url)
       ngx.log(ngx.ERR, "request error is :", err)
       return false, err
    end
    local cache_page_content = res.body
    local cache_content_type = res.headers["Content-Type"]
    return true,cache_page_content,cache_content_type
end


local function get_user_dict(tag, key)
    local user_data = ngx.shared.model_data
    local dict_key = {}
    table.insert(dict_key, tag)
    table.insert(dict_key, key)
    local tmp_dict_key = ngx.md5(table.concat(dict_key, "|"))
    return user_data:get(tmp_dict_key)
end

local function set_user_dict(tag, key, value, expire_time)
    local user_data = ngx.shared.model_data
    local dict_key = {}
    table.insert(dict_key, tag)
    table.insert(dict_key, key)
    local tmp_dict_key = ngx.md5(table.concat(dict_key, "|"))
    return user_data:set(tmp_dict_key, value, tonumber(expire_time))
end

function _M.jxwaf_model_query(model_data, host, port)
    local token = model_data['token']
    local raw_string = model_data['raw_string']
    local digest = ngx.hmac_sha1('jxwaf', token)
    local token_auth = str.to_hex(digest)
    local tag = "model_token"
    local dict_value = get_user_dict(tag, token)
    if dict_value then
        local decoded = cjson.decode(dict_value)
        if decoded and decoded.result ~= "none" then
            return decoded
        end
    end

    local sock = ngx.socket.tcp()
    sock:settimeout(30000)
    local ok, err = sock:connect(host, tonumber(port))
    if not ok then
        ngx.log(ngx.ERR, err)
        return nil, "connect_failed: " .. (err or "unknown")
    end

    local ssl_enabled = init_config['jxwaf_model_server_ssl'] == 'true'
    if ssl_enabled then
        local session, err = sock:sslhandshake(nil, host, true)
        if not session then
            ngx.log(ngx.ERR, "ssl handshake failed: ", err)
            sock:close()
            return nil, "ssl_handshake_failed: " .. (err or "unknown")
        end
    end

    local req = {
        raw_string = raw_string,
        token = token,
        token_auth = token_auth
    }
    local json_req = cjson.encode(req)
    local bytes, err = sock:send(json_req .. "\n")
    if not bytes then
        ngx.log(ngx.ERR, err)
        sock:close()
        return nil, "send_failed: " .. (err or "unknown")
    end

    local res, err = sock:receive("*l")
    if not res then
        sock:close()
        return nil, "receive_failed: " .. (err or "unknown")
    end
    sock:close()

    local decode_res = cjson.decode(res)
    if not decode_res then
        ngx.log(ngx.ERR, res)
        return nil, "message_failed"
    end

    if decode_res.status == "error" then
        ngx.log(ngx.ERR, "model query error: ", decode_res.result)
        return nil, decode_res.result or "query_error"
    end

    if decode_res.result ~= "none" then
        set_user_dict(tag, token, res, 3600)
    end

    return decode_res
end

function _M.jxwaf_model_sync()
    local host = init_config['jxwaf_model_server_host']
    local port = init_config['jxwaf_model_server_port']
    local waf_update_conf_data = ngx.shared.waf_update_conf_data

    local ai_model_sync_time = waf_update_conf_data:get("ai_model_sync_time") or ''
    local ai_model_sync_id = waf_update_conf_data:get("ai_model_sync_id") or '0'

    local digest = ngx.hmac_sha1('jxwaf', ai_model_sync_time)
    local sync_auth = str.to_hex(digest)

    local sock = ngx.socket.tcp()
    sock:settimeout(10000)
    local ok, err = sock:connect(host, tonumber(port))
    if not ok then
        ngx.log(ngx.ERR, "connect failed: ", err)
        return nil, "connect_failed: " .. (err or "unknown")
    end

    local ssl_enabled = init_config['jxwaf_model_server_ssl'] == 'true'
    if ssl_enabled then
        local session, err = sock:sslhandshake(nil, host, true)
        if not session then
            ngx.log(ngx.ERR, "ssl handshake failed: ", err)
            sock:close()
            return nil, "ssl_handshake_failed: " .. (err or "unknown")
        end
    end

    local req = {
        ai_model_sync_time = ai_model_sync_time,
        ai_model_sync_id = tonumber(ai_model_sync_id),
        sync_auth = sync_auth
    }
    local json_req = cjson.encode(req)
    local bytes, err = sock:send(json_req .. "\n")
    if not bytes then
        ngx.log(ngx.ERR, "send failed: ", err)
        sock:close()
        return nil, "send_failed: " .. (err or "unknown")
    end

    local res, err = sock:receive("*l")
    if not res then
        ngx.log(ngx.ERR, "receive failed: ", err)
        sock:close()
        return nil, "receive_failed: " .. (err or "unknown")
    end
    sock:close()

    local decode_res = cjson.decode(res)
    if not decode_res then
        ngx.log(ngx.ERR, "json decode failed: ", res)
        return nil, "json_decode_failed"
    end

    if decode_res.status == "error" then
        ngx.log(ngx.ERR, "sync error: ", decode_res.result or "unknown")
        return nil, decode_res.result or "sync_error"
    end

    local sync_data = decode_res.result or {}

    if #sync_data > 0 then
        local last_item = sync_data[#sync_data]
        if last_item.last_updated then
            local success, err = waf_update_conf_data:set("ai_model_sync_time", last_item.last_updated)
            if not success then
                ngx.log(ngx.ERR, "failed to set ai_model_sync_time: ", err)
            end
        end
        if last_item.id then
            local success, err = waf_update_conf_data:set("ai_model_sync_id", tostring(last_item.id))
            if not success then
                ngx.log(ngx.ERR, "failed to set ai_model_sync_id: ", err)
            end
        end
    end

    return sync_data
end

return _M
