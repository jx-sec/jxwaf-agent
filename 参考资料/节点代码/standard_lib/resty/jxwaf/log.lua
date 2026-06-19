local logger_socket = require "resty.jxwaf.socket"
local cjson = require "cjson.safe"
local waf = require "resty.jxwaf.waf"
local string_sub = string.sub
local config_info = waf.get_config_info()
local table_concat = table.concat
local table_insert = table.insert
local request = require "resty.jxwaf.request"
local aes = require "resty.aes"
local ctx_waf_log = ngx.ctx.waf_log

local waf_log = {}

if ctx_waf_log  then
  local waf_log = {}
  waf_log['host'] = ngx.var.http_host or ngx.var.host or ""
  waf_log['request_uuid'] = ngx.ctx.request_uuid
  waf_log['waf_node_uuid'] = config_info['waf_node_uuid']
  waf_log['status'] = ngx.var.status
  waf_log['request_time'] = ngx.localtime()
  waf_log['jxwaf_devid'] = request.get_args("cookie_args","jxwaf_devid") or ""
  local raw_headers = request.get_args("http_args","raw_header") or ""
  if #raw_headers > 8192 then
    waf_log['raw_headers'] = string_sub(raw_headers,1,8192)
  else
    waf_log['raw_headers'] = raw_headers
  end
  waf_log['scheme'] = ngx.var.scheme
  waf_log['version'] = tostring(ngx.req.http_version())
  waf_log['uri'] = ngx.var.uri
  waf_log['method'] = ngx.req.get_method()
  waf_log['query_string'] = ngx.var.query_string or ""
  local raw_body = request.get_args("http_args","raw_body") or ""
  if #raw_body > 8192 then
    waf_log['raw_body'] = string_sub(raw_body,1,8192)
  else
    waf_log['raw_body'] = raw_body
  end
  waf_log['src_ip'] = ngx.ctx.src_ip or ngx.var.remote_addr
  waf_log['raw_src_ip'] = ngx.var.remote_addr
  waf_log['user_agent'] = ngx.var.http_user_agent or ""
  waf_log['cookie'] = ngx.var.http_cookie or ""
  waf_log['iso_code'] = ngx.ctx.iso_code  or ""

  waf_log['waf_module']  = ctx_waf_log['waf_module']
  waf_log['waf_policy']  = ctx_waf_log['waf_policy']
  waf_log['waf_action']  = ctx_waf_log['waf_action']
  waf_log['waf_extra']  = ctx_waf_log['waf_extra'] or ""

  if ngx.var.scheme == "https" then
    local jxwaf_ssl_fingerprint = {}
    jxwaf_ssl_fingerprint['ssl_client_hello_exts'] = ngx.ctx.ssl_client_hello_exts or ""
    jxwaf_ssl_fingerprint['ssl_client_hello_ciphers'] = ngx.ctx.ssl_client_hello_ciphers or ""
    jxwaf_ssl_fingerprint['ssl_client_hello_versions'] = ngx.ctx.ssl_client_hello_versions or ""
    jxwaf_ssl_fingerprint['ssl_client_hello_alpn_protocols'] = ngx.ctx.ssl_client_hello_alpn_protocols or ""
    jxwaf_ssl_fingerprint['ssl_client_hello_signature_algorithms'] = ngx.ctx.ssl_client_hello_signature_algorithms or ""
    jxwaf_ssl_fingerprint['ssl_client_hello_signature_algorithms_has_grease'] = ngx.ctx.ssl_client_hello_signature_algorithms_has_grease or ""
    jxwaf_ssl_fingerprint['ssl_client_hello_supported_groups'] = ngx.ctx.ssl_client_hello_supported_groups or ""
    jxwaf_ssl_fingerprint['ssl_client_hello_supported_groups_has_grease'] = ngx.ctx.ssl_client_hello_supported_groups_has_grease or ""
    jxwaf_ssl_fingerprint['ssl_curve'] = ngx.var.ssl_curve  or ""
    jxwaf_ssl_fingerprint['ssl_curves'] = ngx.var.ssl_curves  or ""
    jxwaf_ssl_fingerprint['ssl_session_id'] = ngx.var.ssl_session_id  or ""
    jxwaf_ssl_fingerprint['ssl_session_reused'] = ngx.var.ssl_session_reused  or ""
    jxwaf_ssl_fingerprint['ssl_cipher'] = ngx.var.ssl_cipher  or ""
    jxwaf_ssl_fingerprint['ssl_ciphers'] = ngx.var.ssl_ciphers  or ""
    jxwaf_ssl_fingerprint['ssl_protocol'] = ngx.var.ssl_protocol  or ""
    local fingerprint_json = cjson.encode(jxwaf_ssl_fingerprint)
    if fingerprint_json then
        local aes_enc = aes:new("jxwaf", nil, aes.cipher(128, "ecb"), aes.hash.sha1)
        local encrypted = aes_enc:encrypt(fingerprint_json)
        waf_log['jxwaf_ssl_fingerprint'] = ngx.encode_base64(encrypted) or ""
    else
        waf_log['jxwaf_ssl_fingerprint'] = ""
    end
else
    waf_log['jxwaf_ssl_fingerprint'] = ""
end

    local logger = logger_socket:new()
    if not logger:initted() then
      local ok,err = logger:init{
        host = config_info['log_ip'],
        port = tonumber(config_info['log_port']),
        sock_type = "tcp",
        flush_limit = 1,
        timeout = 2000,
        max_retry_times = 1
      }
      if not ok then
        ngx.log(ngx.ERR,"failed to initialize the logger: ",err)
        return
      end
    end
    local _, send_err = logger:log(cjson.encode(waf_log).."\n")
    if send_err then
      ngx.log(ngx.ERR, "failed to log message: ", send_err)
    end

end


