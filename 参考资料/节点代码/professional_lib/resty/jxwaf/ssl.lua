local ssl = require "ngx.ssl"
local byte = string.byte
local waf = require "resty.jxwaf.waf"
local string_find = string.find
local string_sub = string.sub
local string_format = string.format
local table_concat = table.concat
local ssl_host = nil
local config_info = waf.get_config_info()
local host = ssl.server_name()
local server_port = ssl.server_port()

if not host then
  return ngx.exit(444)
end



local waf_domain_data = waf.get_waf_domain_data()
local waf_ssl_manage_data = waf.get_waf_ssl_manage_data()

local wildcard_host = nil



if waf_domain_data[host] then
  ssl_host = waf_domain_data[host]
else
  local dot_pos = string_find(host,".",1,true)
  if dot_pos then
    wildcard_host = "*"..string_sub(host,dot_pos) 
  end
  if wildcard_host and waf_domain_data[wildcard_host] then
    ssl_host = waf_domain_data[wildcard_host]
  end
end

  

if server_port ~= 443 then
  local custom_host = host..":"..tostring(server_port)
  if waf_domain_data[custom_host] then
    ssl_host = waf_domain_data[custom_host]
  else
      local dot_pos = string_find(host,".",1,true)
      if dot_pos then
          wildcard_host = "*"..string_sub(host,dot_pos)
      end
      if wildcard_host then
        local custom_wildcard_host = wildcard_host..":"..tostring(server_port)
        if waf_domain_data[custom_wildcard_host] then
          ssl_host = waf_domain_data[custom_wildcard_host]
        end
      end
  end
end


if ssl_host and ssl_host["https"] == 'true' then
    local clear_ok, clear_err = ssl.clear_certs()
    if not clear_ok then
        ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates: ", clear_err)
        return ngx.exit(444)
    end
    
    local ssl_domain = ssl_host["ssl_domain"]
    local ssl_manage_data = waf_ssl_manage_data[ssl_domain]
    
    if not ssl_manage_data then
        ngx.log(ngx.ERR, "waf_ssl_manage_data configure error")
        return ngx.exit(444)
    end

    -- 【修改点】优先获取 DER 数据
    local der_cert_chain = ssl_manage_data["der_public_key"]
    local der_pkey = ssl_manage_data["der_private_key"]

    -- 降级逻辑：如果 init_worker 没转换成功或旧数据格式，尝试实时转换
    if not der_cert_chain and ssl_manage_data["public_key"] then
        der_cert_chain = ssl.cert_pem_to_der(ssl_manage_data["public_key"])
    end
    
    if not der_pkey and ssl_manage_data["private_key"] then
        der_pkey = ssl.priv_key_pem_to_der(ssl_manage_data["private_key"])
    end

    if not der_cert_chain or not der_pkey then
        ngx.log(ngx.ERR, "failed to get or convert certificates for: ", host)
        return ngx.exit(444)
    end

    -- 设置证书
    local set_ok, set_err = ssl.set_der_cert(der_cert_chain)
    if not set_ok then
        ngx.log(ngx.ERR, "failed to set DER cert: ", set_err)
        return ngx.exit(444)
    end

    local set_key_ok, set_key_err = ssl.set_der_priv_key(der_pkey)
    if not set_key_ok then
        ngx.log(ngx.ERR, "failed to set DER private key: ", set_key_err)
        return ngx.exit(444)
    end
else
    return ngx.exit(444)
end

