local waf = require "resty.jxwaf.waf"
local host = ngx.var.http_host or ngx.var.host
local string_find = string.find
local string_sub = string.sub
local waf_domain_data = waf.get_waf_domain_data()
local scheme = ngx.var.scheme
local origin_protocol 

if waf_domain_data[host] then
    origin_protocol = waf_domain_data[host]['origin_protocol']
else
    local wildcard_host = nil 
    local dot_pos = string_find(host,".",1,true)
    if dot_pos then
      wildcard_host = "*"..string_sub(host,dot_pos)
    end
    if wildcard_host and waf_domain_data[wildcard_host] then
      origin_protocol = waf_domain_data[wildcard_host]['origin_protocol']
    end
end

if origin_protocol == "https" or (origin_protocol == "follow" and scheme == "https") then
  ngx.var.proxy_pass_https_flag = "true"
end