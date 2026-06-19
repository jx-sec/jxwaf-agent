local balancer = require "ngx.balancer"
local waf = require "resty.jxwaf.waf"
local request = require "resty.jxwaf.request"
local balance_host =  ngx.ctx.req_host
local string_sub = string.sub
local table_insert = table.insert
local table_concat = table.concat
local table_remove = table.remove
local point_cache = require "resty.jxwaf.point_cache"
local scheme = ngx.var.scheme
local host = ngx.var.host

if balance_host and balance_host[scheme] == "true" then
    local connect_timeout = balance_host["connect_timeout"]
    local send_timeout = balance_host["send_timeout"]
    local read_timeout = balance_host["read_timeout"]
    if connect_timeout and send_timeout and read_timeout then
        local ok, err = balancer.set_timeouts(tonumber(connect_timeout), tonumber(send_timeout),tonumber(read_timeout))
        if not ok then
            ngx.log(ngx.ERR, "failed to set timeouts: ", err)
            return ngx.exit(503)
        end
    end

    local ip_lists = ngx.ctx.component_source_ip or balance_host["waf_update_source_ip"]
    local source_http_port = ngx.ctx.component_source_http_port or balance_host["source_http_port"]
    local source_https_port = ngx.ctx.component_source_https_port or balance_host["source_https_port"]
    local source_port = tonumber(source_http_port) or 80
    local origin_protocol = balance_host["origin_protocol"]
    if origin_protocol == "https" or (origin_protocol == "follow" and scheme == "https") then
        source_port = tonumber(source_https_port) or 443
    end
	local balance_type =  balance_host["balance_type"]
	local domain = balance_host["domain"]

    if not ip_lists or #ip_lists == 0 then
        ngx.log(ngx.ERR, "ip_lists is empty or nil")
        return ngx.exit(503)
    end

	if #ip_lists == 1 then
	    local ok,err = balancer.set_current_peer(ip_lists[1],source_port)
	    if not ok then
            ngx.log(ngx.ERR,"failed to set the current peer: ",err)
            return ngx.exit(503)
	    end
	    return 
	end


	if balance_type == "round_robin" then
        local cache = point_cache.get_cache()
        local point = cache:get(domain)
        if not point or point < 1 or point > #ip_lists then
            point = 1
        end

        local _host, _port
        local state_name = balancer.get_last_failure()
        
        if state_name == "failed" or state_name == "next" then
            _host = ip_lists[point]
            _port = source_port
        else
            _host = ip_lists[point]
            _port = source_port
            local next_point = (point % #ip_lists) + 1
            cache:set(domain, next_point)
            balancer.set_more_tries(1)
        end

        local ok, err = balancer.set_current_peer(_host, _port)
        if not ok then
            ngx.log(ngx.ERR, "failed to set the current peer: ", err)
            return ngx.exit(503)
        end
    else
            local ip = ngx.ctx.src_ip or ngx.var.remote_addr
            if not ip or ip == "" then
                ngx.log(ngx.ERR, "invalid ip address")
                return ngx.exit(503)
            end
            
            local hash = ngx.crc32_short(ip)
            local ip_count = (hash % #ip_lists) + 1

            local _host = ip_lists[ip_count]
            local _port = source_port
            local state_name = balancer.get_last_failure()
            
            if state_name == "failed" or state_name == "next" then
                local next_idx = (ip_count % #ip_lists) + 1
                _host = ip_lists[next_idx]
                _port = source_port
            else
                local ok, err = balancer.set_more_tries(1)
                if not ok then
                    ngx.log(ngx.ERR, "failed to set more tries: ", err)
                end
            end
            
            local ok, err = balancer.set_current_peer(_host, _port)
            if not ok then
                ngx.log(ngx.ERR, "failed to set the current peer: ", err)
                return ngx.exit(503)
            end
	end
else
	return ngx.exit(503)
end 