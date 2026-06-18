--[[
防护组件示例：CDN 源 IP 提取

功能：从 cdn-src-ip 请求头中提取真实客户端 IP，设置到 ngx.ctx.src_ip，
      供后续 Web/流量规则通过 ctx_args:src_ip 引用。

这是一个典型的"组件 + 规则联合判断"示例：
  组件设置 ngx.ctx.src_ip → 规则匹配 ctx_args:src_ip

conf 字段示例（JSON）：
  {}  -- 此组件不需要配置参数

对应的规则匹配条件：
  {"match_args": [{"key": "ctx_args", "value": "src_ip"}], ...}
--]]

local _M = {}

-- IP 地址格式验证
local function is_valid_ip(ip)
    if not ip or type(ip) ~= "string" then
        return false
    end

    -- IPv4 验证
    local ipv4_match = ngx.re.match(ip, "^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$", "jo")
    if ipv4_match then
        for i = 1, 4 do
            local num = tonumber(ipv4_match[i])
            if not num or num < 0 or num > 255 then
                return false
            end
        end
        return true
    end

    -- IPv6 验证
    if ngx.re.match(ip, "^[a-fA-F0-9:]+$", "jo") or
       ngx.re.match(ip, "^[a-fA-F0-9:]+\\.\\d+\\.\\d+\\.\\d+\\.\\d+$", "jo") then
        return true
    end

    return false
end

function _M.check(conf_data)
    if conf_data == nil then
        return
    end

    -- 读取 cdn-src-ip 请求头
    local cdn_ip = ngx.req.get_headers()['cdn-src-ip']

    if cdn_ip and type(cdn_ip) == "string" then
        -- header 值为字符串
        if is_valid_ip(cdn_ip) then
            ngx.ctx.src_ip = cdn_ip
        end
    elseif cdn_ip and type(cdn_ip) == "table" then
        -- header 可能返回 table（多个同名 header 时）
        if is_valid_ip(cdn_ip[1]) then
            ngx.ctx.src_ip = cdn_ip[1]
        end
    end

    return
end

return _M
