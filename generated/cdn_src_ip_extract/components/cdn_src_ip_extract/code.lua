--[[
防护组件：CDN 源 IP 提取（带白名单校验）

仅当 src_ip 命中白名单 CDN 网段时，才从 cdn-src-ip 头提取真实客户端 IP 覆盖 ngx.ctx.src_ip。
防止攻击者伪造 cdn-src-ip 头绕过 IP 防护策略。

conf 示例：{"cdn_whitelist_cidrs": ["8.134.210.0/24", "61.174.128.69"]}
纯 IP 自动视为 /32。
--]]

local bit = require "bit"
local _M = {}

local function ip_to_uint(ip)
    local o1, o2, o3, o4 = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not o1 then return nil end
    o1, o2, o3, o4 = tonumber(o1), tonumber(o2), tonumber(o3), tonumber(o4)
    if not o1 or o1 > 255 or o2 > 255 or o3 > 255 or o4 > 255 then return nil end
    return bit.bor(bit.lshift(o1, 24), bit.lshift(o2, 16), bit.lshift(o3, 8), o4)
end

local function ip_in_cidr(ip, cidr)
    local ip_uint = ip_to_uint(ip)
    if not ip_uint then return false end

    local ip_str, prefix = cidr:match("^([%d%.]+)/(%d+)$")
    if ip_str then
        prefix = tonumber(prefix)
    else
        ip_str, prefix = cidr, 32
    end
    local net_uint = ip_to_uint(ip_str)
    if not net_uint or prefix > 32 then return false end

    -- prefix=0 时 mask=0（bit.lshift 移位量掩码到 5 位，32 会被当作 0）
    local mask = prefix == 0 and 0 or bit.lshift(0xFFFFFFFF, 32 - prefix)
    return bit.band(ip_uint, mask) == bit.band(net_uint, mask)
end

function _M.check(conf_data)
    if conf_data == nil then return end

    local cidrs = conf_data['cdn_whitelist_cidrs']
    if not cidrs or type(cidrs) ~= "table" or #cidrs == 0 then return end

    local request = require "resty.jxwaf.request"
    local src_ip = request.get_args("http_args", "src_ip")
    if not src_ip or type(src_ip) ~= "string" then return end

    local trusted = false
    for _, cidr in ipairs(cidrs) do
        if ip_in_cidr(src_ip, cidr) then
            trusted = true
            break
        end
    end
    if not trusted then return end

    local cdn_ip = ngx.req.get_headers()['cdn-src-ip']
    if type(cdn_ip) == "table" then cdn_ip = cdn_ip[1] end
    if cdn_ip and ip_to_uint(cdn_ip) then
        ngx.ctx.src_ip = cdn_ip
    end
end

return _M
