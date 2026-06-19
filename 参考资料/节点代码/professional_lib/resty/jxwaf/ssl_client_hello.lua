local ssl_clt = require "ngx.ssl.clienthello"
local ssl = require "ngx.ssl"
local md5 = ngx.md5
local byte = string.byte
local sub = string.sub
local format = string.format
local waf = require "resty.jxwaf.waf"
local config_info = waf.get_config_info()

-- 扩展类型常量
local EXT_ALPN = 16
local EXT_SIGNATURE_ALGORITHMS = 13
local EXT_SUPPORTED_GROUPS = 10
local EXT_SESSION_TICKET = 35
local EXT_PRE_SHARED_KEY = 41

----------------------------------------------------------------
-- 解析 ALPN 协议列表
----------------------------------------------------------------
local function parse_alpn(ext_data)
    if not ext_data or #ext_data < 2 then return nil end
    local protocols = {}
    local offset = 3
    while offset <= #ext_data do
    local proto_len = byte(ext_data, offset)
    if offset + proto_len > #ext_data then break end
        local proto = sub(ext_data, offset + 1, offset + proto_len)
        table.insert(protocols, proto)
        offset = offset + 1 + proto_len
    end
    return protocols
end

----------------------------------------------------------------
-- 解析 signature_algorithms
----------------------------------------------------------------
local function parse_signature_algorithms(ext_data)
    if not ext_data or #ext_data < 2 then return nil end
    local algorithms = {}
    local offset = 3
    while offset + 1 <= #ext_data do
        local hash_alg = byte(ext_data, offset)
        local sig_alg = byte(ext_data, offset + 1)
        table.insert(algorithms, {hash = hash_alg, signature = sig_alg})
        offset = offset + 2
    end
    return algorithms
end

----------------------------------------------------------------
-- 解析 supported_groups
----------------------------------------------------------------
local function parse_supported_groups(ext_data)
    if not ext_data or #ext_data < 2 then return nil end
    local groups = {}
    local offset = 3
    while offset + 1 <= #ext_data do
        local group_id = byte(ext_data, offset) * 256 + byte(ext_data, offset + 1)
        table.insert(groups, group_id)
        offset = offset + 2
    end
    return groups
end


----------------------------------------------------------------
-- GREASE 值判断
-- GREASE 值特征: 高字节 == 低字节, 且 (低字节 & 0x0F) == 0x0A
----------------------------------------------------------------
local function is_grease(value)
    local low = value % 256
    local high = (value - low) / 256
    return low == high and (low % 16) == 10
end

----------------------------------------------------------------
-- 检测 supported_groups 是否包含 GREASE
----------------------------------------------------------------
local function has_grease_in_groups(ext_data)
    if not ext_data or #ext_data < 3 then return false end
    
    local offset = 3  -- 跳过 2 字节列表长度
    while offset + 1 <= #ext_data do
        local group_id = byte(ext_data, offset) * 256 + byte(ext_data, offset + 1)
        if is_grease(group_id) then
            return true
        end
        offset = offset + 2
    end
    return false
end

----------------------------------------------------------------
-- 检测 signature_algorithms 是否包含 GREASE
----------------------------------------------------------------
local function has_grease_in_signature_algorithms(ext_data)
    if not ext_data or #ext_data < 3 then return false end
    
    local offset = 3  -- 跳过 2 字节列表长度
    while offset + 1 <= #ext_data do
        local sig_alg_id = byte(ext_data, offset) * 256 + byte(ext_data, offset + 1)
        if is_grease(sig_alg_id) then
            return true
        end
        offset = offset + 2
    end
    return false
end

----------------------------------------------------------------
-- 解析 TLS 1.3 pre_shared_key 扩展中的第一个 ticket
-- 格式:
--   2 bytes: identities 列表长度
--   对每个 identity:
--     2 bytes: identity 长度
--     N bytes: identity 数据 (即 ticket)
--     4 bytes: obfuscated_ticket_age
--   2 bytes: binders 列表长度
--   ...
----------------------------------------------------------------
local function parse_psk_first_identity(ext_data)
    if not ext_data or #ext_data < 4 then return nil end
    -- 读取 identities 列表长度
    local identities_len = byte(ext_data, 1) * 256 + byte(ext_data, 2)
    if identities_len == 0 then return nil end
    -- 读取第一个 identity 的长度
    local offset = 3
    local identity_len = byte(ext_data, offset) * 256 + byte(ext_data, offset + 1)
    offset = offset + 2
    -- identity 长度为 0 或数据不完整
    if identity_len == 0 then return nil end
    if offset + identity_len - 1 > #ext_data then return nil end
    local ticket = sub(ext_data, offset, offset + identity_len - 1)
    return ticket
end


----------------------------------------------------------------
-- 主逻辑
----------------------------------------------------------------
        
local server_name,server_name_err = ssl_clt.get_client_hello_server_name()
if not server_name then
    ngx.log(ngx.ERR, "get_client_hello_server_name error: ", server_name_err)
    return ngx.exit(444)
end




if config_info['ssl_attack_protect'] == "true" then
    local ssl_attack_stat_time = config_info['ssl_attack_stat_time']
    local ssl_attack_stat_count = config_info['ssl_attack_stat_count']
    local ssl_attack_block_time = config_info['ssl_attack_block_time']

    -- 确保配置参数完整
    if ssl_attack_stat_time and ssl_attack_stat_count and ssl_attack_block_time then
        local addr, addrtyp, err = ssl.raw_client_addr()
        if not addr then
            ngx.log(ngx.ERR, "failed to fetch raw client addr: ", err)
            return ngx.exit(444)
        end

        local addr_md5 = ngx.md5(addr)
        
        local ssl_attack_stat = ngx.shared.ssl_attack_stat
        local ssl_black_ip = ngx.shared.ssl_black_ip
        
        -- 1. 优先检查黑名单 (快速路径)
        local black_result = ssl_black_ip:get(addr_md5)
        if black_result then
            return ngx.exit(444)
        end

        -- 2. 计数与限流
        -- incr(key, value, init, init_ttl)
        -- 返回值: new_val, err
        local stat_result, err = ssl_attack_stat:incr(addr_md5, 1, 0, ssl_attack_stat_time)
        
        if not stat_result then
            ngx.log(ngx.ERR, "failed to incr ssl attack stat: ", err)
        else
            -- 3. 阈值判断
            if stat_result > ssl_attack_stat_count then
                -- 将 IP 加入黑名单
                -- 注意：这里存在极小概率的竞态条件(多个请求同时超过阈值)，但通常可接受
                local success, set_err, forcible = ssl_black_ip:set(addr_md5, true, ssl_attack_block_time)
                if not success then
                    ngx.log(ngx.ERR, "failed to set ssl black ip: ", set_err)
                else
                    ngx.log(ngx.ERR, "ssl black ip : ", addr)
                end
            end
        end
    end
end


-- 1. 扩展类型列表
local exts = ssl_clt.get_client_hello_ext_present()
if exts then
    --ngx.log(ngx.ERR, "extensions_present: ", table.concat(exts, ", "))
    ngx.ctx.ssl_client_hello_exts = table.concat(exts, ",")
end

-- 2. 加密套件
local ciphers = ssl_clt.get_client_hello_ciphers()
if ciphers then
    --ngx.log(ngx.ERR, "ciphers: ", table.concat(ciphers, ", "))
    ngx.ctx.ssl_client_hello_ciphers = table.concat(ciphers, ",")
end

-- 3. 支持的版本
local versions = ssl_clt.get_supported_versions()
if versions then
    --ngx.log(ngx.ERR, "supported_versions: ", table.concat(versions, ", "))
    ngx.ctx.ssl_client_hello_versions = table.concat(versions, ",")
end

-- 4. ALPN
local alpn_ext = ssl_clt.get_client_hello_ext(EXT_ALPN)
if alpn_ext then
    ngx.ctx.ssl_client_hello_alpn_protocols = md5(alpn_ext)
    --local protocols = parse_alpn(alpn_ext)
    --if protocols then
    --    ngx.log(ngx.ERR, "ALPN: ", table.concat(protocols, ", "))
    --    ngx.ctx.ssl_client_hello_alpn_protocols = protocols
    --end
    
end

-- 5. Signature Algorithms
local sig_ext = ssl_clt.get_client_hello_ext(EXT_SIGNATURE_ALGORITHMS)
if sig_ext then
    ngx.ctx.ssl_client_hello_signature_algorithms = md5(sig_ext)
    ngx.ctx.ssl_client_hello_signature_algorithms_has_grease = has_grease_in_signature_algorithms(sig_ext)
    --local algorithms = parse_signature_algorithms(sig_ext)
    --if algorithms then
    --    local t = {}
    --    for _, alg in ipairs(algorithms) do
    --        table.insert(t, format("%d,%d", alg.hash, alg.signature))
    --    end

    --    ngx.log(ngx.ERR, "signature_algorithms: ", table.concat(t, ","))
    --    ngx.ctx.ssl_client_hello_signature_algorithms = table.concat(t, ",")
    --end
end

-- 6. Supported Groups
local groups_ext = ssl_clt.get_client_hello_ext(EXT_SUPPORTED_GROUPS)
if groups_ext then
    ngx.ctx.ssl_client_hello_supported_groups = md5(groups_ext)
    ngx.ctx.ssl_client_hello_supported_groups_has_grease = has_grease_in_groups(groups_ext)
    --local groups = parse_supported_groups(groups_ext)
    --if groups then
    --    ngx.log(ngx.ERR, "supported_groups: ", table.concat(groups, ","))
    --    ngx.ctx.ssl_client_hello_supported_groups = table.concat(groups, ",")
    --end
end

--[=[
-- 7. Session Ticket (兼容 TLS 1.2 和 TLS 1.3)
local ticket_hash = ""
-- 优先检查 TLS 1.3 的 pre_shared_key 扩展
local psk_ext = ssl_clt.get_client_hello_ext(EXT_PRE_SHARED_KEY)
if psk_ext and #psk_ext > 0 then
-- TLS 1.3: ticket 数据在 pre_shared_key 扩展中
local ticket = parse_psk_first_identity(psk_ext)
if ticket and #ticket > 0 then
ticket_hash = md5(ticket)
end
else
-- TLS 1.2: session_ticket 扩展包含 ticket 数据
local ticket_ext = ssl_clt.get_client_hello_ext(EXT_SESSION_TICKET)
if ticket_ext and #ticket_ext > 0 then
ticket_hash = md5(ticket_ext)
end
end
ngx.ctx.ssl_session_ticket_hash = ticket_hash
--]=]
