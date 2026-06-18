--[[
防护组件：校验 /api/test 接口 GET 请求的 id 参数

检测 /api/test 接口的 GET 请求中 id 参数是否存在且为纯数字（正整数）。
若校验失败，设置 ngx.ctx.api_id_invalid = true，供 Web 规则匹配拦截。
]]

local _M = {}

function _M.check(conf_data)
    local request = require "resty.jxwaf.request"
    local path = request.get_args("http_args", "path")
    local method = request.get_args("http_args", "method")

    -- 仅检测 /api/test 接口的 GET 请求
    if path ~= "/api/test" then return end
    if method ~= "GET" then return end

    local id_value = request.get_args("uri_args", "id")

    -- id 必须存在且为纯数字（正整数）
    if type(id_value) ~= "string" or not id_value:match("^%d+$") then
        ngx.ctx.api_id_invalid = true
    end
end

return _M
