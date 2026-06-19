--[[
    JxWAF 安全初始化脚本 (综合加强版 v2)
    
    关键改进：调用栈检测在 resty.core 加载之前执行
]]

-- ============================================================
-- 第一阶段：信任基点建立 (仅 debug 库，不加载 resty.core)
-- ============================================================

local local_debug          = debug
local local_getinfo        = local_debug.getinfo
local local_gethook        = local_debug.gethook

-- 验证检测工具本身未被篡改
local function check_is_c_function(func, func_name)
    if type(func) ~= "function" then
        error("SECURITY HALT: " .. func_name .. " is not a function", 0)
    end
    local info = local_getinfo(func, "S")
    if not info or info.what ~= "C" then
        error("SECURITY HALT: Detection tool [" .. func_name .. "] has been corrupted!", 0)
    end
end

check_is_c_function(local_getinfo, "debug.getinfo")
check_is_c_function(local_gethook, "debug.gethook")


-- ============================================================
-- 第二阶段：调用栈完整性校验 (在 resty.core 加载前)
-- ============================================================

--[[
调用栈结构分析：

Nginx init_by_lua_file 直接执行:
  Level 0: init.lua (当前脚本)
  Level 1: [C] 或 不存在  ← getinfo(2) 可能返回 nil，这是正常的

攻击场景A (loadfile):
  Level 1: attacker.lua (Lua) ← 拦截

攻击场景B (dofile/require):
  Level 1: [C] dofile/require
  Level 2: attacker.lua (Lua) ← 拦截
]]

local caller_level_1 = local_getinfo(2, "S")
if caller_level_1 and caller_level_1.what ~= "C" then
    error("SECURITY HALT: Init script loaded by unexpected Lua caller! " ..
          "Source: " .. (caller_level_1.source or "unknown"), 0)
end

local caller_level_2 = local_getinfo(3, "S")
if caller_level_2 and caller_level_2.what ~= "C" then
    error("SECURITY HALT: Init script loaded by wrapper script! " ..
          "Source: " .. (caller_level_2.source or "unknown"), 0)
end


-- ============================================================
-- 第三阶段：加载 resty.core (调用栈检测完成后)
-- ============================================================

require "resty.core"


-- ============================================================
-- 第四阶段：缓存其他关键全局函数
-- ============================================================

local local_require        = require
local local_load           = load
local local_loadfile       = loadfile
local local_dofile         = dofile
local local_loadstring     = loadstring
local local_io_open        = io.open
local local_pairs          = pairs
local local_package_loaded = package.loaded


-- ============================================================
-- 第五阶段：全局环境完整性校验
-- ============================================================

local critical_functions = {
    { name = "load",       func = local_load },
    { name = "loadfile",   func = local_loadfile },
    { name = "dofile",     func = local_dofile },
    { name = "loadstring", func = local_loadstring },
    { name = "io.open",    func = local_io_open },
}

for _, item in local_pairs(critical_functions) do
    local info = local_getinfo(item.func, "S")
    if not info or info.what ~= "C" then
        error("SECURITY HALT: Global function [" .. item.name .. "] has been hooked!", 0)
    end
end


-- ============================================================
-- 第六阶段：反调试检测
-- ============================================================

local hook_func = local_gethook()
if hook_func then
    error("SECURITY HALT: Active debug hook detected!", 0)
end

local known_debuggers = {
    "resty.debug",
    "debugger",
    "mobdebug",
    "remdebug",
    "luadebug",
}

for _, mod_name in local_pairs(known_debuggers) do
    if local_package_loaded[mod_name] then
        error("SECURITY HALT: Debugger module [" .. mod_name .. "] detected!", 0)
    end
end


-- ============================================================
-- 第七阶段：业务初始化
-- ============================================================

local waf = local_require "resty.jxwaf.waf"
local config_path = "/opt/jxwaf/nginx/conf/jxwaf/jxwaf_config.json"
local jxcore_path = "/opt/jxwaf/nginx/conf/jxwaf/jxcore"
waf.init(config_path, jxcore_path)

-- ============================================================
-- 第八阶段：环境清理 (精细化处理)
-- ============================================================

if _G.debug then
    -- 删除危险函数
    _G.debug.sethook      = nil
    _G.debug.setlocal     = nil
    _G.debug.setupvalue   = nil
    _G.debug.setmetatable = nil
    _G.debug.setfenv      = nil
    _G.debug.getregistry  = nil
    _G.debug.setmetatable = nil 
end