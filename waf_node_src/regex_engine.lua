--[[
JxWAF 规则匹配引擎

本文件整合自节点源码 operator.lua（匹配运算符）与 preprocess.lua（参数预处理），
供 AI 深度排查时理解匹配逻辑。实际运行环境为 OpenResty + ngx.lua。

两部分：
  1. preprocess  参数预处理（解码/大小写/长度计算）
  2. operator    匹配运算符（字符串/数字/正则/IP/存在性判断）

调用链：
  request.get_args(key, value)  →  取原始参数值
  preprocess.process_args(k, v) →  按顺序解码/处理
  operator.match(op, arg, pattern) → 匹配判断
--]]

local _M = {}

--============================================================================
-- 第一部分：参数预处理（preprocess）
-- 对应节点源码 resty.jxwaf.preprocess
--============================================================================

local ngx_decode_base64 = ngx.decode_base64
local ngx_unescape_uri = ngx.unescape_uri
local string_lower = string.lower
local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local table_insert = table.insert
local table_concat = table.concat
local bit = require("bit")
local bit_band = bit.band
local bit_bor = bit.bor
local bit_rshift = bit.rshift

-- BASE64 解码（失败返回原值）
local function base64_decode(value)
  if not value then return value end
  local val = ngx_decode_base64(tostring(value))
  return val or value
end

-- 长度计算（返回字符串形式的长度）
local function length(value)
  if not value then return value end
  return tostring(#tostring(value))
end

-- 小写转换
local function lowercase(value)
  if not value then return value end
  return string_lower(tostring(value))
end

-- URL 解码
local function uri_decode(value)
  if not value then return value end
  return ngx_unescape_uri(tostring(value))
end

-- Unicode 解码（\u00XX 形式，仅处理 0-255 范围）
local function uni_decode(value)
  if not value or type(value) ~= "string" then return value end
  if not value:find("\\u00%x%x") then return value end
  return value:gsub("\\u00(%x%x)", function(hex)
    return string_char(tonumber(hex, 16))
  end)
end

-- 十六进制解码（\xNN 形式，转 UTF-8）
local function hex_decode(value)
  if type(value) ~= "string" then return value end
  if not value:find("\\x", 1, true) then return value end

  local result = {}
  local i = 1
  while i <= #value do
    local num = string_byte(value, i)
    local unicode
    if num and value:sub(i, i + 1) == "\\x" then
      unicode = tonumber(value:sub(i + 2, i + 3), 16)
      if unicode then
        i = i + 4
      else
        unicode = num
        i = i + 1
      end
    else
      unicode = num
      i = i + 1
    end
    -- UTF-8 编码
    if unicode <= 0x7f then
      table_insert(result, string_char(unicode))
    elseif unicode <= 0x7ff then
      table_insert(result, string_char(bit_bor(0xc0, bit_band(bit_rshift(unicode, 6), 0x1f))))
      table_insert(result, string_char(bit_bor(0x80, bit_band(unicode, 0x3f))))
    elseif unicode <= 0xffff then
      table_insert(result, string_char(bit_bor(0xe0, bit_band(bit_rshift(unicode, 12), 0x0f))))
      table_insert(result, string_char(bit_bor(0x80, bit_band(bit_rshift(unicode, 6), 0x3f))))
      table_insert(result, string_char(bit_bor(0x80, bit_band(unicode, 0x3f))))
    end
  end
  return table_concat(result)
end

--[[
  参数预处理入口
  k: 处理方式标识
  v: 待处理的参数值
  返回处理后的值
]]
function _M.process_args(k, v)
  if k == "none" then
    return v
  elseif k == "base64Decode" then
    return base64_decode(v)
  elseif k == "length" then
    return length(v)
  elseif k == "lowerCase" then
    return lowercase(v)
  elseif k == "uriDecode" then
    return uri_decode(v)
  elseif k == "hexDecode" then
    return hex_decode(v)
  elseif k == "uniDecode" then
    return uni_decode(v)
  elseif k == "type" then
    -- 返回值类型（number/string/boolean 等）
    if tonumber(v) then return "number" end
    return type(v)
  end
  return nil
end

--============================================================================
-- 第二部分：匹配运算符（operator）
-- 对应节点源码 resty.jxwaf.operator
--============================================================================

local string_find = string.find
local ngx_re_match = ngx.re.match
local iputils = require "resty.jxwaf.iputils"
local ngx_re_split = (require "ngx.re").split

-- 字符串包含（plain 模式，非 Lua pattern）
local function str_contain(input, pattern)
  if not input or not pattern then return false end
  return string_find(input, pattern, 1, true) ~= nil
end

-- 字符串不包含
local function str_ncontain(input, pattern)
  if not input or not pattern then return true end
  return string_find(input, pattern, 1, true) == nil
end

-- 字符串相等
local function str_eq(input, pattern)
  return tostring(input) == tostring(pattern)
end

-- 字符串不等
local function str_neq(input, pattern)
  return tostring(input) ~= tostring(pattern)
end

-- 前缀匹配
local function str_prefix(input, pattern)
  if not input or not pattern then return false end
  local from = string_find(input, pattern, 1, true)
  return from == 1
end

-- 后缀匹配
local function str_suffix(input, pattern)
  if not input or not pattern then return false end
  local from = string_find(input, pattern, -#pattern, true)
  return from ~= nil
end

-- 数字大于（双方需 tonumber 成功）
local function greater(input, pattern)
  local a, b = tonumber(input), tonumber(pattern)
  if a and b then return a > b end
  return false
end

-- 数字小于
local function less(input, pattern)
  local a, b = tonumber(input), tonumber(pattern)
  if a and b then return a < b end
  return false
end

-- 数字等于
local function equals(input, pattern)
  local a, b = tonumber(input), tonumber(pattern)
  if a and b then return a == b end
  return false
end

-- 数字不等于
local function nequals(input, pattern)
  local a, b = tonumber(input), tonumber(pattern)
  if a and b then return a ~= b end
  return false
end

-- 正则匹配（ngx.re.match，选项 oij：缓存+忽略大小写+JIT）
local function regex(input, pattern)
  if not input or not pattern then return false end
  local captures, err = ngx_re_match(input, pattern, "oij")
  if err then
    ngx.log(ngx.ERR, "regex error: ", err)
    return false
  end
  return captures ~= nil
end

-- 参数存在判断
-- rule_pattern: "exist"（存在时命中）/ "no_exist"（不存在时命中）
local function status_check(var, rule_pattern)
  if var == nil then
    return rule_pattern == "no_exist"
  else
    return rule_pattern == "exist"
  end
end

-- IP 在单个 CIDR 内
local function ip_in_cidr(input, pattern)
  if not input or not pattern then return false end
  local whitelist = iputils.parse_cidrs({ pattern })
  if whitelist then
    return iputils.ip_in_cidrs(input, whitelist)
  end
  return false
end

-- IP 在多个 CIDR 内（逗号分隔）
local function ip_in_cidrs(input, pattern)
  if not input or not pattern then return false end
  local res = ngx_re_split(pattern, ",")
  if res then
    local whitelist = iputils.parse_cidrs(res)
    if whitelist then
      return iputils.ip_in_cidrs(input, whitelist)
    end
  end
  return false
end

--[[
  匹配运算入口
  k:        运算符标识
  var:      待匹配的参数值（已预处理）
  pattern:  匹配值
  返回: true(命中) / false(未命中) / nil(未知运算符)
]]
function _M.match(k, var, pattern)
  if k == "rx" then
    return regex(var, pattern)
  elseif k == "status_check" then
    return status_check(var, pattern)
  elseif k == "str_contain" then
    return str_contain(var, pattern)
  elseif k == "str_prefix" then
    return str_prefix(var, pattern)
  elseif k == "str_suffix" then
    return str_suffix(var, pattern)
  elseif k == "str_eq" then
    return str_eq(var, pattern)
  elseif k == "str_neq" then
    return str_neq(var, pattern)
  elseif k == "str_ncontain" then
    return str_ncontain(var, pattern)
  elseif k == "lt" then
    return less(var, pattern)
  elseif k == "gt" then
    return greater(var, pattern)
  elseif k == "neq" then
    return nequals(var, pattern)
  elseif k == "eq" then
    return equals(var, pattern)
  elseif k == "ip_in_cidr" then
    return ip_in_cidr(var, pattern)
  elseif k == "ip_in_cidrs" then
    return ip_in_cidrs(var, pattern)
  end
  return nil
end

return _M
