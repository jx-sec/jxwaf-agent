local string_find = string.find
local iputils = require 'resty.jxwaf.iputils'
local ngx_re = require "ngx.re"
local _M = {}
_M.version = "jxwaf_base_v4"

local function _equals(input,pattern)
	local result, output
  local a = tonumber(input)
  local b = tonumber(pattern)
  if a and b then
    result = a == b
  end
	if (result) then
		output = input
	end
	return result, output
end

local function _nequals(input,pattern)
  local result, output
  local a = tonumber(input)
  local b = tonumber(pattern)
  if a and b then
    result = a ~= b
  end
  if (result) then
    output = input
  end
  return result, output
end


local function _greater(input,pattern)
	local result, output
  local a = tonumber(input)
  local b = tonumber(pattern)
  if a and b then
    result = a > b
  end
	if (result) then
		output = input
	end
	return result, output
end


local function _less(input,pattern)
	local result, output
  local a = tonumber(input)
  local b = tonumber(pattern)
  if a and b then
    result = a < b
  end
	if (result) then
		output = input
	end
	return result, output
end

local function _regex( input, pattern)
	local opts = 'oij'
	local captures, err, result,output
	captures, err = ngx.re.match(input, pattern, opts)
	if err then
		ngx.log(ngx.ERR,"regex error",captures,err)
		ngx.exit(500)
	end
	if captures then
		result = true		
    output = input
		return result, output 
	end
	return result, output
end

local function _str_eq(input,pattern)
  local result,output
  if tostring(input) == tostring(pattern)  then
    result = true
		output = input
  end
  return result,output
end

local function _str_neq(input,pattern)
  local result,output
  if tostring(input) ~= tostring(pattern)  then
    result = true
    output = input
  end
  return result,output
end

local function _str_contain(input,pattern)
  local result,output
  local from,to,err = string_find(input,pattern,1,true)
  if from then
    result = true
    output = input
  end
  return result,output
end

local function _str_ncontain(input,pattern)
  local result,output
  local from,to,err = string_find(input,pattern,1,true)
  if from then
    result = false
  else
    result = true
    output = input
  end
  return result,output
end

local function _str_prefix(input,pattern)
  local result,output
  local from,to = string_find(input,pattern,1,true)
  if from == 1 then
    result = true
    output = input
  end
  return result,output
end

local function _str_suffix(input,pattern)
  local result,output
  local from,to = string_find(input,pattern,-#pattern,true)
  if from then
    result = true
    output = input
  end
  return result,output
end

local function _table_contain(input,pattern)
  local result,output
  if tostring(input) == tostring(pattern)  then
    result = true
    output = input
  end
  return result,output
end

local function _ip_in_cidr(input,pattern)
  local result
  local whitelist = iputils.parse_cidrs(pattern)
  if whitelist then
    result = iputils.ip_in_cidrs(input, whitelist) 
  end
  return result
end

local function _ip_in_cidrs(input,pattern)
  local result
  local res = ngx_re.split(pattern, ",")
  if res then
    local whitelist = iputils.parse_cidrs(res)
    if  whitelist then
      result = iputils.ip_in_cidrs(input, whitelist) 
    end
  end
  return result
end

local function _status_check(var, rule_pattern)
    local var_type = type(var)

    if var == nil then
        return rule_pattern == "no_exist"
    else
        return rule_pattern == "exist"
    end

    return nil
end

function _M.match(k,var,rule_pattern)
  if k == "rx" then
    return _regex(var,rule_pattern)
  elseif k == "status_check" then
    return _status_check(var,rule_pattern)
  elseif k == "str_contain" then
    return _str_contain(var,rule_pattern)
  elseif k == "str_prefix" then
    return _str_prefix(var,rule_pattern)
  elseif k == "str_suffix" then
    return _str_suffix(var,rule_pattern)
  elseif k == "str_eq" then
    return _str_eq(var,rule_pattern)
  elseif k == "str_neq" then
    return _str_neq(var,rule_pattern)
  elseif k == "str_ncontain" then
    return _str_ncontain(var,rule_pattern)
  elseif k == "lt" then
    return _less(var,rule_pattern)
  elseif k == "gt" then
    return _greater(var,rule_pattern)
  elseif k == "neq" then
    return _nequals(var,rule_pattern)
  elseif k == "eq" then
    return _equals(var,rule_pattern)
  elseif k == "ip_in_cidr" then
    return _ip_in_cidr(var,rule_pattern)
  elseif k == "ip_in_cidrs" then
    return _ip_in_cidrs(var,rule_pattern)
  else
    return nil 
  end
end

return _M