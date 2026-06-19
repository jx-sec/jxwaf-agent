--[[
JXWAF 节点规则检测核心逻辑（access 阶段）

本文件整理自节点源码 waf.lua 中的 Web 防护规则与流量防护规则检测函数，
供 AI 深度排查时参考。实际运行环境为 OpenResty + ngx.lua。

依赖模块：
  - resty.jxwaf.request    请求参数获取
  - resty.jxwaf.preprocess 参数预处理（解码/大小写/长度等）
  - resty.jxwaf.operator   匹配运算符
  - resty.jxwaf.unify_action 统一动作执行
  - cjson.safe             JSON 解析
  - ngx.shared.jxwaf_inner 共享内存（流量统计与处罚缓存）

关键上下文变量（ngx.ctx）：
  - domain_conf_data       当前域名的全量防护配置
  - web_bypass             Web 防护跳过标志（白名单命中后置 true）
  - flow_bypass            流量防护跳过标志
  - src_ip                 客户端真实 IP（已处理代理透传）
  - waf_log                当前请求的处置日志（waf_module/waf_policy/waf_action/waf_extra）
--]]

local cjson = require "cjson.safe"
local request = require "resty.jxwaf.request"
local preprocess = require "resty.jxwaf.preprocess"
local operator = require "resty.jxwaf.operator"
local unify_action = require "resty.jxwaf.unify_action"

local _M = {}

--[[
  通用规则匹配函数
  所有基于规则引擎的模块（Web规则/流量规则/白名单/防篡改/高级配置）均调用此函数。

  参数：
    rule_matchs  规则匹配条件数组，结构：
      [{
        match_args     = [{key="http_args", value="path"}, ...],  -- OR 关系
        args_prepocess = {"none", "lowerCase", ...},              -- 按顺序执行
        match_operator = "str_contain",                            -- 匹配方式
        match_value    = "/admin"                                  -- 匹配值
      }, ...]                                                      -- AND 关系

  返回：
    true  所有条件命中（规则触发）
    false 任一条件未命中（规则不触发）
]]
local function match_rules(rule_matchs)
  if not rule_matchs then
    return true  -- 无匹配条件视为全匹配（流量规则 filter=false 时）
  end

  for _, rule_match in ipairs(rule_matchs) do
    local match_args = rule_match['match_args']
    local args_prepocess = rule_match['args_prepocess']
    local match_operator = rule_match['match_operator']
    local match_value = rule_match['match_value']
    local operator_result = false

    -- OR 逻辑：任一 match_arg 命中即可
    for _, match_arg in ipairs(match_args) do
      local arg = request.get_args(match_arg.key, match_arg.value)

      -- 按顺序执行参数预处理
      for _, arg_prepocess in ipairs(args_prepocess) do
        arg = preprocess.process_args(arg_prepocess, arg)
      end

      -- status_check（参数存在判断）不需要 arg 有值；其他运算符需要 arg 非空
      if arg or match_operator == 'status_check' then
        local result = operator.match(match_operator, arg, match_value)
        if result then
          operator_result = true
          break  -- 命中即跳出 OR 循环
        end
      end
    end

    -- AND 逻辑：任一 rule_match 未命中则整条规则不命中
    if not operator_result then
      return false
    end
  end

  return true
end

_M.match_rules = match_rules

--[[
  Web 白名单规则检测

  数据来源：domain_conf_data['web_white_rule_data']
  规则字段：rule_name, rule_matchs, rule_action(固定 web_bypass), action_value

  执行时机：在 web_rule_protection 之前
  作用：命中后设置 ngx.ctx.web_bypass = true，后续 web_rule_protection /
        web_engine_protection / web_page_tamper_proof 自动跳过

  特点：
    - 使用与防护规则相同的 match_rules 函数
    - rule_action 固定为 web_bypass，不执行拦截
    - 命中后立即 return，不再匹配后续白名单规则
]]
function _M.web_white_rule(domain_conf_data)
  local web_white_rule_data = domain_conf_data['web_white_rule_data']
  if not web_white_rule_data then
    return
  end

  for _, rule_conf in ipairs(web_white_rule_data) do
    local rule_name = rule_conf['rule_name']
    local rule_matchs = rule_conf['rule_matchs']

    if match_rules(rule_matchs) then
      ngx.ctx.waf_log = {
        waf_module = "web_white_rule",
        waf_policy = "Web白名单-" .. rule_name,
        waf_action = "web_bypass",
        waf_extra = "",
      }
      -- 设置 bypass 标志，后续 Web 规则模块入口检测后自动跳过
      ngx.ctx.web_bypass = true
      return  -- 命中即终止，不再匹配后续白名单
    end
  end
end

--[[
  流量白名单规则检测

  数据来源：domain_conf_data['flow_white_rule_data']
  规则字段：rule_name, rule_matchs, rule_action(固定 flow_bypass), action_value

  执行时机：在 flow_rule_protection 之前（位于 flow_white_rule → flow_ip_region_block
            → flow_rule_protection → flow_engine_protection 链路首位）
  作用：命中后设置 ngx.ctx.flow_bypass = true，后续流量规则模块自动跳过

  特点：
    - 使用与防护规则相同的 match_rules 函数
    - rule_action 固定为 flow_bypass，不执行拦截
    - 命中后立即 return，不再匹配后续白名单规则
]]
function _M.flow_white_rule(domain_conf_data)
  local flow_white_rule_data = domain_conf_data['flow_white_rule_data']
  if not flow_white_rule_data then
    return
  end

  for _, rule_conf in ipairs(flow_white_rule_data) do
    local rule_name = rule_conf['rule_name']
    local rule_matchs = rule_conf['rule_matchs']

    if match_rules(rule_matchs) then
      ngx.ctx.waf_log = {
        waf_module = "flow_white_rule",
        waf_policy = "流量白名单-" .. rule_name,
        waf_action = "flow_bypass",
        waf_extra = "",
      }
      ngx.ctx.flow_bypass = true
      return
    end
  end
end

--[[
  Web 防护规则检测

  数据来源：domain_conf_data['web_rule_protection_data']
  规则字段：rule_name, rule_matchs, rule_action, action_value

  支持动作：
    block           阻断请求（返回拦截页面）
    reject_response 拒绝响应（不返回数据，与 block 同处理）
    watch           观察模式（仅记录日志）

  特点：
    - 单次请求即时检测，无频率统计
    - 命中后立即执行动作并终止（ngx.exit）
    - 仅支持 block/watch，不支持 bot_check/network_block
]]
function _M.web_rule_protection(domain_conf_data, sys_conf_data)
  local web_rule_protection_data = domain_conf_data['web_rule_protection_data']
  if not web_rule_protection_data or ngx.ctx.web_bypass then
    return
  end

  for _, rule_conf in ipairs(web_rule_protection_data) do
    local rule_name = rule_conf['rule_name']
    local rule_matchs = rule_conf['rule_matchs']
    local rule_action = rule_conf['rule_action']
    local action_value = rule_conf['action_value']

    if match_rules(rule_matchs) then
      -- 记录处置日志
      local waf_log = {
        waf_module = "web_rule_protection",
        waf_policy = "Web防护规则-" .. rule_name,
        waf_action = rule_action,
        waf_extra = action_value,
      }
      ngx.ctx.waf_log = waf_log

      -- 执行动作
      if rule_action == "block" or rule_action == "reject_response" then
        local page_conf = {}
        if sys_conf_data['custom_deny_page'] == 'true' then
          page_conf['code'] = sys_conf_data['waf_deny_code']
          page_conf['html'] = sys_conf_data['waf_deny_html']
        end
        unify_action.block(page_conf)  -- 内部调用 ngx.exit，不会返回
      end
      -- watch 模式仅记录日志，不拦截，继续匹配下一条规则
    end
  end
end

--[[
  流量防护规则检测

  数据来源：domain_conf_data['flow_rule_protection_data']
  规则字段：rule_name, rule_matchs, rule_action, action_value,
            filter, entity, stat_time, exceed_count, block_time

  支持动作：
    block           阻断请求
    reject_response 拒绝响应
    bot_check       人机识别
    network_block   网络封禁（立即执行，不依赖缓存）
    watch           观察模式

  特点：
    - 基于频率统计，使用 ngx.shared.jxwaf_inner 共享内存
    - 处罚缓存机制：触发后写入 flow_rule_block<src_ip>，TTL=block_time
    - network_block 立即执行网络层封禁，其余动作依赖缓存命中

  统计 key 构造：
    "flow_rule_stat" + entity各字段值拼接
    例：entity=[{key="http_args",value="src_ip"},{key="http_args",value="path"}]
        key = "flow_rule_stat1.1.1.1/admin"
]]
function _M.flow_rule_protection(domain_conf_data, sys_conf_data, config_info)
  local flow_rule_protection_data = domain_conf_data['flow_rule_protection_data']
  if not flow_rule_protection_data or ngx.ctx.flow_bypass then
    return
  end

  local jxwaf_inner = ngx.shared.jxwaf_inner
  local src_ip = request.get_args("http_args", "src_ip")

  -- 1. 检查处罚缓存：若 src_ip 已被处罚，直接执行缓存中的动作
  local block_result = jxwaf_inner:get("flow_rule_block" .. src_ip)
  if block_result then
    local block_action = cjson.decode(block_result)
    local rule_name = block_action['rule_name']
    local rule_action = block_action['rule_action']
    local action_value = block_action['action_value']

    local waf_log = {
      waf_module = "flow_rule_protection",
      waf_policy = "流量防护规则-" .. rule_name,
      waf_action = rule_action,
      waf_extra = action_value,
    }
    ngx.ctx.waf_log = waf_log

    if rule_action == "block" then
      local page_conf = {}
      if sys_conf_data['custom_deny_page'] == 'true' then
        page_conf['code'] = sys_conf_data['waf_deny_code']
        page_conf['html'] = sys_conf_data['waf_deny_html']
      end
      unify_action.block(page_conf)
    elseif rule_action == "reject_response" then
      unify_action.reject_response()
    elseif rule_action == "bot_check" then
      unify_action.bot_commit_auth()
      unify_action.bot_check_ip(action_value)
    end
    return  -- 处罚缓存命中后直接返回
  end

  -- 2. 遍历流量防护规则
  for _, rule_conf in ipairs(flow_rule_protection_data) do
    local rule_name = rule_conf['rule_name']
    local filter = rule_conf['filter']
    local rule_matchs = rule_conf['rule_matchs']
    local entity = rule_conf['entity']
    local stat_time = tonumber(rule_conf['stat_time'])
    local exceed_count = tonumber(rule_conf['exceed_count'])
    local rule_action = rule_conf['rule_action']
    local action_value = rule_conf['action_value']
    local block_time = tonumber(rule_conf['block_time'])

    -- 2.1 匹配条件过滤
    local matchs_result = true
    if filter == "true" then
      matchs_result = match_rules(rule_matchs)
    end
    -- filter == "false" 时 matchs_result 恒为 true，对所有请求生效

    -- 2.2 频率统计
    if matchs_result then
      -- 构造统计 key
      local statics_object_table = { "flow_rule_stat" }
      local nil_exist = false

      for _, v in ipairs(entity) do
        local return_value = request.get_args(v.key, v.value)
        if type(return_value) == "string" then
          table.insert(statics_object_table, return_value)
        elseif type(return_value) == "table" and type(return_value[1]) == "string" then
          table.insert(statics_object_table, return_value[1])
        else
          nil_exist = true
          break  -- entity 任一字段为空，跳过统计
        end
      end

      if not nil_exist then
        local statics_object_key = table.concat(statics_object_table)
        -- incr(key, value, init, ttl)：自增 1，初始值 0，TTL=stat_time
        local count = jxwaf_inner:incr(statics_object_key, 1, 0, stat_time)

        -- 2.3 超过阈值触发处罚
        if count > exceed_count then
          -- network_block 立即执行（网络层封禁）
          if rule_action == "network_block" then
            local waf_log = {
              waf_module = "flow_rule_protection",
              waf_policy = "流量防护规则-" .. rule_name,
              waf_action = rule_action,
              waf_extra = action_value,
            }
            ngx.ctx.waf_log = waf_log
            unify_action.network_block(config_info, src_ip, action_value)
          end

          -- 写入处罚缓存（后续请求在步骤 1 直接命中）
          local block_action = {
            rule_name = rule_name,
            rule_action = rule_action,
            action_value = action_value,
          }
          jxwaf_inner:set("flow_rule_block" .. src_ip, cjson.encode(block_action), block_time)
        end
      end
    end
  end
end

return _M
