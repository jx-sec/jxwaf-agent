--[[
JXWAF 防护组件与名单防护节点逻辑

本文件整理自节点源码 waf.lua 中的 base_component 与 global_name_list 函数，
供 AI 深度排查时参考。实际运行环境为 OpenResty + ngx.lua。

两大模块：
  1. base_component       防护组件（自定义 Lua 代码检测）
  2. global_name_list     名单防护（键值查找匹配）

联合判断机制：
  - 组件通过 ngx.ctx 设置变量 → 规则通过 ctx_args 引用
  - 名单通过 bypass 动作 → 跳过后续规则模块
  - 名单通过 global_name_list_result → 规则引用匹配结果

依赖模块：
  - resty.jxwaf.request      请求参数获取
  - resty.jxwaf.unify_action 统一动作执行
  - cjson.safe               JSON 解析
--]]

local cjson = require "cjson.safe"
local request = require "resty.jxwaf.request"
local unify_action = require "resty.jxwaf.unify_action"

local _M = {}

--============================================================================
-- 第一部分：防护组件（base_component）
-- 对应节点源码 waf.lua 中的 base_component 函数
--============================================================================

--[[
  防护组件检测

  数据来源：domain_conf_data['waf_component_data']
  组件字段：name, detail, code(Base64), conf(JSON), rule_order_time, status

  执行特点：
    - 在 access 阶段最先执行（先于名单防护和所有规则）
    - 按 rule_order_time 升序执行
    - pcall 包裹，单个组件异常不影响后续
    - 组件内可直接调用 unify_action 执行动作（会 ngx.exit 终止）
    - 组件可通过 ngx.ctx 设置变量供后续规则引用

  组件代码结构（code 字段 Base64 解码后）：
    local _M = {}
    function _M.check(conf_data)
      -- conf_data 为 conf 字段 JSON 解码后的 table
      -- 可使用 request.get_args / unify_action / ngx.ctx 等
      return
    end
    return _M
]]
function _M.base_component(domain_conf_data, waf_component_code)
  local waf_component_data = domain_conf_data['waf_component_data']
  if not waf_component_data then
    return
  end

  for _, component_conf in ipairs(waf_component_data) do
    local name = component_conf['name']
    local conf = component_conf['conf']

    -- conf 字段为 JSON 字符串，解码为 Lua table
    local conf_data = nil
    if conf and conf ~= "" then
      conf_data = cjson.decode(conf)
    end

    -- waf_component_code[name] 为已 loadstring 加载的模块 table
    local component_module = waf_component_code and waf_component_code[name]
    if component_module and type(component_module.check) == "function" then
      -- pcall 包裹确保异常不中断请求
      local ok, err = pcall(component_module.check, conf_data)
      if not ok then
        ngx.log(ngx.ERR, "component error: ", name, ", ", err)
      end
      -- 若组件内调用了 unify_action.block() 等，已 ngx.exit，不会执行到此处
    end
  end
end

--============================================================================
-- 第二部分：名单防护（global_name_list）
-- 对应节点源码 waf.lua 中的 global_name_list 函数
--============================================================================

--[[
  名单防护检测

  数据来源：
    domain_conf_data['waf_global_name_list_data']       名单配置数组
    domain_conf_data['waf_global_name_list_item_data']  名单条目（按 name_list_name 分组）

  名单配置字段：name_list_name, name_list_rule(JSON), name_list_action,
                action_value, name_list_expire, name_list_expire_time, status

  名单条目结构：{ [name_list_name] = { [item_value] = true, ... }, ... }

  name_list_rule 结构（JSON 数组）：
    [{"key": "http_args", "value": "src_ip"}, {"key": "header_args", "value": "host"}]
    → 查找 key = src_ip值 .. host值（顺序拼接）

  支持动作：
    block / reject_response / bot_check / network_block / watch
    all_bypass / web_bypass / flow_bypass

  联合判断：
    - bypass 动作设置 ngx.ctx.web_bypass / flow_bypass，后续规则模块自动跳过
    - 匹配结果可通过 ngx.ctx.global_name_list_result 传递给规则（需自定义写入）
]]
function _M.global_name_list(domain_conf_data, sys_conf_data, config_info)
  local waf_global_name_list_data = domain_conf_data['waf_global_name_list_data']
  local waf_global_name_list_item_data = domain_conf_data['waf_global_name_list_item_data']

  if not waf_global_name_list_data or not waf_global_name_list_item_data then
    return
  end

  for _, name_list_conf in ipairs(waf_global_name_list_data) do
    local name_list_name = name_list_conf['name_list_name']
    local name_list_rule = name_list_conf['name_list_rule']
    local name_list_action = name_list_conf['name_list_action']
    local action_value = name_list_conf['action_value']

    -- name_list_rule 为 JSON 字符串，需解码
    local rule_list = cjson.decode(name_list_rule)
    if not rule_list then
      goto continue
    end

    -- 获取该名单的所有条目
    local name_list_item_data = waf_global_name_list_item_data[name_list_name]
    if not name_list_item_data then
      goto continue
    end

    -- 构造查找 key：按 rule_list 顺序取值并拼接
    local item_value_table = {}
    local nil_exist = false

    for _, rule in ipairs(rule_list) do
      local return_value = request.get_args(rule['key'], rule['value'])
      if type(return_value) == "string"
         or type(return_value) == "number"
         or type(return_value) == "boolean" then
        table.insert(item_value_table, tostring(return_value))
      else
        -- 任一字段为 nil（非 string/number/boolean），跳过该名单
        nil_exist = true
        break
      end
    end

    if not nil_exist then
      local item_value = table.concat(item_value_table)

      -- 在条目表中查找（O(1) 哈希查找）
      if name_list_item_data[item_value] then
        -- 命中！记录处置日志
        ngx.ctx.waf_log = {
          waf_module = "name_list",
          waf_policy = "名单防护-" .. name_list_name,
          waf_action = name_list_action,
          waf_extra = item_value,
        }

        -- 执行动作
        if name_list_action == "block" then
          local page_conf = {}
          if sys_conf_data['custom_deny_page'] == 'true' then
            page_conf['code'] = sys_conf_data['waf_deny_code']
            page_conf['html'] = sys_conf_data['waf_deny_html']
          end
          unify_action.block(page_conf)

        elseif name_list_action == "reject_response" then
          unify_action.reject_response()

        elseif name_list_action == "bot_check" then
          unify_action.bot_commit_auth()
          unify_action.bot_check_ip(action_value)

        elseif name_list_action == "network_block" then
          local src_ip = request.get_args("http_args", "src_ip")
          unify_action.network_block(config_info, src_ip, action_value)

        elseif name_list_action == "all_bypass" then
          -- 跳过 Web + 流量所有安全防护
          ngx.ctx.web_bypass = true
          ngx.ctx.flow_bypass = true

        elseif name_list_action == "web_bypass" then
          -- 仅跳过 Web 安全防护
          ngx.ctx.web_bypass = true

        elseif name_list_action == "flow_bypass" then
          -- 仅跳过流量安全防护
          ngx.ctx.flow_bypass = true

        elseif name_list_action == "watch" then
          -- 观察模式：仅记录日志，不执行动作
        end

        -- 若需将匹配结果传递给后续规则（global_name_list_result），
        -- 可在此处写入 ngx.ctx（需根据实际需求启用）：
        -- ngx.ctx["global_name_list_result_" .. name_list_name] = true
      end
    end

    ::continue::
  end
end

--============================================================================
-- 第三部分：组件代码加载辅助函数
--============================================================================

--[[
  加载组件代码（在 init_worker 阶段调用）

  将 Base64 编码的组件代码解码并 loadstring 加载为 Lua 模块。
  返回 { [name] = module_table, ... }

  参数：
    waf_component_data  组件配置数组（含 name, code 字段）

  返回：
    table  组件模块映射表
]]
function _M.load_component_code(waf_component_data)
  local component_code_map = {}

  if not waf_component_data then
    return component_code_map
  end

  for _, component_conf in ipairs(waf_component_data) do
    local name = component_conf['name']
    local code = component_conf['code']

    if code and code ~= "" then
      -- Base64 解码
      local decoded_code = ngx.decode_base64(code)
      if decoded_code then
        -- loadstring 加载为函数并执行（返回模块 table）
        local func, err = loadstring(decoded_code)
        if func then
          local ok, module = pcall(func)
          if ok and type(module) == "table" and type(module.check) == "function" then
            component_code_map[name] = module
          else
            ngx.log(ngx.ERR, "component load error: ", name)
          end
        else
          ngx.log(ngx.ERR, "component loadstring error: ", name, ", ", err)
        end
      end
    end
  end

  return component_code_map
end

return _M
