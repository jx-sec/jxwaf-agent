--[[
防护组件：CC 攻击接口自动人机识别防护

检测逻辑：
  1. 统计每个 URL 接口下，每个源 IP 在统计时间窗口（默认 60 秒）内的请求数
  2. 当某 IP 对某接口的请求数超过阈值（默认 100），标记为"高频 IP"
  3. 当某接口的高频 IP 数量超过阈值（默认 1000），判定为 CC 攻击
  4. 对被攻击的接口开启人机识别防护，持续 10 分钟（默认 600 秒）
  5. 防护期间，所有访问该接口的请求均触发人机识别

conf 字段示例（JSON）：
  {
    "stat_time": 60,
    "ip_request_threshold": 100,
    "high_freq_ip_threshold": 1000,
    "protect_time": 600,
    "bot_check_type": "auto"
  }

conf 字段说明：
  stat_time              统计时间窗口（秒），默认 60
  ip_request_threshold   单 IP 单接口请求阈值，超过即标记为高频 IP，默认 100
  high_freq_ip_threshold 高频 IP 数量阈值，超过即判定为 CC 攻击，默认 1000
  protect_time           防护持续时间（秒），默认 600
  bot_check_type         人机识别类型，对应 unify_action.bot_check_ip 入参：
                         auto（无交互自动检测）/ slipper（滑块）/ puzzle（滑块拼图）/ words（文字点击），默认 auto
                         注意：取值必须为上述 4 个之一，其他值会导致人机识别页面不显示（防护静默失效）
]]

local _M = {}

function _M.check(conf_data)
    local request = require "resty.jxwaf.request"
    local unify_action = require "resty.jxwaf.unify_action"
    local jxwaf_user = ngx.shared.jxwaf_user

    local path = request.get_args("http_args", "path")
    local src_ip = request.get_args("http_args", "src_ip")
    if type(path) ~= "string" or type(src_ip) ~= "string" then return end
    if path == "" or src_ip == "" then return end

    -- 读取配置（带默认值）
    local stat_time = 60
    local ip_request_threshold = 100
    local high_freq_ip_threshold = 1000
    local protect_time = 600
    local bot_check_type = "auto"

    if conf_data then
        stat_time = tonumber(conf_data["stat_time"]) or stat_time
        ip_request_threshold = tonumber(conf_data["ip_request_threshold"]) or ip_request_threshold
        high_freq_ip_threshold = tonumber(conf_data["high_freq_ip_threshold"]) or high_freq_ip_threshold
        protect_time = tonumber(conf_data["protect_time"]) or protect_time
        if type(conf_data["bot_check_type"]) == "string" then
            bot_check_type = conf_data["bot_check_type"]
        end
    end

    -- 1. 检查接口是否已处于防护状态（命中则直接触发人机识别）
    local protect_key = "cc_attack_defense_protect|" .. path
    if jxwaf_user:get(protect_key) then
        ngx.ctx.waf_log = {
            waf_module = "component",
            waf_policy = "防护组件-cc_attack_detect",
            waf_action = "bot_check",
            waf_extra = "cc_protect_path=" .. path,
        }
        unify_action.bot_commit_auth()
        unify_action.bot_check_ip(bot_check_type)
        return
    end

    -- 2. 统计 (path, src_ip) 在时间窗口内的请求数
    local freq_key = "cc_attack_defense_freq|" .. path .. "|" .. src_ip
    local freq_count = jxwaf_user:incr(freq_key, 1, 0, stat_time)
    if not freq_count then return end

    -- 3. 当 IP 请求数超过阈值时，标记为高频 IP 并累计接口的高频 IP 数
    if freq_count <= ip_request_threshold then return end

    -- 原子标记：add 仅在 key 不存在时写入，返回 true 表示首次标记（避免同一 IP 重复计数）
    local marked_key = "cc_attack_defense_marked|" .. path .. "|" .. src_ip
    local ok = jxwaf_user:add(marked_key, true, stat_time)
    if not ok then return end

    -- 4. 累计该接口的高频 IP 数量
    local count_key = "cc_attack_defense_count|" .. path
    local high_freq_count = jxwaf_user:incr(count_key, 1, 0, stat_time)
    if not high_freq_count then return end

    -- 5. 高频 IP 数量超过阈值，开启接口防护并立即触发人机识别
    if high_freq_count <= high_freq_ip_threshold then return end

    jxwaf_user:set(protect_key, "1", protect_time)
    ngx.ctx.waf_log = {
        waf_module = "component",
        waf_policy = "防护组件-cc_attack_detect",
        waf_action = "bot_check",
        waf_extra = "cc_attack_triggered path=" .. path .. " high_freq_ip_count=" .. tostring(high_freq_count),
    }
    unify_action.bot_commit_auth()
    unify_action.bot_check_ip(bot_check_type)
end

return _M
