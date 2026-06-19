local cjson = require "cjson.safe"
local process = require "ngx.process"
local resty_random = require "resty.random"
local resty_string = require "resty.string"

local init_config_path = "/opt/jxwaf_admin_server/nginx/conf/waf_config.json"
local read_config = assert(io.open(init_config_path,'r+'))
local raw_config_info = read_config:read('*all')
read_config:close()
local config_info = cjson.decode(raw_config_info)
if config_info == nil then
  ngx.log(ngx.ERR,"init fail,can not decode config file")
end

local mysql_config = {
    host = config_info['host'],
    port = config_info['port'],
    user = config_info['user'],
    database = config_info['database'],
    password = config_info['password'],
    charset = "utf8mb4",
    max_packet_size = 64 * 1024 * 1024
}
db_config = mysql_config
init_config = config_info
local ok, err = process.enable_privileged_agent()
if not ok then
  ngx.log(ngx.ERR, "enables privileged agent failed error:", err)
end