local process = require "ngx.process"
local db_query = require 'resty.admin_server.db_query'
local mysql = require "resty.mysql"
local tools = require 'resty.admin_server.tools'
local cjson = require "cjson.safe"
local http = require "resty.admin_server.http"

local function _update_at(auto_update_period,global_update_rule)
  local global_ok, global_err = ngx.timer.at(tonumber(auto_update_period),global_update_rule)
  if not global_ok then
    if global_err ~= "process exiting" then
      ngx.log(ngx.ERR, "failed to create the cycle timer: ", global_err)
    end
  end
end

local function create_database()
  local db, err = mysql:new()
  if not db then
    ngx.log(ngx.ERR, "failed to instantiate mysql: ", err)
    return nil, err
  end
  db:set_timeout(3000)
  local ok, err, errcode, sqlstate = db:connect{
    host = db_config['host'],
    port = db_config['port'],
    database = "mysql",
    user = db_config['user'],
    password = db_config['password'],
    charset = db_config['charset'],
  }
  if not ok then
    db:close()
    ngx.log(ngx.ERR, "failed to connect to mysql: ", err, ": ", errcode, " ", sqlstate)
    return _update_at(3,create_database)
  end
  local create_db_sql = "CREATE DATABASE IF NOT EXISTS " .. db_config['database'] .. " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  local res, query_err, query_errno, query_sqlstate = db:query(create_db_sql)
  if not res then
    db:close()
    ngx.log(ngx.ERR, "bad result: ", query_err, ": ", query_errno, ": ", query_sqlstate, ".")
    return _update_at(3,create_database)
  end
  db:close()
  return true
end

local function create_jxwaf_admin_account()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_admin_account (
      user_name VARCHAR(100) PRIMARY KEY,
      user_password VARCHAR(100) NOT NULL,
      otp_auth VARCHAR(100) DEFAULT 'true' NOT NULL,
      otp_secret_key VARCHAR(100) NOT NULL,
      waf_auth VARCHAR(100) NOT NULL
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_admin_account table failed")
    return _update_at(3,create_jxwaf_admin_account)
  end
end

local function create_jxwaf_waf_domain_group()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_domain_group (
      user_name VARCHAR(100) NOT NULL,     
      group_name VARCHAR(1000) NOT NULL,
      group_detail VARCHAR(2000) NOT NULL,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))

  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_domain_group table failed")
    return _update_at(3,create_jxwaf_waf_domain_group)
  end
end

--  learn business_priority  security_priority offline
--  deepseek   tongyi

local function create_jxwaf_waf_group_web_engine_protection()
  
  local sql = [[
      CREATE TABLE IF NOT EXISTS jxwaf_waf_group_web_engine_protection (
          user_name VARCHAR(100) NOT NULL,
          group_name VARCHAR(1000) NOT NULL,
          ai_protection  VARCHAR(100) DEFAULT 'false' NOT NULL,
          protection_mode VARCHAR(100) DEFAULT 'business_priority' NOT NULL,
          model_provider  VARCHAR(100) DEFAULT 'jxwaf' NOT NULL,
          model_api_key   VARCHAR(1000) DEFAULT '' NOT NULL,
          engine_protection  VARCHAR(100) DEFAULT 'block' NOT NULL,
          INDEX idx_user_name (user_name),
          INDEX idx_group_name (group_name(256)),
          INDEX idx_a_b (user_name,group_name(256))
      );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_web_engine_protection table failed")
        return _update_at(3,create_jxwaf_waf_group_web_engine_protection)

  end
end

local function create_jxwaf_waf_group_web_rule_protection()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_web_rule_protection (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      rule_matchs TEXT NOT NULL,
      rule_action VARCHAR(1000) DEFAULT '',
      action_value VARCHAR(1000) DEFAULT '',
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_web_rule_protection table failed")
            return _update_at(3,create_jxwaf_waf_group_web_rule_protection)

  end
end

local function create_jxwaf_waf_group_web_white_rule()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_web_white_rule (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      rule_matchs TEXT NOT NULL,
      rule_action VARCHAR(1000) DEFAULT '',
      action_value VARCHAR(1000) DEFAULT '',
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_web_white_rule table failed")
                return _update_at(3,create_jxwaf_waf_group_web_white_rule)

  end
end

local function create_jxwaf_waf_group_flow_engine_protection()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_flow_engine_protection (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      engine_status VARCHAR(20) DEFAULT 'false' COMMENT '总开关 true/false',
      protection_plan VARCHAR(50) DEFAULT 'daily_observe' COMMENT '当前生效预案: daily_observe/daily_protect/attack_protect/emergency_protect',
      plans_config JSON COMMENT '所有预案配置(JSON格式)',
      UNIQUE KEY uk_user_group (user_name, group_name(255)),
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256))
  );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_flow_engine_protection table failed")
    return _update_at(3,create_jxwaf_waf_group_flow_engine_protection)
  end
end

local function create_jxwaf_waf_group_flow_rule_protection()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_flow_rule_protection (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      filter VARCHAR(1000) DEFAULT 'false',
      rule_matchs TEXT NOT NULL,
      entity TEXT NOT NULL,
      stat_time VARCHAR(1000) DEFAULT '',
      exceed_count VARCHAR(1000) DEFAULT '',
      rule_action VARCHAR(1000) DEFAULT '',
      action_value VARCHAR(1000) DEFAULT '',
      block_time VARCHAR(1000) DEFAULT '3600',
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_flow_rule_protection table failed")
     return _update_at(3,create_jxwaf_waf_group_flow_rule_protection)
  end
end

local function create_jxwaf_waf_group_flow_ip_region_block()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_flow_ip_region_block (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      ip_region_block VARCHAR(50) DEFAULT 'false',
      check_model VARCHAR(50) DEFAULT 'white',
      country_list TEXT,
      block_action VARCHAR(1000) DEFAULT 'block',
      action_value VARCHAR(1000) DEFAULT '',
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_flow_ip_region_block table failed")
    return _update_at(3,create_jxwaf_waf_group_flow_ip_region_block)
  end
end

local function create_jxwaf_waf_group_flow_white_rule()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_flow_white_rule (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      rule_matchs TEXT NOT NULL,
      rule_action VARCHAR(1000) DEFAULT '',
      action_value VARCHAR(1000) DEFAULT '',
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_flow_white_rule table failed")
    return _update_at(3,create_jxwaf_waf_group_flow_white_rule)
  end
end

-- origin_protocol  http  https follow
local function create_jxwaf_waf_domain()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_domain (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      domain VARCHAR(1000) NOT NULL,
      detail VARCHAR(2000) NOT NULL DEFAULT '',
      http VARCHAR(50) NOT NULL DEFAULT 'true',
      https VARCHAR(50) NOT NULL DEFAULT 'false',
      ssl_domain VARCHAR(1000) DEFAULT '',
      source_ip VARCHAR(2000) DEFAULT '',
      waf_update_source_ip VARCHAR(2000) DEFAULT '',
      source_http_port VARCHAR(50) NOT NULL DEFAULT '80',
      source_https_port VARCHAR(50) NOT NULL DEFAULT '443',
      origin_protocol VARCHAR(100) NOT NULL DEFAULT 'http',
      balance_type VARCHAR(100) NOT NULL DEFAULT 'round_robin',
      pre_proxy VARCHAR(100) NOT NULL DEFAULT 'false',
      real_ip_conf VARCHAR(100) NOT NULL DEFAULT 'XRI',
      connect_timeout VARCHAR(100) NOT NULL DEFAULT '5',
      send_timeout VARCHAR(100) NOT NULL DEFAULT '60',
      read_timeout VARCHAR(100) NOT NULL DEFAULT '60',
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_domain_name (domain(256)),
      INDEX idx_a_b (user_name,group_name(256)),
      INDEX idx_a_b_c (user_name,group_name(256),domain(256))
  );
  ]]
  local result = db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_domain table failed")
    return _update_at(3,create_jxwaf_waf_domain)
  end
end

local function create_jxwaf_waf_group_web_page_tamper_proof()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_web_page_tamper_proof (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      rule_matchs TEXT NOT NULL,
      cache_page_url VARCHAR(1000) DEFAULT '',
      cache_content_type VARCHAR(1000) DEFAULT '',
      cache_page_content TEXT NOT NULL,
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_web_page_tamper_proof table failed")
    return _update_at(3,create_jxwaf_waf_group_web_page_tamper_proof)
  end
end

-- custom upstream

local function create_jxwaf_waf_group_custom_request_header()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_custom_request_header (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      filter VARCHAR(1000) DEFAULT 'false',
      rule_matchs TEXT NOT NULL,
      header_name VARCHAR(2000) DEFAULT '',
      header_value VARCHAR(2000) DEFAULT '',
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_custom_request_header table failed")
    return _update_at(3,create_jxwaf_waf_group_custom_request_header)
  end
end

local function create_jxwaf_waf_group_custom_response_header()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_custom_response_header (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      filter VARCHAR(1000) DEFAULT 'false',
      rule_matchs TEXT NOT NULL,
      header_name VARCHAR(2000) DEFAULT '',
      header_value VARCHAR(2000) DEFAULT '',
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_custom_response_header table failed")
        return _update_at(3,create_jxwaf_waf_group_custom_response_header)
  end
end

local function create_jxwaf_waf_group_custom_response_content()

  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_custom_response_content (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      filter VARCHAR(1000) DEFAULT 'false',
      rule_matchs TEXT NOT NULL,
      content_type VARCHAR(100) DEFAULT '',
      return_code VARCHAR(50) DEFAULT '',
      return_content TEXT NOT NULL,
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]

  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_custom_response_content table failed")
            return _update_at(3,create_jxwaf_waf_group_custom_response_content)

  end
end


local function create_jxwaf_waf_group_custom_upstream_address()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_group_custom_upstream_address (
      user_name VARCHAR(100) NOT NULL,
      group_name VARCHAR(1000) NOT NULL,
      rule_name VARCHAR(1000) DEFAULT '',
      rule_detail VARCHAR(1000) DEFAULT '',
      filter VARCHAR(1000) DEFAULT 'false',
      rule_matchs TEXT NOT NULL,
      source_ip VARCHAR(2000) DEFAULT '',
      source_http_port VARCHAR(2000) DEFAULT '',
      source_https_port VARCHAR(2000) DEFAULT '',
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_group_name (group_name(256)),
      INDEX idx_a_b (user_name,group_name(256))
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_group_custom_upstream_address table failed")
                return _update_at(3,create_jxwaf_waf_group_custom_upstream_address)

  end
end

local function create_jxwaf_waf_global_name_list()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_global_name_list (
      user_name VARCHAR(100) NOT NULL,
      name_list_name VARCHAR(1000) DEFAULT '',
      name_list_detail VARCHAR(1000) DEFAULT '',
      name_list_rule VARCHAR(2000) DEFAULT '',
      name_list_action VARCHAR(1000) DEFAULT '',
      action_value VARCHAR(1000) DEFAULT '',
      name_list_expire VARCHAR(1000) DEFAULT 'false',
      name_list_expire_time BIGINT DEFAULT 0,
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_name_list_name (name_list_name(256)),
      INDEX idx_a_b (user_name,name_list_name(256))
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_global_name_list table failed")
     return _update_at(3,create_jxwaf_waf_global_name_list)

  end
end

local function create_jxwaf_waf_global_name_list_item()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_global_name_list_item (
      user_name VARCHAR(100) NOT NULL,
      name_list_name VARCHAR(1000) DEFAULT '',
      name_list_item VARCHAR(2000) DEFAULT '',
      name_list_expire VARCHAR(1000) DEFAULT 'false',
      name_list_item_expire_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_name_list_name (name_list_name(256)),
      INDEX idx_user_name_and_idx_name_list_name (user_name,name_list_name(256))
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_global_name_list_item table failed")
         return _update_at(3,create_jxwaf_waf_global_name_list_item)

  end
end

local function create_jxwaf_waf_component()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_component (
      user_name VARCHAR(100) NOT NULL,
      name VARCHAR(1000) DEFAULT '',
      detail VARCHAR(2000) DEFAULT '',
      code MEDIUMTEXT NOT NULL,
      conf MEDIUMTEXT NOT NULL,
      status VARCHAR(1000) DEFAULT 'true',
      rule_order_time BIGINT DEFAULT 0,
      INDEX idx_user_name (user_name),
      INDEX idx_name_list_name (name(256)),
      INDEX idx_user_name_and_idx_name (user_name,name(256))
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_component table failed")
             return _update_at(3,create_jxwaf_waf_component)

  end
end

-- source custom   system

local function create_jxwaf_waf_ssl_manage()

  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_waf_ssl_manage (
      user_name VARCHAR(100) NOT NULL,
      ssl_domain VARCHAR(1000) DEFAULT '',
      detail VARCHAR(2000) DEFAULT '',
      private_key TEXT NOT NULL,
      public_key TEXT NOT NULL,
      update_time VARCHAR(100) DEFAULT '',
      INDEX idx_user_name (user_name),
      INDEX idx_ssl_domain (ssl_domain(256)),
      INDEX idx_user_name_and_idx_ssl_domain (user_name,ssl_domain(256))
  );
  ]]

  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_waf_ssl_manage table failed")
     return _update_at(3,create_jxwaf_waf_ssl_manage)
  end
end

local function create_jxwaf_sys_conf()
  
  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_sys_conf (
      user_name VARCHAR(100) NOT NULL,
      log_conf_local_debug VARCHAR(100) DEFAULT 'false',
      log_conf_remote VARCHAR(100) DEFAULT 'false',
      log_ip VARCHAR(100) DEFAULT '127.0.0.1',
      log_port VARCHAR(100) DEFAULT '8877',
      log_response VARCHAR(100) DEFAULT 'false',
      log_all VARCHAR(100) DEFAULT 'false',
      report_conf VARCHAR(100) DEFAULT 'false',
      report_conf_ch_host VARCHAR(100) DEFAULT '',
      report_conf_ch_port VARCHAR(100) DEFAULT '9004',
      report_conf_ch_user VARCHAR(100) DEFAULT 'jxlog',
      report_conf_ch_password VARCHAR(100) DEFAULT 'jxlog',
      report_conf_ch_database VARCHAR(100) DEFAULT 'jxwaf',
      report_conf_ch_table VARCHAR(100) DEFAULT 'jxlog',
      custom_deny_page VARCHAR(100) DEFAULT 'false',
      waf_deny_code VARCHAR(100) DEFAULT '403',
      waf_deny_html TEXT,
      custom_not_find_page VARCHAR(100) DEFAULT 'false',
      not_find_code VARCHAR(100) DEFAULT '404',
      not_find_html TEXT,
      webtds_check VARCHAR(100) DEFAULT 'false',
      webtds_node_ip VARCHAR(100) DEFAULT '127.0.0.1',
      webtds_node_port VARCHAR(100) DEFAULT '9988'
  );
  ]]
  
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_sys_conf table failed")
         return _update_at(3,create_jxwaf_sys_conf)

  end
end

local function create_jxwaf_node_monitor()

  local sql = [[
    CREATE TABLE IF NOT EXISTS jxwaf_node_monitor (
      user_name VARCHAR(100) NOT NULL,
      node_uuid VARCHAR(100) DEFAULT '',
      node_hostname VARCHAR(1000) DEFAULT '',
      node_ip VARCHAR(1000) DEFAULT '',
      node_status_update_time VARCHAR(100) DEFAULT '',
      waf_conf_update_time VARCHAR(100) DEFAULT '',
      INDEX idx_user_name (user_name),
      INDEX idx_node_uuid (node_uuid),
      INDEX idx_user_name_and_idx_node_uuid (user_name,node_uuid)
  );
  ]]

  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_node_monitor table failed")
    return _update_at(3,create_jxwaf_node_monitor)
  end
end

local function create_jxwaf_soc_network_ip()
  local sql = [[
	CREATE TABLE IF NOT EXISTS jxwaf_soc_network_ip (
      user_name    VARCHAR(100) NOT NULL,
      ip           VARCHAR(100)  NOT NULL,
      status       TINYINT      NOT NULL DEFAULT 1 COMMENT '1:封禁, 2:加白',
      expire_time   BIGINT       NOT NULL DEFAULT 0 COMMENT '过期时间戳' ,
      operator_type VARCHAR(20)  NOT NULL DEFAULT '' COMMENT 'auto_create, user_create',
      operator_time BIGINT       NOT NULL DEFAULT 0 COMMENT '更新时间戳，用于增量同步',
      UNIQUE KEY uk_user_ip (user_name, ip),
      INDEX idx_operator_time (operator_time)
	);
  ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_soc_network_ip table failed")
    return _update_at(3,create_jxwaf_soc_network_ip)
  end
end

local function create_jxwaf_soc_network_ip_node_update()
  local sql = [[
	CREATE TABLE IF NOT EXISTS jxwaf_soc_network_ip_node_update (
      user_name    VARCHAR(100) NOT NULL,
      ip           VARCHAR(100) NOT NULL,
      update_time  BIGINT       NOT NULL DEFAULT 0,
      UNIQUE KEY uk_user_ip (user_name, ip),
      INDEX idx_user_name (user_name)
	);
  ]]
  local result = db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_soc_network_ip_node_update table failed")
    return _update_at(3,create_jxwaf_soc_network_ip_node_update)
  end
end

-- attack_type  sql  xss  rce  code_exec
local function create_jxwaf_soc_web_protection_model()

  local sql = [[
      CREATE TABLE IF NOT EXISTS jxwaf_soc_web_protection_model (
        user_name VARCHAR(100) NOT NULL,
        token VARCHAR(255) DEFAULT '' NOT NULL,
        raw_string MEDIUMTEXT,
        attack_type VARCHAR(100) DEFAULT '' NOT NULL,
        ai_analysis_result VARCHAR(100) DEFAULT '' NOT NULL,
        ai_model VARCHAR(100) DEFAULT '' NOT NULL,
        model_api_key VARCHAR(1000) DEFAULT '' NOT NULL,
        host VARCHAR(255) DEFAULT '' NOT NULL,
        uri VARCHAR(2000) DEFAULT '' NOT NULL,
        src_ip VARCHAR(100) DEFAULT '' NOT NULL,
        request_time VARCHAR(100) DEFAULT '' NOT NULL,
        PRIMARY KEY (token),
        INDEX idx_token (token),
        INDEX idx_attack_type (attack_type),
        INDEX idx_attack_result_time (attack_type, ai_analysis_result, request_time)
    );
      ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_soc_web_protection_model table failed")
    return _update_at(3,create_jxwaf_soc_web_protection_model)
  end
end

local function create_jxwaf_soc_web_protection_model_sync()

  local sql = [[
      CREATE TABLE IF NOT EXISTS jxwaf_soc_web_protection_model_sync (
        token VARCHAR(255) DEFAULT '' NOT NULL,
        attack_type VARCHAR(100) DEFAULT '' NOT NULL,
        ai_analysis_result VARCHAR(100) DEFAULT '' NOT NULL,
        request_time VARCHAR(100) DEFAULT '' NOT NULL,
        ai_model VARCHAR(100) DEFAULT '' NOT NULL,
        PRIMARY KEY (token, ai_model, request_time),
        INDEX idx_token (token),
        INDEX idx_attack_type (attack_type),
        INDEX idx_attack_result_time (attack_type, ai_analysis_result, request_time)
      );
      ]]
  local result =   db_query.query_mysql(sql)
  if not result then
    ngx.log(ngx.ERR, "db init jxwaf_soc_web_protection_model_sync table failed")
    return _update_at(3,create_jxwaf_soc_web_protection_model_sync)
  end
end


local function list_to_dict(list)
    local data = {}
    for _, key in ipairs(list) do
        data[key] = true
    end
    return data
end

local function black_ip_list_to_dict(list)
  local data = {}
  for _, v in ipairs(list) do
    data[v.ip] = {
      rule_action = v.rule_action,
      action_value = v.action_value
    }
  end
  return data
end

local function get_waf_data(sql)
    local waf_data_result,waf_data_error = db_query.query_mysql(sql)
    if not waf_data_result or waf_data_error then
      ngx.log(ngx.ERR,"waf_update_conf get waf data error,sql is:"..sql)
      return {}
    end
    return waf_data_result
end  

local function filter_by_user(data_list, user_name)
  local result = {}
  for _, item in ipairs(data_list) do
    if item.user_name == user_name then
      table.insert(result, item)
    end
  end
  return result
end

local function generate_user_conf_data(user_name, all_data)
  local conf_data = {}

  local waf_group_web_engine_protection_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_web_engine_protection, user_name)) do
    waf_group_web_engine_protection_data[result['group_name']] = {
      ai_protection = result['ai_protection'],
      protection_mode = result['protection_mode'],
      model_provider = result['model_provider'],
      model_api_key = result['model_api_key'],
      engine_protection = result['engine_protection']
      }
  end

  local waf_group_web_rule_protection_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_web_rule_protection, user_name)) do
    if result.status == 'true' then
      if not waf_group_web_rule_protection_data[result['group_name']] then
        waf_group_web_rule_protection_data[result['group_name']] = {}
      end
      table.insert(waf_group_web_rule_protection_data[result['group_name']], {
        rule_name = result.rule_name,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        rule_action = result.rule_action,
        action_value = result.action_value
      })
    end
  end

  local waf_group_web_white_rule_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_web_white_rule, user_name)) do
    if result.status == 'true' then
      if not waf_group_web_white_rule_data[result['group_name']] then
        waf_group_web_white_rule_data[result['group_name']] = {}
      end
      table.insert(waf_group_web_white_rule_data[result['group_name']], {
        rule_name = result.rule_name,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        rule_action = result.rule_action,
        action_value = result.action_value
      })
    end
  end

  local waf_group_web_page_tamper_proof_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_web_page_tamper_proof, user_name)) do
    if result.status == 'true' then
      if not waf_group_web_page_tamper_proof_data[result['group_name']] then
        waf_group_web_page_tamper_proof_data[result['group_name']] = {}
      end
      table.insert(waf_group_web_page_tamper_proof_data[result['group_name']], {
          rule_name = result.rule_name,
          rule_matchs = cjson.decode(result.rule_matchs) or {},
          cache_page_url = result.cache_page_url,
          cache_content_type = result.cache_content_type,
          cache_page_content = result.cache_page_content
      })
    end
  end

  local waf_group_flow_engine_protection_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_flow_engine_protection, user_name)) do
    local protection_plan = result['protection_plan'] or 'daily_observe'
    local plans_config = {}
    if result['plans_config'] and result['plans_config'] ~= ngx.null then
      plans_config = cjson.decode(result['plans_config']) or {}
    end
    local plan_config = plans_config[protection_plan] or {}
    waf_group_flow_engine_protection_data[result['group_name']] = {
      engine_status = result['engine_status'],
      protection_plan = protection_plan,
      ip_access_limit_status = plan_config['ip_access_limit_status'],
      ip_access_limit_stat_time = plan_config['ip_access_limit_stat_time'],
      ip_access_limit_threshold = plan_config['ip_access_limit_threshold'],
      ip_access_limit_action = plan_config['ip_access_limit_action'],
      ip_access_limit_action_extra_parameter = plan_config['ip_access_limit_action_extra_parameter'],
      ip_access_limit_duration = plan_config['ip_access_limit_duration'],
      ip_count_limit_status = plan_config['ip_count_limit_status'],
      ip_count_limit_stat_time = plan_config['ip_count_limit_stat_time'],
      ip_count_limit_threshold = plan_config['ip_count_limit_threshold'],
      ip_count_limit_action = plan_config['ip_count_limit_action'],
      ip_count_limit_action_extra_parameter = plan_config['ip_count_limit_action_extra_parameter'],
      domain_access_limit_status = plan_config['domain_access_limit_status'],
      domain_access_limit_stat_time = plan_config['domain_access_limit_stat_time'],
      domain_access_limit_threshold = plan_config['domain_access_limit_threshold'],
      domain_access_limit_action = plan_config['domain_access_limit_action'],
      domain_access_limit_action_extra_parameter = plan_config['domain_access_limit_action_extra_parameter'],
      ssl_fingerprint_protection_status = plan_config['ssl_fingerprint_protection_status'],
      ssl_fingerprint_protection_action = plan_config['ssl_fingerprint_protection_action'],
      ssl_fingerprint_protection_action_extra_parameter = plan_config['ssl_fingerprint_protection_action_extra_parameter'],
      emergency_protection_status = plan_config['emergency_protection_status'],
      emergency_protection_action = plan_config['emergency_protection_action'],
      emergency_protection_action_extra_parameter = plan_config['emergency_protection_action_extra_parameter']
    }
  end

  local waf_group_flow_rule_protection_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_flow_rule_protection, user_name)) do
    if result.status == 'true' then
      if not waf_group_flow_rule_protection_data[result['group_name']] then
        waf_group_flow_rule_protection_data[result['group_name']] = {}
      end
      table.insert(waf_group_flow_rule_protection_data[result['group_name']], {
        rule_name = result.rule_name,
        filter = result.filter,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        entity = cjson.decode(result.entity) or {},
        stat_time = cjson.decode(result.stat_time) or {},
        exceed_count = cjson.decode(result.exceed_count) or {},
        rule_action = result.rule_action,
        action_value = result.action_value,
        block_time = result.block_time
      })
    end
  end

  local waf_group_flow_ip_region_block_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_flow_ip_region_block, user_name)) do
    local tmp_country_list = cjson.decode(result.country_list)
    local country_list = {}
    if tmp_country_list then
        country_list = list_to_dict(tmp_country_list)
    end
    waf_group_flow_ip_region_block_data[result['group_name']] = {
      ip_region_block = result.ip_region_block,
      check_model = result.check_model,
      country_list = country_list,
      block_action = result.block_action,
      action_value = result.action_value
      }
  end

  local waf_group_flow_white_rules_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_flow_white_rule, user_name)) do
    if result.status == 'true' then
      if not waf_group_flow_white_rules_data[result['group_name']] then
        waf_group_flow_white_rules_data[result['group_name']] = {}
      end
      table.insert(waf_group_flow_white_rules_data[result['group_name']], {
        rule_name = result.rule_name,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        rule_action = result.rule_action,
        action_value = result.action_value
      })
    end
  end

  local waf_group_custom_request_header_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_custom_request_header, user_name)) do
    if result.status == 'true' then
      if not waf_group_custom_request_header_data[result['group_name']] then
        waf_group_custom_request_header_data[result['group_name']] = {}
      end
      table.insert(waf_group_custom_request_header_data[result['group_name']], {
        rule_name = result.rule_name,
        filter = result.filter,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        header_name = result.header_name,
        header_value = result.header_value,
      })
    end
  end

  local waf_group_custom_response_header_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_custom_response_header, user_name)) do
    if result.status == 'true' then
      if not waf_group_custom_response_header_data[result['group_name']] then
         waf_group_custom_response_header_data[result['group_name']] = {}
      end
      table.insert(waf_group_custom_response_header_data[result['group_name']], {
        rule_name = result.rule_name,
        filter = result.filter,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        header_name = result.header_name,
        header_value = result.header_value,
      })
    end
  end

  local waf_group_custom_response_content_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_custom_response_content, user_name)) do
    if result.status == 'true' then
      if not waf_group_custom_response_content_data[result['group_name']] then
         waf_group_custom_response_content_data[result['group_name']] = {}
      end
      table.insert(waf_group_custom_response_content_data[result['group_name']], {
        rule_name = result.rule_name,
        filter = result.filter,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        content_type = result.content_type,
        return_code = result.return_code,
        return_content = result.return_content,
      })
    end
  end

  local waf_group_custom_upstream_address_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_group_custom_upstream_address, user_name)) do
    if result.status == 'true' then
      if not waf_group_custom_upstream_address_data[result['group_name']] then
        waf_group_custom_upstream_address_data[result['group_name']] = {}
      end
      table.insert(waf_group_custom_upstream_address_data[result['group_name']], {
        rule_name = result.rule_name,
        filter = result.filter,
        rule_matchs = cjson.decode(result.rule_matchs) or {},
        source_ip = result.source_ip,
        source_http_port = result.source_http_port,
      })
    end
  end

  local waf_domain_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_domain, user_name)) do
    waf_domain_data[result['domain']] = {
      domain = result['domain'],
      group_name = result['group_name'],
      http = result['http'],
      https = result['https'],
      ssl_domain = result['ssl_domain'],
      source_ip = cjson.decode(result['source_ip']) or {},
      waf_update_source_ip = cjson.decode(result['waf_update_source_ip']) or {},
      source_http_port = result['source_http_port'],
      source_https_port = result['source_https_port'],
      origin_protocol = result['origin_protocol'],
      balance_type = result['balance_type'],
      pre_proxy = result['pre_proxy'],
      real_ip_conf = result['real_ip_conf'],
      connect_timeout = result['connect_timeout'],
      send_timeout = result['send_timeout'],
      read_timeout = result['read_timeout']
      }
  end

  local waf_global_name_list_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_global_name_list, user_name)) do
    if result.status == 'true' then
      local tmp_global_name_list_data = {
        name_list_name = result['name_list_name'],
        name_list_rule = cjson.decode(result.name_list_rule) or {},
        name_list_action =  result.name_list_action,
        action_value = result.action_value,
      }
      table.insert(waf_global_name_list_data, tmp_global_name_list_data)
    end
  end

  local waf_global_name_list_item_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_global_name_list_item, user_name)) do
    if not waf_global_name_list_item_data[result['name_list_name']] then
      waf_global_name_list_item_data[result['name_list_name']] = {}
    end
    waf_global_name_list_item_data[result['name_list_name']][result['name_list_item']] = true
  end

  local waf_component_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_component, user_name)) do
    if result.status == 'true' then
      table.insert(waf_component_data, {name = result['name'], conf = cjson.decode(result.conf) or {}, code = result.code})
    end
  end

  local waf_ssl_manage_data = {}
  for _, result in ipairs(filter_by_user(all_data.waf_ssl_manage, user_name)) do
    waf_ssl_manage_data[result['ssl_domain']] = {
      private_key = result.private_key,
      public_key =  result.public_key
      }
  end

  local sys_conf_data = {}
  for _, result in ipairs(filter_by_user(all_data.sys_conf, user_name)) do
    sys_conf_data = {
      log_conf_local_debug = result.log_conf_local_debug,
      log_conf_remote =  result.log_conf_remote,
      log_ip = result.log_ip,
      log_port = result.log_port,
      log_response = result.log_response,
      log_all = result.log_all,
      report_conf = result.report_conf,
      report_conf_ch_host = result.report_conf_ch_host,
      report_conf_ch_port = result.report_conf_ch_port,
      report_conf_ch_user = result.report_conf_ch_user,
      report_conf_ch_password = result.report_conf_ch_password,
      report_conf_ch_database = result.report_conf_ch_database,
      report_conf_ch_table = result.report_conf_ch_table,
      custom_deny_page = result.custom_deny_page,
      waf_deny_code = result.waf_deny_code,
      waf_deny_html = result.waf_deny_html,
      custom_not_find_page = result.custom_not_find_page,
      not_find_code = result.not_find_code,
      not_find_html = result.not_find_html,
      webtds_check = result.webtds_check,
      webtds_node_ip = result.webtds_node_ip,
      webtds_node_port = result.webtds_node_port,
      }
  end

  local waf_domain_conf_data = {}
  for k, v in pairs(waf_domain_data) do
    local group_name = v['group_name']
    waf_domain_conf_data[k] = {}
    waf_domain_conf_data[k]['web_engine_protection_data'] = waf_group_web_engine_protection_data[group_name]
    waf_domain_conf_data[k]['web_rule_protection_data'] = waf_group_web_rule_protection_data[group_name]
    waf_domain_conf_data[k]['web_white_rule_data'] = waf_group_web_white_rule_data[group_name]
    waf_domain_conf_data[k]['web_page_tamper_proof_data'] = waf_group_web_page_tamper_proof_data[group_name]
    waf_domain_conf_data[k]['flow_engine_protection_data'] = waf_group_flow_engine_protection_data[group_name]
    waf_domain_conf_data[k]['flow_rule_protection_data'] = waf_group_flow_rule_protection_data[group_name]
    waf_domain_conf_data[k]['flow_ip_region_block_data'] = waf_group_flow_ip_region_block_data[group_name]
    waf_domain_conf_data[k]['flow_white_rule_data'] = waf_group_flow_white_rules_data[group_name]
    waf_domain_conf_data[k]['custom_request_header_data'] = waf_group_custom_request_header_data[group_name]
    waf_domain_conf_data[k]['custom_response_header_data'] = waf_group_custom_response_header_data[group_name]
    waf_domain_conf_data[k]['custom_response_content_data'] = waf_group_custom_response_content_data[group_name]
    waf_domain_conf_data[k]['custom_upstream_address_data'] = waf_group_custom_upstream_address_data[group_name]
  end

  conf_data['waf_domain_data'] = waf_domain_data
  conf_data['waf_domain_conf_data'] = waf_domain_conf_data
  conf_data['waf_global_name_list_data'] = waf_global_name_list_data
  conf_data['waf_global_name_list_item_data'] = waf_global_name_list_item_data
  conf_data['waf_component_data'] = waf_component_data
  conf_data['waf_ssl_manage_data'] = waf_ssl_manage_data
  conf_data['sys_conf_data'] = sys_conf_data
  return conf_data
end

local function waf_update_conf_data()
  local all_data = {}
  all_data.waf_group_web_engine_protection = get_waf_data("SELECT * FROM jxwaf_waf_group_web_engine_protection;")
  all_data.waf_group_web_rule_protection = get_waf_data("SELECT * FROM jxwaf_waf_group_web_rule_protection ORDER BY rule_order_time ASC;")
  all_data.waf_group_web_white_rule = get_waf_data("SELECT * FROM jxwaf_waf_group_web_white_rule ORDER BY rule_order_time ASC;")
  all_data.waf_group_web_page_tamper_proof = get_waf_data("SELECT * FROM jxwaf_waf_group_web_page_tamper_proof ORDER BY rule_order_time ASC;")
  all_data.waf_group_flow_engine_protection = get_waf_data("SELECT * FROM jxwaf_waf_group_flow_engine_protection;")
  all_data.waf_group_flow_rule_protection = get_waf_data("SELECT * FROM jxwaf_waf_group_flow_rule_protection ORDER BY rule_order_time ASC;")
  all_data.waf_group_flow_ip_region_block = get_waf_data("SELECT * FROM jxwaf_waf_group_flow_ip_region_block;")
  all_data.waf_group_flow_white_rule = get_waf_data("SELECT * FROM jxwaf_waf_group_flow_white_rule ORDER BY rule_order_time ASC;")
  all_data.waf_group_custom_request_header = get_waf_data("SELECT * FROM jxwaf_waf_group_custom_request_header ORDER BY rule_order_time ASC;")
  all_data.waf_group_custom_response_header = get_waf_data("SELECT * FROM jxwaf_waf_group_custom_response_header ORDER BY rule_order_time ASC;")
  all_data.waf_group_custom_response_content = get_waf_data("SELECT * FROM jxwaf_waf_group_custom_response_content ORDER BY rule_order_time ASC;")
  all_data.waf_group_custom_upstream_address = get_waf_data("SELECT * FROM jxwaf_waf_group_custom_upstream_address ORDER BY rule_order_time ASC;")
  all_data.waf_domain = get_waf_data("SELECT * FROM jxwaf_waf_domain;")
  all_data.waf_global_name_list = get_waf_data("SELECT * FROM jxwaf_waf_global_name_list ORDER BY rule_order_time ASC;")
  all_data.waf_global_name_list_item = get_waf_data("SELECT * FROM jxwaf_waf_global_name_list_item;")
  all_data.waf_component = get_waf_data("SELECT * FROM jxwaf_waf_component ORDER BY rule_order_time ASC;")
  all_data.waf_ssl_manage = get_waf_data("SELECT * FROM jxwaf_waf_ssl_manage;")
  all_data.sys_conf = get_waf_data("SELECT * FROM jxwaf_sys_conf;")

  local user_list_sql = "SELECT user_name FROM jxwaf_admin_account;"
  local user_list_result = get_waf_data(user_list_sql)
  if not user_list_result or #user_list_result == 0 then
    return
  end
  
  local waf_update_conf_data = ngx.shared.waf_update_conf_data
  
  for _, user in ipairs(user_list_result) do
    local user_name = user.user_name
    local conf_data = generate_user_conf_data(user_name, all_data)
    local waf_conf_data = cjson.encode(conf_data)
    local waf_conf_md5 = tools.get_md5(waf_conf_data)
    waf_update_conf_data:set(user_name .. ":waf_conf_data", waf_conf_data)
    waf_update_conf_data:set(user_name .. ":waf_conf_md5", waf_conf_md5)
  end
end

local function isIP(str)
    local pattern = [[^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$]]
    local match, err = ngx.re.match(str, pattern)
    if match then
        return true
    else
        return false
    end
end

local function waf_update_domain_source_ip_data()
  local sql = "SELECT * FROM jxwaf_waf_domain ;"
  local query_result,query_error = db_query.query_mysql(sql)
  if not query_result or query_error then
    ngx.log(ngx.ERR,query_error)
    return
  end
  for _,result in ipairs(query_result) do
    local source_ip_result = cjson.decode(result.source_ip or '[]')
    local waf_update_source_ip_table = {}
    if source_ip_result and type(source_ip_result) == 'table' then
        for _,source_ip in ipairs(source_ip_result) do
            local check_ip_result = isIP(source_ip)
            if not check_ip_result then
                 local ip_list = tools.get_dns_resolver_ip(source_ip)
                 if ip_list then
                     for _,ip in ipairs(ip_list) do
                        table.insert(waf_update_source_ip_table,ip)
                     end
                 end
            else
                table.insert(waf_update_source_ip_table,source_ip)
            end
        end
    end
    local waf_update_source_ip = cjson.encode(waf_update_source_ip_table)
    local update_sql = "UPDATE jxwaf_waf_domain  SET  waf_update_source_ip = ? WHERE group_name = ? AND user_name = ? AND domain = ?;"
    local update_sql_params = {waf_update_source_ip,result.group_name,result.user_name,result.domain}
    local update_sql_result,update_sql_error = db_query.query_mysql(update_sql,update_sql_params)
    if not update_sql_result then
        ngx.log(ngx.ERR,update_sql_error)
    end
  end
end

local function name_list_item_delete()
  local sql = "DELETE FROM jxwaf_waf_global_name_list_item WHERE name_list_expire = 'true' and name_list_item_expire_time < UNIX_TIMESTAMP();"
  local sql_query_result,sql_query_error = db_query.query_mysql(sql)
  if not sql_query_result or sql_query_error then
    ngx.log(ngx.ERR,sql_query_error)
  end
end

local function network_ip_delete()
  local block_sql = "DELETE FROM jxwaf_soc_network_ip WHERE expire_time > 0 AND expire_time < UNIX_TIMESTAMP();"
  local block_sql_query_result,block_sql_query_error = db_query.query_mysql(block_sql)
  if not block_sql_query_result or block_sql_query_error then
    ngx.log(ngx.ERR,block_sql_query_error)
  end
end

local function waf_update_model_data()
    local waf_update_conf_data = ngx.shared.waf_update_conf_data

    local model_data = {}

    local model_sync_query = "SELECT * FROM jxwaf_soc_web_protection_model_sync where ai_analysis_result <> '' ORDER BY request_time ASC;"
    local model_sync_result = get_waf_data(model_sync_query)
    for _, result in ipairs(model_sync_result) do
        if result.ai_analysis_result == 'true' then
            model_data[result.token] = cjson.decode(result.attack_type) or result.attack_type
        else
            model_data[result.token] = false
        end
    end

    local model_query = "SELECT * FROM jxwaf_soc_web_protection_model where ai_analysis_result <> '' ORDER BY request_time ASC;"
    local model_result = get_waf_data(model_query)
    for _, result in ipairs(model_result) do
        if result.ai_analysis_result == 'true' then
            model_data[result.token] = cjson.decode(result.attack_type) or result.attack_type
        else
            model_data[result.token] = false
        end
    end

    local model_update_time_query = "SELECT MAX(request_time) as max_time FROM jxwaf_soc_web_protection_model where ai_analysis_result <> '';"
    local model_update_time_result = get_waf_data(model_update_time_query)
    local model_update_time = "0"
    if model_update_time_result and #model_update_time_result > 0 and model_update_time_result[1].max_time and model_update_time_result[1].max_time ~= ngx.null then
        model_update_time = model_update_time_result[1].max_time
    end

    local model_sync_update_time_query = "SELECT MAX(request_time) as max_time FROM jxwaf_soc_web_protection_model_sync where ai_analysis_result <> '';"
    local model_sync_update_time_result = get_waf_data(model_sync_update_time_query)
    if model_sync_update_time_result and #model_sync_update_time_result > 0 and model_sync_update_time_result[1].max_time and model_sync_update_time_result[1].max_time ~= ngx.null then
        if model_sync_update_time_result[1].max_time > model_update_time then
            model_update_time = model_sync_update_time_result[1].max_time
        end
    end

    waf_update_conf_data:set("model_data", cjson.encode(model_data))
    waf_update_conf_data:set("model_update_time", model_update_time)
end

local function ai_model_analysis()
    local model_query = "SELECT * FROM jxwaf_soc_web_protection_model where ai_analysis_result = '' order by request_time limit 100;"
    local model_result = get_waf_data(model_query)
    local host = init_config['jxwaf_model_server_host']
    local port = init_config['jxwaf_model_server_port']
    for _, result in ipairs(model_result) do
        local model_data = {
            token = result['token'],
            raw_string = result['raw_string']
        }
        local query_result, err = tools.jxwaf_model_query(model_data, host, port)
        if query_result and query_result.status == "ok" then
            local ai_analysis_result = query_result.result
            if ai_analysis_result == "none" then
                ai_analysis_result = ''
            end
            if ai_analysis_result ~= '' then
                local attack_type = query_result.attack_type
                if attack_type == cjson.null then
                    attack_type = {}
                end
                local attack_type_json = cjson.encode(attack_type or {})
                local update_sql = "UPDATE jxwaf_soc_web_protection_model SET ai_analysis_result = ?, attack_type = ? WHERE token = ?;"
                local update_params = {ai_analysis_result, attack_type_json, result['token']}
                db_query.query_mysql(update_sql, update_params)
            end
        else
            ngx.log(ngx.ERR, "jxwaf_model_query failed: ", err)
        end
    end
end

local function ai_model_sync()
    local sync_data, err = tools.jxwaf_model_sync()
    if not sync_data then
        ngx.log(ngx.ERR, "jxwaf_model_sync failed: ", err)
        return
    end
    for _, v in ipairs(sync_data) do
        local token = v['token']
        local attack_type = v['attack_type']
        if attack_type == cjson.null then
            attack_type = {}
        end
        local attack_type_json = cjson.encode(attack_type or {})
        local ai_analysis_result = v['result']
        if ai_analysis_result == "none" then
            ai_analysis_result = ''
        end
        local last_updated = v['last_updated']

        local create_sql = "INSERT INTO jxwaf_soc_web_protection_model_sync (token, attack_type, ai_analysis_result, request_time) VALUES (?,?,?,?);"
        local create_sql_params = {token, attack_type_json, ai_analysis_result, last_updated}
        local create_result, create_err = db_query.query_mysql(create_sql, create_sql_params)
        if not create_result then
            ngx.log(ngx.ERR, create_err)
        end
    end
end

if process.type() == "privileged agent" then
  ngx.timer.at(0,create_database)
  ngx.timer.at(2,create_jxwaf_admin_account)
  ngx.timer.at(2,create_jxwaf_waf_domain_group)
  -- protection
  ngx.timer.at(2,create_jxwaf_waf_group_web_engine_protection)
  ngx.timer.at(2,create_jxwaf_waf_group_web_rule_protection)
  ngx.timer.at(2,create_jxwaf_waf_group_web_white_rule)
  ngx.timer.at(2,create_jxwaf_waf_group_web_page_tamper_proof)
  ngx.timer.at(2,create_jxwaf_waf_group_flow_engine_protection)
  ngx.timer.at(2,create_jxwaf_waf_group_flow_rule_protection)
  ngx.timer.at(2,create_jxwaf_waf_group_flow_ip_region_block)
  ngx.timer.at(2,create_jxwaf_waf_group_flow_white_rule)
  ngx.timer.at(2,create_jxwaf_waf_domain)
  -- custom_upstream
  ngx.timer.at(2,create_jxwaf_waf_group_custom_request_header)
  ngx.timer.at(2,create_jxwaf_waf_group_custom_response_header)
  ngx.timer.at(2,create_jxwaf_waf_group_custom_response_content)
  ngx.timer.at(2,create_jxwaf_waf_group_custom_upstream_address)
  -- global_name_list
  ngx.timer.at(2,create_jxwaf_waf_global_name_list)
  ngx.timer.at(2,create_jxwaf_waf_global_name_list_item)
  -- component
  ngx.timer.at(2,create_jxwaf_waf_component)
  -- sys
  ngx.timer.at(2,create_jxwaf_waf_ssl_manage)
  ngx.timer.at(2,create_jxwaf_sys_conf)
  -- monitor
  ngx.timer.at(2,create_jxwaf_node_monitor)
  -- soc
  ngx.timer.at(2,create_jxwaf_soc_network_ip)
  ngx.timer.at(2,create_jxwaf_soc_network_ip_node_update)
  -- ai model
  ngx.timer.at(2,create_jxwaf_soc_web_protection_model)
  ngx.timer.at(2,create_jxwaf_soc_web_protection_model_sync)

  local waf_update_conf_data_hdl, waf_update_conf_data_err = ngx.timer.every(3,waf_update_conf_data)
  if waf_update_conf_data_err then
    ngx.log(ngx.ERR, "failed to create the waf_update_conf_data worker update timer: ", waf_update_conf_data_err)
  end

  local waf_update_domain_source_ip_data_hdl, waf_update_domain_source_ip_data_err = ngx.timer.every(60,waf_update_domain_source_ip_data)
  if waf_update_domain_source_ip_data_err then
    ngx.log(ngx.ERR, "failed to create the waf_update_domain_source_ip_data worker update timer: ", waf_update_domain_source_ip_data_err)
  end

  local name_list_item_delete_hdl, name_list_item_delete_err = ngx.timer.every(3,name_list_item_delete)
  if name_list_item_delete_err then
    ngx.log(ngx.ERR, "failed to create the name_list_item_delete worker update timer: ", name_list_item_delete_err)
  end

  local network_ip_delete_hdl, network_ip_delete_err = ngx.timer.every(3,network_ip_delete)
  if network_ip_delete_err then
    ngx.log(ngx.ERR, "failed to create the network_ip_delete worker update timer: ", network_ip_delete_err)
  end

  local waf_update_model_data_hdl, waf_update_model_data_err = ngx.timer.every(3,waf_update_model_data)
  if waf_update_model_data_err then
    ngx.log(ngx.ERR, "failed to create the waf_update_model_data worker update timer: ", waf_update_model_data_err)
  end

  if init_config['jxwaf_model_server_host'] and init_config['jxwaf_model_server_port']  then
      local ai_model_analysis_hdl, ai_model_analysis_err = ngx.timer.every(5,ai_model_analysis)
      if ai_model_analysis_err then
        ngx.log(ngx.ERR, "failed to create the ai_model_analysis worker update timer: ", ai_model_analysis_err)
      end
      local ai_model_sync_hdl, ai_model_sync_err = ngx.timer.every(5,ai_model_sync)
      if ai_model_sync_err then
        ngx.log(ngx.ERR, "failed to create the ai_model_sync worker update timer: ", ai_model_sync_err)
      end
  end

end