local http = require "resty.jxwaf.http"
local request = require "resty.jxwaf.request" 
local cjson = require "cjson.safe"
local b64 = require("ngx.base64")
local uuid = require "resty.jxwaf.uuid"
local aes = require "resty.aes"
local math_randomseed = math.randomseed
local math_random = math.random

local _M = {}
_M.version = ""


local default_block_code = 403

local default_block_html = [=[<!DOCTYPE html>
<html lang="cn">
<head>
    <meta charset="utf-8">
    <title>JXWAF拦截页面</title>
    <meta name="keywords" content="JXWAF,JXWAF控制台,WAF,锦衣盾,Web应用防火墙" />
    <meta name="description" content="JXWAF，开源Web应用防火墙" />
    <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black">
    <meta name="screen-orientation" content="portrait">
    <meta name="x5-orientation" content="portrait">
    <meta name="full-screen" content="no">
    <meta name="x5-fullscreen" content="true">
    <meta name="x5-page-mode" content="app">
    <meta name="msapplication-tap-highlight" content="no">
    <meta name="renderer" content="webkit">
    <meta name="referrer" content="always">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <!-- 替换 favicon 为外部 URL（也可继续保留原 base64，这里一并替换为同一个 URL） -->
    <link rel="shortcut icon" href="https://static.jxwaf.top/logo.jpg">
    <style>
        html {
            height: 100%;
        }
        body {
            margin: 0;
            height: 100%;
        }
        .container {
            text-align: center;
            word-break: keep-all;
            height: 100%;
            width: 100%;
            background: white;
            font-size: 14px;
            min-height: 480px;
            position: relative;
        }
        .content {
            width: 100%;
            height: 100%;
        }
        .logo {
            text-align: center;
        }
        .intercepted {
            margin-top: 1.5rem;
            margin-bottom: 1.5rem;
            font-size: 20px;
            line-height: 1.6;
            color: black;
        }
        .intercepted-tips {
            margin: 8px 0;
            font-size: 14px;
            color: rgba(0, 0, 0, 0.7);
        }
        .intercepted-item {
            margin: 8px 0;
            color: rgba(0, 0, 0, 0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <table class="content">
            <tr>
                <td>
                    <div class="logo">
                        <!-- 替换 logo 图片为外部 URL -->
                        <img style="width: 150px;" src="https://static.jxwaf.top/logo.png" />
                    </div>
                    <div class="intercepted">
                        当前请求存在风险,已被拦截
                    </div>
                    <div class="intercepted-item">请求ID: {{request_uuid}}</div>
                    <div class="intercepted-item">
                        <span>拦截时间</span>: <span id="nowTime"></span>
                    </div>
                </td>
            </tr>
        </table>
    </div>
</body>
<script>
    function timestring() {
      var d = new Date();
      function p(d) {
        return d < 10 ? "0" + d : d;
      }
      return (
        d.getFullYear() +
        "-" +
        p(d.getMonth() + 1) +
        "-" +
        p(d.getDate()) +
        " " +
        p(d.getHours()) +
        ":" +
        p(d.getMinutes())
      );
    }
    document.getElementById("nowTime").innerText = timestring();
  </script>
</html>]=]

function _M.block(page_conf)
  local code = page_conf['code']
  local html = page_conf['html']
  local request_uuid = ngx.ctx.request_uuid
  ngx.header.request_uuid = request_uuid
  ngx.header.content_type = "text/html;charset=utf-8"
  if code and html then
    if #html > 0 then
       local output = string.gsub(html, "{{request_uuid}}", request_uuid)
       ngx.status = tonumber(code)
       ngx.say(output)
       return ngx.exit(tonumber(code))
    else
       ngx.status = tonumber(code)
       ngx.say("")
       return ngx.exit(tonumber(code))
    end
  else
    code = default_block_code
    local output = string.gsub(default_block_html, "{{request_uuid}}", request_uuid)
    ngx.status = tonumber(code)
    ngx.say(output)
    return ngx.exit(tonumber(code))
  end
end

function _M.not_find(page_conf)
  local code = page_conf['code']
  local html = page_conf['html']
  local request_uuid = ngx.ctx.request_uuid
  ngx.header.request_uuid = request_uuid
  ngx.header.content_type = "text/html;charset=utf-8"
  ngx.status = tonumber(code)
  if #html > 0 then
    ngx.say(html)
  else
    ngx.say("")
  end
  return ngx.exit(tonumber(code))
end

function _M.allow()
  return ngx.exit(0)
end

function _M.page_tamper_proof(cache_content_type,cache_page_content)
  local request_uuid = ngx.ctx.request_uuid
  ngx.header.request_uuid = request_uuid
  ngx.header.content_type = cache_content_type
  ngx.status = 200
  ngx.say(cache_page_content)
  return ngx.exit(200)
end

function _M.reject_response()
  return ngx.exit(444)
end


function _M.network_block(config_info,ip,expire_time)
  if not expire_time then
    return 
  end
  local expire_seconds = tonumber(expire_time)
  if not expire_seconds or expire_seconds <= 0 then
      return
  end
  local jxwaf_inner = ngx.shared.jxwaf_inner
  local network_block_key = "network_block"..ip
  local network_block_result = jxwaf_inner:get(network_block_key)
  if network_block_result then
    return ngx.exit(444)
  end
  local network_block_website = config_info.jxwaf_server.."/network_block"
  local httpc = http.new()
  httpc:set_timeouts(3000, 3000, 5000)
  local api_key = config_info.waf_auth or ""
  local post_data = {}
  post_data['waf_auth'] = api_key
  post_data['ip'] = ip
  post_data['expire_time'] = ngx.time() + tonumber(expire_time)
  post_data['operator_type'] = "auto_create"
  local res, err = httpc:request_uri( network_block_website , {
    method = "POST",
    body = cjson.encode(post_data)
  })
  if res then
      local res_body = cjson.decode(res.body)
      if  res_body and res_body['result'] == true  then
        jxwaf_inner:set(network_block_key,true,tonumber(expire_time))
      else
        ngx.log(ngx.ERR,"result is fail,message is : ", res.body)
      end
  else
    ngx.log(ngx.ERR,"failed to request: ", err)
  end
  return ngx.exit(444)
end


function _M.token_ai_analysis(premature,config_info,token,raw_string,model_provider,model_api_key,host,uri,src_ip)
  local jxwaf_inner = ngx.shared.jxwaf_inner
  local check_key = "ai_analysis"..token
  local check_key_result = jxwaf_inner:get(check_key)
  if check_key_result then
    return
  end
  jxwaf_inner:set(check_key,true,60)

  local website = config_info.jxwaf_server.."/token_ai_analysis"
  local httpc = http.new()
  local post_data = {}
  post_data['waf_auth'] = config_info.waf_auth
  post_data['token'] = token
  post_data['raw_string'] = raw_string
  post_data['host'] = host
  post_data['uri'] = uri
  post_data['request_time'] = ngx.localtime()
  post_data['src_ip'] = src_ip
  post_data['model_provider'] = model_provider
  post_data['model_api_key'] = model_api_key

  local res, err = httpc:request_uri( website , {
    method = "POST",
    body = cjson.encode(post_data)
  })
  if res then
      local res_body = cjson.decode(res.body)
      if  not res_body then
        ngx.log(ngx.ERR,"result is fail,message is : ", res.body)
        return
      end
  else
    ngx.log(ngx.ERR,"failed to request: ", err)
  end
end


-- cc_auth_check

local default_bot_auto_check_html = [=[<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>安全验证 - 普通验证</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: linear-gradient(90deg, #155799, #159957);
        min-height: 100vh;
        overflow: hidden;
      }

      .bg-decoration {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: 
          radial-gradient(circle at 20% 80%, rgba(255, 255, 255, 0.1) 0%, transparent 50%),
          radial-gradient(circle at 80% 20%, rgba(255, 255, 255, 0.1) 0%, transparent 50%),
          radial-gradient(circle at 40% 40%, rgba(255, 255, 255, 0.05) 0%, transparent 30%);
        pointer-events: none;
        z-index: 0;
      }
      .bg-decoration::before, .bg-decoration::after {
          content: '';
          position: absolute;
          border-radius: 50%;
          background: rgba(255, 255, 255, 0.1);
      }
      .bg-decoration::before {
          width: 300px;
          height: 300px;
          top: -100px;
          left: -100px;
      }
      .bg-decoration::after {
          width: 200px;
          height: 200px;
          bottom: -50px;
          right: -50px;
      }

      .verification-container {
        position: relative;
        z-index: 1;
        width: 100%;
        height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
      }

      .verification-card {
        background: rgba(255, 255, 255, 0.95);
        border-radius: 16px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        width: 100%;
        max-width: 348px;
        overflow: hidden;
        backdrop-filter: blur(10px);
      }

      .card-header {
        display: flex;
        align-items: center;
        padding: 20px 24px;
        border-bottom: 1px solid rgba(0, 0, 0, 0.05);
        gap: 12px;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
      }

      .header-icon {
        width: 50px;
        height: 50px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        flex-shrink: 0;
      }

      .header-icon img {
        width: 100%;
        height: 100%;
        object-fit: cover;
        border-radius: 12px;
      }

      .header-text {
        flex: 1;
      }

      .header-text h3 {
        font-size: 16px;
        font-weight: 600;
        color: #1a1a2e;
        margin-bottom: 2px;
      }

      .header-text p {
        font-size: 12px;
        color: #6c757d;
      }

      .card-body {
        padding: 24px;
      }

      .md5-container {
        width: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 120px;
      }

      .md5-content {
        text-align: center;
      }

      .loading-spinner {
        width: 48px;
        height: 48px;
        border: 4px solid #f3f3f3;
        border-top: 4px solid #3a7dbc;
        border-radius: 50%;
        margin: 0 auto 20px;
        animation: spin 1s linear infinite;
      }

      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }

      #md5-info {
        font-size: 16px;
        color: #333;
        opacity: 1;
        transition: opacity 0.3s ease;
      }

      .footer-hint {
        padding: 16px 24px;
        background: #f8f9fa;
        border-top: 1px solid #f0f0f0;
      }

      .footer-hint p {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        font-size: 12px;
        color: #868e96;
      }

      .footer-hint svg {
        width: 14px;
        height: 14px;
        fill: #868e96;
      }

      .success-modal {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s ease;
      }

      .success-modal.show {
        opacity: 1;
        visibility: visible;
      }

      .success-content {
        background: white;
        padding: 40px 60px;
        border-radius: 16px;
        text-align: center;
        transform: scale(0.8);
        transition: transform 0.3s ease;
      }

      .success-modal.show .success-content {
        transform: scale(1);
      }

      .success-icon {
        width: 80px;
        height: 80px;
        background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 20px;
      }

      .success-icon svg {
        width: 40px;
        height: 40px;
        fill: white;
      }

      .success-content h2 {
        font-size: 24px;
        color: #1a1a2e;
        margin-bottom: 8px;
      }

      .success-content p {
        font-size: 14px;
        color: #666;
      }
    </style>
  </head>
  <body>
    <div class="bg-decoration"></div> 
    <div class="verification-container">
      <div class="verification-card">
        <div class="card-header">
          <div class="header-icon">
            <img src="https://static.jxwaf.top/logo.jpg" alt="Logo" />
          </div>
          <div class="header-text">
            <h3>安全验证</h3>
            <p>正在自动检测访问环境</p>
          </div>
        </div>
        <div class="card-body">
          <div class="md5-container">
            <div class="md5-content">
              <div class="loading-spinner"></div>
              <p id="md5-info">安全检测中…</p>
            </div>
          </div>
        </div>
        <div class="footer-hint">
          <p>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
              <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
            </svg>
            系统正在验证您的访问
          </p>
        </div>
      </div>
    </div>

    <div class="success-modal" id="successModal">
      <div class="success-content">
        <div class="success-icon">
          <svg viewBox="0 0 24 24">
            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
          </svg>
        </div>
        <h2>验证成功</h2>
        <p>您已通过安全验证</p>
      </div>
    </div>
    <script type="text/javascript" src="{{CC_JS_URL}}.js"></script>
  </body>
</html>
]=]


local default_bot_slipper_check_html = [=[<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>安全验证 - 滑块验证</title>
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(90deg, #155799, #159957);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        overflow: hidden;
      }
      .bg-decoration {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        overflow: hidden;
        z-index: 0;
      }
      .bg-decoration::before, .bg-decoration::after {
        content: '';
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.1);
      }
      .bg-decoration::before { width: 300px; height: 300px; top: -100px; left: -100px; }
      .bg-decoration::after { width: 200px; height: 200px; bottom: -50px; right: -50px; }
      .verification-container { position: relative; z-index: 1; }
      .verification-card {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(20px);
        border-radius: 20px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(255, 255, 255, 0.1);
        overflow: hidden;
      }
      .card-header {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        padding: 20px 24px;
        border-bottom: 1px solid rgba(0, 0, 0, 0.05);
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .header-icon { width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center; overflow: hidden; }
      .header-icon img { width: 100%; height: 100%; object-fit: contain; border-radius: 12px; }
      .header-text { flex: 1; }
      .header-text h3 { font-size: 16px; font-weight: 600; color: #1a1a2e; margin-bottom: 2px; }
      .header-text p { font-size: 12px; color: #6c757d; }
      .card-body { position: relative; padding: 24px; }
      .input-content { text-align: center; }
      .input-content > p { display: none; }
      .md5-input { display: flex; justify-content: center; padding: 0 !important; }
      #drag-verify-box {
        position: relative;
        text-align: center;
        line-height: 40px;
        background: #f7f9fa;
        color: #45494c;
        border-radius: 2px;
        max-width: 300px !important;
        height: 40px !important;
        border: 1px solid #e6e8eb;
      }
      #drag-verify-box .bgColor {
        position: absolute;
        left: 0;
        top: 0;
        height: 40px;
        background: #D1E9FE;
        border-radius: 2px;
      }
      #drag-verify-box .txt {
        position: absolute;
        width: 100%;
        height: 40px;
        line-height: 40px;
        font-size: 14px;
        color: #45494c;
        user-select: none;
      }
      #drag-verify-box .slider {
        position: absolute;
        left: 0;
        top: 0;
        width: 40px !important;
        height: 40px !important;
        background: #fff;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 0 3px rgba(0, 0, 0, 0.3);
        transition: background 0.2s linear;
      }
      #drag-verify-box .slider:hover { background: #1991FA; }
      #drag-verify-box .slider:hover span { color: #fff; }
      .sliderIcon { display: flex; align-items: center; justify-content: center; }
      #md5-button {
        text-decoration: none;
        width: 300px;
        height: 40px;
        display: inline-block;
        color: #fefefe;
        background-color: #1991FA;
        line-height: 40px;
        text-align: center;
        border-radius: 4px;
        margin-top: 16px;
        transition: background-color 0.2s linear;
      }
      #md5-button:hover { background-color: #0d7dd9; }
      .footer-hint {
        text-align: center;
        padding: 16px 24px;
        background: #f8f9fa;
        border-top: 1px solid rgba(0, 0, 0, 0.05);
      }
      .footer-hint p {
        font-size: 12px;
        color: #868e96;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
      }
      .footer-hint svg { width: 14px; height: 14px; fill: #868e96; }
      #md5-info {
        font-size: 16px !important;
        color: #333;
        text-align: center;
        background: #f8f9fa;
        border-radius: 12px;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        opacity: 0;
      }
    </style>
  </head>
  <body>
    <div class="bg-decoration"></div>
    
    <div class="verification-container">
      <div class="verification-card">
        <div class="card-header">
          <div class="header-icon">
            <img src="https://static.jxwaf.top/logo.jpg" alt="Logo" />
          </div>
          <div class="header-text">
            <h3>安全验证</h3>
            <p>请完成下方验证以继续操作</p>
          </div>
        </div>
        <div class="card-body">
          <div class="input-content">
              <p style="font-weight: bold;">请滑动滑块进行人机识别</p>
              <div style="display: flex; justify-content: center; padding: 20px;" class="md5-input"> 
                <div id="drag-verify-box" onselectstart="return false;" style="position: relative;width: 310px;height: 40px;background-color: #eee;">
                  <div class="bgColor" style="position: absolute;left: 0;top: 0;width: 40px;height: 40px;background-color: #76c61d;"></div>
                  <div class="txt" style="position: absolute;width: 100%;height: 40px;line-height: 40px;font-size: 14px;color: #333;">请按住滑块，拖动到最右侧</div>
                  <div class="slider">
                    <span class="sliderIcon"><svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6-1.41-1.41z"></path></svg></span>
                  </div>
                </div>
              </div>
              <a id="md5-button" href="javascript:;">确定</a>
          </div>
          <p style="font-size: 20px; opacity: 0;" id="md5-info">验证中，请稍等……</p>
        </div>
        <div class="footer-hint">
          <p>
            <svg viewBox="0 0 24 24">
              <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
            </svg>
            拖动滑块完成人机验证
          </p>
        </div>
      </div>
    </div>
    <script type="text/javascript" src="{{CC_JS_URL}}.js"></script>
  </body>
</html>
]=]

local default_bot_puzzle_check_html = [=[<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>安全验证 - 滑块拼图验证</title>
    <style>
        body {
        overflow-x: hidden;
        }

        .block {
        position: absolute;
        left: 0;
        top: 0;
        }

        .sliderContainer {
        position: relative;
        text-align: center;
        line-height: 40px;
        background: #f7f9fa;
        color: #45494c;
        border-radius: 2px;
        }

        .sliderbg {
        position: absolute;
        left: 0;
        right: 0;
        top: 0;
        background-color: #f7f9fa;
        height: 40px;
        border-radius: 2px;
        border: 1px solid #e6e8eb;
        }

        .sliderContainer_active .slider {
        border: 1px solid #1991FA;
        }

        .sliderContainer_success .slider {
        border: 1px solid #52CCBA;
        background-color: #52CCBA !important;
        }

        .sliderContainer_success .sliderMask {
        background-color: #D2F4EF;
        }

        .sliderContainer_fail .slider {
        border: 1px solid #f57a7a;
        background-color: #f57a7a !important;
        }

        .sliderContainer_fail .sliderMask {
        background-color: #fce1e1;
        }

        .sliderContainer_fail .sliderIcon svg {
        fill: #fff;
        }

        .sliderContainer_active .sliderText,
        .sliderContainer_success .sliderText,
        .sliderContainer_fail .sliderText {
        z-index: -1;
        }

        .sliderMask {
        position: absolute;
        left: 0;
        top: 0;
        height: 40px;
        border: 0 solid #1991FA;
        background: #D1E9FE;
        border-radius: 2px;
        }

        .slider {
        position: absolute;
        top: 0;
        left: 0;
        width: 40px;
        height: 40px;
        background: #fff;
        box-shadow: 0 0 3px rgba(0, 0, 0, 0.3);
        cursor: pointer;
        transition: background .2s linear;
        border-radius: 2px;
        display: flex;
        align-items: center;
        justify-content: center;
        }

        .slider:hover {
        background: #1991FA;
        }

        .slider:hover .sliderIcon svg {
        fill: #fff;
        }

        .sliderText {
        position: relative;
        
        }

        .sliderIcon {
        display: flex;
        align-items: center;
        justify-content: center;
        }

        .sliderIcon svg {
        fill: #45494c;
        transition: fill 0.2s linear;
        }

        .sliderContainer_success .sliderIcon svg {
        fill: #fff;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(90deg,#155799,#159957);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            overflow: hidden;
        }

        .bg-decoration {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            overflow: hidden;
            z-index: 0;
        }

        .bg-decoration::before,
        .bg-decoration::after {
            content: '';
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.1);
        }

        .bg-decoration::before {
            width: 300px;
            height: 300px;
            top: -100px;
            left: -100px;
        }

        .bg-decoration::after {
            width: 200px;
            height: 200px;
            bottom: -50px;
            right: -50px;
        }

        .verification-container {
            position: relative;
            z-index: 1;
        }

        .verification-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            box-shadow: 
                0 25px 50px -12px rgba(0, 0, 0, 0.25),
                0 0 0 1px rgba(255, 255, 255, 0.1);
            overflow: hidden;
        }

        .card-header {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px 24px;
            border-bottom: 1px solid rgba(0, 0, 0, 0.05);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .header-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .header-icon svg {
            width: 22px;
            height: 22px;
            fill: white;
        }

        .header-icon img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            border-radius: 12px;
        }

        .header-text {
            flex: 1;
        }

        .header-text h3 {
            font-size: 16px;
            font-weight: 600;
            color: #1a1a2e;
            margin-bottom: 2px;
        }

        .header-text p {
            font-size: 12px;
            color: #6c757d;
        }

        .header-refresh {
            width: 36px;
            height: 36px;
            background: rgb(198, 226, 255);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            color: #409EFF;
            transition: all 0.3s ease;
        }

        .header-refresh:hover {
            transform: rotate(180deg);
        }

        .card-body {
            padding: 24px;
        }

        .slidercaptcha {
            width: 300px;
        }

        .slidercaptcha canvas:first-child {
            border-radius: 0;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .footer-hint {
            text-align: center;
            padding: 16px 24px;
            background: #f8f9fa;
            border-top: 1px solid rgba(0, 0, 0, 0.05);
        }

        .footer-hint p {
            font-size: 12px;
            color: #868e96;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }

        .footer-hint svg {
            width: 14px;
            height: 14px;
            fill: #868e96;
        }

        .brand {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            color: rgba(255, 255, 255, 0.7);
            font-size: 13px;
            z-index: 1;
        }

        .success-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }

        .success-modal.show {
            display: flex;
        }

        .success-content {
            background: white;
            padding: 40px 50px;
            border-radius: 20px;
            text-align: center;
        }

        .success-icon {
            width: 70px;
            height: 70px;
            background: linear-gradient(135deg, #52CCBA 0%, #38b2ac 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 10px 30px rgba(82, 204, 186, 0.4);
        }

        .success-icon svg {
            width: 35px;
            height: 35px;
            fill: white;
        }

        .success-content h2 {
            font-size: 22px;
            color: #1a1a2e;
            margin-bottom: 8px;
        }

        .success-content p {
            color: #6c757d;
            font-size: 14px;
        }
    </style>
</head>

<body>
    <div class="bg-decoration"></div>
    
    <div class="verification-container">
        <div class="verification-card">
            <div class="card-header">
                <div class="header-icon">
                    <img src="https://static.jxwaf.top/logo.jpg" alt="Logo" />
                </div>
                <div class="header-text">
                    <h3>安全验证</h3>
                    <p>请完成下方验证以继续操作</p>
                </div>
                <span class="header-refresh" id="refreshBtn">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                        <path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
                    </svg>
                </span>
            </div>
            <div class="card-body">
                <div class="slidercaptcha">
                    <div id="captcha"></div>
                </div>
            </div>
            <div class="footer-hint">
                <p>
                    <svg viewBox="0 0 24 24">
                        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                    </svg>
                    拖动滑块完成人机验证
                </p>
            </div>
        </div>
    </div>

    <div class="success-modal" id="successModal">
        <div class="success-content">
            <div class="success-icon">
                <svg viewBox="0 0 24 24">
                    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
                </svg>
            </div>
            <h2>验证成功</h2>
            <p>您已通过安全验证</p>
        </div>
    </div>

    <script type="text/javascript" src="{{CC_JS_URL}}.js"></script>
</body>

</html>
]=]

local default_bot_words_check_html = [=[<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>安全验证 - 文字点击验证</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(90deg,#155799,#159957);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            overflow-x: hidden;
        }
        .bg-decoration {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            overflow: hidden;
            z-index: 0;
        }
        .bg-decoration::before, .bg-decoration::after {
            content: '';
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.1);
        }
        .bg-decoration::before { width: 300px; height: 300px; top: -100px; left: -100px; }
        .bg-decoration::after { width: 200px; height: 200px; bottom: -50px; right: -50px; }
        .verification-container { position: relative; z-index: 1; }
        .verification-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(255, 255, 255, 0.1);
            overflow: hidden;
        }
        .card-header {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px 24px;
            border-bottom: 1px solid rgba(0, 0, 0, 0.05);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header-icon { width: 50px; height: 50px; border-radius: 12px; display: flex; align-items: center; justify-content: center; }
        .header-icon img { width: 100%; height: 100%; object-fit: contain; border-radius: 12px; }
        .header-text { flex: 1; }
        .header-text h3 { font-size: 16px; font-weight: 600; color: #1a1a2e; margin-bottom: 2px; }
        .header-text p { font-size: 12px; color: #6c757d; }
        .header-refresh {
            width: 36px;
            height: 36px;
            background: rgb(198, 226, 255);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            color: #409EFF;
            transition: all 0.3s ease;
        }
        .header-refresh:hover {
            background: rgba(64, 158, 255, 0.2);
            transform: rotate(180deg);
        }
        .card-body { padding: 24px; }
        .points-verify-wrapper { width: 300px; }
        .footer-hint {
            text-align: center;
            padding: 16px 24px;
            background: #f8f9fa;
            border-top: 1px solid rgba(0, 0, 0, 0.05);
        }
        .footer-hint p {
            font-size: 12px;
            color: #868e96;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }
        .footer-hint svg { width: 14px; height: 14px; fill: #868e96; }
        .success-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .success-modal.show { display: flex; }
        .success-content {
            background: white;
            padding: 40px 50px;
            border-radius: 20px;
            text-align: center;
        }
        .success-icon {
            width: 70px;
            height: 70px;
            background: linear-gradient(135deg, #52CCBA 0%, #38b2ac 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 10px 30px rgba(82, 204, 186, 0.4);
        }
        .success-icon svg { width: 35px; height: 35px; fill: white; }
        .success-content h2 { font-size: 22px; color: #1a1a2e; margin-bottom: 8px; }
        .success-content p { color: #6c757d; font-size: 14px; }
        .verify-img-out { position: relative; }
        .verify-img-panel {
            margin: 0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border: none;
            position: relative;
        }
        .verify-img-panel canvas { display: block; border-radius: 8px; }
        .verify-bar-area {
            position: relative;
            background: #f7f9fa;
            text-align: center;
            border-radius: 8px;
            margin-top: 12px;
            border: 1px solid #e6e8eb;
            line-height: 40px;
        }
        .verify-bar-area .verify-msg { color: #45494c; font-size: 14px; }
        .point-area {
            background: linear-gradient(135deg, #52CCBA 0%, #38b2ac 100%) !important;
            color: #fff !important;
            z-index: 9999;
            width: 30px !important;
            height: 30px !important;
            text-align: center;
            line-height: 30px !important;
            border-radius: 50%;
            position: absolute;
            font-weight: 600;
            box-shadow: 0 2px 8px rgba(82, 204, 186, 0.4);
        }
    </style>
</head>
<body>
    <div class="bg-decoration"></div>
    
    <div class="verification-container">
        <div class="verification-card">
            <div class="card-header">
                <div class="header-icon">
                    <img src="https://static.jxwaf.top/logo.jpg" alt="Logo" />
                </div>
                <div class="header-text">
                    <h3>安全验证</h3>
                    <p>请完成下方验证以继续操作</p>
                </div>
                <span class="header-refresh" id="refreshBtn">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                        <path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
                    </svg>
                </span>
            </div>
            <div class="card-body">
                <div class="points-verify-wrapper">
                    <div id="mpanel6"></div>
                </div>
            </div>
            <div class="footer-hint">
                <p>
                    <svg viewBox="0 0 24 24">
                        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                    </svg>
                    按顺序点击图中文字
                </p>
            </div>
        </div>
    </div>

    <div class="success-modal" id="successModal">
        <div class="success-content">
            <div class="success-icon">
                <svg viewBox="0 0 24 24">
                    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
                </svg>
            </div>
            <h2>验证成功</h2>
            <p>您已通过安全验证</p>
        </div>
    </div>
    <script type="text/javascript" src="{{CC_JS_URL}}.js"></script>
</body>
</html>]=]


local bot_check_info_auto = {
    ["fc8d8a75510149f9851293a45d5e0c5b"] = "5954628888346560243",
    ["0d9bbaab6ac0495c8f75c2b29c95bab9"] = "5021808915391271474",
    ["834d137b5768411cae037744d1dbcbb0"] = "9334828446213960351",
    ["0aff91586ab54a2ab6b867e8d603f679"] = "5723358538571845245",
    ["2aa829659077491fa3d5bd30b62118ec"] = "8456888652011581203",
    ["6f91c4a2bbb14ca4b7ee4a955ea0470a"] = "9998598901095544174",
    ["e18529c362444edea88ad5dcf2483537"] = "9115868135549192512",
    ["9558a26e13664ef393768d15350f9e06"] = "7170898427080754095",
    ["cda1bf79f0e74c90a7dcb3d4a3b7d9df"] = "7241718525017790305",
    ["0f1ef4c0111e47b7b1f66660f7a735ef"] = "8673498826859492422",
    ["49219da53ecc49e8b37e8aff665bfec6"] = "7277268571015279025",
    ["bb70a3d0e924441a9fad3295e01a70ce"] = "9185608596181285702",
    ["2ad632ef24ab456ba2f9fa17c443ddb6"] = "5474768102089549244",
    ["13211d4e39d24d4a98baa669487e6168"] = "6610668007464321530",
    ["a23afddb07174ba1b5aeccb91c772e56"] = "5988388908827065532",
    ["9d637c3ece30414caa6ca3c9026af6b4"] = "7339418059098288635",
    ["85cb71481ea14a7dab2425e8f0523539"] = "8988068820835866626",
    ["990dce5d909149c3af11146b46e36709"] = "8753188758797789562",
    ["dbedbf8604714ca49c2be9a65a2567f1"] = "8873008879645158440",
    ["46ec3b609ee0435d80fa5341287c675f"] = "5031188973291134295",
    ["5cffddfadc144267b89d62648d5be5f9"] = "9343788505755526956",
    ["ead0725c927d491db01c861c8c852bde"] = "783183875365326158",
    ["1c6a4c7ef7e14d9a8c51e425a527cd69"] = "8040188241049487079",
    ["f3fc5345ad7b448a830b7104f85f6391"] = "6117698052147223521",
    ["8e28af7141df4f568bd82483f8ba7062"] = "5374638608628401688",
    ["d8e88d8be8d3483aaaccca89f1b53182"] = "5276478314754137259",
    ["429c1b159ee946eea4734d6eb31b3a96"] = "9494958661621858252",
    ["58c9330a0c1b4314bd7c1c4b086b627e"] = "6032138677164067134",
    ["79926c7b0df64a5f942b8e5a0d507d51"] = "6413778028956369776",
    ["5416ece45cbc43a69a2d5e5022e784e6"] = "9581628009644759023",
    ["9015972e3f4941e4bdd036da9c3db690"] = "7127998483155811103",
    ["6e82efa53eb64023a37fca4e06fab758"] = "7276128599822540246",
    ["47701c6e9545473fab9cb96dad840cd6"] = "928843880467173353",
    ["23d4e81a53d3476e863546b6ea831fac"] = "7027888486755286102",
    ["6435c314924241399606f21a20ecb828"] = "6480018345198080438",
    ["3263ed29e6ef433d979e34d7cb92c51f"] = "8520518976529798580",
    ["482661f797c747ccb20136e3d781db38"] = "6736298538640969051",
    ["19ea6a61cd4e429fadc3ac9eb5de62ea"] = "9752138152134402992",
    ["0d1d6f4080cf4c65ae5bdd5217c5723c"] = "7800608388631742795",
    ["71293fbfd99345cbac39324c1dc2d3ef"] = "8725118212293016059",
    ["422056df126f4eddb1feae0f7937492e"] = "9906958762024125424",
    ["6ee3b821d0564cdda3ee398a65ffd2c5"] = "6687198399828344660",
    ["9e755bc73e1544329906e5eb6d717ef9"] = "7876408528018853765",
    ["dfe8fcddc24744d1a0edeb6cc3f04a42"] = "9642008289958287198",
    ["84dadefa948943c8aa3c881ff82d3ef5"] = "9723308471758693001",
    ["2f3674c7dd0a4178a674bfd8e63525d5"] = "9376178836229741217",
    ["39cc6374065c4da6b789a2528cd5db8f"] = "5427578475590980320",
    ["4cefd977b51e40759f5338be73289f61"] = "9100308781338323234",
    ["48180b1dc7564da5b22316cdada74d25"] = "7095448033818540895",
    ["1da5fb50d6fa48828241dee6048c3afd"] = "628565887284572117",
    ["b32a37c3804541d1a8685393a77fb89e"] = "8811638026582579681",
    ["41ae2ffe452e449ebdbf9fa1fca5517b"] = "8252258331717554934",
    ["0a0f4ca4ee4b41f9b198709f04d5d0c2"] = "5038288244568310539",
    ["46a4276cde654768a4729c221ce5aa45"] = "825112871153991701",
    ["58cc0cf415094ef18f51c6d79c455c08"] = "5666278319917491446",
    ["cd4e3e8630164e469bc723d34f98be1e"] = "996796887536068469",
    ["3176f91468c443789ce5933c7d2bc16c"] = "5729588065873937839",
    ["a93a3320f29244419e268f9656fda84a"] = "5707428066489847572",
    ["e191574fd5c3492baedd1e8b1acbd0da"] = "9391258617852237169",
    ["9f71bab4f6bb4054b4340c76bbd07fb8"] = "9761598960429894090",
    ["573afce536b44c7ba85592b3316ef1a9"] = "7636468060489191819",
    ["1831ce28ba8149b8bcd726f92218ece4"] = "5839188188897229131",
    ["4facb1ca864b4f409b39e7b5f68e50a0"] = "7655198207652379679",
    ["004cfdb5fabe4e6586f7d70e5a822e5f"] = "5904678850928998479",
    ["ff9a16aa4da243378a0aebe6467bc6a6"] = "9422138025776554999",
    ["1bb4bbed7e4b4deb8c6f9deee02253f1"] = "544832887203550345",
    ["c37eb30b361249a189f114026fa4bdc0"] = "79997483140249827",
    ["0bbe20794f564abf84a43d22d04d6fa1"] = "5040298426350690491",
    ["c15b366c96d1459f95fc59d3795eb512"] = "8389138613175861958",
    ["0fbecb7dbaa0478e8bedfe1165086cfe"] = "7507728810253579566",
    ["92e3e4cbdbbb46f4954c59c7aa69fe10"] = "5038068022983934070",
    ["100d3cc5688d4fcf96f33901a8fe76c4"] = "8125688393066922488",
    ["b80d4f0f35eb4cc485ac0c209f93daf9"] = "7279398023122217314",
    ["888d94973fb74fa1a5a539798f2f2fe0"] = "6663068019081236989",
    ["a653c99618974ed9930aae88466bc33f"] = "5219848265131167774",
    ["f3cc9036d1ad4b44a8700a5a36d36702"] = "5907698648972629615",
    ["0a2b5d8e2e3b4418ab57734005affff1"] = "8031968952142565053",
    ["a01299cde160405a89a7eec2c3ebc22a"] = "9762608281084728639",
    ["000ab4096a74449d9ad8d7b0ba91c686"] = "7221988093615978722",
    ["3b64b52db2ed44f8a56de22ab38ebb40"] = "8105968008560443813",
    ["e0e5a9f460164d14b13af0490ebf201c"] = "9727008917492493825",
    ["a5bbca5487c0477f8131a6019b8d8f5b"] = "8647728591938246177",
    ["20e035603b2d492bb13fcc99ec0f210d"] = "6097888855941341195",
    ["e4645db88bd14b7c9ec08a5100a206c0"] = "5342238648215140732",
    ["8f95edee45994ab693d01baa373c4859"] = "5245798329428002127",
    ["452e742d57a04cf0bf8b3c68f3e0dc3d"] = "5280408967117408094",
    ["95b9b63cf9d3489ead6dfb0c0d7c9277"] = "5855358716681575722",
    ["bea20fb34a3b4d52a37bf6c2cd0c37f8"] = "7953998501271623362",
    ["52c500a409a64726aaa06727a7305bf3"] = "7509958109462420269",
    ["eb29b22e00714582853d8e68032b019c"] = "9961918229373527166",
    ["5bc26b6f57854a668590b3cb999d482b"] = "6056038626683932251",
    ["965bee49161344ef8ac7e8b4153b2182"] = "7882908512464395971",
    ["160bccefe59546cf9695f2318033befd"] = "9845508966242210533",
    ["b8655d27c6e84a52a3741ba21f967bc0"] = "7265448679711456940",
    ["3dff80dab2b94960aec7f889cf4f4210"] = "5612668117778540312",
    ["cfbff2532bc747138d11c324f856cd04"] = "8049068257866886291",
    ["9ea248a9e8734cb1ae4b54c2406f1557"] = "6249048509698565198",
    ["fba2cb711c1b4c69bd88be5e88a07d82"] = "9293648188776129352",
    ["a88bb32973b24272af700c9c8232aff4"] = "5700388463931729982",
    ["f887de23739c4db3b9c4945ab4e8d310"] = "5299998194187859872"
}

local bot_check_key_auto = {
    "fc8d8a75510149f9851293a45d5e0c5b",
    "0d9bbaab6ac0495c8f75c2b29c95bab9",
    "834d137b5768411cae037744d1dbcbb0",
    "0aff91586ab54a2ab6b867e8d603f679",
    "2aa829659077491fa3d5bd30b62118ec",
    "6f91c4a2bbb14ca4b7ee4a955ea0470a",
    "e18529c362444edea88ad5dcf2483537",
    "9558a26e13664ef393768d15350f9e06",
    "cda1bf79f0e74c90a7dcb3d4a3b7d9df",
    "0f1ef4c0111e47b7b1f66660f7a735ef",
    "49219da53ecc49e8b37e8aff665bfec6",
    "bb70a3d0e924441a9fad3295e01a70ce",
    "2ad632ef24ab456ba2f9fa17c443ddb6",
    "13211d4e39d24d4a98baa669487e6168",
    "a23afddb07174ba1b5aeccb91c772e56",
    "9d637c3ece30414caa6ca3c9026af6b4",
    "85cb71481ea14a7dab2425e8f0523539",
    "990dce5d909149c3af11146b46e36709",
    "dbedbf8604714ca49c2be9a65a2567f1",
    "46ec3b609ee0435d80fa5341287c675f",
    "5cffddfadc144267b89d62648d5be5f9",
    "ead0725c927d491db01c861c8c852bde",
    "1c6a4c7ef7e14d9a8c51e425a527cd69",
    "f3fc5345ad7b448a830b7104f85f6391",
    "8e28af7141df4f568bd82483f8ba7062",
    "d8e88d8be8d3483aaaccca89f1b53182",
    "429c1b159ee946eea4734d6eb31b3a96",
    "58c9330a0c1b4314bd7c1c4b086b627e",
    "79926c7b0df64a5f942b8e5a0d507d51",
    "5416ece45cbc43a69a2d5e5022e784e6",
    "9015972e3f4941e4bdd036da9c3db690",
    "6e82efa53eb64023a37fca4e06fab758",
    "47701c6e9545473fab9cb96dad840cd6",
    "23d4e81a53d3476e863546b6ea831fac",
    "6435c314924241399606f21a20ecb828",
    "3263ed29e6ef433d979e34d7cb92c51f",
    "482661f797c747ccb20136e3d781db38",
    "19ea6a61cd4e429fadc3ac9eb5de62ea",
    "0d1d6f4080cf4c65ae5bdd5217c5723c",
    "71293fbfd99345cbac39324c1dc2d3ef",
    "422056df126f4eddb1feae0f7937492e",
    "6ee3b821d0564cdda3ee398a65ffd2c5",
    "9e755bc73e1544329906e5eb6d717ef9",
    "dfe8fcddc24744d1a0edeb6cc3f04a42",
    "84dadefa948943c8aa3c881ff82d3ef5",
    "2f3674c7dd0a4178a674bfd8e63525d5",
    "39cc6374065c4da6b789a2528cd5db8f",
    "4cefd977b51e40759f5338be73289f61",
    "48180b1dc7564da5b22316cdada74d25",
    "1da5fb50d6fa48828241dee6048c3afd",
    "b32a37c3804541d1a8685393a77fb89e",
    "41ae2ffe452e449ebdbf9fa1fca5517b",
    "0a0f4ca4ee4b41f9b198709f04d5d0c2",
    "46a4276cde654768a4729c221ce5aa45",
    "58cc0cf415094ef18f51c6d79c455c08",
    "cd4e3e8630164e469bc723d34f98be1e",
    "3176f91468c443789ce5933c7d2bc16c",
    "a93a3320f29244419e268f9656fda84a",
    "e191574fd5c3492baedd1e8b1acbd0da",
    "9f71bab4f6bb4054b4340c76bbd07fb8",
    "573afce536b44c7ba85592b3316ef1a9",
    "1831ce28ba8149b8bcd726f92218ece4",
    "4facb1ca864b4f409b39e7b5f68e50a0",
    "004cfdb5fabe4e6586f7d70e5a822e5f",
    "ff9a16aa4da243378a0aebe6467bc6a6",
    "1bb4bbed7e4b4deb8c6f9deee02253f1",
    "c37eb30b361249a189f114026fa4bdc0",
    "0bbe20794f564abf84a43d22d04d6fa1",
    "c15b366c96d1459f95fc59d3795eb512",
    "0fbecb7dbaa0478e8bedfe1165086cfe",
    "92e3e4cbdbbb46f4954c59c7aa69fe10",
    "100d3cc5688d4fcf96f33901a8fe76c4",
    "b80d4f0f35eb4cc485ac0c209f93daf9",
    "888d94973fb74fa1a5a539798f2f2fe0",
    "a653c99618974ed9930aae88466bc33f",
    "f3cc9036d1ad4b44a8700a5a36d36702",
    "0a2b5d8e2e3b4418ab57734005affff1",
    "a01299cde160405a89a7eec2c3ebc22a",
    "000ab4096a74449d9ad8d7b0ba91c686",
    "3b64b52db2ed44f8a56de22ab38ebb40",
    "e0e5a9f460164d14b13af0490ebf201c",
    "a5bbca5487c0477f8131a6019b8d8f5b",
    "20e035603b2d492bb13fcc99ec0f210d",
    "e4645db88bd14b7c9ec08a5100a206c0",
    "8f95edee45994ab693d01baa373c4859",
    "452e742d57a04cf0bf8b3c68f3e0dc3d",
    "95b9b63cf9d3489ead6dfb0c0d7c9277",
    "bea20fb34a3b4d52a37bf6c2cd0c37f8",
    "52c500a409a64726aaa06727a7305bf3",
    "eb29b22e00714582853d8e68032b019c",
    "5bc26b6f57854a668590b3cb999d482b",
    "965bee49161344ef8ac7e8b4153b2182",
    "160bccefe59546cf9695f2318033befd",
    "b8655d27c6e84a52a3741ba21f967bc0",
    "3dff80dab2b94960aec7f889cf4f4210",
    "cfbff2532bc747138d11c324f856cd04",
    "9ea248a9e8734cb1ae4b54c2406f1557",
    "fba2cb711c1b4c69bd88be5e88a07d82",
    "a88bb32973b24272af700c9c8232aff4",
    "f887de23739c4db3b9c4945ab4e8d310"
}

local bot_check_info_slipper = {
    ["8cee1c9bb05a4cb4b84ac3a872b084a2"] = "6575667193232757893",
    ["839f673915714336b75c7c88a80fb6cb"] = "8537457353819167482",
    ["d15e26f9047e4c8586bdd5288ea81e26"] = "8347367642918910721",
    ["b8153a177a8d40459e0964ca0979fe2f"] = "7291137631655157412",
    ["f412fcee1754479d9b090ac7aba9a0e5"] = "9805737049062478160",
    ["fc288b1778ad44d185d580bbadff8540"] = "7302137300372076683",
    ["6ee81fcedc8d489d8f0577285ee6fd61"] = "7880187315714780637",
    ["0844577ec18946039c7a5126e7f58c51"] = "5878797665567882896",
    ["f92fe65edc784f1599c1417d615f1850"] = "7278837098644122832",
    ["daae938818e5460ea40f6d55435b81b8"] = "7894237306826034318",
    ["c5f1307903ea47658059b5eb646f7369"] = "6106967388482356916",
    ["f2e999cb845c4e1a9d6aafc02e94e3d5"] = "7598637919186610461",
    ["4b5da01f6f494c5b95171ba13467b8d0"] = "8167237864769593558",
    ["e6dc94e0cb9e4a51bebe34221abb0000"] = "6221067594035985014",
    ["20f6a9e848094b498f89f9fb905b5ba1"] = "9605827688632051246",
    ["22784d05c9b54f5aa2dbf615ac07c194"] = "6786087323222044648",
    ["8c7defbd4b2e4776a19eaab85583ef4c"] = "7803347740640712660",
    ["ac88ada3e74641fdac47af83aee76172"] = "845786748999471103",
    ["1dd78cc8072848b1a025e24cbc475bff"] = "7070487490193166731",
    ["8923d07a7788442787164909beb0b206"] = "8344997812421814440",
    ["b4c01ca4ce6541bbb0ab58f492d8eead"] = "9754157033730484299",
    ["a774c9ef536d46889901739e7dcf58a8"] = "6645757017177379389",
    ["dfdab1da075a4c8dacb8245ce44af043"] = "8773737775391603548",
    ["bdca3ac509c34ce28f6c2dfb95d08cc5"] = "8114347034086024345",
    ["07262aae0c8e44b0aa74b8cb56fd77d6"] = "5453687227142894339",
    ["be911febaa7242c1a02cd6fdedede9ec"] = "8038047845293674234",
    ["2c26b9f49dd24e2595064ab04060ac0d"] = "7863457747045216693",
    ["4489ce73cd8b41e2b8d59845bffe68bb"] = "8413727909389612411",
    ["f3a7eee8afdf4d73b1bccbc039746010"] = "7638777551021816854",
    ["77dd093fd67c4e168e3d8cfd478e7beb"] = "7423507889839255339",
    ["60d3c981e6b34ea1835dd3bc2aa38191"] = "7485437580988796601",
    ["36484c905a374c7998cc5ef3140ff023"] = "9318107176113087262",
    ["724716e6a86347ac88c13984a7cef654"] = "8390707903431788765",
    ["c62f655808924dbcb6889274f9d6edd0"] = "7608337519880345574",
    ["55c0ab5a31cb414b876ed01efdeac327"] = "7443827211586626703",
    ["382dacd8037f4d75bb5acd1ae25fcb8b"] = "7040007886333208599",
    ["9424b004d75d46d7a47c031704cf649c"] = "6263297041323975450",
    ["50f354eafbb84dda94241e916cb8c288"] = "814837759933568105",
    ["f070d2c3a91043f5b9340bb06e3e17ca"] = "7135967823584912738",
    ["23437eee6fcd4bc4bc0b4307ac01e38d"] = "5532667753396973376",
    ["fb36f5a674814d4086898a8582592ab9"] = "9506727201465644864",
    ["c5b760941a45486e90bfade4bfd4afb0"] = "68708672998300668",
    ["a9216ddf3a9442e48fc6a8d966c0c4bb"] = "8387277296524892873",
    ["0a2dda4b4e0f403a87eb7e9a180be215"] = "6360397082944569561",
    ["c7a27914d77f400abc42e05e7ff98227"] = "7191477120197989013",
    ["c90d1200153242d3add0bc1250184584"] = "5049507896311157540",
    ["c71947fd01d440c68edaf03c97b871e3"] = "5431617440521021289",
    ["fd05a7652008416787c13a3248c38bb8"] = "7397627331464051460",
    ["14ed680037f3439cbfb8ad554059974b"] = "8586127249554113676",
    ["8193bbd378f642eaa88835c7936e14fa"] = "9907527069798883968",
    ["606151bbd9a64fc1bb619552ee454de4"] = "9191037707829648559",
    ["bd4fe2cd826349d192e9bbbd5d3fc3be"] = "9936047529965565230",
    ["4acc5b3bd28b44c288a3248795f1b272"] = "6134867687140442485",
    ["90de45f130524b7cbf3637c678937aee"] = "6487617432781999527",
    ["c16d938ae39c483fa0ac767cffecd240"] = "7395117895219549140",
    ["7390926cf95143719c5534c11045c158"] = "7308347100940136228",
    ["27a139907b91444e9382f7ea9c93b02a"] = "7381897140182532574",
    ["914e7a71c5ab434a98b3b30493e894f1"] = "7032487239999128817",
    ["063af182743848ed898885260a7a5c9b"] = "6035567099368207462",
    ["7c77a7d9aa274d4abd4c2140b79550b0"] = "9087707852066444074",
    ["6577c2e2283c4725a9be4762ff3dc32b"] = "8219437637128111292",
    ["d105392d9b714c219647dc6faaa666aa"] = "5991437773620041891",
    ["90c43d20edcb4471956bb645ce5c94cf"] = "8903557889228976349",
    ["b4c2e6c64dd1476d9c298a52c51a8b50"] = "8014867561917142134",
    ["a194c2017556475b8b04b8e4729accfe"] = "7134247429851691921",
    ["49ea6a2ecd6d4633ab8c75fb7f3e442c"] = "5692397580131331181",
    ["5bf881ab3b154e98964d8db3ebeacbb2"] = "6624687216570915303",
    ["d89e48cba05e48078d11e426a7a3ae48"] = "7825557023010875142",
    ["8c327b591f434472a1f479ff3be5c8ae"] = "6757827857058399973",
    ["6a87b63b0267479396e451b1dbb79124"] = "793509732176195481",
    ["54ecb969d75d49a69840fee4bea2ede8"] = "9090227369391064408",
    ["f596affbb6f24d07a5f707af02577961"] = "9695987267443671377",
    ["3f192e3499004b59afbfba3143d7e141"] = "6791657407890959851",
    ["7db182d9126143fba5a9a4634725e2b2"] = "6288217287579030292",
    ["640fba050acc4e35a5cb59fc7c1eb737"] = "8413717985744625949",
    ["4f32d1f3c6e442aa811624d7185f4fdb"] = "8875767853348066517",
    ["3e51602dd86942d4a8da8abe4e704494"] = "7154697747429138768",
    ["c22e63995c124022b09c2c35a5263515"] = "8925337934268719115",
    ["06ec9767ec2b478d8d9ce4be266a27f5"] = "9579837020066642271",
    ["9ee26f65e5064316a94fd02986a21bbe"] = "9823937092299443306",
    ["ca7e628c757c463eac10130df8b293e4"] = "9137547406116362727",
    ["a570d17eac6b4588a11019129c7ff336"] = "9851547333722621895",
    ["7ff335435c3d4784a8212247758e9edf"] = "5641697355371404925",
    ["58b2b9daa11544dc885849ddd87c11bf"] = "6118247378076653618",
    ["27e691dc84c04b579baa384bbf933ddf"] = "8504997535181859421",
    ["2f122a4b20194697bc789c87342dcffa"] = "8453977649656076899",
    ["b180b35e8464461eada78e916b51450f"] = "785266785503687357",
    ["2ffbf954f23b41409409e018cbe0fe7b"] = "9953157990579003439",
    ["ee13b14acbfa424583749580a3b680e4"] = "5198997729983515186",
    ["6cde2d0df40641db9c5e9846c08b907d"] = "9030467589191743792",
    ["dfa0b6460fbb4b61ac2736eac95267aa"] = "5970607408220726414",
    ["042711977d1342e99f808614be494dc4"] = "6517967571617842099",
    ["2708063c4be44744aa366bfbba5d9701"] = "6012807223651108981",
    ["4333b6e7b8454256b5b4e2c8fc8752ab"] = "9011117280498848159",
    ["dfb993d340da47e9948edcccdda0614c"] = "914038764021971496",
    ["e46cc2c138cf4c47957dd1abfdc927bc"] = "6616487105535774850",
    ["2daa64c913ca4b04909c5f05c56d9520"] = "5268577288911105787",
    ["d78690967648477ba4abc26884107adf"] = "944247785608445001",
    ["d5686fcd6e564ba38be9c601f997cbf3"] = "5338117789995197920",
    ["ce7235de3c47401580210895684c2d47"] = "7963637452950818861"
}

local bot_check_key_slipper = {
    "8cee1c9bb05a4cb4b84ac3a872b084a2",
    "839f673915714336b75c7c88a80fb6cb",
    "d15e26f9047e4c8586bdd5288ea81e26",
    "b8153a177a8d40459e0964ca0979fe2f",
    "f412fcee1754479d9b090ac7aba9a0e5",
    "fc288b1778ad44d185d580bbadff8540",
    "6ee81fcedc8d489d8f0577285ee6fd61",
    "0844577ec18946039c7a5126e7f58c51",
    "f92fe65edc784f1599c1417d615f1850",
    "daae938818e5460ea40f6d55435b81b8",
    "c5f1307903ea47658059b5eb646f7369",
    "f2e999cb845c4e1a9d6aafc02e94e3d5",
    "4b5da01f6f494c5b95171ba13467b8d0",
    "e6dc94e0cb9e4a51bebe34221abb0000",
    "20f6a9e848094b498f89f9fb905b5ba1",
    "22784d05c9b54f5aa2dbf615ac07c194",
    "8c7defbd4b2e4776a19eaab85583ef4c",
    "ac88ada3e74641fdac47af83aee76172",
    "1dd78cc8072848b1a025e24cbc475bff",
    "8923d07a7788442787164909beb0b206",
    "b4c01ca4ce6541bbb0ab58f492d8eead",
    "a774c9ef536d46889901739e7dcf58a8",
    "dfdab1da075a4c8dacb8245ce44af043",
    "bdca3ac509c34ce28f6c2dfb95d08cc5",
    "07262aae0c8e44b0aa74b8cb56fd77d6",
    "be911febaa7242c1a02cd6fdedede9ec",
    "2c26b9f49dd24e2595064ab04060ac0d",
    "4489ce73cd8b41e2b8d59845bffe68bb",
    "f3a7eee8afdf4d73b1bccbc039746010",
    "77dd093fd67c4e168e3d8cfd478e7beb",
    "60d3c981e6b34ea1835dd3bc2aa38191",
    "36484c905a374c7998cc5ef3140ff023",
    "724716e6a86347ac88c13984a7cef654",
    "c62f655808924dbcb6889274f9d6edd0",
    "55c0ab5a31cb414b876ed01efdeac327",
    "382dacd8037f4d75bb5acd1ae25fcb8b",
    "9424b004d75d46d7a47c031704cf649c",
    "50f354eafbb84dda94241e916cb8c288",
    "f070d2c3a91043f5b9340bb06e3e17ca",
    "23437eee6fcd4bc4bc0b4307ac01e38d",
    "fb36f5a674814d4086898a8582592ab9",
    "c5b760941a45486e90bfade4bfd4afb0",
    "a9216ddf3a9442e48fc6a8d966c0c4bb",
    "0a2dda4b4e0f403a87eb7e9a180be215",
    "c7a27914d77f400abc42e05e7ff98227",
    "c90d1200153242d3add0bc1250184584",
    "c71947fd01d440c68edaf03c97b871e3",
    "fd05a7652008416787c13a3248c38bb8",
    "14ed680037f3439cbfb8ad554059974b",
    "8193bbd378f642eaa88835c7936e14fa",
    "606151bbd9a64fc1bb619552ee454de4",
    "bd4fe2cd826349d192e9bbbd5d3fc3be",
    "4acc5b3bd28b44c288a3248795f1b272",
    "90de45f130524b7cbf3637c678937aee",
    "c16d938ae39c483fa0ac767cffecd240",
    "7390926cf95143719c5534c11045c158",
    "27a139907b91444e9382f7ea9c93b02a",
    "914e7a71c5ab434a98b3b30493e894f1",
    "063af182743848ed898885260a7a5c9b",
    "7c77a7d9aa274d4abd4c2140b79550b0",
    "6577c2e2283c4725a9be4762ff3dc32b",
    "d105392d9b714c219647dc6faaa666aa",
    "90c43d20edcb4471956bb645ce5c94cf",
    "b4c2e6c64dd1476d9c298a52c51a8b50",
    "a194c2017556475b8b04b8e4729accfe",
    "49ea6a2ecd6d4633ab8c75fb7f3e442c",
    "5bf881ab3b154e98964d8db3ebeacbb2",
    "d89e48cba05e48078d11e426a7a3ae48",
    "8c327b591f434472a1f479ff3be5c8ae",
    "6a87b63b0267479396e451b1dbb79124",
    "54ecb969d75d49a69840fee4bea2ede8",
    "f596affbb6f24d07a5f707af02577961",
    "3f192e3499004b59afbfba3143d7e141",
    "7db182d9126143fba5a9a4634725e2b2",
    "640fba050acc4e35a5cb59fc7c1eb737",
    "4f32d1f3c6e442aa811624d7185f4fdb",
    "3e51602dd86942d4a8da8abe4e704494",
    "c22e63995c124022b09c2c35a5263515",
    "06ec9767ec2b478d8d9ce4be266a27f5",
    "9ee26f65e5064316a94fd02986a21bbe",
    "ca7e628c757c463eac10130df8b293e4",
    "a570d17eac6b4588a11019129c7ff336",
    "7ff335435c3d4784a8212247758e9edf",
    "58b2b9daa11544dc885849ddd87c11bf",
    "27e691dc84c04b579baa384bbf933ddf",
    "2f122a4b20194697bc789c87342dcffa",
    "b180b35e8464461eada78e916b51450f",
    "2ffbf954f23b41409409e018cbe0fe7b",
    "ee13b14acbfa424583749580a3b680e4",
    "6cde2d0df40641db9c5e9846c08b907d",
    "dfa0b6460fbb4b61ac2736eac95267aa",
    "042711977d1342e99f808614be494dc4",
    "2708063c4be44744aa366bfbba5d9701",
    "4333b6e7b8454256b5b4e2c8fc8752ab",
    "dfb993d340da47e9948edcccdda0614c",
    "e46cc2c138cf4c47957dd1abfdc927bc",
    "2daa64c913ca4b04909c5f05c56d9520",
    "d78690967648477ba4abc26884107adf",
    "d5686fcd6e564ba38be9c601f997cbf3",
    "ce7235de3c47401580210895684c2d47"
}

local bot_check_info_puzzle = {
    ["e69428d9fd14401080bc4a3907a1cabf"] = "6535216015430750013",
    ["8b35eeab4e714112b01815caec138e7c"] = "9594036868496886920",
    ["1a2678d14b3e4fb487e5aa7eead63ab1"] = "6276396560193467559",
    ["0aa20e21e35340d38c489583dd961ead"] = "5815166753488650231",
    ["6f77251c4517497ebdf3dc3224343e2f"] = "8274626088932577011",
    ["7bde3fcacda74b128436af7b2e63c640"] = "6631916590542787286",
    ["b8ac271b272647a299fad83777977257"] = "7751746458669592837",
    ["2bc846ed90be4e2c965b90be3c16733a"] = "5894496173222151577",
    ["7fd9becb9200488da5bba4b0f9f619ac"] = "5042376076171221768",
    ["441d19c8419845789432848f76f45236"] = "9859896430745193671",
    ["e4280659cddd4af88a357038a6c76f86"] = "8207796595079880269",
    ["e5e8756a33ea442e944fbb8c7f8f7649"] = "5876926094579778270",
    ["a4f544f0b6e1475bb00f404c5fc5fac1"] = "9575816304497733658",
    ["ea19358ec8c14e2e9cd4dfebdc790cbf"] = "6261806970780995428",
    ["0ab1e526287d4a3bbf8477ff150d0980"] = "6823426646698267624",
    ["f5aa7f431b164c5c86612cfbd3aea484"] = "549936694385985242",
    ["59880a2db9564a66b4dae899f6d738f9"] = "9570486449217207056",
    ["aef64a4fc4d1490db7b2e5cf43fa7e53"] = "6646076552227907916",
    ["eea5113c748d40039ecbee0d736436a9"] = "5870326209027594336",
    ["b23eff1a5c0c45eda0fc2946b9aee248"] = "6242466848833952816",
    ["6cbd17ec5d534740b96a8fc91b3d1304"] = "8861696058556209047",
    ["8d94612b62f64ce1ad5aacbcc7264b46"] = "5282236785871722268",
    ["3a1f97e837a242c4b042dd4b28f123a3"] = "6435666277933551896",
    ["f5bed3d33af84880a444f9c207fa30c5"] = "6399976356862335921",
    ["67eab9d3ef1d49e9926862c92f89b87b"] = "6427266131762988782",
    ["9f7d25b935a241b8a65e43ae235d244a"] = "5782996363682419221",
    ["7b577710c410464a947ec9317deb00a6"] = "937254643509375833",
    ["d70cde5b0a7947a0888abbb6f4ff3b35"] = "6703446737138045250",
    ["3b9dec7574ba4d4bb380402b81da5199"] = "6974606716659635661",
    ["df0c7b08b8164034bb00666cd084ce1a"] = "8140926382498366995",
    ["418b0902e41b4c2bbdf5595de2322901"] = "6656236933185681758",
    ["bdf96443225544678997e62213bdbfda"] = "6628366838847223157",
    ["c87e74cf388049d98209124e5c41f6b0"] = "7013906607799869685",
    ["a94009e11eb74c408523c04ee0116080"] = "613736675312282481",
    ["cb8224f3828c48b9a5bb9a680ec2ed8a"] = "6768056218413415486",
    ["8da44e5cb7e74daa8f24e069e34cca89"] = "6755186436924421184",
    ["72ef0147d74f47f6a92bd545a89f1d30"] = "5999836860220773619",
    ["801f734493de46df9a2c3b9e28401d80"] = "5512176940219333110",
    ["175bdd055cf54d9cb066d8617448624c"] = "522681622349036027",
    ["a03adf9b03dd4ee7be9c91977d8fb4cf"] = "8994466242393680435",
    ["e41ce1c7164843c3bda7a90188a75a52"] = "9801736387283101866",
    ["ed2680ccd343469b8968b33ee6fea87a"] = "5329306816662122895",
    ["6d7b45fac86f4caf8c7bead4806a46e8"] = "7029876214323408331",
    ["94ecfb4e580048458b17464f886c17dd"] = "7213986631028992176",
    ["19f6b0d0e148413f98940ea4151528e3"] = "6668566251916352059",
    ["27a38b62bf0b4e699f2b5aa44f219497"] = "9077156706751258394",
    ["eb388d351baa42d98bb7c64088cdc4ad"] = "9469576941555306934",
    ["4617e41f06fb47d7930a129ec89192b9"] = "9497366128945838030",
    ["1fb76646715e4fecb2b6c64c26a8d575"] = "7002376374462492453",
    ["96e7b86031b04b8c8eca41e3632fa105"] = "8919906493189630334",
    ["e90f670108c7450895e908860b0fadd6"] = "581476653927310045",
    ["4bd5a8d7fd554c9d8c03232039893837"] = "5661056879126951456",
    ["e5f6449af2704a11952765a747102bee"] = "7240446051392739895",
    ["8f5a772450984a16a53c5733cec5f938"] = "8422926505994693286",
    ["2b4b088649f948b98a20a6948fcde58d"] = "6697246036523529142",
    ["b5b1836a52f04b5aa4c28ced9296db8e"] = "6252806822791172547",
    ["5365cf6355444080bdc3219a239b7a45"] = "6387386664423289288",
    ["5b17756625784850a31c4ec871dec7b2"] = "6774546806676155195",
    ["5b2d0d0ed4e742479ee5c7b77ac1b402"] = "8928056153910277630",
    ["9c233400048f44c9929d6dd68785a268"] = "8298406305640428357",
    ["dd675117ab204680b6671eccd83accf3"] = "9115296309663621647",
    ["649b1f8047fe4bc0bbf68cdce1394ec3"] = "7932106216682532898",
    ["256debff65a3424093b01acf934587b7"] = "8570866278112725154",
    ["2dec4dee6a32433c9fd9ba017bbd8c3e"] = "5305296651959154772",
    ["f5e9210df1484d7a8592997c6bfa19ba"] = "9451946797091617869",
    ["92442d24246f405e89f60c7ec6257f13"] = "8590096813961624101",
    ["1d87fc092adb4d54b411e0908b3fa616"] = "7013416505392617799",
    ["1c692c07bfe940cc9db090d8d249c687"] = "6793146223318414758",
    ["ede356795ce24313983d94a2b2bab517"] = "9047136191443754488",
    ["ebd0a19feb03481292b4110f8529df5d"] = "5960626747481981521",
    ["74c02e8daeef4896822d063cee43a93c"] = "5991986108519475455",
    ["3d98d37f4aeb4be3a1c8feedf56a23f7"] = "5605846991114451353",
    ["dc3b34b2ca40451a92b61ede0738eb54"] = "525647628408860982",
    ["9e3d910e46ee48f19c06fc57db5ddbff"] = "6140836930710989338",
    ["28c7d6864ed0477eab32ea8e9105a065"] = "6476466890065579691",
    ["86806d3c83554586acc80088d0bacc10"] = "6089716850235513077",
    ["2673f3e562084821ac113667ad65c733"] = "7132196157395112942",
    ["618f7e724368411eb1de602a7bb7c15d"] = "5573366503036294215",
    ["75d223d7c707456492979ece7a01460a"] = "6525366029431744345",
    ["9add85b2be5c4824b1a340802094ded3"] = "588043682622694070",
    ["d8b0af8e4ec64557a641882685452854"] = "8067556783483778888",
    ["9b31500caeb44eb0b1c88d1439d1d5bd"] = "6378406445540747105",
    ["cb458c4141244508af25ce42d7884eee"] = "5261626094829173056",
    ["b9b0dd1b1482440ca0608cd92c9aaa42"] = "8245006692552608848",
    ["73a35ebcbfdc466d8cc7ab6a99991fdf"] = "6578856721174530584",
    ["5306e471bcf445a6b233e66ac80e4133"] = "9446356527255931072",
    ["4c33453a0d524f17b7601507cfb53fdc"] = "6658726614550601159",
    ["d4d5f82008d548e79cd2aab5bf32dbea"] = "8023926102173886839",
    ["992d7f706f30413b9ce8d2a76b890b53"] = "6252756144828814156",
    ["8e127e44fb414dff81aa99a77d8e93c2"] = "5944116178684666885",
    ["f21b9f0dbf11445481ff1dabac303b3c"] = "7436366449148760516",
    ["cd5ca0f85e99417e8118063c123cfe8d"] = "9345076158448773869",
    ["3b9eca6d02d64e669d379d66ef8f300a"] = "5192486003125786745",
    ["a8cb58858758419fa91e7acc467b622c"] = "8179526816851609004",
    ["e8d3bbe5834d4df7ac856dcbbee92445"] = "9586096142698474201",
    ["e35197b18e1f433d87f4cc91aee6917e"] = "5274786267058816396",
    ["93f9505d03d644138a8e396216f18ef4"] = "960337650216204023",
    ["bf39c4b5ae7a48aeac5f677d5a697570"] = "9515486421249631311",
    ["c169289eac5a46d5a1e73ecc3598c31f"] = "8219366921042435269",
    ["2df9fb285ca146ed8efdfb084ca1137d"] = "5907266167236077187"
}

local bot_check_key_puzzle = {
    "e69428d9fd14401080bc4a3907a1cabf",
    "8b35eeab4e714112b01815caec138e7c",
    "1a2678d14b3e4fb487e5aa7eead63ab1",
    "0aa20e21e35340d38c489583dd961ead",
    "6f77251c4517497ebdf3dc3224343e2f",
    "7bde3fcacda74b128436af7b2e63c640",
    "b8ac271b272647a299fad83777977257",
    "2bc846ed90be4e2c965b90be3c16733a",
    "7fd9becb9200488da5bba4b0f9f619ac",
    "441d19c8419845789432848f76f45236",
    "e4280659cddd4af88a357038a6c76f86",
    "e5e8756a33ea442e944fbb8c7f8f7649",
    "a4f544f0b6e1475bb00f404c5fc5fac1",
    "ea19358ec8c14e2e9cd4dfebdc790cbf",
    "0ab1e526287d4a3bbf8477ff150d0980",
    "f5aa7f431b164c5c86612cfbd3aea484",
    "59880a2db9564a66b4dae899f6d738f9",
    "aef64a4fc4d1490db7b2e5cf43fa7e53",
    "eea5113c748d40039ecbee0d736436a9",
    "b23eff1a5c0c45eda0fc2946b9aee248",
    "6cbd17ec5d534740b96a8fc91b3d1304",
    "8d94612b62f64ce1ad5aacbcc7264b46",
    "3a1f97e837a242c4b042dd4b28f123a3",
    "f5bed3d33af84880a444f9c207fa30c5",
    "67eab9d3ef1d49e9926862c92f89b87b",
    "9f7d25b935a241b8a65e43ae235d244a",
    "7b577710c410464a947ec9317deb00a6",
    "d70cde5b0a7947a0888abbb6f4ff3b35",
    "3b9dec7574ba4d4bb380402b81da5199",
    "df0c7b08b8164034bb00666cd084ce1a",
    "418b0902e41b4c2bbdf5595de2322901",
    "bdf96443225544678997e62213bdbfda",
    "c87e74cf388049d98209124e5c41f6b0",
    "a94009e11eb74c408523c04ee0116080",
    "cb8224f3828c48b9a5bb9a680ec2ed8a",
    "8da44e5cb7e74daa8f24e069e34cca89",
    "72ef0147d74f47f6a92bd545a89f1d30",
    "801f734493de46df9a2c3b9e28401d80",
    "175bdd055cf54d9cb066d8617448624c",
    "a03adf9b03dd4ee7be9c91977d8fb4cf",
    "e41ce1c7164843c3bda7a90188a75a52",
    "ed2680ccd343469b8968b33ee6fea87a",
    "6d7b45fac86f4caf8c7bead4806a46e8",
    "94ecfb4e580048458b17464f886c17dd",
    "19f6b0d0e148413f98940ea4151528e3",
    "27a38b62bf0b4e699f2b5aa44f219497",
    "eb388d351baa42d98bb7c64088cdc4ad",
    "4617e41f06fb47d7930a129ec89192b9",
    "1fb76646715e4fecb2b6c64c26a8d575",
    "96e7b86031b04b8c8eca41e3632fa105",
    "e90f670108c7450895e908860b0fadd6",
    "4bd5a8d7fd554c9d8c03232039893837",
    "e5f6449af2704a11952765a747102bee",
    "8f5a772450984a16a53c5733cec5f938",
    "2b4b088649f948b98a20a6948fcde58d",
    "b5b1836a52f04b5aa4c28ced9296db8e",
    "5365cf6355444080bdc3219a239b7a45",
    "5b17756625784850a31c4ec871dec7b2",
    "5b2d0d0ed4e742479ee5c7b77ac1b402",
    "9c233400048f44c9929d6dd68785a268",
    "dd675117ab204680b6671eccd83accf3",
    "649b1f8047fe4bc0bbf68cdce1394ec3",
    "256debff65a3424093b01acf934587b7",
    "2dec4dee6a32433c9fd9ba017bbd8c3e",
    "f5e9210df1484d7a8592997c6bfa19ba",
    "92442d24246f405e89f60c7ec6257f13",
    "1d87fc092adb4d54b411e0908b3fa616",
    "1c692c07bfe940cc9db090d8d249c687",
    "ede356795ce24313983d94a2b2bab517",
    "ebd0a19feb03481292b4110f8529df5d",
    "74c02e8daeef4896822d063cee43a93c",
    "3d98d37f4aeb4be3a1c8feedf56a23f7",
    "dc3b34b2ca40451a92b61ede0738eb54",
    "9e3d910e46ee48f19c06fc57db5ddbff",
    "28c7d6864ed0477eab32ea8e9105a065",
    "86806d3c83554586acc80088d0bacc10",
    "2673f3e562084821ac113667ad65c733",
    "618f7e724368411eb1de602a7bb7c15d",
    "75d223d7c707456492979ece7a01460a",
    "9add85b2be5c4824b1a340802094ded3",
    "d8b0af8e4ec64557a641882685452854",
    "9b31500caeb44eb0b1c88d1439d1d5bd",
    "cb458c4141244508af25ce42d7884eee",
    "b9b0dd1b1482440ca0608cd92c9aaa42",
    "73a35ebcbfdc466d8cc7ab6a99991fdf",
    "5306e471bcf445a6b233e66ac80e4133",
    "4c33453a0d524f17b7601507cfb53fdc",
    "d4d5f82008d548e79cd2aab5bf32dbea",
    "992d7f706f30413b9ce8d2a76b890b53",
    "8e127e44fb414dff81aa99a77d8e93c2",
    "f21b9f0dbf11445481ff1dabac303b3c",
    "cd5ca0f85e99417e8118063c123cfe8d",
    "3b9eca6d02d64e669d379d66ef8f300a",
    "a8cb58858758419fa91e7acc467b622c",
    "e8d3bbe5834d4df7ac856dcbbee92445",
    "e35197b18e1f433d87f4cc91aee6917e",
    "93f9505d03d644138a8e396216f18ef4",
    "bf39c4b5ae7a48aeac5f677d5a697570",
    "c169289eac5a46d5a1e73ecc3598c31f",
    "2df9fb285ca146ed8efdfb084ca1137d"
}

local bot_check_info_words = {
    ["920987d2c84c438e8b0577cc7429ff57"] = "7119785119841661458",
    ["e8749404c3174ed18bd65f7661754455"] = "6077695543531144043",
    ["6de4435175c44c00a3bec1972d9df627"] = "9789045676418508232",
    ["651720202c8041a8a8d3f41419abf65d"] = "5498535485327644425",
    ["40d216f1690a4ebf9708e48cddc00613"] = "7521605382064963708",
    ["423c193e1c744d3480269fe9789af48a"] = "7909625862196284457",
    ["a1a98da4f77c4c0d85928b7176d4d3c0"] = "9331415648255063585",
    ["5dac39a021e24637b7b7220e099db123"] = "5306775164769342403",
    ["9f9a41b58b4749da932b08f2703c0164"] = "5144515295275373237",
    ["758ffe4120a648a3958ef424c7d9aed4"] = "8114365834031632737",
    ["f8f92209179846c0b80e2cf33000c702"] = "7999595000587794255",
    ["efb3990ac9d74ad68857fcc96b9b4d23"] = "5050345099274134713",
    ["a1f017ca135147879d074485033e60bb"] = "9282785427877033109",
    ["dc796b127d43470da08adc513cc8f321"] = "712431519961378578",
    ["0d218bc4acef4474af68824c2cf60da8"] = "9972655119591484801",
    ["1ee2d4985a084189b6aafef5dfdbf106"] = "581858540171745534",
    ["7c0ac5e18aec468aac05b726c06ff77f"] = "6630715170143321137",
    ["07c0155f32034827803a0a9059394ebd"] = "7972435206764014058",
    ["9750a152fbe34d9389d57b81b19f5e62"] = "9140705622791974550",
    ["b9a68288194f44ca887950398321ff5f"] = "7746435833382766791",
    ["3f61895cba5e4528b387874e9f4f4fcb"] = "8782015832949074421",
    ["ab65e9c40f7e4e16b8f8cc5baaf088c4"] = "8691025444230006888",
    ["3132977999e64a8ba6b108ef6c2b4fec"] = "867605511984519509",
    ["73e52564404b49bfa845fedd01c86f86"] = "6136215654745234554",
    ["32abae9142f74182afdefc5b00c71b7a"] = "7407995963257248168",
    ["6c3e6d01121f4d6db112d224290b0da5"] = "9041545655489842515",
    ["174a6749e13b48208a56a3978c68c611"] = "7475915520098801290",
    ["219ac99411c144e1a7ed8b6b9928c170"] = "8382145943362230563",
    ["724a0bed6f4240abba3e160021bc959d"] = "6158995713675650647",
    ["7c3e826620c64ba091ee3bf53fd9782a"] = "8566115419689170639",
    ["a9dff9b1557f4f7992bc66137c7a163d"] = "9829165899067023211",
    ["b30da6442d6e42699b0b7dd4d55d0aa7"] = "5270315758927946766",
    ["115817695acc42dd8009972e1d0585ed"] = "8796225424118240463",
    ["2f0bea49e10942148fc9bbf1443dc244"] = "8502345221788296178",
    ["b4b2c0689ca948afb8fc2ee4c1522d03"] = "9571985874092752285",
    ["c4127ed9c4214dd1ad605b88b83c9d71"] = "6630085326045860988",
    ["3bf5f36a79b247d8b91c881db5dc6525"] = "5479895611470645757",
    ["339d4eac24ec4051b395901a66fa9924"] = "779653554818372430",
    ["3ade25240f8e4215a27190c022076c41"] = "5020295824849529269",
    ["ceb597759e4445e8b6052b25ccd95574"] = "897104567895807366",
    ["ddc7778dcb5644fd812d5bbb1e43bf05"] = "8554275558950130771",
    ["49ee9a6d5f5249f1921f60e78631d22e"] = "6838995221974975342",
    ["c5d3abc83305435e9cad059fca5b5f13"] = "9835935675980419293",
    ["5ff9e38333884146b10f22be17c403aa"] = "7362545637977459516",
    ["22cd9605629443b1be5abf71399da196"] = "530640570492637694",
    ["913005d23583484c8398899ff1b86a39"] = "627569565223019525",
    ["89a519b000054825a578de7f87700c97"] = "7870215348648968873",
    ["edc1233147fb4e6ebd99a04dea934556"] = "8553025612531055506",
    ["fcdf3054ed824d1082acbbcbce208f2b"] = "7860725906728396174",
    ["d405f5b3f6f647b0923204abe39fe203"] = "9035445129776287864",
    ["a61465e7744249528d8b57d6fb03a7ab"] = "6271095045459717076",
    ["4cdd4eeaefea48eab9f5637a4cff4aca"] = "9228825442917895949",
    ["9279cc80f8b04da888497c58e23772c4"] = "746624523825623896",
    ["2ca63b4ff99a49d092ffbedcf3f1e034"] = "6468485958847373343",
    ["b0370fa0ea174b2aaa5ac9d86bd12bd7"] = "741392586611272523",
    ["e5e74fdffd634d2a9dc18b9e5ad8330f"] = "6288705867525228750",
    ["284af0e7368f40d087db7a30cba0995b"] = "8683105749870081351",
    ["77093d540cba475a87a4247ff8cbf214"] = "7870575553225925517",
    ["79499048999645c18146b1593313dcd3"] = "9818525505680525411",
    ["c136ba0885c04f5fa808769d8746e615"] = "9996915023062115630",
    ["1ab0167e34f14e538e6029c0720a532a"] = "9167255341779309494",
    ["2a156426f16a412084ed4ebf9026a352"] = "9035335892143064268",
    ["8f4832e8a9464ddfb91a15e9b8a00849"] = "5536645017880302581",
    ["763916b7ed044a24a635044ad53908c4"] = "5227705508088036421",
    ["d84f8ea6890e43a0ac0951663b140943"] = "6277805487340616205",
    ["aea74251d0c149148a6faa0836cdb5a5"] = "7646955642142301232",
    ["ec0500da5b4e42808d3878c39cfe5bed"] = "9976375025679802750",
    ["caf00dda4afa4577bbc1877864f13f44"] = "8615975097649365358",
    ["65e22f19eb2d49d3ba9df160c5fd2cc9"] = "7520035367846451061",
    ["38207224f5b9422fbb957893604e1cab"] = "9961845752538502529",
    ["57a8181014ef421a9f9119ccd566c542"] = "7073555071440075522",
    ["476d60a2ef994e5ca6fb5fe9bfa1373b"] = "8553525007594868293",
    ["614086cf61374c0399c19ddb3a948dbd"] = "7687655119789364319",
    ["997747e1ca0f4222aad3c8e0954452a7"] = "6571045206721246480",
    ["5976b5e304d54b54bcebeabde82b8a3d"] = "5205675731822606576",
    ["ba267d3de98a41619133ca987032c2e8"] = "7619075889832299148",
    ["5ddcb6c083124248ac90166908ced478"] = "7903535864747478015",
    ["5de0a22b1fe84197af96343c0346f303"] = "5401245828233321378",
    ["7071b96c735d49c9baa08c34cbbfe9c2"] = "566785592096939873",
    ["484b17cff9cb4c6998667ca0c2557211"] = "6343305248448806603",
    ["abca05fb71b444df9d501d9d22440741"] = "7372715333833860520",
    ["0ce5dbe85ee4499a850a5d8056af42aa"] = "6415275156258425954",
    ["7c04cc27a5744f108918609cd8944187"] = "8897945618845188834",
    ["2ad1ad99c5a442a8a639ac05ac43c134"] = "5874945451689024939",
    ["aaae4d099c7b46998f7ff2096aa3e52b"] = "8959345395653138580",
    ["6789535618874ce287f5443564251ab6"] = "8849845912416352296",
    ["18d7318d230849bba432c2bf8a5a959b"] = "6443055049480064687",
    ["6234744df5444b64bab74364ba9ec680"] = "7192535500376621741",
    ["30a98430067040c0b4eb495de3b42e66"] = "8635985155353091679",
    ["83e18bfeb2394579b8555ff28c6bbba4"] = "604755533767146445",
    ["78a4431b95774aa0a1070d63100d8e8f"] = "5762225177025720351",
    ["e2e43f4ee9b54befbd25b5e7b7220fbf"] = "7506385670699430328",
    ["57a879a877d146f38b77c42ccc7e832b"] = "9020515134475162623",
    ["6988792079cb43a599a0a2bc1fbe411a"] = "5471215308179922046",
    ["0fe5cd95c0944a9aad7335bf7d4f2612"] = "7460555540444000996",
    ["1092cea2a4d74fcb872024bab6904350"] = "8703205004327243052",
    ["99ca0e7f8e08415788731f81ac627457"] = "9987915030492404511",
    ["bee7b003fb544052a8c246e12c9f8b43"] = "823384545102733952",
    ["7b6ba9a617664f549c02de259eb09a53"] = "6398505421375878808",
    ["5fb7ebe0da0c45fca0d813e85397d156"] = "724885594418722638"
}

local bot_check_key_words = {
    "920987d2c84c438e8b0577cc7429ff57",
    "e8749404c3174ed18bd65f7661754455",
    "6de4435175c44c00a3bec1972d9df627",
    "651720202c8041a8a8d3f41419abf65d",
    "40d216f1690a4ebf9708e48cddc00613",
    "423c193e1c744d3480269fe9789af48a",
    "a1a98da4f77c4c0d85928b7176d4d3c0",
    "5dac39a021e24637b7b7220e099db123",
    "9f9a41b58b4749da932b08f2703c0164",
    "758ffe4120a648a3958ef424c7d9aed4",
    "f8f92209179846c0b80e2cf33000c702",
    "efb3990ac9d74ad68857fcc96b9b4d23",
    "a1f017ca135147879d074485033e60bb",
    "dc796b127d43470da08adc513cc8f321",
    "0d218bc4acef4474af68824c2cf60da8",
    "1ee2d4985a084189b6aafef5dfdbf106",
    "7c0ac5e18aec468aac05b726c06ff77f",
    "07c0155f32034827803a0a9059394ebd",
    "9750a152fbe34d9389d57b81b19f5e62",
    "b9a68288194f44ca887950398321ff5f",
    "3f61895cba5e4528b387874e9f4f4fcb",
    "ab65e9c40f7e4e16b8f8cc5baaf088c4",
    "3132977999e64a8ba6b108ef6c2b4fec",
    "73e52564404b49bfa845fedd01c86f86",
    "32abae9142f74182afdefc5b00c71b7a",
    "6c3e6d01121f4d6db112d224290b0da5",
    "174a6749e13b48208a56a3978c68c611",
    "219ac99411c144e1a7ed8b6b9928c170",
    "724a0bed6f4240abba3e160021bc959d",
    "7c3e826620c64ba091ee3bf53fd9782a",
    "a9dff9b1557f4f7992bc66137c7a163d",
    "b30da6442d6e42699b0b7dd4d55d0aa7",
    "115817695acc42dd8009972e1d0585ed",
    "2f0bea49e10942148fc9bbf1443dc244",
    "b4b2c0689ca948afb8fc2ee4c1522d03",
    "c4127ed9c4214dd1ad605b88b83c9d71",
    "3bf5f36a79b247d8b91c881db5dc6525",
    "339d4eac24ec4051b395901a66fa9924",
    "3ade25240f8e4215a27190c022076c41",
    "ceb597759e4445e8b6052b25ccd95574",
    "ddc7778dcb5644fd812d5bbb1e43bf05",
    "49ee9a6d5f5249f1921f60e78631d22e",
    "c5d3abc83305435e9cad059fca5b5f13",
    "5ff9e38333884146b10f22be17c403aa",
    "22cd9605629443b1be5abf71399da196",
    "913005d23583484c8398899ff1b86a39",
    "89a519b000054825a578de7f87700c97",
    "edc1233147fb4e6ebd99a04dea934556",
    "fcdf3054ed824d1082acbbcbce208f2b",
    "d405f5b3f6f647b0923204abe39fe203",
    "a61465e7744249528d8b57d6fb03a7ab",
    "4cdd4eeaefea48eab9f5637a4cff4aca",
    "9279cc80f8b04da888497c58e23772c4",
    "2ca63b4ff99a49d092ffbedcf3f1e034",
    "b0370fa0ea174b2aaa5ac9d86bd12bd7",
    "e5e74fdffd634d2a9dc18b9e5ad8330f",
    "284af0e7368f40d087db7a30cba0995b",
    "77093d540cba475a87a4247ff8cbf214",
    "79499048999645c18146b1593313dcd3",
    "c136ba0885c04f5fa808769d8746e615",
    "1ab0167e34f14e538e6029c0720a532a",
    "2a156426f16a412084ed4ebf9026a352",
    "8f4832e8a9464ddfb91a15e9b8a00849",
    "763916b7ed044a24a635044ad53908c4",
    "d84f8ea6890e43a0ac0951663b140943",
    "aea74251d0c149148a6faa0836cdb5a5",
    "ec0500da5b4e42808d3878c39cfe5bed",
    "caf00dda4afa4577bbc1877864f13f44",
    "65e22f19eb2d49d3ba9df160c5fd2cc9",
    "38207224f5b9422fbb957893604e1cab",
    "57a8181014ef421a9f9119ccd566c542",
    "476d60a2ef994e5ca6fb5fe9bfa1373b",
    "614086cf61374c0399c19ddb3a948dbd",
    "997747e1ca0f4222aad3c8e0954452a7",
    "5976b5e304d54b54bcebeabde82b8a3d",
    "ba267d3de98a41619133ca987032c2e8",
    "5ddcb6c083124248ac90166908ced478",
    "5de0a22b1fe84197af96343c0346f303",
    "7071b96c735d49c9baa08c34cbbfe9c2",
    "484b17cff9cb4c6998667ca0c2557211",
    "abca05fb71b444df9d501d9d22440741",
    "0ce5dbe85ee4499a850a5d8056af42aa",
    "7c04cc27a5744f108918609cd8944187",
    "2ad1ad99c5a442a8a639ac05ac43c134",
    "aaae4d099c7b46998f7ff2096aa3e52b",
    "6789535618874ce287f5443564251ab6",
    "18d7318d230849bba432c2bf8a5a959b",
    "6234744df5444b64bab74364ba9ec680",
    "30a98430067040c0b4eb495de3b42e66",
    "83e18bfeb2394579b8555ff28c6bbba4",
    "78a4431b95774aa0a1070d63100d8e8f",
    "e2e43f4ee9b54befbd25b5e7b7220fbf",
    "57a879a877d146f38b77c42ccc7e832b",
    "6988792079cb43a599a0a2bc1fbe411a",
    "0fe5cd95c0944a9aad7335bf7d4f2612",
    "1092cea2a4d74fcb872024bab6904350",
    "99ca0e7f8e08415788731f81ac627457",
    "bee7b003fb544052a8c246e12c9f8b43",
    "7b6ba9a617664f549c02de259eb09a53",
    "5fb7ebe0da0c45fca0d813e85397d156"
}

local default_cc_js_base_url = "https://static.jxwaf.top/"

function _M.bot_check_ip(bot_check_mode)
  local limit_bot = ngx.shared.jxwaf_limit_bot
  local ip_addr = request.get_args("http_args","src_ip")
  local bot_auth_key = request.get_args("cookie_args","jxwaf_bot_check")
  if bot_auth_key then     
    local server_secret = _config_info.waf_auth
    local user_agent = ngx.var.http_user_agent or ""
    local ssl_client_hello_ciphers = ngx.ctx.ssl_client_hello_ciphers or ""
    local ssl_client_hello_versions = ngx.ctx.ssl_client_hello_versions or ""
    local ssl_client_hello_signature_algorithms = ngx.ctx.ssl_client_hello_signature_algorithms or ""
    local ssl_client_hello_alpn_protocols = ngx.ctx.ssl_client_hello_alpn_protocols or ""
    
    local as_key_table = {server_secret, user_agent, ssl_client_hello_ciphers, ssl_client_hello_versions, ssl_client_hello_signature_algorithms, ssl_client_hello_alpn_protocols}
    local aes_key = ngx.md5(table.concat(as_key_table))
    local aes_init = aes:new(aes_key, nil, aes.cipher(256, "ecb"),aes.hash.sha1)
    
    local decoded_key = b64.decode_base64url(bot_auth_key)
    if decoded_key  then
      local uuid_key = aes_init:decrypt(decoded_key)
      if uuid_key then
          return true
      end
    end
  end

  local bot_check_key = {}
  if bot_check_mode == "auto" then
    bot_check_key  = ngx.ctx.bot_check_key_auto or bot_check_key_auto
  elseif bot_check_mode == "slipper" then
    bot_check_key  = ngx.ctx.bot_check_key_slipper or bot_check_key_slipper
  elseif bot_check_mode == "puzzle" then
    bot_check_key  = ngx.ctx.bot_check_key_puzzle or bot_check_key_puzzle
  elseif bot_check_mode == "words" then
    bot_check_key = ngx.ctx.bot_check_key_words or bot_check_key_words
  end

  if #bot_check_key > 0 then
    math_randomseed(ngx.time())
    local num = math_random(1,#bot_check_key)
    local bot_check_uuid = bot_check_key[num]
    local cc_js_base_url =  ngx.ctx.cc_js_base_url or default_cc_js_base_url
    local cc_js_url = cc_js_base_url..bot_check_uuid
    local bot_check_html = ""
    if bot_check_mode == "auto" then
      local bot_auto_check_html = ngx.ctx.bot_auto_check_html or  default_bot_auto_check_html
      bot_check_html = string.gsub(bot_auto_check_html,"{{CC_JS_URL}}",cc_js_url) 
    elseif bot_check_mode == "slipper" then
      local bot_slipper_check_html = ngx.ctx.bot_slipper_check_html or  default_bot_slipper_check_html
      bot_check_html = string.gsub(bot_slipper_check_html,"{{CC_JS_URL}}",cc_js_url) 
    elseif bot_check_mode == "puzzle" then
      local bot_puzzle_check_html = ngx.ctx.bot_puzzle_check_html or  default_bot_puzzle_check_html
      bot_check_html = string.gsub(bot_puzzle_check_html,"{{CC_JS_URL}}",cc_js_url) 
    elseif bot_check_mode == "words" then
      local bot_words_check_html = ngx.ctx.bot_words_check_html or  default_bot_words_check_html
      bot_check_html = string.gsub(bot_words_check_html,"{{CC_JS_URL}}",cc_js_url) 
    end
    local request_uuid = ngx.ctx.request_uuid
    ngx.header.request_uuid = request_uuid
    ngx.header.content_type = "text/html;charset=utf-8"
    ngx.status = 200
    ngx.say(bot_check_html)
    return ngx.exit(200)
  end
end



function _M.bot_commit_auth()
  if ngx.var.uri == '/a20be899-96a6-40b2-88ba-32f1f75f1552-jxwaf' then
    local post_args = ngx.req.get_post_args()
    local post_args_key = post_args['key'] 
    local post_args_value = post_args['value'] 
    if not post_args_key or not post_args_value then
      return 
    end
    local uuid_key = uuid.generate_random()
    local bot_check_auto = ngx.ctx.bot_check_info_auto or bot_check_info_auto
    local bot_check_slipper = ngx.ctx.bot_check_info_slipper or bot_check_info_slipper
    local bot_check_puzzle = ngx.ctx.bot_check_info_puzzle or bot_check_info_puzzle
    local bot_check_words = ngx.ctx.bot_check_info_words or bot_check_info_words
    if  (bot_check_auto[post_args_key] == post_args_value or bot_check_slipper[post_args_key] == post_args_value or bot_check_puzzle[post_args_key] == post_args_value or bot_check_words[post_args_key] == post_args_value) then
        local server_secret = _config_info.waf_auth
        local user_agent = ngx.var.http_user_agent or ""
        local ssl_client_hello_ciphers = ngx.ctx.ssl_client_hello_ciphers or ""
        local ssl_client_hello_versions = ngx.ctx.ssl_client_hello_versions or ""
        local ssl_client_hello_signature_algorithms = ngx.ctx.ssl_client_hello_signature_algorithms or ""
        local ssl_client_hello_alpn_protocols = ngx.ctx.ssl_client_hello_alpn_protocols or ""
        local aes_key_table = {server_secret, user_agent, ssl_client_hello_ciphers, ssl_client_hello_versions, ssl_client_hello_signature_algorithms, ssl_client_hello_alpn_protocols}
        local aes_key = ngx.md5(table.concat(aes_key_table))
        local aes_init = aes:new(aes_key,nil,aes.cipher(256,"ecb"),aes.hash.sha1)
        ngx.header.content_type = "text/html;charset=utf-8"
        local cookie_value = b64.encode_base64url(aes_init:encrypt(uuid_key))
        ngx.header['Set-Cookie'] = "jxwaf_bot_check=" .. cookie_value .. "; path=/; Expires=" .. ngx.cookie_time(ngx.time() + 86400)
        return ngx.exit(200)
    end
  end
end



return _M