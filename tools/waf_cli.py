#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JxWAF 控制台 CLI 工具

对接 JxWAF 控制台 API，支持 Web 防护规则、流量防护规则、防护组件、名单防护的管理操作。
配置从 config.env 或环境变量读取。

用法示例：
  # Web 防护规则
  python waf_cli.py web-rule list --group default
  python waf_cli.py web-rule create --group default --name block_admin \
    --matchs '[{"match_args":[{"key":"http_args","value":"path"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"/admin"}]' \
    --action block

  # 流量防护规则
  python waf_cli.py flow-rule list --group default
  python waf_cli.py flow-rule create --group default --name cc_protect \
    --action bot_check --action-value slipper --filter true \
    --entity '[{"key":"http_args","value":"src_ip"}]' --stat-time 10 --exceed-count 20 --block-time 600

  # 防护组件
  python waf_cli.py component list
  python waf_cli.py component create --name scan_detect --detail "恶意扫描检测" \
    --code-base64 $(base64 -b component_code.lua) --conf '{"patterns":["sqlmap","nikto"]}'

  # 名单防护
  python waf_cli.py name-list list
  python waf_cli.py name-list create --name ip_blacklist --action block \
    --rule '[{"key":"http_args","value":"src_ip"}]'
  python waf_cli.py name-list add-item --name ip_blacklist --item 1.2.3.4
  python waf_cli.py name-list del-item --name ip_blacklist --item 1.2.3.4

  # Web 白名单规则（命中则跳过 Web 防护规则）
  python waf_cli.py web-white-rule list --group default
  python waf_cli.py web-white-rule create --group default --name allow_admin_ip \
    --matchs '[{"match_args":[{"key":"http_args","value":"src_ip"}],"args_prepocess":["none"],"match_operator":"ip_in_cidr","match_value":"192.168.1.0/24"}]'

  # 流量白名单规则（命中则跳过流量防护规则）
  python waf_cli.py flow-white-rule list --group default
  python waf_cli.py flow-white-rule create --group default --name allow_health_check \
    --matchs '[{"match_args":[{"key":"header_args","value":"User-Agent"}],"args_prepocess":["none"],"match_operator":"str_contain","match_value":"HealthCheck"}]'
"""

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# ============================================================================
# 配置加载
# ============================================================================

def load_config():
    """从 config.env 文件或环境变量加载配置"""
    config = {
        "JXWAF_API_URL": os.environ.get("JXWAF_API_URL", ""),
        "JXWAF_WAF_AUTH": os.environ.get("JXWAF_WAF_AUTH", ""),
        "JXWAF_GROUP": os.environ.get("JXWAF_GROUP", "default"),
    }

    # 尝试从 config.env 加载
    env_path = Path(__file__).parent.parent / "config.env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and value:
                        config[key] = value

    return config


# ============================================================================
# HTTP 请求封装
# ============================================================================

def api_request(config, path, data=None, use_waf_auth=False):
    """发送 POST 请求到 JxWAF 控制台 API"""
    base_url = config.get("JXWAF_API_URL", "").rstrip("/")
    if not base_url:
        print("错误：JXWAF_API_URL 未配置，请检查 config.env", file=sys.stderr)
        sys.exit(1)

    url = base_url + path

    # 构建请求数据
    if data is None:
        data = {}
    if use_waf_auth:
        waf_auth = config.get("JXWAF_WAF_AUTH", "")
        if not waf_auth:
            print("错误：JXWAF_WAF_AUTH 未配置，请检查 config.env", file=sys.stderr)
            sys.exit(1)
        data["waf_auth"] = waf_auth

    body = json.dumps(data).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    req = Request(url, data=body, headers=headers, method="POST")

    try:
        with urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result
    except HTTPError as e:
        print(f"HTTP 错误 {e.code}: {e.reason}", file=sys.stderr)
        try:
            err_body = e.read().decode("utf-8")
            print(f"响应: {err_body}", file=sys.stderr)
        except Exception:
            pass
        sys.exit(1)
    except URLError as e:
        print(f"请求失败: {e.reason}", file=sys.stderr)
        sys.exit(1)


def print_result(result):
    """格式化输出 API 响应"""
    if isinstance(result, dict):
        if result.get("result") is False:
            print(f"失败: {result.get('error', '未知错误')}", file=sys.stderr)
            sys.exit(1)
        # 提取核心数据输出
        if "records" in result:
            records = result["records"]
            print(f"共 {result.get('total_records', len(records))} 条记录，"
                  f"第 {result.get('page', 1)} 页，"
                  f"共 {result.get('total_pages', 1)} 页\n")
            for record in records:
                print(json.dumps(record, ensure_ascii=False, indent=2))
                print("-" * 60)
        elif "data" in result:
            print(json.dumps(result["data"], ensure_ascii=False, indent=2))
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result)


# ============================================================================
# Web 防护规则命令
# ============================================================================

def cmd_web_rule(args, config):
    group = args.group or config.get("JXWAF_GROUP", "default")

    if args.subcmd == "list":
        result = api_request(config, "/waf/get_group_web_rule_protection_list",
                             {"page": args.page, "group_name": group})
        print_result(result)

    elif args.subcmd == "get":
        result = api_request(config, "/waf/get_group_web_rule_protection",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "create":
        result = api_request(config, "/waf/create_group_web_rule_protection", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs,
            "rule_action": args.action,
            "action_value": args.action_value or "",
        })
        print_result(result)

    elif args.subcmd == "edit":
        result = api_request(config, "/waf/edit_group_web_rule_protection", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs,
            "rule_action": args.action,
            "action_value": args.action_value or "",
        })
        print_result(result)

    elif args.subcmd == "delete":
        result = api_request(config, "/waf/delete_group_web_rule_protection",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "status":
        result = api_request(config, "/waf/edit_group_web_rule_protection_status",
                             {"group_name": group, "rule_name": args.name, "status": args.status})
        print_result(result)


# ============================================================================
# 流量防护规则命令
# ============================================================================

def cmd_flow_rule(args, config):
    group = args.group or config.get("JXWAF_GROUP", "default")

    if args.subcmd == "list":
        result = api_request(config, "/waf/get_group_flow_rule_protection_list",
                             {"page": args.page, "group_name": group})
        print_result(result)

    elif args.subcmd == "get":
        result = api_request(config, "/waf/get_group_flow_rule_protection",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "create":
        result = api_request(config, "/waf/create_group_flow_rule_protection", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs or "[]",
            "rule_action": args.action,
            "action_value": args.action_value or "",
            "filter": args.filter,
            "entity": args.entity,
            "stat_time": str(args.stat_time),
            "exceed_count": str(args.exceed_count),
            "block_time": str(args.block_time),
        })
        print_result(result)

    elif args.subcmd == "edit":
        result = api_request(config, "/waf/edit_group_flow_rule_protection", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs or "[]",
            "rule_action": args.action,
            "action_value": args.action_value or "",
            "filter": args.filter,
            "entity": args.entity,
            "stat_time": str(args.stat_time),
            "exceed_count": str(args.exceed_count),
            "block_time": str(args.block_time),
        })
        print_result(result)

    elif args.subcmd == "delete":
        result = api_request(config, "/waf/delete_group_flow_rule_protection",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "status":
        result = api_request(config, "/waf/edit_group_flow_rule_protection_status",
                             {"group_name": group, "rule_name": args.name, "status": args.status})
        print_result(result)


# ============================================================================
# 防护组件命令
# ============================================================================

def cmd_component(args, config):
    if args.subcmd == "list":
        result = api_request(config, "/waf/get_component_list", {"page": args.page})
        print_result(result)

    elif args.subcmd == "get":
        result = api_request(config, "/waf/get_component", {"name": args.name})
        print_result(result)

    elif args.subcmd == "create":
        # code 字段需 Base64 编码
        code_value = args.code_base64
        if args.code_file:
            with open(args.code_file, "r", encoding="utf-8") as f:
                code_value = base64.b64encode(f.read().encode("utf-8")).decode("utf-8")
        if not code_value:
            print("错误：需提供 --code-base64 或 --code-file", file=sys.stderr)
            sys.exit(1)
        result = api_request(config, "/waf/create_component", {
            "name": args.name,
            "detail": args.detail or "",
            "code": code_value,
            "conf": args.conf or "{}",
        })
        print_result(result)

    elif args.subcmd == "edit":
        code_value = args.code_base64
        if args.code_file:
            with open(args.code_file, "r", encoding="utf-8") as f:
                code_value = base64.b64encode(f.read().encode("utf-8")).decode("utf-8")
        if not code_value:
            print("错误：需提供 --code-base64 或 --code-file", file=sys.stderr)
            sys.exit(1)
        result = api_request(config, "/waf/edit_component", {
            "name": args.name,
            "detail": args.detail or "",
            "code": code_value,
            "conf": args.conf or "{}",
        })
        print_result(result)

    elif args.subcmd == "delete":
        result = api_request(config, "/waf/delete_component", {"name": args.name})
        print_result(result)

    elif args.subcmd == "status":
        result = api_request(config, "/waf/edit_component_status",
                             {"name": args.name, "status": args.status})
        print_result(result)


# ============================================================================
# 名单防护命令
# ============================================================================

def cmd_name_list(args, config):
    if args.subcmd == "list":
        result = api_request(config, "/waf/get_global_name_list_list", {"page": args.page})
        print_result(result)

    elif args.subcmd == "get":
        result = api_request(config, "/waf/get_global_name_list",
                             {"name_list_name": args.name})
        print_result(result)

    elif args.subcmd == "create":
        result = api_request(config, "/waf/create_global_name_list", {
            "name_list_name": args.name,
            "name_list_detail": args.detail or "",
            "name_list_rule": args.rule,
            "name_list_action": args.action,
            "action_value": args.action_value or "",
            "name_list_expire": args.expire or "false",
            "name_list_expire_time": args.expire_time or "0",
        })
        print_result(result)

    elif args.subcmd == "edit":
        result = api_request(config, "/waf/edit_global_name_list", {
            "name_list_name": args.name,
            "name_list_detail": args.detail or "",
            "name_list_rule": args.rule,
            "name_list_action": args.action,
            "action_value": args.action_value or "",
            "name_list_expire": args.expire or "false",
            "name_list_expire_time": args.expire_time or "0",
        })
        print_result(result)

    elif args.subcmd == "delete":
        result = api_request(config, "/waf/delete_global_name_list",
                             {"name_list_name": args.name})
        print_result(result)

    elif args.subcmd == "status":
        result = api_request(config, "/waf/edit_global_name_list_status",
                             {"name_list_name": args.name, "status": args.status})
        print_result(result)

    elif args.subcmd == "list-items":
        result = api_request(config, "/waf/get_name_list_item_list_list",
                             {"page": args.page, "name_list_name": args.name})
        print_result(result)

    elif args.subcmd == "add-item":
        # 优先使用外部 API（waf_auth 鉴权），适合自动化
        if args.use_api:
            result = api_request(config, "/api/create_global_name_list_item", {
                "name_list_name": args.name,
                "name_list_item": args.item,
            }, use_waf_auth=True)
        else:
            result = api_request(config, "/waf/create_global_name_list_item", {
                "name_list_name": args.name,
                "name_list_item": args.item,
            })
        print_result(result)

    elif args.subcmd == "del-item":
        if args.use_api:
            result = api_request(config, "/api/delete_global_name_list_item", {
                "name_list_name": args.name,
                "name_list_item": args.item,
            }, use_waf_auth=True)
        else:
            result = api_request(config, "/waf/delete_global_name_list_item", {
                "name_list_name": args.name,
                "name_list_item": args.item,
            })
        print_result(result)

    elif args.subcmd == "search-item":
        if args.use_api:
            result = api_request(config, "/api/search_global_name_list_item", {
                "page": args.page,
                "name_list_name": args.name,
                "search_value": args.search,
            }, use_waf_auth=True)
        else:
            result = api_request(config, "/waf/search_global_name_list_item", {
                "page": args.page,
                "name_list_name": args.name,
                "search_value": args.search,
            })
        print_result(result)


# ============================================================================
# Web 白名单规则命令
# ============================================================================

def cmd_web_white_rule(args, config):
    group = args.group or config.get("JXWAF_GROUP", "default")

    if args.subcmd == "list":
        result = api_request(config, "/waf/get_group_web_white_rule_list",
                             {"page": args.page, "group_name": group})
        print_result(result)

    elif args.subcmd == "get":
        result = api_request(config, "/waf/get_group_web_white_rule",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "create":
        result = api_request(config, "/waf/create_group_web_white_rule", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs,
            "rule_action": "web_bypass",
            "action_value": args.action_value or "",
        })
        print_result(result)

    elif args.subcmd == "edit":
        result = api_request(config, "/waf/edit_group_web_white_rule", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs,
            "rule_action": "web_bypass",
            "action_value": args.action_value or "",
        })
        print_result(result)

    elif args.subcmd == "delete":
        result = api_request(config, "/waf/delete_group_web_white_rule",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "status":
        result = api_request(config, "/waf/edit_group_web_white_rule_status",
                             {"group_name": group, "rule_name": args.name, "status": args.status})
        print_result(result)

    elif args.subcmd == "priority":
        data = {
            "group_name": group,
            "rule_name": args.name,
            "type": args.type,
        }
        if args.type == "exchange":
            data["exchange_rule_name"] = args.exchange_name
        result = api_request(config, "/waf/exchange_group_web_white_rule_priority", data)
        print_result(result)


# ============================================================================
# 流量白名单规则命令
# ============================================================================

def cmd_flow_white_rule(args, config):
    group = args.group or config.get("JXWAF_GROUP", "default")

    if args.subcmd == "list":
        result = api_request(config, "/waf/get_group_flow_white_rule_list",
                             {"page": args.page, "group_name": group})
        print_result(result)

    elif args.subcmd == "get":
        result = api_request(config, "/waf/get_group_flow_white_rule",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "create":
        result = api_request(config, "/waf/create_group_flow_white_rule", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs,
            "rule_action": "flow_bypass",
            "action_value": args.action_value or "",
        })
        print_result(result)

    elif args.subcmd == "edit":
        result = api_request(config, "/waf/edit_group_flow_white_rule", {
            "group_name": group,
            "rule_name": args.name,
            "rule_detail": args.detail or "",
            "rule_matchs": args.matchs,
            "rule_action": "flow_bypass",
            "action_value": args.action_value or "",
        })
        print_result(result)

    elif args.subcmd == "delete":
        result = api_request(config, "/waf/delete_group_flow_white_rule",
                             {"group_name": group, "rule_name": args.name})
        print_result(result)

    elif args.subcmd == "status":
        result = api_request(config, "/waf/edit_group_flow_white_rule_status",
                             {"group_name": group, "rule_name": args.name, "status": args.status})
        print_result(result)

    elif args.subcmd == "priority":
        data = {
            "group_name": group,
            "rule_name": args.name,
            "type": args.type,
        }
        if args.type == "exchange":
            data["exchange_rule_name"] = args.exchange_name
        result = api_request(config, "/waf/exchange_group_flow_white_rule_priority", data)
        print_result(result)


# ============================================================================
# 参数解析
# ============================================================================

def build_parser():
    parser = argparse.ArgumentParser(
        description="JxWAF 控制台 CLI 工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="module", help="功能模块")

    # --- Web 防护规则 ---
    web = subparsers.add_parser("web-rule", help="Web 防护规则管理")
    web_sub = web.add_subparsers(dest="subcmd")
    web_sub.add_parser("list", help="规则列表").add_argument("--page", type=int, default=1)
    web_sub.add_parser("get", help="查询单条").add_argument("--name", required=True)
    wc = web_sub.add_parser("create", help="创建规则")
    wc.add_argument("--name", required=True)
    wc.add_argument("--detail")
    wc.add_argument("--matchs", required=True, help="匹配条件 JSON")
    wc.add_argument("--action", required=True, choices=["block", "watch"])
    wc.add_argument("--action-value", default="")
    we = web_sub.add_parser("edit", help="编辑规则")
    we.add_argument("--name", required=True)
    we.add_argument("--detail")
    we.add_argument("--matchs", required=True)
    we.add_argument("--action", required=True, choices=["block", "watch"])
    we.add_argument("--action-value", default="")
    web_sub.add_parser("delete", help="删除规则").add_argument("--name", required=True)
    ws = web_sub.add_parser("status", help="切换状态")
    ws.add_argument("--name", required=True)
    ws.add_argument("--status", required=True, choices=["true", "false"])
    for sp in [web]:
        sp.add_argument("--group", help="分组名（专业版）")

    # --- 流量防护规则 ---
    flow = subparsers.add_parser("flow-rule", help="流量防护规则管理")
    flow_sub = flow.add_subparsers(dest="subcmd")
    flow_sub.add_parser("list", help="规则列表").add_argument("--page", type=int, default=1)
    flow_sub.add_parser("get", help="查询单条").add_argument("--name", required=True)
    fc = flow_sub.add_parser("create", help="创建规则")
    fc.add_argument("--name", required=True)
    fc.add_argument("--detail")
    fc.add_argument("--matchs", default="[]")
    fc.add_argument("--action", required=True,
                    choices=["block", "reject_response", "bot_check", "network_block", "watch"])
    fc.add_argument("--action-value", default="")
    fc.add_argument("--filter", required=True, choices=["true", "false"])
    fc.add_argument("--entity", required=True, help="统计对象 JSON")
    fc.add_argument("--stat-time", type=int, required=True)
    fc.add_argument("--exceed-count", type=int, required=True)
    fc.add_argument("--block-time", type=int, required=True)
    fe = flow_sub.add_parser("edit", help="编辑规则")
    fe.add_argument("--name", required=True)
    fe.add_argument("--detail")
    fe.add_argument("--matchs", default="[]")
    fe.add_argument("--action", required=True,
                    choices=["block", "reject_response", "bot_check", "network_block", "watch"])
    fe.add_argument("--action-value", default="")
    fe.add_argument("--filter", required=True, choices=["true", "false"])
    fe.add_argument("--entity", required=True)
    fe.add_argument("--stat-time", type=int, required=True)
    fe.add_argument("--exceed-count", type=int, required=True)
    fe.add_argument("--block-time", type=int, required=True)
    flow_sub.add_parser("delete", help="删除规则").add_argument("--name", required=True)
    fs = flow_sub.add_parser("status", help="切换状态")
    fs.add_argument("--name", required=True)
    fs.add_argument("--status", required=True, choices=["true", "false"])
    flow.add_argument("--group", help="分组名（专业版）")

    # --- 防护组件 ---
    comp = subparsers.add_parser("component", help="防护组件管理")
    comp_sub = comp.add_subparsers(dest="subcmd")
    comp_sub.add_parser("list", help="组件列表").add_argument("--page", type=int, default=1)
    comp_sub.add_parser("get", help="查询单个").add_argument("--name", required=True)
    cc = comp_sub.add_parser("create", help="创建组件")
    cc.add_argument("--name", required=True)
    cc.add_argument("--detail")
    cc.add_argument("--code-base64", help="Base64 编码的 Lua 代码")
    cc.add_argument("--code-file", help="Lua 代码文件路径（自动 Base64 编码）")
    cc.add_argument("--conf", default="{}", help="组件配置 JSON")
    ce = comp_sub.add_parser("edit", help="编辑组件")
    ce.add_argument("--name", required=True)
    ce.add_argument("--detail")
    ce.add_argument("--code-base64")
    ce.add_argument("--code-file")
    ce.add_argument("--conf", default="{}")
    comp_sub.add_parser("delete", help="删除组件").add_argument("--name", required=True)
    cs = comp_sub.add_parser("status", help="切换状态")
    cs.add_argument("--name", required=True)
    cs.add_argument("--status", required=True, choices=["true", "false"])

    # --- 名单防护 ---
    nl = subparsers.add_parser("name-list", help="名单防护管理")
    nl_sub = nl.add_subparsers(dest="subcmd")
    nl_sub.add_parser("list", help="名单列表").add_argument("--page", type=int, default=1)
    nl_sub.add_parser("get", help="查询单个名单").add_argument("--name", required=True)
    nlc = nl_sub.add_parser("create", help="创建名单")
    nlc.add_argument("--name", required=True)
    nlc.add_argument("--detail")
    nlc.add_argument("--rule", required=True, help="匹配规则 JSON")
    nlc.add_argument("--action", required=True,
                     choices=["block", "reject_response", "bot_check", "network_block",
                              "watch", "all_bypass", "web_bypass", "flow_bypass"])
    nlc.add_argument("--action-value", default="")
    nlc.add_argument("--expire", default="false", choices=["true", "false"])
    nlc.add_argument("--expire-time", default="0")
    nle = nl_sub.add_parser("edit", help="编辑名单")
    nle.add_argument("--name", required=True)
    nle.add_argument("--detail")
    nle.add_argument("--rule", required=True)
    nle.add_argument("--action", required=True,
                     choices=["block", "reject_response", "bot_check", "network_block",
                              "watch", "all_bypass", "web_bypass", "flow_bypass"])
    nle.add_argument("--action-value", default="")
    nle.add_argument("--expire", default="false", choices=["true", "false"])
    nle.add_argument("--expire-time", default="0")
    nl_sub.add_parser("delete", help="删除名单").add_argument("--name", required=True)
    nls = nl_sub.add_parser("status", help="切换状态")
    nls.add_argument("--name", required=True)
    nls.add_argument("--status", required=True, choices=["true", "false"])
    # 条目管理
    nli = nl_sub.add_parser("list-items", help="条目列表")
    nli.add_argument("--name", required=True)
    nli.add_argument("--page", type=int, default=1)
    nai = nl_sub.add_parser("add-item", help="添加条目")
    nai.add_argument("--name", required=True)
    nai.add_argument("--item", required=True)
    nai.add_argument("--use-api", action="store_true", help="使用外部 API（waf_auth 鉴权）")
    ndi = nl_sub.add_parser("del-item", help="删除条目")
    ndi.add_argument("--name", required=True)
    ndi.add_argument("--item", required=True)
    ndi.add_argument("--use-api", action="store_true")
    nsi = nl_sub.add_parser("search-item", help="搜索条目")
    nsi.add_argument("--name", required=True)
    nsi.add_argument("--search", required=True)
    nsi.add_argument("--page", type=int, default=1)
    nsi.add_argument("--use-api", action="store_true")

    # --- Web 白名单规则 ---
    wweb = subparsers.add_parser("web-white-rule", help="Web 白名单规则管理")
    wweb_sub = wweb.add_subparsers(dest="subcmd")
    wweb_sub.add_parser("list", help="白名单列表").add_argument("--page", type=int, default=1)
    wweb_sub.add_parser("get", help="查询单条").add_argument("--name", required=True)
    wwc = wweb_sub.add_parser("create", help="创建白名单")
    wwc.add_argument("--name", required=True)
    wwc.add_argument("--detail")
    wwc.add_argument("--matchs", required=True, help="匹配条件 JSON")
    wwc.add_argument("--action-value", default="")
    wwe = wweb_sub.add_parser("edit", help="编辑白名单")
    wwe.add_argument("--name", required=True)
    wwe.add_argument("--detail")
    wwe.add_argument("--matchs", required=True)
    wwe.add_argument("--action-value", default="")
    wweb_sub.add_parser("delete", help="删除白名单").add_argument("--name", required=True)
    wws = wweb_sub.add_parser("status", help="切换状态")
    wws.add_argument("--name", required=True)
    wws.add_argument("--status", required=True, choices=["true", "false"])
    wwp = wweb_sub.add_parser("priority", help="调整优先级")
    wwp.add_argument("--name", required=True)
    wwp.add_argument("--type", required=True, choices=["top", "exchange"],
                     help="top=置顶, exchange=交换")
    wwp.add_argument("--exchange-name", help="交换目标规则名（type=exchange 时必填）")
    wweb.add_argument("--group", help="分组名（专业版）")

    # --- 流量白名单规则 ---
    wflow = subparsers.add_parser("flow-white-rule", help="流量白名单规则管理")
    wflow_sub = wflow.add_subparsers(dest="subcmd")
    wflow_sub.add_parser("list", help="白名单列表").add_argument("--page", type=int, default=1)
    wflow_sub.add_parser("get", help="查询单条").add_argument("--name", required=True)
    fwc = wflow_sub.add_parser("create", help="创建白名单")
    fwc.add_argument("--name", required=True)
    fwc.add_argument("--detail")
    fwc.add_argument("--matchs", required=True, help="匹配条件 JSON")
    fwc.add_argument("--action-value", default="")
    fwe = wflow_sub.add_parser("edit", help="编辑白名单")
    fwe.add_argument("--name", required=True)
    fwe.add_argument("--detail")
    fwe.add_argument("--matchs", required=True)
    fwe.add_argument("--action-value", default="")
    wflow_sub.add_parser("delete", help="删除白名单").add_argument("--name", required=True)
    fws = wflow_sub.add_parser("status", help="切换状态")
    fws.add_argument("--name", required=True)
    fws.add_argument("--status", required=True, choices=["true", "false"])
    fwp = wflow_sub.add_parser("priority", help="调整优先级")
    fwp.add_argument("--name", required=True)
    fwp.add_argument("--type", required=True, choices=["top", "exchange"],
                     help="top=置顶, exchange=交换")
    fwp.add_argument("--exchange-name", help="交换目标规则名（type=exchange 时必填）")
    wflow.add_argument("--group", help="分组名（专业版）")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(1)

    config = load_config()

    if args.module == "web-rule":
        cmd_web_rule(args, config)
    elif args.module == "flow-rule":
        cmd_flow_rule(args, config)
    elif args.module == "component":
        cmd_component(args, config)
    elif args.module == "name-list":
        cmd_name_list(args, config)
    elif args.module == "web-white-rule":
        cmd_web_white_rule(args, config)
    elif args.module == "flow-white-rule":
        cmd_flow_white_rule(args, config)


if __name__ == "__main__":
    main()
