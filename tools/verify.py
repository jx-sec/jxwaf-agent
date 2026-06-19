#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JXWAF 验证脚本

发送请求到目标 URL，根据响应状态码/内容判定 WAF 防护是否生效。
支持单次请求验证（Web 规则）和高频请求验证（流量规则）。

用法示例：
  # 验证 Web 规则拦截（单次请求）
  python verify.py --url https://demo.jxwaf.com/admin --expect block

  # 验证 Web 规则放行
  python verify.py --url https://demo.jxwaf.com/ --expect pass

  # 验证 SQL 注入拦截
  python verify.py --url "https://demo.jxwaf.com/?id=1' OR 1=1--" --expect block

  # 验证流量规则（高频请求触发限速）
  python verify.py --url https://demo.jxwaf.com/api/login --mode flow \
    --count 150 --interval 0.1 --expect block

  # 验证白名单放行（指定 IP）
  python verify.py --url https://demo.jxwaf.com/admin \
    --header "X-Real-IP: 192.168.1.100" --expect pass

  # 批量验证（从 payloads.json 加载测试用例）
  python verify.py --batch ../tests/payloads.json --base-url https://demo.jxwaf.com
"""

import argparse
import json
import os
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from http.client import HTTPConnection, HTTPSConnection
import ssl


# ============================================================================
# 单次请求验证
# ============================================================================

def send_request(url, headers=None, method="GET", body=None, timeout=10):
    """发送 HTTP 请求，返回 (status_code, response_body, response_headers)"""
    req = Request(url, data=body, headers=headers or {}, method=method)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, body, dict(e.headers) if e.headers else {}
    except URLError as e:
        return -1, str(e.reason), {}
    except Exception as e:
        return -1, str(e), {}


def verify_single(url, expect, headers=None, method="GET", body=None):
    """验证单次请求"""
    status, resp_body, resp_headers = send_request(url, headers, method, body)

    # 判定逻辑
    blocked = False
    if status == 403:
        blocked = True
    elif status == 429:
        blocked = True
    elif status == 200 and ("blocked" in resp_body.lower() or "拦截" in resp_body
                             or "waf" in resp_body.lower()):
        blocked = True
    elif status == 0 or status == -1:
        # 连接被拒绝（reject_response 动作）
        blocked = True

    result = "block" if blocked else "pass"
    passed = (result == expect)

    return {
        "url": url,
        "status": status,
        "expect": expect,
        "actual": result,
        "passed": passed,
        "body_preview": resp_body[:200] if resp_body else "",
    }


# ============================================================================
# 高频请求验证（流量规则）
# ============================================================================

def verify_flow(url, count, interval, expect, headers=None):
    """高频发送请求，验证流量防护规则"""
    results = []
    blocked_count = 0

    for i in range(count):
        status, resp_body, _ = send_request(url, headers)
        blocked = False
        if status in (403, 429, 0, -1):
            blocked = True
        elif status == 200 and ("blocked" in resp_body.lower() or "拦截" in resp_body):
            blocked = True

        if blocked:
            blocked_count += 1

        results.append({
            "seq": i + 1,
            "status": status,
            "blocked": blocked,
        })

        if interval > 0:
            time.sleep(interval)

    # 判定：如果有请求被拦截，则认为流量规则生效
    actual = "block" if blocked_count > 0 else "pass"
    passed = (actual == expect)

    return {
        "url": url,
        "total_requests": count,
        "blocked_count": blocked_count,
        "expect": expect,
        "actual": actual,
        "passed": passed,
        "first_block_seq": next((r["seq"] for r in results if r["blocked"]), None),
    }


# ============================================================================
# 批量验证
# ============================================================================

def verify_batch(batch_file, base_url):
    """从 JSON 文件加载测试用例并批量验证"""
    with open(batch_file, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    total = len(test_cases)
    passed_count = 0

    print(f"加载 {total} 个测试用例\n")
    print(f"{'#':>3}  {'模块':<20} {'用例':<30} {'期望':<8} {'实际':<8} {'结果'}")
    print("-" * 90)

    for i, case in enumerate(test_cases):
        name = case.get("name", f"case-{i+1}")
        module = case.get("module", "unknown")
        expect = case.get("expect", "block")
        url = case.get("url", "")
        headers = case.get("headers", {})
        method = case.get("method", "GET")

        # 拼接 base_url
        if base_url and not url.startswith("http"):
            url = base_url.rstrip("/") + "/" + url.lstrip("/")

        if case.get("mode") == "flow":
            result = verify_flow(url, case.get("count", 100),
                                 case.get("interval", 0.1), expect, headers)
            actual = result["actual"]
        else:
            result = verify_single(url, expect, headers, method)
            actual = result["actual"]

        passed = result["passed"]
        if passed:
            passed_count += 1

        status_str = "PASS" if passed else "FAIL"
        print(f"{i+1:>3}  {module:<20} {name:<30} {expect:<8} {actual:<8} {status_str}")

    print("-" * 90)
    print(f"总计: {total}, 通过: {passed_count}, 失败: {total - passed_count}")
    return passed_count == total


# ============================================================================
# 主函数
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="JXWAF 验证脚本")
    parser.add_argument("--url", help="目标 URL")
    parser.add_argument("--expect", choices=["block", "pass"], default="block",
                        help="期望结果（block=被拦截, pass=放行）")
    parser.add_argument("--header", action="append", help="自定义请求头（可多次指定）")
    parser.add_argument("--method", default="GET", help="HTTP 方法")
    parser.add_argument("--data", help="请求体数据")
    parser.add_argument("--mode", choices=["single", "flow"], default="single",
                        help="验证模式：single=单次, flow=高频")
    parser.add_argument("--count", type=int, default=100, help="高频模式请求次数")
    parser.add_argument("--interval", type=float, default=0.1, help="高频模式请求间隔（秒）")
    parser.add_argument("--batch", help="批量验证，指定 payloads.json 文件路径")
    parser.add_argument("--base-url", help="批量验证时的基础 URL")
    args = parser.parse_args()

    # 批量模式
    if args.batch:
        success = verify_batch(args.batch, args.base_url or "")
        sys.exit(0 if success else 1)

    # 单次/高频模式
    if not args.url:
        parser.error("--url 或 --batch 必须指定一个")

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, _, value = h.partition(":")
                headers[key.strip()] = value.strip()

    body = args.data.encode("utf-8") if args.data else None

    if args.mode == "flow":
        result = verify_flow(args.url, args.count, args.interval, args.expect, headers)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        result = verify_single(args.url, args.expect, headers, args.method, body)
        print(json.dumps(result, ensure_ascii=False, indent=2))

    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
