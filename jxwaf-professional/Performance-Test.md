# 性能测试报告

## 测试环境说明

### 整体架构

![性能测试架构图](/images/jxwaf_performance_test_architecture.png)

### 硬件规格

| 角色 | 实例规格 | CPU | 内存 | 系统盘 | 网络 | 数量 |
|------|----------|-----|------|--------|------|------|
| WAF 节点 | 阿里云 ecs.c9i.xlarge | 4 vCPU | 8 GiB | 40 GB ESSD PL0 | 1 Gbps | 1 |
| 业务服务器 | 阿里云 ecs.c9i.xlarge | 4 vCPU | 8 GiB | 40 GB ESSD PL0 | 1 Gbps | 3 |
| 压测客户端 | 阿里云 ecs.c9i.xlarge | 4 vCPU | 8 GiB | 40 GB ESSD PL0 | 1 Gbps | 1 |

### 软件环境

| 组件 | 版本/说明 |
|------|-----------|
| 操作系统 | Debian 12.8 (kernel 6.1.0-18-amd64) |
| WAF 版本 | JXWAF 专业版 |
| 业务后端 | JXWAF安全模型服务，接口返回内容为 JSON 格式 |
| 压测工具 | wrk 4.2.0 |
| 网络 | 所有节点处于同一 VPC 内网 |

本次压测的目标接口为 `/demo/web_attack_check`，正常业务请求及响应示例如下：

```bash
curl http://tmp-test.jxwaf.com/demo/web_attack_check -d 'a=1'
```

返回 JSON：

```json
{"result":"safe","ai_model":"","status":"ok","token":"d3e45f050abd83df364dfd31676c46b0a01b8ee9"}
```

后续所有压力测试均通过 wrk 以 POST 表单方式模拟此类正常业务流量，以评估不同防护模式下的性能表现。

## 测试结果

为保证压测条件一致，所有测试方案均使用以下 wrk 配置：

```bash
cat > post.lua <<'EOF'
wrk.method = "POST"
wrk.body   = "id=1"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
EOF

wrk -t4 -c1000 -d60s --timeout 10s -s post.lua http://tmp-test.jxwaf.com/demo/web_attack_check
```

| 测试方案 | HTTP QPS | HTTPS QPS | HTTP 相对损耗 | HTTPS 相对损耗 |
|----------|----------|-----------|---------------|----------------|
| **方案一：纯转发（所有防护关闭）** | 48,262 | 30,422 | — | — |
| **方案二：Web 防护引擎（AI防护+语义防护）** | 31,159 | 21,343 | ↓ 35.5% | ↓ 29.8% |
| **方案三：Web 防护引擎+流量防护引擎（所有流量防护模块开启）** | 18,462 | 13,253 | ↓ 61.7% | ↓ 56.4% |

## 测试结论

基于单节点 4 核 8G 配置，本次测试充分验证了 JXWAF 专业版在不同防护模式下的性能表现：

- **高性能转发**  
  纯转发模式下，单节点可提供 **48,262 HTTP QPS** 与 **30,422 HTTPS QPS** 的吞吐能力，为高并发业务代理打下坚实基础。

- **AI 语义防护低开销**  
  开启 AI 安全模型与语义分析引擎后，HTTP QPS 仍达 **31,159**（下降仅 35.5%），HTTPS QPS 达 **21,343**（下降仅 29.8%），以极小的性能损失换取深度安全检测能力。

- **全场景防护强劲可靠**  
  部署全部防护模块（Web 引擎 + 流量引擎）后，单节点依然稳定支撑 **18,462 HTTP QPS** 与 **13,253 HTTPS QPS**，平均延迟分别为 **55.67ms** 和 **75.64ms**，单核吞吐超 **4,600 QPS**。单节点日均即可处理超 15 亿次请求检测，完全满足企业高并发场景下的安全防护需求。

- **低成本弹性扩展**  
  本次测试基于 4 核 8G 经济型云服务器，JXWAF 支持集群化水平扩展，通过增加节点即可线性提升整体吞吐能力，帮助企业在有限预算下获得企业级安全防护。

## 附录：wrk 原始测试输出

### 方案一：纯转发（所有防护关闭）

**HTTP**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua http://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ http://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    21.11ms   10.89ms 464.77ms   98.15%
    Req/Sec    12.14k   284.46    14.21k    76.04%
  2897894 requests in 1.00m, 1.30GB read
Requests/sec:  48262.36
Transfer/sec:     22.09MB
```

**HTTPS**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua https://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ https://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    33.23ms   17.33ms 616.06ms   98.48%
    Req/Sec     7.71k   371.03     8.30k    93.74%
  1826884 requests in 1.00m, 836.28MB read
Requests/sec:  30422.85
Transfer/sec:     13.93MB
```

### 方案二：Web 防护引擎（AI防护+语义防护）

**HTTP**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua http://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ http://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    32.82ms   17.45ms 674.13ms   97.26%
    Req/Sec     7.84k   235.10     8.97k    78.17%
  1871496 requests in 1.00m, 856.70MB read
Requests/sec:  31159.35
Transfer/sec:     14.26MB
```

**HTTPS**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua https://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ https://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    46.95ms   18.56ms 601.54ms   95.63%
    Req/Sec     5.41k   267.63     6.07k    92.86%
  1281719 requests in 1.00m, 586.72MB read
Requests/sec:  21343.80
Transfer/sec:      9.77MB
```

### 方案三：Web 防护引擎+流量防护引擎（所有防护模块开启）

**HTTP**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua http://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ http://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    55.67ms   31.36ms   1.07s    97.84%
    Req/Sec     4.64k   151.17     5.40k    73.67%
  1108527 requests in 1.00m, 507.44MB read
Requests/sec:  18462.64
Transfer/sec:      8.45MB
```

**HTTPS**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua https://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ https://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    75.64ms   18.45ms 590.15ms   96.97%
    Req/Sec     3.36k   195.45     3.79k    83.82%
  795963 requests in 1.00m, 364.36MB read
Requests/sec:  13253.93
Transfer/sec:      6.07MB
```
