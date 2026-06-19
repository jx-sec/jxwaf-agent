# 性能测试报告


## 测试环境说明


### 整体架构

标准版将 WAF 节点、控制台、数据库部署在同一台服务器上，架构如下：

```
  ┌───────────────────────────┐
  │       压测客户端 (wrk)     │
  └─────────────┬─────────────┘
                │ HTTP 请求
                ▼
  ┌─────────────────────────────────────────┐
  │          JXWAF 标准版服务器               │
  │  ┌─────────┐  ┌───────────┐              │
  │  │ WAF 节点 │  │ JXWAF     │              │
  │  │ (Nginx) │  │ 控制台     │              │
  │  └────┬────┘  └─────┬─────┘              │
  │       │             │                    │
  │       │      ┌──────┴──────┐             │
  │       │      │   MySQL     │             │
  │       │      └─────────────┘             │
  └───────┼─────────────────────────────────┘
          │ 代理转发
          ▼
  ┌───────────────────────────┐
  │       业务服务器           │
  │  (安全模型服务，JSON响应)   │
  └───────────────────────────┘
```

> 专业版中 WAF 节点与控制台、日志数据库分属不同服务器独立部署；标准版将三者合一，简化架构的同时降低硬件成本。


### 硬件规格


| 角色 | 实例规格 | CPU | 内存 | 系统盘 | 网络 | 数量 |
|------|----------|-----|------|--------|------|------|
| WAF 服务器（含节点+控制台+MySQL） | 阿里云 ecs.c9i.xlarge | 4 vCPU | 8 GiB | 40 GB ESSD PL0 | 1 Gbps | 1 |
| 业务服务器 | 阿里云 ecs.c9i.xlarge | 4 vCPU | 8 GiB | 40 GB ESSD PL0 | 1 Gbps | 1 |
| 压测客户端 | 阿里云 ecs.c9i.xlarge | 4 vCPU | 8 GiB | 40 GB ESSD PL0 | 1 Gbps | 1 |


### 软件环境


| 组件 | 版本/说明 |
|------|-----------|
| 操作系统 | Debian 12.8 (kernel 6.1.0-18-amd64) |
| WAF 版本 | JXWAF 标准版 |
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


| 测试方案 | HTTP QPS | HTTPS QPS |
|----------|----------|-----------|
| **方案一：纯转发（所有防护关闭）** | 67,849 | 55,227 |
| **方案二：Web 防护引擎（AI防护+语义防护）** | 36,388 | 31,081 |
| **方案三：Web 防护引擎+流量防护引擎（所有流量防护模块开启）** | 10,574 | 7,739 |


## 测试结论


基于单节点 4 核 8G 配置，本次测试充分验证了 JXWAF 标准版在不同防护模式下的性能表现：


- **高性能转发**  
  纯转发模式下，单节点可提供 **67,849 HTTP QPS** 与 **55,227 HTTPS QPS** 的吞吐能力，为高并发业务代理打下坚实基础。


- **AI 语义防护低开销**  
  开启 AI 安全模型与语义分析引擎后，HTTP QPS 仍达 **36,388**，HTTPS QPS 达 **31,081**，以较小的性能损失换取深度安全检测能力。


- **全场景防护强劲可靠**  
  部署全部防护模块（Web 引擎 + 流量引擎）后，单节点依然稳定支撑 **10,574 HTTP QPS** 与 **7,739 HTTPS QPS**，单核吞吐超 **2,600 QPS**。单节点日均即可处理超 8 亿次请求检测，完全满足企业高并发场景下的安全防护需求。

  > 开启流量防护引擎后性能降幅较大，主要原因是标准版将 WAF 节点、控制台、MySQL 部署在同一台服务器上，流量防护引擎触发处置时需写入 MySQL 日志，导致磁盘 I/O 及系统资源竞争。若将 MySQL 独立部署或使用专业版分离架构，可有效缓解此问题。

## 附录：wrk 原始测试输出


### 方案一：纯转发（所有防护关闭）


**HTTP**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua http://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ http://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    15.10ms    7.54ms 369.61ms   89.71%
    Req/Sec    17.06k     2.02k   21.84k    66.25%
  4074102 requests in 1.00m, 1.82GB read
Requests/sec:  67848.72
Transfer/sec:     31.06MB
```


**HTTPS**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua https://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ https://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    19.32ms   21.85ms 751.10ms   97.97%
    Req/Sec    14.01k     1.87k   17.17k    71.60%
  3317735 requests in 1.00m, 1.48GB read
Requests/sec:  55226.57
Transfer/sec:     25.28MB
```


### 方案二：Web 防护引擎（AI防护+语义防护）


**HTTP**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua http://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ http://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    29.28ms   26.96ms   1.03s    95.01%
    Req/Sec     9.15k     1.19k   14.06k    70.17%
  2184898 requests in 1.00m, 0.98GB read
Requests/sec:  36387.71
Transfer/sec:     16.66MB
```


**HTTPS**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua https://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ https://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    33.40ms   23.41ms 632.60ms   90.48%
    Req/Sec     7.88k     1.17k   10.57k    70.92%
  1866705 requests in 1.00m, 854.50MB read
Requests/sec:  31081.06
Transfer/sec:     14.23MB
```


### 方案三：Web 防护引擎+流量防护引擎（所有防护模块开启）


**HTTP**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua http://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ http://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   111.68ms  215.79ms   5.30s    99.05%
    Req/Sec     2.66k   411.13     4.41k    68.71%
  635002 requests in 1.00m, 4.40GB read
Requests/sec:  10574.23
Transfer/sec:     75.07MB
```


**HTTPS**
```
wrk -t4 -c1000 -d60s --timeout 10s -s post.lua https://tmp-test.jxwaf.com/demo/web_attack_check
Running 1m test @ https://tmp-test.jxwaf.com/demo/web_attack_check
  4 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   129.19ms   41.06ms 674.06ms   77.48%
    Req/Sec     1.96k   355.35     2.99k    68.78%
  464801 requests in 1.00m, 212.77MB read
Requests/sec:   7738.83
Transfer/sec:      3.54MB
```
