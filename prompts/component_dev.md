# 防护组件开发规范

## 代码模板
```lua
local _M = {}

function _M.check(conf_data)
    if conf_data == nil then
        return
    end
    local request = require "resty.jxwaf.request"
    -- 检测逻辑
    -- 独立完成：调用 unify_action 执行动作
    -- 联合判断：ngx.ctx.<var> = <value>
    return
end

return _M
```

## LuaJIT 兼容性（最高频踩坑点）
运行环境：OpenResty 1.29.2.3 + LuaJIT 2.1（基于 Lua 5.1），不支持 Lua 5.2+ 语法。
使用不兼容语法会导致组件加载失败，节点报 "can not decode component_data"。

### 位运算符（禁止 → 替代）
| 禁止（Lua 5.2+） | 替代（LuaJIT 兼容） |
|------------------|---------------------|
| a & b | bit.band(a, b) |
| a \| b | bit.bor(a, b) |
| a ~ b | bit.bxor(a, b) |
| ~a | bit.bnot(a) |
| a >> n | bit.rshift(a, n) |
| a << n | bit.lshift(a, n) |
| a &= b | a = bit.band(a, b) |
| a // b | math.floor(a / b) |

使用前需声明：`local bit = require "bit"`

### 控制流语法
| 禁止 | 替代 |
|------|------|
| goto label | 重构为循环/函数 |
| ::label:: | 同上 |
| continue | do break end（在 for 循环内） |

### 其他禁止
- 整数除法 //（用 math.floor(a/b)）
- 64位整数字面量 1LL/1ULL（直接用 number）
- string.pack / string.unpack（手动拼接字节）
- table.move（手动 for 循环复制）
- math.tointeger（用 type(x)=="number" and x==math.floor(x)）
- utf8.char / utf8.codepoint（Lua 5.3+ 的 utf8 库）
- goto 语句、::label:: 标签
- 复合赋值 <<= >>= |= &=

## 共享字典 ngx.shared.jxwaf_user
所有组件共用的共享字典，写入时 key 必须拼接项目名称前缀避免冲突。

### key 命名规范
```
<project_name>_<purpose>_<key>
```
示例：`"api_test_count_" .. src_ip`、`"cdn_src_cache_" .. cdn_ip`

### 常用 API
| 方法 | 说明 |
|------|------|
| get(key) | 读取值 |
| set(key, value, ttl) | 写入值（ttl 秒，0 为永不过期） |
| incr(key, value, init, ttl) | 原子递增（init 为初始值，ttl 为过期时间） |
| expire(key, ttl) | 设置过期时间 |
| delete(key) | 删除 |

### 注意事项
1. key 前缀必须拼接项目名
2. 必须 set TTL，避免内存无限增长
3. 禁止写入 jxwaf_inner（WAF 内部字典）
4. value 只能是 string/number/boolean，存储 table 需 cjson.encode

## 开发风格（必须遵守）
1. 简洁优先：每个组件独立运行，一个组件只解决一个问题
2. 内联实现：辅助函数直接写在组件文件内，不抽取公共库
3. 扁平结构：头部注释 → 辅助函数 → check 函数 → return _M
4. 最小依赖：只 require 必要模块，不引入第三方库
5. 直白逻辑：优先 if/else 和 for 循环，不用元表、闭包工厂、高阶函数
6. 注释克制：只在「为什么这么做」需要解释时加注释

## 错误处理
节点 base_component 已用 pcall 包裹 check 调用，组件内无需再包 pcall。
异常自动记录 ERR 日志，不影响后续组件和规则执行。
组件内若需主动终止请求，调用 unify_action（会 ngx.exit）。

## Base64 编码
组件代码需 Base64 编码后存入 code 字段：
```bash
python3 -c "import base64; print(base64.b64encode(open('code.lua','rb').read()).decode('ascii'))"
```
