# API 调用

## 名单管理接口

### 1. 获取名单条目列表

获取指定名单下的所有条目。

**接口地址**：`POST /api_get_name_list_item_list_list`

**请求参数**：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| page | integer | 是 | 页码，默认为 1 |
| name_list_name | string | 是 | 名单名称 |
| waf_auth | string | 是 | 鉴权令牌 |

**请求示例**：

```json
{
  "page": 1,
  "name_list_name": "blacklist",
  "waf_auth": "5aac27e9-8b3c-4a14-b884-7cad44a09535"
}
```

**返回参数**：

| 参数名 | 类型 | 说明 |
|--------|------|------|
| result | boolean | 是否成功 |
| page | integer | 当前页码 |
| total_pages | integer | 总页数 |
| total_records | integer | 总记录数 |
| records | array | 名单条目列表 |
| records[].id | integer | 条目ID |
| records[].user_name | string | 用户名 |
| records[].name_list_name | string | 所属名单名称 |
| records[].name_list_item | string | 名单条目内容（如IP地址） |
| records[].name_list_expire | string | 过期时间配置（秒），"false" 表示永不过期 |
| records[].name_list_item_expire_time | integer | 条目过期时间戳（Unix时间戳） |

**返回示例**：

```json
{
  "result": true,
  "page": 1,
  "total_pages": 1,
  "total_records": 2,
  "records": [
    {
      "id": 1,
      "user_name": "admin",
      "name_list_name": "blacklist",
      "name_list_item": "192.168.1.100",
      "name_list_expire": "86400",
      "name_list_item_expire_time": 1735776000
    },
    {
      "id": 2,
      "user_name": "admin",
      "name_list_name": "blacklist",
      "name_list_item": "10.0.0.5",
      "name_list_expire": "86400",
      "name_list_item_expire_time": 1735776000
    }
  ]
}
```

---

### 2. 创建/更新名单条目

向指定名单添加条目。如果条目已存在则更新其过期时间。

**接口地址**：`POST /api/create_global_name_list_item`

**请求参数**：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| name_list_name | string | 是 | 目标名单名称 |
| name_list_item | string | 是 | 要添加的条目内容（如IP地址） |
| waf_auth | string | 是 | 鉴权令牌 |

**请求示例**：

```json
{
  "name_list_name": "blacklist",
  "name_list_item": "192.168.1.200",
  "waf_auth": "5aac27e9-8b3c-4a14-b884-7cad44a09535"
}
```

**返回参数**：

| 参数名 | 类型 | 说明 |
|--------|------|------|
| result | boolean | 是否成功 |
| message | string | 操作结果消息 |

**返回示例**：

新增成功：
```json
{
  "result": true,
  "message": "create_success"
}
```

更新已存在条目：
```json
{
  "result": true,
  "message": "edit_success"
}
```

**错误示例**：

名单不存在：
```json
{
  "result": false,
  "message": "name_list_name not exist"
}
```

---

### 3. 删除名单条目

从指定名单中删除条目。

**接口地址**：`POST /api/delete_global_name_list_item`

**请求参数**：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| name_list_name | string | 是 | 名单名称 |
| name_list_item | string | 是 | 要删除的条目内容 |
| waf_auth | string | 是 | 鉴权令牌 |

**请求示例**：

```json
{
  "name_list_name": "blacklist",
  "name_list_item": "192.168.1.200",
  "waf_auth": "5aac27e9-8b3c-4a14-b884-7cad44a09535"
}
```

**返回参数**：

| 参数名 | 类型 | 说明 |
|--------|------|------|
| result | boolean | 是否成功 |
| message | string | 操作结果消息 |

**返回示例**：

```json
{
  "result": true,
  "message": "delete_success"
}
```

---

### 4. 搜索名单条目

在指定名单中搜索匹配的条目（模糊搜索）。

**接口地址**：`POST /api/search_global_name_list_item`

**请求参数**：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| page | integer | 是 | 页码，默认为 1 |
| name_list_name | string | 是 | 名单名称 |
| search_value | string | 是 | 搜索关键词（支持模糊匹配） |
| waf_auth | string | 是 | 鉴权令牌 |

**请求示例**：

```json
{
  "page": 1,
  "name_list_name": "blacklist",
  "search_value": "192.168",
  "waf_auth": "5aac27e9-8b3c-4a14-b884-7cad44a09535"
}
```

**返回参数**：

| 参数名 | 类型 | 说明 |
|--------|------|------|
| result | boolean | 是否成功 |
| page | integer | 当前页码 |
| total_pages | integer | 总页数 |
| total_records | integer | 匹配的总记录数 |
| records | array | 匹配的名单条目列表 |
| records[].id | integer | 条目ID |
| records[].user_name | string | 用户名 |
| records[].name_list_name | string | 所属名单名称 |
| records[].name_list_item | string | 名单条目内容 |
| records[].name_list_expire | string | 过期时间配置 |
| records[].name_list_item_expire_time | integer | 条目过期时间戳 |

**返回示例**：

```json
{
  "result": true,
  "page": 1,
  "total_pages": 1,
  "total_records": 3,
  "records": [
    {
      "id": 1,
      "user_name": "admin",
      "name_list_name": "blacklist",
      "name_list_item": "192.168.1.100",
      "name_list_expire": "86400",
      "name_list_item_expire_time": 1735776000
    },
    {
      "id": 3,
      "user_name": "admin",
      "name_list_name": "blacklist",
      "name_list_item": "192.168.1.101",
      "name_list_expire": "3600",
      "name_list_item_expire_time": 1735699200
    },
    {
      "id": 5,
      "user_name": "admin",
      "name_list_name": "blacklist",
      "name_list_item": "192.168.2.50",
      "name_list_expire": "false",
      "name_list_item_expire_time": 0
    }
  ]
}
```

---

## 错误处理

所有接口在发生错误时返回统一的错误格式：

```json
{
  "result": false,
  "message": "错误描述信息"
}
```

**常见错误码及说明**：

| 错误消息 | 说明 | 解决方案 |
|---------|------|---------|
| `name_list_name not exist` | 指定的名单不存在 | 先创建名单或检查名单名称是否正确 |
| 鉴权失败 | waf-auth 无效或过期 | 重新获取有效的鉴权令牌 |
| 参数缺失 | 必填参数未提供 | 检查请求体中是否包含所有必填参数 |

---

## 使用场景

### 场景1：通过外部系统自动封禁攻击 IP

当安全设备检测到攻击行为时，可调用 **创建名单条目接口** 自动将攻击 IP 加入黑名单：

```bash
curl -X POST http://admin.jxwaf.com/api/create_global_name_list_item \
  -H "Content-Type: application/json" \
  -d '{
    "name_list_name": "auto_blacklist",
    "name_list_item": "203.0.113.50",
    "waf_auth": "your-auth-token"
  }'
```

### 场景2：查询当前黑名单中的所有 IP

调用 **获取名单条目列表接口** 获取完整名单：

```bash
curl -X POST http://admin.jxwaf.com/api_get_name_list_item_list_list \
  -H "Content-Type: application/json" \
  -d '{
    "page": 1,
    "name_list_name": "auto_blacklist",
    "waf_auth": "your-auth-token"
  }'
```

### 场景3：解封特定 IP

调用 **删除名单条目接口** 从名单中移除 IP：

```bash
curl -X POST http://admin.jxwaf.com/api/delete_global_name_list_item \
  -H "Content-Type: application/json" \
  -d '{
    "name_list_name": "auto_blacklist",
    "name_list_item": "203.0.113.50",
    "waf_auth": "your-auth-token"
  }'
```