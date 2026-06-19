local cjson = require "cjson.safe"
local mysql = require "resty.mysql"
local _M = {}

local function build_query(statement, values)
    local newStatement = ""
    local index = 1
    for i = 1, #statement do
        local char = statement:sub(i, i)
        if char == "?" then
            if index <= #values then
                local value = values[index]
                if type(value) == "number" then
                    newStatement = newStatement .. tostring(value)
                else
                    newStatement = newStatement .. ngx.quote_sql_str(tostring(value))
                end
                index = index + 1
            end
        else
            newStatement = newStatement .. char
        end
    end
    return newStatement
end

function _M.table_build_query(statement, values)
    local newStatement = ""
    local index = 1
    for i = 1, #statement do
        local char = statement:sub(i, i)
        if char == "?" then
            if index <= #values then
                local value = values[index]
                if index == 1 then
                    newStatement = newStatement .. value
                else
                    if type(value) == "number" then
                        newStatement = newStatement .. tostring(value)
                    else
                        newStatement = newStatement .. ngx.quote_sql_str(tostring(value))
                    end
                end
                index = index + 1
            end
        else
            newStatement = newStatement .. char
        end
    end
    return newStatement
end

function _M.query_mysql(sql,params)
    local db, err = mysql:new()
    if not db then
        ngx.log(ngx.ERR, "failed to instantiate mysql: ", err)
        return nil, err
    end

    db:set_timeout(5000)

    local connect_ok, connect_err, connect_errno, connect_sqlstate = db:connect(db_config)
    if not connect_ok then
        ngx.log(ngx.ERR, "failed to connect to mysql: ", connect_err, ": ", connect_errno, " ", connect_sqlstate)
        return nil, connect_err
    end

    local query_sql
    if  not params  then
      query_sql = sql
    else
      query_sql = build_query(sql, params)
    end
    local res, query_err, query_errno, query_sqlstate = db:query(query_sql)
    if not res then
      ngx.log(ngx.ERR, "bad sql: ", query_sql)
      ngx.log(ngx.ERR, "bad result: ", query_err, ": ", query_errno, ": ", query_sqlstate, ".")
      return nil, query_err
    end
    local ok, keepalive_err = db:set_keepalive(10000, 100)
    if not ok then
      ngx.log(ngx.ERR, "failed to set keepalive: ", keepalive_err)
    end
    return res
end

function _M.clickhouse_query_mysql(sql,clickhouse_db_config,params)
    local db, err = mysql:new()
    if not db then
        ngx.log(ngx.ERR, "failed to instantiate mysql: ", err)
        return nil, err
    end

    db:set_timeout(5000)
    local connect_ok, connect_err, connect_errno, connect_sqlstate = db:connect(clickhouse_db_config)
    if not connect_ok then
        ngx.log(ngx.ERR, "failed to connect to mysql: ", connect_err, ": ", connect_errno, " ", connect_sqlstate)
        return nil, connect_err
    end

    local query_sql
    if  not params  then
      query_sql = sql
    else
      query_sql = build_query(sql, params)
    end
    local res, query_err, query_errno, query_sqlstate = db:query(query_sql)
    if not res then
      ngx.log(ngx.ERR, "bad sql: ", query_sql)
      ngx.log(ngx.ERR, "bad result: ", query_err, ": ", query_errno, ": ", query_sqlstate, ".")
      return nil, query_err
    end
    local ok, keepalive_err = db:set_keepalive(10000, 100)
    if not ok then
      ngx.log(ngx.ERR, "failed to set keepalive: ", keepalive_err)
    end
    return res
end

return _M 