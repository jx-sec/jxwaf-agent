package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/spf13/cobra"
)

// socLogFields SOC 攻击日志可查字段白名单（对齐 jxlog ClickHouse 表结构，三版本通用）。
// 服务端对 sql_rules.field 做字符串拼接，CLI 侧把好入口：白名单外字段直接报错。
var socLogFields = map[string]bool{
	"host": true, "group_name": true, "request_uuid": true, "waf_node_uuid": true,
	"upstream_addr": true, "upstream_response_time": true, "upstream_status": true,
	"status": true, "process_time": true, "request_time": true, "raw_headers": true,
	"scheme": true, "version": true, "uri": true, "request_uri": true, "method": true,
	"query_string": true, "raw_body": true, "src_ip": true, "user_agent": true,
	"cookie": true, "raw_resp_headers": true, "raw_resp_body": true, "iso_code": true,
	"waf_module": true, "waf_policy": true, "waf_action": true, "waf_extra": true,
	"jxwaf_devid": true, "raw_src_ip": true, "jxwaf_ssl_fingerprint": true,
}

const (
	socFetchDefaultMax  = 1000 // max_records 默认值
	socFetchHardMax     = 10000
	socFetchPageDefense = 500 // 翻页防御上限（服务端每页 20 条）
	socLogTimeLayout    = "2006-01-02 15:04:05"
)

var lastSpanRe = regexp.MustCompile(`^(\d+)([smhd])$`)

// parseLastSpan 解析相对时间跨度（"30s" / "15m" / "24h" / "7d"）。
func parseLastSpan(v string) (time.Duration, error) {
	m := lastSpanRe.FindStringSubmatch(v)
	if m == nil {
		return 0, fmt.Errorf("last 格式非法 %q：需为 <数字><s|m|h|d>，如 30s/15m/24h/7d", v)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("last 数值非法 %q", v)
	}
	var unit time.Duration
	switch m[2] {
	case "s":
		unit = time.Second
	case "m":
		unit = time.Minute
	case "h":
		unit = time.Hour
	case "d":
		unit = 24 * time.Hour
	}
	return time.Duration(n) * unit, nil
}

// socLogRecords 从服务端响应中提取记录数组。
// 版本差异：专业版/标准版记录在 message（数组），云WAF在 records；两者兼容。
func socLogRecords(raw map[string]any) []any {
	if v, ok := raw["message"].([]any); ok {
		return v
	}
	if v, ok := raw["records"].([]any); ok {
		return v
	}
	return nil
}

// socLogTotal 从服务端响应中提取总记录数（专业版/标准版 total_count，云WAF total_records）。
func socLogTotal(raw map[string]any) (int, bool) {
	for _, key := range []string{"total_count", "total_records"} {
		switch v := raw[key].(type) {
		case float64:
			return int(v), true
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// validateSqlRules 校验 sql_rules 的 field 白名单与 operation 枚举。
func validateSqlRules(rules []any) error {
	ops := map[string]bool{"contains": true, "prefix": true, "suffix": true, "equals": true, "not_equals": true}
	for i, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			return fmt.Errorf("sql_rules[%d] 需为对象 {field, operation, value}", i)
		}
		field, _ := m["field"].(string)
		if !socLogFields[field] {
			return fmt.Errorf("sql_rules[%d].field %q 不在可查字段白名单内", i, field)
		}
		if op, _ := m["operation"].(string); !ops[op] {
			return fmt.Errorf("sql_rules[%d].operation %q 非法，允许 contains/prefix/suffix/equals/not_equals", i, op)
		}
		if _, ok := m["value"]; !ok {
			return fmt.Errorf("sql_rules[%d] 缺少 value", i)
		}
	}
	return nil
}

// projectRecords 按字段列表裁剪记录（CLI 侧投影，减少输出体积）。
func projectRecords(records []any, fields []string) []any {
	if len(fields) == 0 {
		return records
	}
	keep := make(map[string]bool, len(fields))
	for _, f := range fields {
		keep[f] = true
	}
	out := make([]any, 0, len(records))
	for _, r := range records {
		m, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		p := make(map[string]any, len(fields))
		for k, v := range m {
			if keep[k] {
				p[k] = v
			}
		}
		out = append(out, p)
	}
	return out
}

// newSocLogFetchCmd 构造 soc log fetch 命令：自动翻页全量拉取攻击日志。
func newSocLogFetchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "全量拉取攻击日志（自动翻页；last 相对时间 / from_time+to_time / sql_rules 过滤 / fields 投影 / max_records 上限）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, err := resolve()
			if err != nil {
				return nil, err
			}
			params, err := getParams(cmd)
			if err != nil {
				return nil, err
			}
			return fetchSocLogs(a, c, params)
		}),
	}
	addParamsFlag(cmd)
	return cmd
}

// fetchSocLogs 自动翻页拉取 SOC 攻击日志全量。
// params：last（相对时间，与 from_time/to_time 互斥）、from_time/to_time、sql_rules、fields、max_records。
func fetchSocLogs(a *adapter.Adapter, c *client.Client, params map[string]any) (map[string]any, error) {
	// 时间窗：last 展开或显式 from/to（二选一）
	now := time.Now()
	from, to := "", ""
	if last, _ := params["last"].(string); last != "" {
		if _, ok := params["from_time"]; ok {
			return nil, errors.New("last 与 from_time/to_time 互斥，只能选一种时间指定方式")
		}
		span, err := parseLastSpan(last)
		if err != nil {
			return nil, err
		}
		from = now.Add(-span).Format(socLogTimeLayout)
		to = now.Format(socLogTimeLayout)
	} else {
		from, _ = params["from_time"].(string)
		to, _ = params["to_time"].(string)
		if from == "" || to == "" {
			return nil, errors.New("需指定时间窗：last（如 24h）或 from_time+to_time（YYYY-MM-DD HH:MM:SS）")
		}
	}

	sqlRules, _ := params["sql_rules"].([]any)
	if err := validateSqlRules(sqlRules); err != nil {
		return nil, err
	}

	// fields 投影（白名单校验）
	var fields []string
	switch v := params["fields"].(type) {
	case []any:
		for _, f := range v {
			s, _ := f.(string)
			if !socLogFields[s] {
				return nil, fmt.Errorf("fields 中 %q 不在可查字段白名单内", s)
			}
			fields = append(fields, s)
		}
	case nil:
	default:
		return nil, errors.New("fields 需为字符串数组")
	}

	maxRecords := socFetchDefaultMax
	if v, ok := params["max_records"].(float64); ok {
		maxRecords = int(v)
		if maxRecords <= 0 || maxRecords > socFetchHardMax {
			return nil, fmt.Errorf("max_records 需为 1~%d", socFetchHardMax)
		}
	}

	query := func(page int) (map[string]any, error) {
		body := map[string]any{
			"from_time": from, "to_time": to, "page": page,
			"sql_rules": sqlRules,
		}
		return callOp(a, c, adapter.OpSocLogQuery, body)
	}

	first, err := query(1)
	if err != nil {
		return nil, err
	}
	total, hasTotal := socLogTotal(first)
	all := append([]any{}, socLogRecords(first)...)
	pages := 1

	// 翻页：优先按 total_pages，缺失时按空页停止（均受页数防御与 max_records 约束）
	totalPages := 1
	switch tp := first["total_pages"].(type) {
	case float64:
		totalPages = int(tp)
	case string:
		if n, err := strconv.Atoi(tp); err == nil {
			totalPages = n
		}
	}
	for page := 2; page <= totalPages && page <= socFetchPageDefense && len(all) < maxRecords; page++ {
		next, err := query(page)
		if err != nil {
			// 后续页失败不致命：保留已取数据并停止翻页（数据为时点快照）
			break
		}
		recs := socLogRecords(next)
		if len(recs) == 0 {
			break
		}
		all = append(all, recs...)
		pages = page
	}

	truncated := hasTotal && len(all) < total
	if len(all) > maxRecords {
		all = all[:maxRecords]
		truncated = true
	}

	out := map[string]any{
		"result":        true,
		"type":          "soc_log_fetch",
		"from_time":     from,
		"to_time":       to,
		"total_count":   total,
		"fetched":       len(all),
		"truncated":     truncated,
		"pages_queried": pages,
		"records":       projectRecords(all, fields),
	}
	if truncated {
		out["hint"] = "结果不完整（超过 max_records 或翻页中断）：建议收窄时间窗或加 sql_rules 过滤后分批拉取"
	}
	return out, nil
}
