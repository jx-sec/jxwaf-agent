package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/jx-sec/jxwaf-agent/internal/config"
	"github.com/spf13/cobra"
)

// 官方测试沙盒：专业版固定账号 + 固定设施，所有人共享（沙盒约定：验证流程自动回到空环境）。
// 官方沙盒使用独立命令组 `jxwaf-cli sandbox`，与自有环境命令彻底分开。
// 可用环境变量 JXWAF_OFFICIAL_BASE_URL / JXWAF_OFFICIAL_MASTER_AUTH / JXWAF_OFFICIAL_TEST_URL 覆盖。
const (
	defaultOfficialBaseURL    = "https://waf-demo.jxwaf.com"
	defaultOfficialMasterAuth = "6e61ff97-1ba8-4828-bc07-b7b4eeb2d4bd"
	defaultOfficialTestURL    = "" // 待官方提供：官方测试域名（sandbox verify 默认目标）
	sandboxEnvName            = "sandbox"
)

// resolveSandbox 解析官方沙盒环境（默认环境名 sandbox，可用 --env 显式覆盖）。
func resolveSandbox() (*adapter.Adapter, *client.Client, string, error) {
	c, err := config.Load()
	if err != nil {
		return nil, nil, "", err
	}
	name := envFlag
	if name == "" {
		name = sandboxEnvName
	}
	env, ok := c.Environments[name]
	if !ok {
		return nil, nil, "", fmt.Errorf("官方沙盒环境 %q 不存在，请先运行 jxwaf-cli sandbox init", name)
	}
	a, err := adapter.New(env)
	if err != nil {
		return nil, nil, "", err
	}
	return a, client.New(env.BaseURL), name, nil
}

// createToDeleteVer 创建操作 → 删除操作（sandbox verify 结束自动清理本次配置用）。
var createToDeleteVer = map[string]adapter.Op{
	"web_rule_create":   adapter.OpWebRuleDelete,
	"web_white_create":  adapter.OpWebWhiteDelete,
	"flow_rule_create":  adapter.OpFlowRuleDelete,
	"flow_white_create": adapter.OpFlowWhiteDelete,
	"name_list_create":  adapter.OpNameListDelete,
	"component_create":  adapter.OpComponentDelete,
	// domain_create 不自动清理：域名删除有接入依赖，显式 cleanup 处理
}

// deployNameKey 返回清理时使用的名称字段。
func deployNameKey(op adapter.Op) (string, bool) {
	table := map[adapter.Op]string{
		adapter.OpWebRuleDelete:   "rule_name",
		adapter.OpWebWhiteDelete:  "rule_name",
		adapter.OpFlowRuleDelete:  "rule_name",
		adapter.OpFlowWhiteDelete: "rule_name",
		adapter.OpNameListDelete:  "name_list_name",
		adapter.OpComponentDelete: "name",
	}
	k, ok := table[op]
	return k, ok
}

func newSandboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "官方测试沙盒（独立命令组，与自有环境命令隔离）",
	}
	cmd.AddCommand(
		newSandboxInitCmd(),
		newSandboxVerifyCmd(),
		newSandboxResetCmd(),
		newSandboxCleanupCmd(),
	)
	return cmd
}

func newSandboxInitCmd() *cobra.Command {
	var (
		baseURL   string
		envName   string
		groupName string
	)
	cmd := &cobra.Command{
		Use:   "init [--base-url URL] [--name ENV] [--group-name G]",
		Short: "初始化：保存官方沙盒固定凭据（专业版，不影响自有环境的 active 配置）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			baseURL = orDefault(baseURL, orDefault(os.Getenv("JXWAF_OFFICIAL_BASE_URL"), defaultOfficialBaseURL))
			envName = orDefault(envName, sandboxEnvName)
			masterAuth := orDefault(os.Getenv("JXWAF_OFFICIAL_MASTER_AUTH"), defaultOfficialMasterAuth)
			if masterAuth == "" {
				return nil, fmt.Errorf("缺少官方沙盒凭据（环境变量 JXWAF_OFFICIAL_MASTER_AUTH 或内置默认值）")
			}
			// 域名组：显式指定优先，否则尝试在线发现
			warning := ""
			if groupName == "" {
				g, err := discoverGroup(baseURL, masterAuth)
				if err != nil {
					warning = fmt.Sprintf("未能自动发现域名组（%v）：请用 --group-name 指定后重新初始化", err)
				} else {
					groupName = g
				}
			}
			cfg, err := config.Load()
			if err != nil {
				return nil, err
			}
			// 不修改 Active：沙盒环境与自有环境彻底分离，通用命令默认不会命中沙盒
			cfg.Environments[envName] = config.Environment{
				Name:      envName,
				Version:   config.VersionProfessional,
				BaseURL:   baseURL,
				WafAuth:   masterAuth,
				GroupName: groupName,
			}
			if err := config.Save(cfg); err != nil {
				return nil, err
			}
			return map[string]any{
				"env":        envName,
				"version":    "professional",
				"group_name": groupName,
				"hint":       "官方沙盒已保存（环境名 " + envName + "）。请使用 sandbox verify/sandbox reset/sandbox cleanup 操作沙盒；自有环境用通用命令。 " + warning,
			}, nil
		}),
	}
	cmd.Flags().StringVar(&baseURL, "base-url", "", "沙盒管理控制台地址（默认官方环境）")
	cmd.Flags().StringVar(&envName, "name", "", "保存的环境名（默认 sandbox）")
	cmd.Flags().StringVar(&groupName, "group-name", "", "专业版域名组（留空则尝试自动发现）")
	return cmd
}

// discoverGroup 调用域名组列表接口，取第一个组的名称（专业版防护操作必须指定域名组）。
func discoverGroup(baseURL, wafAuth string) (string, error) {
	c := client.New(baseURL)
	resp, err := c.Post("/admin_api/get_domain_group_list",
		map[string]string{"jxwaf_waf_auth": wafAuth}, map[string]any{"page": 1})
	if err != nil {
		return "", err
	}
	if !resp.Result {
		return "", fmt.Errorf("%s", resp.Message)
	}
	records, _ := resp.Raw["records"].([]any)
	if len(records) == 0 {
		return "", fmt.Errorf("环境里没有域名组，请先在控制台创建域名组")
	}
	if m, ok := records[0].(map[string]any); ok {
		if name, ok := m["group_name"].(string); ok && name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("域名组列表响应格式无法解析: %v", resp.Raw)
}

func newSandboxVerifyCmd() *cobra.Command {
	var (
		targetURL string
		waitSec   int
		keep      bool
		noFresh   bool
	)
	cmd := &cobra.Command{
		Use:   "verify <用例文件> [--url 站点]",
		Short: "沙盒一键验证：清空基线→部署→打流量→查日志→报告→清理（环境回到空态）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if targetURL == "" {
				targetURL = orDefault(os.Getenv("JXWAF_OFFICIAL_TEST_URL"), defaultOfficialTestURL)
			}
			if targetURL == "" {
				return nil, fmt.Errorf("--url 必填：官方测试域名（经 WAF 节点接入）")
			}
			u, err := url.Parse(targetURL)
			if err != nil || u.Host == "" {
				return nil, fmt.Errorf("--url 需为完整地址（含 http/https 与域名）")
			}
			vf, err := loadVerifyFile(args[0])
			if err != nil {
				return nil, err
			}
			cases := vf.cases()
			if len(cases) == 0 {
				return nil, fmt.Errorf("用例文件为空")
			}

			a, c, envName, err := resolveSandbox()
			if err != nil {
				return nil, err
			}
			out := map[string]any{"env": envName}

			// 清空基线（保证从空环境开始）
			if !noFresh {
				plans, err := collectPlans(a, c)
				if err != nil {
					return nil, err
				}
				results, summary := executePlans(a, c, plans)
				out["fresh_cleared"] = map[string]any{"summary": summary, "results": results}
			}

			// 部署本次配置（信封形态时）
			deployOp := adapter.Op(vf.Op)
			if vf.Op != "" && len(vf.Config) > 0 {
				path, err := a.Path(deployOp)
				if err != nil {
					return nil, err
				}
				body := cloneMap(vf.Config)
				if err := a.InjectTenant(deployOp, body, tenantOpts()); err != nil {
					return nil, err
				}
				resp, err := c.Post(path, a.HeaderMap(), body)
				if err != nil {
					return nil, err
				}
				out["deployed"] = map[string]any{"op": vf.Op, "result": resp.Result, "message": resp.Message}
				if !resp.Result {
					out["deploy_warning"] = "部署失败，以下流量验证结果可能无意义"
				}
			}

			// 打测试流量 + SOC 日志
			results, start, err := runVerifyTraffic(cases, targetURL, waitSec)
			if err != nil {
				return nil, err
			}
			socRaw, socErr := runSocQuery(a, c, u.Host, start)

			// 清理本次部署的配置（除非 --keep）
			if !keep {
				if delOp, ok := createToDeleteVer[vf.Op]; ok {
					if key, ok := deployNameKey(delOp); ok {
						if name, ok := vf.Config[key].(string); ok && name != "" {
							path, _ := a.Path(delOp)
							body := map[string]any{key: name}
							if err := a.InjectTenant(delOp, body, tenantOpts()); err == nil {
								resp, err := c.Post(path, a.HeaderMap(), body)
								if err == nil && resp.Result {
									out["cleaned"] = map[string]any{"op": string(delOp), "name": name}
								}
							}
						}
					}
				}
			}

			out["cases"] = results
			out["summary"] = verdictSummary(results)
			if socErr != nil {
				out["soc_logs"] = map[string]any{"error": socErr.Error()}
			} else {
				out["soc_logs"] = socRaw
			}
			return out, nil
		}),
	}
	addParamsFlag(cmd)
	cmd.Flags().StringVar(&targetURL, "url", "", "被测站点地址（默认官方测试域名）")
	cmd.Flags().IntVar(&waitSec, "wait", 5, "打流量后等待日志落库的秒数")
	cmd.Flags().BoolVar(&keep, "keep", false, "保留本次部署的配置（默认验证后清理）")
	cmd.Flags().BoolVar(&noFresh, "no-fresh", false, "不清空基线（连续调试时使用）")
	return cmd
}

func newSandboxResetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset [--apply]",
		Short: "沙盒全量清空（规则/白名单/名单/组件，不删域名；默认 dry-run）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, envName, err := resolveSandbox()
			if err != nil {
				return nil, err
			}
			apply, _ := cmd.Flags().GetBool("apply")
			plans, err := collectPlans(a, c)
			if err != nil {
				return nil, err
			}
			if !apply {
				preview := make([]map[string]any, 0, len(plans))
				for _, p := range plans {
					path, _ := a.Path(p.op)
					preview = append(preview, map[string]any{"path": path, "body": map[string]any{nameKeyOf(p.op): p.name}})
				}
				return map[string]any{
					"env":     envName,
					"dry_run": true,
					"summary": countByType(plans),
					"total":   len(plans),
					"plans":   preview,
					"hint":    "预览未执行；确认后使用 --apply 清空（不可恢复；官方兜底建议挂每日定时）",
				}, nil
			}
			results, summary := executePlans(a, c, plans)
			return map[string]any{"env": envName, "summary": summary, "results": results}, nil
		}),
	}
	cmd.Flags().Bool("apply", false, "实际执行清空（默认 dry-run 预览；删除不可恢复）")
	return cmd
}

func newSandboxCleanupCmd() *cobra.Command {
	var (
		rtype string
		names string
	)
	cmd := &cobra.Command{
		Use:   "cleanup --type <资源类型> --names a,b [--apply]",
		Short: "沙盒按名称批量删除配置（默认 dry-run）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, envName, err := resolveSandbox()
			if err != nil {
				return nil, err
			}
			apply, _ := cmd.Flags().GetBool("apply")
			out, err := runCleanup(a, c, rtype, names, apply)
			if err != nil {
				return nil, err
			}
			if m, ok := out.(map[string]any); ok {
				m["env"] = envName
			}
			return out, nil
		}),
	}
	cmd.Flags().StringVar(&rtype, "type", "", "资源类型：web-rule/flow-rule/name-list/component/website")
	cmd.Flags().StringVar(&names, "names", "", "资源名称（逗号分隔）")
	cmd.Flags().Bool("apply", false, "实际执行删除（默认 dry-run 预览，删除不可恢复）")
	return cmd
}

// runVerifyTraffic 逐个执行用例请求，返回结果与起始时间。
func runVerifyTraffic(cases []map[string]any, targetURL string, waitSec int) ([]verifyCase, time.Time, error) {
	start := time.Now()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	results := make([]verifyCase, 0, len(cases))
	for _, tc := range cases {
		method := strOf(tc, "method", "GET")
		p := strOf(tc, "path", "/")
		query := strOf(tc, "query", "")
		reqURL := targetURL + p
		if query != "" {
			reqURL += "?" + query
		}
		req, err := http.NewRequest(method, reqURL, nil)
		if err != nil {
			return nil, start, fmt.Errorf("用例 %s 构造请求失败: %w", strOf(tc, "name", "?"), err)
		}
		if body := strOf(tc, "body", ""); body != "" && (method == "POST" || method == "PUT") {
			req.Body = io.NopCloser(strings.NewReader(body))
		}
		if h, ok := tc["header"].(map[string]any); ok {
			for k, v := range h {
				req.Header.Set(k, fmt.Sprint(v))
			}
		}
		resp, err := httpClient.Do(req)
		vc := verifyCase{Name: strOf(tc, "name", reqURL), URL: reqURL, Expect: strOf(tc, "expect", "pass")}
		if err != nil {
			vc.Verdict = "error"
			vc.Status = -1
			results = append(results, vc)
			continue
		}
		vc.Status = resp.StatusCode
		resp.Body.Close()
		switch {
		case isBlockStatus(vc.Status) && vc.Expect == "block":
			vc.Verdict = "blocked"
		case !isBlockStatus(vc.Status) && vc.Expect == "pass":
			vc.Verdict = "passed"
		default:
			vc.Verdict = "unexpected"
		}
		results = append(results, vc)
	}
	if waitSec > 0 {
		time.Sleep(time.Duration(waitSec) * time.Second)
	}
	return results, start, nil
}

// runSocQuery 查询 SOC 日志窗口（打流量前后 2 分钟，按 host 过滤）。
func runSocQuery(a *adapter.Adapter, c *client.Client, host string, start time.Time) (any, error) {
	from := start.Add(-2 * time.Minute).Format("2006-01-02 15:04:05")
	to := time.Now().Add(time.Minute).Format("2006-01-02 15:04:05")
	raw, err := callOp(a, c, adapter.OpSocLogQuery, map[string]any{
		"from_time": from, "to_time": to, "page": 1,
		"sql_rules": []any{map[string]any{"field": "host", "operation": "equals", "value": host}},
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// verdictSummary 汇总用例判定。
func verdictSummary(results []verifyCase) map[string]any {
	passed, failed := 0, 0
	for _, vc := range results {
		if vc.Verdict == "blocked" || vc.Verdict == "passed" {
			passed++
		} else {
			failed++
		}
	}
	return map[string]any{"total": len(results), "passed": passed, "failed": failed}
}
