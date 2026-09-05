package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/jx-sec/jxwaf-agent/internal/config"
	"github.com/jx-sec/jxwaf-agent/internal/gen"
	"github.com/spf13/cobra"
)

// 测试环境：配置下发生产前的验证环境，独立命令组 `jxwaf-cli test`，与自有环境命令彻底分开。
// 官方已提供共享测试环境（专业版），CLI 不写死其参数：必须经 test init 显式配置
// （--base-url / --waf-auth / --test-url 必填，域名组留空自动发现），保存进项目目录 config.json。
// test_url 为测试环境的测试站点地址（配置下发到测试环境后访问它验证规则生效），
// 保存在测试环境定义中（environments.<test>.test_url）。

// resolveTest 解析测试环境。
// 安全红线：test 命令组固定使用配置中的测试环境名，忽略全局 --env，
// 防止 `test verify --env prod` 之类的误用把清空/删除操作打到自有环境。
func resolveTest() (*adapter.Adapter, *client.Client, string, error) {
	c, err := config.Load()
	if err != nil {
		return nil, nil, "", err
	}
	name := c.TestName()
	env, ok := c.Environments[name]
	if !ok {
		return nil, nil, "", fmt.Errorf("测试环境 %q 未配置：请运行 jxwaf-cli test init 配置（--base-url / --waf-auth / --test-url 必填）", name)
	}
	a, err := adapter.New(env)
	if err != nil {
		return nil, nil, "", err
	}
	return a, client.New(env.BaseURL), name, nil
}

// createToDeleteVer 创建操作 → 删除操作（test verify 结束自动清理本次配置用），由 gen 类型注册表派生。
var createToDeleteVer = func() map[string]adapter.Op {
	out := map[string]adapter.Op{}
	for c, d := range gen.CreateToDelete() {
		out[c] = adapter.Op(d)
	}
	return out
}()

// deployNameKey 返回清理时使用的名称字段。
func deployNameKey(op adapter.Op) (string, bool) {
	k := gen.NameKeyOfOp(string(op))
	return k, k != ""
}

func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "测试环境命令组（独立于自有环境命令；忽略 --env）",
	}
	cmd.AddCommand(
		newTestInitCmd(),
		newTestVerifyCmd(),
		newTestResetCmd(),
		newTestCleanupCmd(),
	)
	return cmd
}

func newTestInitCmd() *cobra.Command {
	var (
		wafAuth   string
		baseURL   string
		envName   string
		groupName string
		testURL   string
	)
	cmd := &cobra.Command{
		Use:   "init --base-url URL --waf-auth AUTH --test-url URL [--name ENV] [--group-name G]",
		Short: "初始化测试环境（保存进项目目录 config.json；官方测试环境已配置好，仅自建或重新配置时使用）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			envName = orDefault(envName, config.DefaultTestEnvName)
			if baseURL == "" {
				return nil, fmt.Errorf("缺少 --base-url：测试环境的管理控制台地址")
			}
			if wafAuth == "" {
				return nil, fmt.Errorf("缺少 --waf-auth：测试环境的凭据")
			}
			if testURL == "" {
				return nil, fmt.Errorf("缺少 --test-url：测试环境的测试站点地址（配置下发后访问它验证）")
			}
			if u, err := url.Parse(testURL); err != nil || u.Host == "" {
				return nil, fmt.Errorf("--test-url 需为完整地址（含 http/https 与域名）")
			}

			unlock, err := config.Lock()
			if err != nil {
				return nil, err
			}
			defer unlock()
			cfg, err := config.LoadOrCreate()
			if err != nil {
				return nil, err
			}

			// 环境名占用保护：仅允许覆盖测试环境自身（切换自建测试环境），拒绝覆盖自有环境
			if _, exists := cfg.Environments[envName]; exists {
				isReinit := envName == cfg.TestName()
				if !isReinit {
					return nil, fmt.Errorf("环境名 %q 已被自有环境占用，测试环境初始化不会覆盖它；请换一个 --name", envName)
				}
			}

			// 域名组：显式指定优先，否则尝试在线发现（用临时适配器，走 adapter 统一端点表）
			warning := ""
			if groupName == "" {
				probe, err := adapter.New(config.Environment{
					Version: config.VersionProfessional, BaseURL: baseURL, WafAuth: wafAuth,
				})
				if err != nil {
					return nil, err
				}
				g, err := discoverGroup(probe, client.New(baseURL))
				if err != nil {
					warning = fmt.Sprintf("未能自动发现域名组（%v）：请用 --group-name 指定后重新初始化", err)
				} else {
					groupName = g
				}
			}

			// 不修改 Active：测试环境与自有环境彻底分离，通用命令默认不会命中测试环境
			cfg.Environments[envName] = config.Environment{
				Name:      envName,
				Version:   config.VersionProfessional,
				BaseURL:   baseURL,
				WafAuth:   wafAuth,
				GroupName: groupName,
				TestURL:   testURL,
			}
			cfg.TestEnv = envName
			if err := config.Save(cfg); err != nil {
				return nil, err
			}
			return map[string]any{
				"env":        envName,
				"version":    "professional",
				"group_name": groupName,
				"test_url":   testURL,
				"hint":       "测试环境已保存（环境名 " + envName + "，测试站点 " + testURL + "）。test 命令组（verify/reset/cleanup）将操作该环境；更换测试环境重新运行 test init 即可。 " + warning,
			}, nil
		}),
	}
	cmd.Flags().StringVar(&wafAuth, "waf-auth", "", "测试环境凭据（必填）")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "测试环境管理控制台地址（必填）")
	cmd.Flags().StringVar(&envName, "name", "", "保存的环境名（默认 test，覆盖即切换测试环境）")
	cmd.Flags().StringVar(&groupName, "group-name", "", "专业版域名组（留空则尝试自动发现）")
	cmd.Flags().StringVar(&testURL, "test-url", "", "测试站点地址（必填；配置下发后访问它验证）")
	return cmd
}

// discoverGroup 调用域名组列表接口，取第一个组的名称（专业版防护操作必须指定域名组）。
func discoverGroup(a *adapter.Adapter, c *client.Client) (string, error) {
	raw, err := callOp(a, c, adapter.OpDomainGroupList, map[string]any{"page": 1})
	if err != nil {
		return "", err
	}
	records, _ := raw["records"].([]any)
	if len(records) == 0 {
		return "", errors.New("环境里没有域名组，请先在控制台创建域名组")
	}
	if m, ok := records[0].(map[string]any); ok {
		if name, ok := m["group_name"].(string); ok && name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("域名组列表响应格式无法解析: %v", raw)
}

func newTestVerifyCmd() *cobra.Command {
	var (
		targetURL string
		waitSec   int
		keep      bool
		noFresh   bool
	)
	cmd := &cobra.Command{
		Use:   "verify <用例文件> [--url 站点]",
		Short: "测试环境一键验证：清空基线→部署→打流量→查日志→报告→清理（环境回到空态）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			// 解析测试环境（固定测试环境，忽略 --env）
			a, c, envName, err := resolveTest()
			if err != nil {
				return nil, err
			}

			// 测试站点取值顺序：--url > 测试环境配置的 test_url（配置下发到测试环境后访问它验证）
			if targetURL == "" {
				if cfg, err := config.Load(); err == nil {
					if env, ok := cfg.Environments[cfg.TestName()]; ok {
						targetURL = env.TestURL
					}
				}
			}
			if targetURL == "" {
				return nil, fmt.Errorf("--url 必填：测试站点地址（或 test init 时用 --test-url 配置）")
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

			out := map[string]any{"env": envName}

			// 清空基线（保证从空环境开始）
			if !noFresh {
				plans, err := collectPlans(a, c)
				if err != nil {
					return nil, err
				}
				results, summary, execErr := executePlans(a, c, plans)
				fc := map[string]any{"summary": summary, "results": results}
				if execErr != nil {
					fc["warning"] = execErr.Error() + "（基线可能未完全清空，验证结果可能受残留配置干扰）"
				}
				out["fresh_cleared"] = fc
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
				} else {
					// 节点每 3 秒拉取一次配置，部署成功后必须等同步完成再打流量，
					// 否则有状态检测（组件计数/流量规则处罚）在旧配置上执行，验证结果失真
					time.Sleep(5 * time.Second)
				}
			}

			// 打测试流量 + SOC 日志
			results, start, err := runVerifyTraffic(cases, targetURL, waitSec)
			if err != nil {
				return nil, err
			}
			socRaw, socErr := runSocQuery(a, c, u.Host, start)

			// 清理本次部署的配置（除非 --keep）；清理失败必须上报，破坏"环境回到空态"时可见
			if !keep {
				if delOp, ok := createToDeleteVer[vf.Op]; ok {
					if key, ok := deployNameKey(delOp); ok {
						if name, ok := vf.Config[key].(string); ok && name != "" {
							cleaned, cleanErr := cleanupDeployed(a, c, delOp, key, name)
							if cleanErr != nil {
								out["clean_failed"] = map[string]any{"op": string(delOp), "name": name, "error": cleanErr.Error()}
							} else if cleaned {
								out["cleaned"] = map[string]any{"op": string(delOp), "name": name}
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
	cmd.Flags().StringVar(&targetURL, "url", "", "被测站点地址（默认取测试环境配置的 test_url）")
	cmd.Flags().IntVar(&waitSec, "wait", 5, "打流量后等待日志落库的秒数")
	cmd.Flags().BoolVar(&keep, "keep", false, "保留本次部署的配置（默认验证后清理）")
	cmd.Flags().BoolVar(&noFresh, "no-fresh", false, "不清空基线（连续调试时使用）")
	return cmd
}

// cleanupDeployed 删除本次部署的配置，返回是否成功。
func cleanupDeployed(a *adapter.Adapter, c *client.Client, delOp adapter.Op, key, name string) (bool, error) {
	path, err := a.Path(delOp)
	if err != nil {
		return false, err
	}
	body := map[string]any{key: name}
	if err := a.InjectTenant(delOp, body, tenantOpts()); err != nil {
		return false, err
	}
	resp, err := c.Post(path, a.HeaderMap(), body)
	if err != nil {
		return false, err
	}
	if !resp.Result {
		return false, fmt.Errorf("%s", resp.Message)
	}
	return true, nil
}

func newTestResetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset [--apply]",
		Short: "测试环境全量清空（规则/白名单/名单/组件，不删域名；默认 dry-run）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, envName, err := resolveTest()
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
			results, summary, execErr := executePlans(a, c, plans)
			if execErr != nil {
				return nil, fmt.Errorf("测试环境清空未全部完成: %w", execErr)
			}
			return map[string]any{"env": envName, "summary": summary, "results": results}, nil
		}),
	}
	cmd.Flags().Bool("apply", false, "实际执行清空（默认 dry-run 预览；删除不可恢复）")
	return cmd
}

func newTestCleanupCmd() *cobra.Command {
	var (
		rtype string
		names string
	)
	cmd := &cobra.Command{
		Use:   "cleanup --type <资源类型> --names a,b [--apply]",
		Short: "测试环境按名称批量删除配置（默认 dry-run）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			a, c, envName, err := resolveTest()
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
// 单个用例构造请求失败只标记该用例为 error，不中断其余用例。
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
		var bodyReader io.Reader
		if body := strOf(tc, "body", ""); body != "" && (method == "POST" || method == "PUT") {
			bodyReader = strings.NewReader(body)
		}
		vc := verifyCase{Name: strOf(tc, "name", reqURL), URL: reqURL, Expect: strOf(tc, "expect", "pass")}
		req, err := http.NewRequest(method, reqURL, bodyReader)
		if err != nil {
			vc.Verdict = "error"
			vc.Status = -1
			results = append(results, vc)
			continue
		}
		if h, ok := tc["header"].(map[string]any); ok {
			for k, v := range h {
				req.Header.Set(k, fmt.Sprint(v))
			}
		}
		// 带_body_的请求若未显式指定 Content-Type，给默认表单类型（可被用例 header 覆盖）
		if bodyReader != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			vc.Verdict = "error"
			vc.Status = -1
			results = append(results, vc)
			continue
		}
		vc.Status = resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body) // 读空响应体以复用连接
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
// 自动翻页（上限 5 页），返回首页原始响应并合并各页 records。
func runSocQuery(a *adapter.Adapter, c *client.Client, host string, start time.Time) (any, error) {
	from := start.Add(-2 * time.Minute).Format("2006-01-02 15:04:05")
	to := time.Now().Add(time.Minute).Format("2006-01-02 15:04:05")
	query := func(page int) (map[string]any, error) {
		return callOp(a, c, adapter.OpSocLogQuery, map[string]any{
			"from_time": from, "to_time": to, "page": page,
			"sql_rules": []any{map[string]any{"field": "host", "operation": "equals", "value": host}},
		})
	}
	raw, err := query(1)
	if err != nil {
		return nil, err
	}
	// 记录数组版本差异：专业版/标准版在 message，云WAF在 records（socLogRecords 兼容两者）
	first := socLogRecords(raw)
	all := append([]any{}, first...)
	pages := 1
	for page := 2; len(first) > 0 && page <= 5; page++ {
		next, err := query(page)
		if err != nil {
			// 后续页查询失败不致命，保留已取数据并停止翻页
			break
		}
		recs := socLogRecords(next)
		if len(recs) == 0 {
			break
		}
		all = append(all, recs...)
		pages = page
	}
	if pages > 1 {
		if _, ok := raw["records"].([]any); ok {
			raw["records"] = all
		} else {
			raw["message"] = all
		}
		raw["pages_queried"] = pages
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
