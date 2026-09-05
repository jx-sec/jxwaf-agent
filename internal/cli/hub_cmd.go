package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/jx-sec/jxwaf-agent/internal/config"
	"github.com/spf13/cobra"
)

// hub 平台枚举（与 hub.jxwaf.com 一期硬编码一致）。
var (
	hubProducts = map[string]bool{"jxwaf": true, "webtds": true}
	hubScenes   = map[string]bool{"流量安全": true, "应用安全": true, "业务安全": true, "功能组件": true, "模型算法": true}
	// hubNameRegexp 平台策略名规则：小写字母/数字/中划线/下划线，不以中划线下划线开头结尾
	hubNameRegexp = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)
)

// hubComponentRequiredFields 对齐控制台 export_component_hub_config 导出的权威结构。
// load_component_hub_config 对 component_data 条目不补全字段、直接拼 SQL 入库，
// 缺失 status/rule_order_time 会导致 SQL 语法错误（near ',)'）。
var hubComponentRequiredFields = []string{"name", "detail", "code", "conf", "status", "rule_order_time"}

// validateHubPolicyContent 校验策略内容为控制台 hub-load 可消费的包装结构：
// {"<资源>_data": {"<名称>": {配置字段...}}}（对齐三版本 admin_server load_*_hub_config 读取 res_body['xxx_data'] 的行为）。
// 扁平单规则对象（如直接放 rule_name/rule_matchs）会导致控制台加载报 "<xxx>_data is nil"，本地快速失败并给出修正指引。
// 条目级字段完整性：控制台 load 函数不补全字段，缺失必填字段会拼出非法 SQL，本地也一并拦截。
func validateHubPolicyContent(data []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("策略内容需为 JSON 对象（控制台 hub-load 要求 {\"<资源>_data\": {\"<名称>\": {...}}} 包装结构）: %w", err)
	}
	for k, v := range obj {
		if !strings.HasSuffix(k, "_data") {
			continue
		}
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(v, &inner); err != nil || len(inner) == 0 {
			return fmt.Errorf("包装键 %s 的值需为非空的 {\"名称\": {配置}} 对象", k)
		}
		for item, cfg := range inner {
			var cfgObj map[string]json.RawMessage
			if err := json.Unmarshal(cfg, &cfgObj); err != nil {
				return fmt.Errorf("包装键 %s 下的 %s 需为配置对象（控制台导出格式：{\"名称\": {字段...}}）", k, item)
			}
			if k == "component_data" {
				var missing []string
				for _, f := range hubComponentRequiredFields {
					if _, ok := cfgObj[f]; !ok {
						missing = append(missing, f)
					}
				}
				if len(missing) > 0 {
					return fmt.Errorf("包装键 component_data 下的 %s 缺少控制台入库必需字段 %v（对齐控制台导出结构 name/detail/code/conf/status/rule_order_time）；"+
						"缺失字段会导致 load_component_hub_config 拼 SQL 报语法错误，可用 component hub-export 导出真实结构对照", item, missing)
				}
			}
		}
		return nil
	}
	return fmt.Errorf("策略内容缺少控制台 hub-load 包装键（*_data，如 web_rule_protection_data/flow_rule_protection_data/component_data）；" +
		"扁平单规则对象会导致控制台加载报 \"..._data is nil\"，请改用 {\"<资源>_data\":{\"<名称>\":{...}}} 结构（参考控制台导出规则功能）")
}

// resolveHub 加载配置并返回已认证的 Hub 客户端（要求已完成 hub login/init）。
func resolveHub() (*client.HubClient, *config.HubConfig, error) {
	c, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	if c.Hub == nil || c.Hub.BaseURL == "" || c.Hub.APIToken == "" {
		return nil, nil, fmt.Errorf("hub 未配置：请先运行 jxwaf-cli hub login（账号密码换取 Token）或 hub init --token <API Token>")
	}
	return client.NewHub(c.Hub.BaseURL, c.Hub.APIToken), c.Hub, nil
}

// saveHub 在配置锁保护下合并保存 hub 配置（未指定字段保留原值）。
func saveHub(h *config.HubConfig) error {
	unlock, err := config.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	c, err := config.Load()
	if err != nil {
		return err
	}
	if c.Hub == nil {
		c.Hub = &config.HubConfig{}
	}
	if h.BaseURL != "" {
		c.Hub.BaseURL = h.BaseURL
	}
	if h.APIToken != "" {
		c.Hub.APIToken = h.APIToken
	}
	if h.DefaultProduct != "" {
		c.Hub.DefaultProduct = h.DefaultProduct
	}
	if h.DefaultScene != "" {
		c.Hub.DefaultScene = h.DefaultScene
	}
	return config.Save(c)
}

// validateHubName 校验平台策略名规则。
func validateHubName(name string) error {
	if len(name) < 3 || len(name) > 100 {
		return fmt.Errorf("策略名长度须为 3-100 字符")
	}
	if !hubNameRegexp.MatchString(name) {
		return fmt.Errorf("策略名仅允许小写字母、数字、中划线、下划线，且不能以中划线或下划线开头结尾")
	}
	return nil
}

// resolveHubDefaults 计算 push 的产品/分类默认值：flag > hub 配置 > 内置默认。
func resolveHubDefaults(h *config.HubConfig, product, scene string) (string, string, error) {
	if product == "" {
		if h != nil && h.DefaultProduct != "" {
			product = h.DefaultProduct
		} else {
			product = "jxwaf"
		}
	}
	if scene == "" {
		if h != nil && h.DefaultScene != "" {
			scene = h.DefaultScene
		} else {
			scene = "应用安全"
		}
	}
	if !hubProducts[product] {
		return "", "", fmt.Errorf("product 必须为 jxwaf/webtds")
	}
	if !hubScenes[scene] {
		return "", "", fmt.Errorf("scene 必须为：流量安全/应用安全/业务安全/功能组件/模型算法")
	}
	return product, scene, nil
}

func newHubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "策略共享平台 JXWAF Hub（策略地址）策略发布与管理（独立于 WAF 环境，不走 --env）",
	}
	cmd.AddCommand(
		newHubLoginCmd(),
		newHubInitCmd(),
		newHubStatusCmd(),
		newHubPushCmd(),
		newHubListCmd(),
		newHubShowCmd(),
		newHubPullCmd(),
		newHubDeleteCmd(),
	)
	return cmd
}

// newHubLoginCmd 账号密码一次性换取 API Token（密码不落盘）。
// 若账号已有 Token 则直接取回（不失效旧 Token）；从未生成过才重新生成。
func newHubLoginCmd() *cobra.Command {
	var (
		username string
		password string
		otpCode  string
		baseURL  string
		product  string
		scene    string
	)
	cmd := &cobra.Command{
		Use:   "login --username U --password P [--otp-code 123456]",
		Short: "登录 Hub 并将 API Token 保存到本地配置（密码用完即弃，不落盘）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			// 凭据优先级：命令行参数 > 环境变量（避免凭据进入 shell history / 进程列表）
			if username == "" {
				username = envCred("JXWAF_HUB_USERNAME")
			}
			if password == "" {
				password = envCred("JXWAF_HUB_PASSWORD")
			}
			if otpCode == "" {
				otpCode = envCred("JXWAF_HUB_OTP_CODE")
			}
			if username == "" || password == "" {
				return nil, fmt.Errorf("--username、--password 为必填参数（或设置环境变量 JXWAF_HUB_USERNAME / JXWAF_HUB_PASSWORD）")
			}
			if baseURL == "" {
				baseURL = config.DefaultHubBaseURL
			}
			hc := client.NewHub(baseURL, "")
			cookie, err := hc.Login(username, password, otpCode)
			if err != nil {
				return nil, err
			}
			token, has, err := hc.GetToken(cookie)
			if err != nil {
				return nil, err
			}
			source := "existing"
			if !has || token == "" {
				if token, err = hc.RegenerateToken(cookie); err != nil {
					return nil, err
				}
				source = "regenerated"
			}
			// 校验默认值合法性后与现有 hub 配置合并保存
			if err := saveHub(&config.HubConfig{BaseURL: baseURL, APIToken: token, DefaultProduct: product, DefaultScene: scene}); err != nil {
				return nil, err
			}
			return map[string]any{
				"username": username, "base_url": baseURL,
				"token_source": source, "has_token": true, "saved": true,
				"note": "API Token 已保存到 config.json（脱敏）；账号密码未保存",
			}, nil
		}),
	}
	cmd.Flags().StringVar(&username, "username", "", "Hub 用户名（或环境变量 JXWAF_HUB_USERNAME）")
	cmd.Flags().StringVar(&password, "password", "", "Hub 密码（或环境变量 JXWAF_HUB_PASSWORD，不落盘）")
	cmd.Flags().StringVar(&otpCode, "otp-code", "", "OTP 双因素验证码（已开启 OTP 时必填）")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "平台地址（默认 https://hub.jxwaf.com）")
	cmd.Flags().StringVar(&product, "product", "", "push 默认产品：jxwaf/webtds（可选）")
	cmd.Flags().StringVar(&scene, "scene", "", "push 默认分类（可选）")
	return cmd
}

// newHubInitCmd 手工指定 API Token（适合 CI/已从网页个人设置页复制的 Token）。
func newHubInitCmd() *cobra.Command {
	var (
		baseURL  string
		apiToken string
		product  string
		scene    string
	)
	cmd := &cobra.Command{
		Use:   "init --token <API Token>",
		Short: "直接配置 API Token（不做登录；Token 在 Hub 网页「个人设置」页获取，或设置环境变量 JXWAF_HUB_TOKEN）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if apiToken == "" {
				apiToken = envCred("JXWAF_HUB_TOKEN")
			}
			if apiToken == "" {
				return nil, fmt.Errorf("--token 为必填参数（或设置环境变量 JXWAF_HUB_TOKEN）")
			}
			if baseURL == "" {
				baseURL = config.DefaultHubBaseURL
			}
			// 保存前用 Token 校验身份，确保凭据可用
			hc := client.NewHub(baseURL, apiToken)
			me, err := hc.Me()
			if err != nil {
				return nil, fmt.Errorf("Token 校验失败: %w", err)
			}
			if err := saveHub(&config.HubConfig{BaseURL: baseURL, APIToken: apiToken, DefaultProduct: product, DefaultScene: scene}); err != nil {
				return nil, err
			}
			return map[string]any{"username": me["username"], "base_url": baseURL, "has_token": true, "saved": true}, nil
		}),
	}
	cmd.Flags().StringVar(&baseURL, "base-url", "", "平台地址（默认 https://hub.jxwaf.com）")
	cmd.Flags().StringVar(&apiToken, "token", "", "用户 API Token（或环境变量 JXWAF_HUB_TOKEN）")
	cmd.Flags().StringVar(&product, "product", "", "push 默认产品：jxwaf/webtds（可选）")
	cmd.Flags().StringVar(&scene, "scene", "", "push 默认分类（可选）")
	return cmd
}

// newHubStatusCmd 查看 hub 配置与登录态（Token 有效性 + 账号身份 + 策略数）。
func newHubStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看 Hub 配置与账号状态（凭据脱敏）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			hc, h, err := resolveHub()
			if err != nil {
				return nil, err
			}
			me, err := hc.Me()
			if err != nil {
				return nil, fmt.Errorf("Token 无效或已重新生成: %w", err)
			}
			list, err := hc.ListPolicies(1, 1)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"base_url": h.BaseURL, "api_token": h.Masked().APIToken,
				"default_product": h.DefaultProduct, "default_scene": h.DefaultScene,
				"username": me["username"], "otp_enabled": me["otp_enabled"],
				"policy_total": list["total"],
			}, nil
		}),
	}
}

// newHubPushCmd 上传/覆盖策略（upsert：不存在创建，存在则覆盖内容）。默认私有、直接执行，无需二次确认。
func newHubPushCmd() *cobra.Command {
	var (
		name        string
		product     string
		scene       string
		publicFlag  bool
		privateFlag bool
		description string
		readmePath  string
	)
	cmd := &cobra.Command{
		Use:   "push <file.json> --name <策略名>",
		Short: "上传策略到 Hub（默认私有直接执行；存在则覆盖，公开策略注意敏感信息）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if publicFlag && privateFlag {
				return nil, fmt.Errorf("--public 与 --private 不能同时指定")
			}
			if name == "" {
				return nil, fmt.Errorf("--name 为必填参数（平台策略名：小写字母/数字/中划线/下划线）")
			}
			if err := validateHubName(name); err != nil {
				return nil, err
			}
			if len(description) > 500 {
				return nil, fmt.Errorf("--description 最多 500 字")
			}
			// 读取并校验 JSON 语法（平台端仅校验语法，本地先校验快速失败）
			data, err := os.ReadFile(args[0])
			if err != nil {
				return nil, fmt.Errorf("读取策略文件失败: %w", err)
			}
			if !json.Valid(data) {
				return nil, fmt.Errorf("策略文件不是合法 JSON")
			}
			if err := validateHubPolicyContent(data); err != nil {
				return nil, err
			}
			jsonContent := string(data)
			readme := ""
			if readmePath != "" {
				rd, err := os.ReadFile(readmePath)
				if err != nil {
					return nil, fmt.Errorf("读取 readme 文件失败: %w", err)
				}
				readme = string(rd)
			}

			hc, h, err := resolveHub()
			if err != nil {
				return nil, err
			}
			product, scene, err := resolveHubDefaults(h, product, scene)
			if err != nil {
				return nil, err
			}
			// upsert 判定：先查现有策略（只读）
			_, exists, err := hc.GetPolicy(name)
			if err != nil {
				return nil, err
			}
			isPrivate := true
			if publicFlag {
				isPrivate = false
			} else if privateFlag {
				isPrivate = true
			}

			if !exists {
				out, err := hc.CreatePolicy(name, product, scene, isPrivate, description, readme, jsonContent)
				if err != nil {
					return nil, err
				}
				return map[string]any{
					"action": "create", "name": name, "product": product, "scene": scene,
					"is_private": isPrivate, "username": out["username"],
					"repo": fmt.Sprintf("%v/%v", out["username"], name),
					"url":  fmt.Sprintf("%s/%v/%s", h.BaseURL, out["username"], name),
				}, nil
			}
			// 更新：仅覆盖提供的字段（未指定的元数据保留平台原值）
			fields := map[string]any{"json_content": jsonContent}
			if description != "" {
				fields["description"] = description
			}
			if readmePath != "" {
				fields["readme"] = readme
			}
			if publicFlag || privateFlag {
				fields["is_private"] = isPrivate
			}
			if cmd.Flags().Changed("product") {
				fields["product"] = product
			}
			if cmd.Flags().Changed("scene") {
				fields["scene"] = scene
			}
			if err := hc.UpdatePolicy(name, fields); err != nil {
				return nil, err
			}
			return map[string]any{
				"action": "update", "name": name, "is_private": isPrivate,
				"note": "策略内容已覆盖更新（平台无版本历史）",
			}, nil
		}),
	}
	cmd.Flags().StringVar(&name, "name", "", "策略名（必填，创建后不可修改）")
	cmd.Flags().StringVar(&product, "product", "", "产品：jxwaf/webtds（默认取 hub 配置或 jxwaf）")
	cmd.Flags().StringVar(&scene, "scene", "", "分类：流量安全/应用安全/业务安全/功能组件/模型算法（默认取 hub 配置或 应用安全）")
	cmd.Flags().BoolVar(&publicFlag, "public", false, "设为公开策略（默认私有）")
	cmd.Flags().BoolVar(&privateFlag, "private", false, "设为私有策略（更新时可用，默认不变更）")
	cmd.Flags().StringVar(&description, "description", "", "简述（可选，最多 500 字）")
	cmd.Flags().StringVar(&readmePath, "readme", "", "详细说明 Markdown 文件路径（可选）")
	return cmd
}

// newHubListCmd 查询当前账号策略列表。
func newHubListCmd() *cobra.Command {
	var page, pageSize int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "查询我在 Hub 的策略列表（分页）",
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			hc, _, err := resolveHub()
			if err != nil {
				return nil, err
			}
			return hc.ListPolicies(page, pageSize)
		}),
	}
	cmd.Flags().IntVar(&page, "page", 1, "页码")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "每页数量")
	return cmd
}

// newHubShowCmd 查看单个策略详情（含 JSON 内容）。
func newHubShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <策略名>",
		Short: "查看我在 Hub 的单个策略详情（含 json_content）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			hc, _, err := resolveHub()
			if err != nil {
				return nil, err
			}
			out, exists, err := hc.GetPolicy(args[0])
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, fmt.Errorf("策略 %q 不存在", args[0])
			}
			return out, nil
		}),
	}
}

// newHubPullCmd 从 Hub 拉取策略原始 JSON（公开免认证，私有自动携带 Token）。
func newHubPullCmd() *cobra.Command {
	var (
		product string
		outPath string
	)
	cmd := &cobra.Command{
		Use:   "pull <username/name> [-o file.json]",
		Short: "按策略地址拉取最新内容（-o 落盘；不指定则输出 JSON）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			repo := args[0]
			parts := strings.Split(repo, "/")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, fmt.Errorf("策略地址格式错误，应为 username/name")
			}
			hc, h, err := resolveHub()
			if err != nil {
				return nil, err
			}
			product, _, err := resolveHubDefaults(h, product, "应用安全")
			if err != nil {
				return nil, err
			}
			raw, err := hc.PullRepo(product, repo)
			if err != nil {
				return nil, err
			}
			if outPath != "" {
				if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
					return nil, fmt.Errorf("创建输出目录失败: %w", err)
				}
				if err := os.WriteFile(outPath, raw, 0o600); err != nil {
					return nil, fmt.Errorf("写入文件失败: %w", err)
				}
				return map[string]any{"repo": repo, "product": product, "saved_to": outPath, "bytes": len(raw)}, nil
			}
			return json.RawMessage(raw), nil
		}),
	}
	cmd.Flags().StringVar(&product, "product", "", "产品端点：jxwaf/webtds（默认取 hub 配置或 jxwaf；须与策略 product 匹配）")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "输出文件路径（可选）")
	return cmd
}

// newHubDeleteCmd 删除策略（硬删除不可恢复；默认 dry-run，--apply 执行）。
func newHubDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <策略名>",
		Short: "删除 Hub 策略（默认 dry-run 预览，--apply 执行；硬删除不可恢复）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			hc, _, err := resolveHub()
			if err != nil {
				return nil, err
			}
			name := args[0]
			out, exists, err := hc.GetPolicy(name)
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, fmt.Errorf("策略 %q 不存在", name)
			}
			apply, _ := cmd.Flags().GetBool("apply")
			if !apply {
				return map[string]any{
					"dry_run": true, "action": "delete", "name": name,
					"product": out["product"], "scene": out["scene"], "pull_count": out["pull_count"],
					"hint": "预览未执行；删除后策略地址立即失效且不可恢复，确认后使用 --apply",
				}, nil
			}
			if err := hc.DeletePolicy(name); err != nil {
				return nil, err
			}
			return map[string]any{"action": "delete", "name": name, "deleted": true, "note": "策略地址已失效且不可恢复"}, nil
		}),
	}
	cmd.Flags().Bool("apply", false, "实际执行（默认 dry-run 仅预览）")
	return cmd
}
