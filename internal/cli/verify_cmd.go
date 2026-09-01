package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

// verifyCase 为单个验证用例执行结果。
type verifyCase struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Expect  string `json:"expect"`
	Verdict string `json:"verdict"` // blocked / passed / unexpected
}

// blockStatus 判定为拦截的 HTTP 状态码（403=WAF拦截，444=连接关闭）。
func isBlockStatus(code int) bool {
	return code == 403 || code == 444
}

// verifyFile 为 verify 的输入文件：generate 信封（含 config+用例）或纯用例数组。
type verifyFile struct {
	Type      string            `json:"type"`
	Op        string            `json:"op"`
	Config    map[string]any    `json:"config"`
	TestCases []json.RawMessage `json:"test_cases"`
	Cases     []map[string]any  `json:"-"` // 纯数组形态
}

// loadVerifyFile 读取用例文件：支持 generate 信封格式或纯用例数组。
func loadVerifyFile(path string) (*verifyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取用例文件失败: %w", err)
	}
	vf := &verifyFile{}
	if err := json.Unmarshal(data, vf); err == nil && vf.Type != "" && len(vf.TestCases) > 0 {
		return vf, nil
	}
	var cases []map[string]any
	if err := json.Unmarshal(data, &cases); err != nil || len(cases) == 0 {
		return nil, fmt.Errorf("用例文件格式错误（需为 generate 输出或用例数组）")
	}
	vf.Cases = cases
	return vf, nil
}

// cases 返回统一用例列表。
func (vf *verifyFile) cases() []map[string]any {
	if len(vf.TestCases) > 0 {
		out := make([]map[string]any, 0, len(vf.TestCases))
		for _, raw := range vf.TestCases {
			var m map[string]any
			if json.Unmarshal(raw, &m) == nil {
				out = append(out, m)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return vf.Cases
}

// newVerifyCmd 通用流量验证：只发流量+查日志出报告，不部署不清空。
// 官方测试环境的一键闭环用 `jxwaf-cli test verify`。
func newVerifyCmd() *cobra.Command {
	var (
		targetURL string
		waitSec   int
	)
	cmd := &cobra.Command{
		Use:   "verify <用例文件> --url <站点地址>",
		Short: "通用流量验证：发送测试流量并查 SOC 日志出报告（不动环境配置）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if targetURL == "" {
				return nil, fmt.Errorf("--url 必填：被测站点地址（官方测试环境闭环请用 test verify，默认官方测试域名）")
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

			a, c, err := resolve()
			if err != nil {
				return nil, err
			}

			results, start, err := runVerifyTraffic(cases, targetURL, waitSec)
			if err != nil {
				return nil, err
			}
			socRaw, socErr := runSocQuery(a, c, u.Host, start)

			out := map[string]any{
				"cases":   results,
				"summary": verdictSummary(results),
			}
			if socErr != nil {
				out["soc_logs"] = map[string]any{"error": socErr.Error()}
			} else {
				out["soc_logs"] = socRaw
			}
			return out, nil
		}),
	}
	cmd.Flags().StringVar(&targetURL, "url", "", "被测站点地址（如 https://www.example.com）")
	cmd.Flags().IntVar(&waitSec, "wait", 5, "打流量后等待日志落库的秒数")
	return cmd
}

func strOf(m map[string]any, k, def string) string {
	if s, ok := m[k].(string); ok && s != "" {
		return s
	}
	return def
}
