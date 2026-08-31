package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/jx-sec/jxwaf-agent/internal/client"
	"github.com/jx-sec/jxwaf-agent/internal/config"
	"github.com/spf13/cobra"
)

// 全局租户参数：专业版域名组（--group）、云WAF(admin)子账号（--sub-user）。
var (
	groupFlag   string
	subUserFlag string
)

// tenantOpts 汇总当前命令的租户参数。
func tenantOpts() adapter.TenantOpts {
	return adapter.TenantOpts{Group: groupFlag, SubUser: subUserFlag}
}

// resolve 加载配置、解析目标环境、构造适配器与 HTTP 客户端。
func resolve() (*adapter.Adapter, *client.Client, error) {
	c, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	env, err := c.Resolve(envFlag)
	if err != nil {
		return nil, nil, err
	}
	a, err := adapter.New(env)
	if err != nil {
		return nil, nil, err
	}
	return a, client.New(env.BaseURL), nil
}

// callOp 执行一次逻辑操作：路径映射、租户注入、认证头、业务结果判定。
// 返回服务器原始响应体（map）；网络错误或业务失败返回 error。
func callOp(a *adapter.Adapter, c *client.Client, op adapter.Op, body map[string]any) (map[string]any, error) {
	path, err := a.Path(op)
	if err != nil {
		return nil, err
	}
	body = cloneMap(body)
	if err := a.InjectTenant(op, body, tenantOpts()); err != nil {
		return nil, err
	}
	resp, err := c.Post(path, a.HeaderMap(), body)
	if err != nil {
		return nil, err
	}
	if !resp.Result {
		return nil, fmt.Errorf("%s [%s]", resp.Message, path)
	}
	return resp.Raw, nil
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// loadParams 解析 --params 值：文件路径、"-"（stdin）或内联 JSON；空值返回空对象。
// 判定顺序：显式 "-" 走 stdin；路径存在（stat 成功）按文件读取（读失败报明确错误）；否则按内联 JSON。
func loadParams(v string) (map[string]any, error) {
	if v == "" {
		return map[string]any{}, nil
	}
	var raw []byte
	switch {
	case v == "-":
		var err error
		raw, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("读取 stdin 失败: %w", err)
		}
	default:
		if fi, err := os.Stat(v); err == nil && !fi.IsDir() {
			data, err := os.ReadFile(v)
			if err != nil {
				return nil, fmt.Errorf("读取参数文件失败 %s: %w", v, err)
			}
			raw = data
		} else {
			raw = []byte(v)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("params 解析失败（需为 JSON 对象；文件路径需存在且内容为 JSON）: %w", err)
	}
	if m == nil {
		return map[string]any{}, nil
	}
	return m, nil
}

// addParamsFlag 为命令注册统一的 --params 参数（JSON 文件路径 / "-" / 内联 JSON）。
func addParamsFlag(cmd *cobra.Command) {
	cmd.Flags().String("params", "", "请求参数：JSON 文件路径、\"-\"（stdin）或内联 JSON")
}

// orDefault 返回第一个非空值。
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// getParams 读取并解析 --params。
func getParams(cmd *cobra.Command) (map[string]any, error) {
	v, err := cmd.Flags().GetString("params")
	if err != nil {
		return nil, err
	}
	return loadParams(v)
}
