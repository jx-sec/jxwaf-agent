package cli

import (
	"encoding/json"
	"os"

	"github.com/jx-sec/jxwaf-agent/internal/gen"
	"github.com/spf13/cobra"
)

func newGenerateCmd() *cobra.Command {
	var outputPath string
	cmd := &cobra.Command{
		Use:   "generate <类型> [--params file|-|inline] [--output path]",
		Short: "语义参数 → 规范化配置（类型: " + joinTypes() + "）",
		Args:  cobra.ExactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			params, err := getParams(cmd)
			if err != nil {
				return nil, err
			}
			r, err := gen.Generate(args[0], params)
			if err != nil {
				return nil, err
			}
			if outputPath != "" {
				env := map[string]any{"type": r.Type, "op": r.Op, "config": r.Config, "test_cases": r.TestCases}
				data, err := json.MarshalIndent(env, "", "  ")
				if err != nil {
					return nil, err
				}
				if err := os.WriteFile(outputPath, data, 0o600); err != nil {
					return nil, err
				}
				r.Config = map[string]any{"saved_to": outputPath}
				r.TestCases = nil
			}
			return map[string]any{
				"type": r.Type, "op": r.Op, "config": r.Config,
				"preview": r.Preview, "test_cases": r.TestCases,
			}, nil
		}),
	}
	addParamsFlag(cmd)
	cmd.Flags().StringVar(&outputPath, "output", "", "将配置 JSON 写入文件（供 apply 使用）")
	return cmd
}

func joinTypes() string {
	ts := gen.Types()
	s := ""
	for i, t := range ts {
		if i > 0 {
			s += "/"
		}
		s += t
	}
	return s
}
