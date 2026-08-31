package cli

import (
	"github.com/jx-sec/jxwaf-agent/internal/adapter"
	"github.com/spf13/cobra"
)

// newSubAccountCmd 子账号管理（仅云WAF主账号模式）。
func newSubAccountCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "subaccount", Short: "子账号管理（仅云WAF主账号）"}
	cmd.AddCommand(
		queryCmd("list", "查询子账号列表（page）", adapter.OpSubAccountList),
		queryCmd("search", "搜索子账号（page/search）", adapter.OpSubAccountSearch),
		queryCmd("get", "查询单个子账号（sub_user_name）", adapter.OpSubAccountGet),
		writeCmd("create", "创建子账号（sub_user_name/user_password/sub_otp_auth/website_access_conf；自动初始化防护配置）", adapter.OpSubAccountCreate),
		writeCmd("edit", "更新子账号（user_password 空串保留原密码）", adapter.OpSubAccountEdit),
		writeCmd("delete", "删除子账号（级联删除 17 张关联表并清理云 DNS A 记录）", adapter.OpSubAccountDelete),
		writeCmd("waf-auth", "重置子账号 waf_auth（旧值立即失效，返回新值）", adapter.OpSubAccountWafAuth),
		writeCmd("otp-reset", "重置子账号 OTP 密钥（返回新密钥与二维码 URL）", adapter.OpSubAccountOtpReset),
	)
	return cmd
}
