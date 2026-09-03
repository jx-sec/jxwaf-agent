package deploy

import "regexp"

// riskyCommandPatterns 风险命令片段（命中即需用户审批）。
// 与 docs/deploy.md「9.2 风险分级与审批」的风险操作红线保持一致。
// 判定原则：宁可多拦、不可漏拦。
var riskyCommandPatterns = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)\b(kill|killall|pkill)\b`), "结束进程"},
	{regexp.MustCompile(`(?i)systemctl\s+(stop|disable|mask|isolate|rescue|emergency|halt|poweroff|reboot|kexec|restart|reload)`), "停止/禁用/重启系统服务"},
	{regexp.MustCompile(`(?i)\bservice\s+\S+\s+(stop|restart|reload|disable)`), "停止/重启服务"},
	{regexp.MustCompile(`(?i)\b(rm|rmdir)\b`), "删除文件或目录"},
	{regexp.MustCompile(`(?i)docker\s+(rm|stop|kill|container\s+(rm|stop|kill)|volume\s+rm|network\s+rm|image\s+rm|system\s+prune|compose\s+down)`), "移除/停止 Docker 容器或资源"},
	{regexp.MustCompile(`(?i)\b(reboot|shutdown|poweroff|halt)\b`), "重启或关机"},
	{regexp.MustCompile(`(?i)\b(mkfs|wipefs|fdisk|parted)\b`), "磁盘格式化或分区"},
	{regexp.MustCompile(`(?i)\bdd\s+if=`), "磁盘写入(dd)"},
	{regexp.MustCompile(`(?i)\biptables\b`), "操作防火墙规则(iptables)"},
	{regexp.MustCompile(`(?i)nft\s+(add|delete|flush|insert)`), "修改防火墙或网络规则"},
	{regexp.MustCompile(`(?i)>\s*/(etc|opt|usr|var|bin|sbin|lib|root|boot)\b`), "重定向覆盖系统文件"},
}

// IsRiskyCommand 判断远程命令是否属于风险操作（需用户审批）。
// 返回是否风险及原因。供 deploy exec 在默认拒绝风险命令时使用。
func IsRiskyCommand(cmd string) (bool, string) {
	for _, p := range riskyCommandPatterns {
		if p.re.MatchString(cmd) {
			return true, p.reason
		}
	}
	return false, ""
}
