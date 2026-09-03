package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/jx-sec/jxwaf-agent/internal/deploy"
	"github.com/spf13/cobra"
)

// newDeployCmd WAF 节点远程部署命令。
// 安全模型（两步审核）：默认 dry-run 仅执行只读前置检查并展示部署计划（含完整 compose 内容），
// 用户确认后加 --apply 才执行安装依赖/上传配置/启动容器等变更动作。
func newDeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "远程部署 WAF（SSH → 环境检查 → Docker → 端口冲突检测 → 容器拉起；默认 dry-run，--apply 执行）",
		Long: `远程部署 JXWAF 到用户自己的服务器（对齐 docs.jxwaf.com 官方部署教程）。

版本形态：
  professional / cloud  节点接入已有控制台（需 --server 指向控制台地址，末尾不带 /）
  standard              单机全栈（控制台+节点+MySQL+日志采集一次部署完成，无需 --server）

认证（二选一）：
  --ssh-key <私钥路径>              SSH 密钥认证
  环境变量 JXWAF_SSH_PASSWORD       SSH 密码（避免密码进入 shell history/进程列表）

凭据安全：--waf-auth 与（standard 版）自动生成的 MySQL 密码只写入远端服务器的
docker-compose.yml（权限 0600），本地不留存任何密码。

子命令：
  jxwaf-cli deploy [--version ...] [--server URL] ...      部署节点（standard 全栈 / prof/cloud 接入已有控制台）
  jxwaf-cli deploy admin --host IP --version professional|cloud  部署管理控制台（mysql+admin+ssl_cert_service）
  jxwaf-cli deploy jlog --host IP --version professional|cloud     部署 jxlog 日志系统（clickhouse+jxlog）
  jxwaf-cli deploy remove --host IP [--target node|admin|jlog]     卸载（--purge-data 连数据删）
  jxwaf-cli deploy exec --host IP --cmd "<命令>" [--approve]      在服务器执行命令（只读直接执行；风险命令需 --approve）
  jxwaf-cli deploy version                                     查看镜像版本配置（versions.json）`,
	}
	cmd.AddCommand(newDeployRunCmd(), newDeployAdminCmd(), newDeployJlogCmd(), newDeployRemoveCmd(), newDeployExecCmd(), newDeployVersionCmd())
	return cmd
}

// newDeployRunCmd 部署执行（原 deploy 主体）。
func newDeployRunCmd() *cobra.Command {
	var (
		host      string
		user      string
		sshKey    string
		version   string
		serverURL string
		wafAuth   string
		httpPort  string
		httpsPort string
		adminPort string
		skipNFT   bool
		nodeImg   string
		nftImg    string
		skipChk   bool
		waitSec   int
		source    string
	)
	cmd := &cobra.Command{
		Use:   "deploy --host IP --user root --version standard|professional|cloud [--server URL] --waf-auth TOKEN",
		Short: "远程部署 WAF（SSH → 环境检查 → Docker → 端口冲突检测 → 容器拉起；默认 dry-run，--apply 执行）",
		Long: `远程部署 JXWAF 到用户自己的服务器（对齐 docs.jxwaf.com 官方部署教程）。

版本形态：
  professional / cloud  节点接入已有控制台（需 --server 指向控制台地址，末尾不带 /）
  standard              单机全栈（控制台+节点+MySQL+日志采集一次部署完成，无需 --server）

认证（二选一）：
  --ssh-key <私钥路径>              SSH 密钥认证
  环境变量 JXWAF_SSH_PASSWORD       SSH 密码（避免密码进入 shell history/进程列表）

凭据安全：--waf-auth 与（standard 版）自动生成的 MySQL 密码只写入远端服务器的
docker-compose.yml（权限 0600），本地不留存任何密码。`,
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if user == "" {
				user = "root"
			}
			images, err := deploy.LoadVersions()
			if err != nil {
				return nil, err
			}
			opts := deploy.Options{
				Host:   host,
				User:   user,
				SSHKey: sshKey,
				Compose: deploy.ComposeParams{
					Version:   version,
					ServerURL: serverURL,
					WafAuth:   wafAuth,
					HTTPPort:  httpPort,
					HTTPSPort: httpsPort,
					AdminPort: adminPort,
					WithNFT:   !skipNFT,
					NodeImage: nodeImg,
					NFTImage:  nftImg,
					Images:    images,
				},
				SkipPortChk: skipChk,
				WaitSec:     waitSec,
			}
			// 参数完整性校验（缺失时报错并说明从哪获取）
			if err := opts.Validate(); err != nil {
				return nil, err
			}
			// 管理端地址规范化（去尾部斜杠，官方要求末尾不带 /）
			if opts.Compose.Version != deploy.VersionStandard {
				u, err := deploy.NormalizeServerURL(opts.Compose.ServerURL)
				if err != nil {
					return nil, err
				}
				opts.Compose.ServerURL = u
			}
			// standard 版 MySQL 密码在此一次性生成（dry-run 与 --apply 共用同一份，避免两次生成不一致）
			if opts.Compose.Version == deploy.VersionStandard && opts.Compose.MySQLPassword == "" {
				opts.Compose.MySQLPassword = deploy.RandomPassword()
			}

			apply, _ := cmd.Flags().GetBool("apply")

			// SSH 连接（提前建立：供服务器 git clone 通道与后续前置检查/部署使用）
			c, err := deploy.DialSSH(opts.Host, opts.User, opts.SSHKey)
			if err != nil {
				return nil, err
			}
			defer c.Close()

			composeYAML, composeSource, degraded, err := resolveCompose(
				c, opts.Compose.Version, "node", source,
				deploy.InjectParams{
					WafAuth:       opts.Compose.WafAuth,
					ServerURL:     opts.Compose.ServerURL,
					MySQLPassword: opts.Compose.MySQLPassword,
					HTTPPort:      opts.Compose.HTTPPort,
					HTTPSPort:     opts.Compose.HTTPSPort,
					AdminPort:     opts.Compose.AdminPort,
				},
				func() (string, error) { return deploy.GenerateCompose(opts.Compose) },
			)
			if err != nil {
				return nil, err
			}

			if !apply {
				rep, err := deploy.Preflight(c, opts)
				if err != nil {
					// 前置检查失败：返回已收集的信息与错误（如端口冲突，让用户决策换端口）
					out := map[string]any{"dry_run": true, "preflight_failed": true, "error": err.Error(), "compose": composeYAML}
					if rep != nil {
						out["report"] = rep
					}
					out["hint"] = "前置检查未通过（见 error）；修正参数后重试，确认后加 --apply 执行部署"
					return out, nil
				}
				rep.Applied = false
				out := map[string]any{
					"dry_run":        true,
					"report":         rep,
					"compose":        composeYAML,
					"compose_source": composeSource,
					"compose_at":     deploy.ComposePath,
					"hint":           "预览未执行；确认以上计划与配置后，加 --apply 实际部署（将安装缺失依赖、写入 " + deploy.ComposePath + "、拉起容器）",
				}
				if degraded != "" {
					out["degraded"] = degraded
				}
				return out, nil
			}

			opts.ComposeYAML = composeYAML
			rep, err := deploy.Deploy(c, opts)
			if rep != nil {
				rep.Applied = err == nil
			}
			if err != nil {
				return nil, err
			}
			return rep, nil
		}),
	}
	cmd.Flags().StringVar(&host, "host", "", "目标服务器 IP（可带 SSH 端口，如 1.2.3.4 或 1.2.3.4:2222）")
	cmd.Flags().StringVar(&user, "user", "root", "SSH 用户（需 root 或免密 sudo）")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH 私钥路径（密码认证改用环境变量 JXWAF_SSH_PASSWORD）")
	cmd.Flags().StringVar(&version, "version", "", "要部署的 WAF 版本：standard/professional/cloud")
	cmd.Flags().StringVar(&serverURL, "server", "", "管理控制台地址（professional/cloud 必填，如 http://1.2.3.4，末尾不带 /；standard 单机全栈无需此参数）")
	cmd.Flags().StringVar(&wafAuth, "waf-auth", "", "节点接入凭据 waf_auth（控制台 waf-auth/基础信息页查看；standard 版为自设 UUID）")
	cmd.Flags().StringVar(&httpPort, "http-port", "80", "节点 HTTP 监听端口（多端口逗号分隔，如 80,8080）")
	cmd.Flags().StringVar(&httpsPort, "https-port", "443", "节点 HTTPS 监听端口（多端口逗号分隔）")
	cmd.Flags().StringVar(&adminPort, "admin-port", "8000", "控制台 HTTP 端口（仅 standard 单机全栈使用）")
	cmd.Flags().BoolVar(&skipNFT, "skip-nft", false, "跳过 jxwaf_nft_node 网络封禁节点（默认完整部署）")
	cmd.Flags().StringVar(&nodeImg, "image", "", "覆盖 WAF 节点镜像（默认用官方教程版本镜像）")
	cmd.Flags().StringVar(&nftImg, "nft-image", "", "覆盖 nft_node 镜像")
	cmd.Flags().BoolVar(&skipChk, "skip-port-check", false, "跳过端口冲突检查（明确接受占用时使用）")
	cmd.Flags().IntVar(&waitSec, "wait", 15, "容器启动后等待验证的秒数")
	cmd.Flags().StringVar(&source, "source", "github", "compose 来源：github（默认，多通道获取官方最新：本机 raw→GitHub API→服务器 git clone，全失败直接报错）| git（服务器 git clone，失败直接报错）| generate（显式本地生成，版本来自 versions.json）")
	cmd.Flags().Bool("apply", false, "实际执行部署（默认 dry-run 仅预览计划）")
	return cmd
}

// newDeployRemoveCmd 卸载部署（对齐官方教程"卸载系统"章节）。
// 安全模型（极高风险）：删除容器与配置默认需 --apply；--purge-data 连数据一起删（不可恢复）。
func newDeployRemoveCmd() *cobra.Command {
	var (
		host   string
		user   string
		sshKey string
		target string
		purge  bool
	)
	cmd := &cobra.Command{
		Use:   "remove --host IP [--target node|admin|jlog] [--purge-data] [--apply]",
		Short: "卸载部署（停止并移除容器、删除配置；--target 选组件，--purge-data 连数据删）",
		Long: `卸载服务器上的 JXWAF 部署（对齐官方"卸载系统"流程）：
  1. docker compose down 停止并移除该目标全部相关容器
  2. 删除对应部署配置（分目录隔离：node=/opt/jxwaf_node，admin=/opt/jxwaf_admin，jlog=/opt/jxwaf_jlog）
  3. 默认保留数据目录 /opt/jxwaf_data（重新部署可复用）
     加 --purge-data 时连数据一起删除（不可恢复；注意同机多组件部署时会删全部组件的数据）`,
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if host == "" {
				return nil, fmt.Errorf("缺少 --host：目标服务器 IP")
			}
			if user == "" {
				user = "root"
			}
			if target == "" {
				target = "node"
			}
			if !deploy.ValidRemoveTarget(target) {
				return nil, fmt.Errorf("非法 --target %q（node/admin/jlog）", target)
			}
			if sshKey == "" && os.Getenv("JXWAF_SSH_PASSWORD") == "" {
				return nil, fmt.Errorf("缺少 SSH 认证：设置环境变量 JXWAF_SSH_PASSWORD（密码）或 --ssh-key <私钥路径>")
			}
			apply, _ := cmd.Flags().GetBool("apply")

			// dry-run：预览将要删除的内容（只读检查）
			c, err := deploy.DialSSH(host, user, sshKey)
			if err != nil {
				return nil, err
			}
			defer c.Close()

			if !apply {
				plan := []string{
					fmt.Sprintf("停止并移除 %s 组件容器（docker compose down）", target),
					fmt.Sprintf("删除配置（%s/docker-compose.yml）", deploy.TargetDir(target)),
					ternary(purge, "删除数据目录 /opt/jxwaf_data（不可恢复，含同机其他组件数据）", "保留数据目录 /opt/jxwaf_data（重新部署可复用）"),
				}
				return map[string]any{
					"dry_run": true,
					"host":    host,
					"target":  target,
					"plan":    plan,
					"hint":    "预览未执行；确认后加 --apply 执行卸载（--purge-data 连数据一起删，不可恢复）",
				}, nil
			}

			rep, err := deploy.Remove(c, deploy.RemoveOptions{Target: target, Purge: purge})
			if rep != nil {
				rep.Applied = err == nil
			}
			if err != nil {
				return nil, err
			}
			return rep, nil
		}),
	}
	cmd.Flags().StringVar(&host, "host", "", "目标服务器 IP（可带 SSH 端口）")
	cmd.Flags().StringVar(&user, "user", "root", "SSH 用户")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH 私钥路径（密码认证改用环境变量 JXWAF_SSH_PASSWORD）")
	cmd.Flags().StringVar(&target, "target", "node", "卸载目标：node（节点/standard全栈）/ admin（控制台）/ jlog（日志系统）")
	cmd.Flags().BoolVar(&purge, "purge-data", false, "连数据目录一起删除（/opt/jxwaf_data，不可恢复）")
	cmd.Flags().Bool("apply", false, "实际执行卸载（默认 dry-run 仅预览）")
	return cmd
}

// ternary 三元辅助。
func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// newDeployAdminCmd 部署管理控制台（prof/cloud 分离部署形态；standard 全栈走 deploy 主体）。
func newDeployAdminCmd() *cobra.Command {
	var (
		host      string
		user      string
		sshKey    string
		version   string
		adminPort string
		adminImg  string
		sslImg    string
		waitSec   int
		source    string
	)
	cmd := &cobra.Command{
		Use:   "admin --host IP --version professional|cloud",
		Short: "部署管理控制台（mysql + admin_server + ssl_cert_service；standard 全栈请用 deploy 主体）",
		Long: `部署 JXWAF 管理控制台（对齐官方教程"控制台部署"章节）：
  mysql_db（仅本机监听，密码自动生成）+ jxwaf_admin_server + ssl_cert_service（泛域名证书自动签发）。

部署完成后：浏览器访问 http://<IP>:<端口> 注册账号 → 系统管理→基础信息 查看 waf_auth
→ 用 ` + "`deploy --server http://<IP>:<端口> --waf-auth <waf_auth>`" + ` 部署节点。
默认端口：8000（--admin-port 可改）。节点是流量入口必须占 80/443，控制台默认不占 80；
仅控制台与节点分机部署、控制台独占一台服务器时，才显式 --admin-port 80。`,
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if user == "" {
				user = "root"
			}
			images, err := deploy.LoadVersions()
			if err != nil {
				return nil, err
			}
			opts := deploy.AdminOptions{
				Host: host, User: user, SSHKey: sshKey, WaitSec: waitSec,
				Compose: deploy.AdminComposeParams{
					Version: version, AdminPort: adminPort, AdminImage: adminImg, SSLCertImage: sslImg, Images: images,
				},
			}
			if err := deploy.ValidateAdmin(opts); err != nil {
				return nil, err
			}
			// MySQL 密码一次性生成（dry-run 与 --apply 共用同一份）
			if opts.Compose.MySQLPassword == "" {
				opts.Compose.MySQLPassword = deploy.RandomPassword()
			}

			c, err := deploy.DialSSH(opts.Host, opts.User, opts.SSHKey)
			if err != nil {
				return nil, err
			}
			defer c.Close()

			composeYAML, composeSource, degraded, err := resolveCompose(
				c, opts.Compose.Version, "admin", source,
				deploy.InjectParams{
					MySQLPassword: opts.Compose.MySQLPassword,
					AdminPort:     opts.Compose.EffectiveAdminPort(),
				},
				func() (string, error) { return deploy.GenerateAdminCompose(opts.Compose) },
			)
			if err != nil {
				return nil, err
			}

			apply, _ := cmd.Flags().GetBool("apply")
			if !apply {
				rep, err := deploy.PreflightStack(c, opts.Compose.Version, opts.Host, opts.User, deploy.AdminCheckPorts(opts.Compose))
				out := map[string]any{"dry_run": true, "compose": composeYAML, "compose_source": composeSource, "compose_at": deploy.AdminComposePath}
				if degraded != "" {
					out["degraded"] = degraded
				}
				if rep != nil {
					rep.Applied = false
					out["report"] = rep
				}
				if err != nil {
					out["preflight_failed"] = true
					out["error"] = err.Error()
					out["hint"] = "前置检查未通过（见 error）；修正参数后重试，确认后加 --apply 执行部署"
					return out, nil
				}
				out["hint"] = "预览未执行；确认后加 --apply 实际部署（写入 " + deploy.AdminComposePath + " 并拉起容器）"
				return out, nil
			}

			opts.ComposeYAML = composeYAML
			rep, err := deploy.DeployAdmin(c, opts)
			if rep != nil {
				rep.Applied = err == nil
			}
			if err != nil {
				return nil, err
			}
			return rep, nil
		}),
	}
	cmd.Flags().StringVar(&host, "host", "", "目标服务器 IP（可带 SSH 端口）")
	cmd.Flags().StringVar(&user, "user", "root", "SSH 用户（需 root 或免密 sudo）")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH 私钥路径（密码认证改用环境变量 JXWAF_SSH_PASSWORD）")
	cmd.Flags().StringVar(&version, "version", "", "WAF 版本：professional/cloud")
	cmd.Flags().StringVar(&adminPort, "admin-port", "", "控制台 HTTP 端口（默认 8000；仅分机部署需控制台独占 80 时显式指定）")
	cmd.Flags().StringVar(&adminImg, "image", "", "覆盖控制台镜像")
	cmd.Flags().StringVar(&sslImg, "ssl-cert-image", "", "覆盖 ssl_cert_service 镜像")
	cmd.Flags().IntVar(&waitSec, "wait", 20, "容器启动后等待验证的秒数（MySQL 首次初始化较慢）")
	cmd.Flags().StringVar(&source, "source", "github", "compose 来源：github（默认，多通道获取官方最新：本机 raw→GitHub API→服务器 git clone，全失败直接报错）| git（服务器 git clone，失败直接报错）| generate（显式本地生成，版本来自 versions.json）")
	cmd.Flags().Bool("apply", false, "实际执行部署（默认 dry-run 仅预览）")
	return cmd
}

// newDeployJlogCmd 部署 jxlog 日志系统（prof/cloud）。
func newDeployJlogCmd() *cobra.Command {
	var (
		host    string
		user    string
		sshKey  string
		version string
		jlogImg string
		chImg   string
		waitSec int
		source  string
	)
	cmd := &cobra.Command{
		Use:   "jlog --host IP --version professional|cloud",
		Short: "部署 jxlog 日志系统（clickhouse + jxlog，SOC 报表/日志查询依赖）",
		Long: `部署 jxlog 日志采集与分析系统（对齐官方教程"JXLOG 日志系统部署"章节）。

部署完成后到控制台对接：
  系统配置→日志传输配置：日志服务器地址填 <本机IP>，端口 8877
  系统配置→日志查询配置：ClickHouse 地址填 <本机IP>，端口 9004，用户/密码 jxlog/jxlog，库 jxwaf，表 jxlog`,
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if user == "" {
				user = "root"
			}
			images, err := deploy.LoadVersions()
			if err != nil {
				return nil, err
			}
			opts := deploy.JlogOptions{
				Host: host, User: user, SSHKey: sshKey, WaitSec: waitSec,
				Compose: deploy.JlogComposeParams{Version: version, JlogImage: jlogImg, CHImage: chImg, Images: images},
			}
			if err := deploy.ValidateJlog(opts); err != nil {
				return nil, err
			}
			c, err := deploy.DialSSH(opts.Host, opts.User, opts.SSHKey)
			if err != nil {
				return nil, err
			}
			defer c.Close()

			composeYAML, composeSource, degraded, err := resolveCompose(
				c, opts.Compose.Version, "jlog", source,
				deploy.InjectParams{},
				func() (string, error) { return deploy.GenerateJlogCompose(opts.Compose) },
			)
			if err != nil {
				return nil, err
			}

			apply, _ := cmd.Flags().GetBool("apply")
			if !apply {
				rep, err := deploy.PreflightStack(c, opts.Compose.Version, opts.Host, opts.User, deploy.JlogCheckPorts())
				out := map[string]any{"dry_run": true, "compose": composeYAML, "compose_source": composeSource, "compose_at": deploy.JlogComposePath}
				if degraded != "" {
					out["degraded"] = degraded
				}
				if rep != nil {
					rep.Applied = false
					out["report"] = rep
				}
				if err != nil {
					out["preflight_failed"] = true
					out["error"] = err.Error()
					out["hint"] = "前置检查未通过（见 error）；修正参数后重试，确认后加 --apply 执行部署"
					return out, nil
				}
				out["hint"] = "预览未执行；确认后加 --apply 实际部署（写入 " + deploy.JlogComposePath + " 并拉起容器）"
				return out, nil
			}

			opts.ComposeYAML = composeYAML
			rep, err := deploy.DeployJlog(c, opts)
			if rep != nil {
				rep.Applied = err == nil
			}
			if err != nil {
				return nil, err
			}
			return rep, nil
		}),
	}
	cmd.Flags().StringVar(&host, "host", "", "目标服务器 IP（可带 SSH 端口）")
	cmd.Flags().StringVar(&user, "user", "root", "SSH 用户（需 root 或免密 sudo）")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH 私钥路径（密码认证改用环境变量 JXWAF_SSH_PASSWORD）")
	cmd.Flags().StringVar(&version, "version", "", "WAF 版本：professional/cloud")
	cmd.Flags().StringVar(&jlogImg, "image", "", "覆盖 jxlog 镜像")
	cmd.Flags().StringVar(&chImg, "clickhouse-image", "", "覆盖 clickhouse 镜像")
	cmd.Flags().IntVar(&waitSec, "wait", 15, "容器启动后等待验证的秒数")
	cmd.Flags().StringVar(&source, "source", "github", "compose 来源：github（默认，多通道获取官方最新：本机 raw→GitHub API→服务器 git clone，全失败直接报错）| git（服务器 git clone，失败直接报错）| generate（显式本地生成，版本来自 versions.json）")
	cmd.Flags().Bool("apply", false, "实际执行部署（默认 dry-run 仅预览）")
	return cmd
}

// newDeployExecCmd 在目标服务器执行命令（AI 自主诊断通道）。
// 安全模型：只读诊断命令直接执行并返回输出；命中风险红线（kill/stop/rm/down/关机/格式化/防火墙）
// 的命令默认拒绝，需显式 --approve（表示用户已审批）才执行。
func newDeployExecCmd() *cobra.Command {
	var (
		host       string
		user       string
		sshKey     string
		cmdStr     string
		approve    bool
		timeoutSec int
	)
	cmd := &cobra.Command{
		Use:   "exec --host IP --cmd \"<命令>\" [--approve]",
		Short: "在目标服务器执行命令（只读直接执行；风险命令需 --approve）",
		Long: `在目标服务器上执行命令，作为 AI 自主诊断的通道。

安全模型：
  - 只读诊断命令（docker ps/logs、ss -tlnp、df/free、systemctl status 等）直接执行并返回输出
  - 命中风险红线（kill/pkill、systemctl stop、rm、docker down/rm/stop、重启关机、磁盘格式化、防火墙修改）的命令默认拒绝，需显式 --approve 才执行

审批流程（AI 编排层）：AI 向用户展示风险命令与影响范围 → 用户明确确认 → AI 加 --approve 执行。

注意：命令输出可能含敏感信息（如 docker-compose.yml 含 waf_auth / MySQL 密码），AI 解读时严禁将凭据明文写入对话或文件。`,
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			if host == "" {
				return nil, fmt.Errorf("缺少 --host：目标服务器 IP（可带 SSH 端口）")
			}
			if cmdStr == "" {
				return nil, fmt.Errorf("缺少 --cmd：要执行的命令")
			}
			if user == "" {
				user = "root"
			}

			// 风险判断前置：本地纯判断，风险命令无 --approve 时直接拒绝（不触碰 SSH）
			risky, reason := deploy.IsRiskyCommand(cmdStr)
			if risky && !approve {
				return nil, fmt.Errorf("风险命令被拒绝（%s）：%s。请先向用户展示命令与影响，用户明确确认后加 --approve 执行", reason, cmdStr)
			}

			if sshKey == "" && os.Getenv("JXWAF_SSH_PASSWORD") == "" {
				return nil, fmt.Errorf("缺少 SSH 认证：设置环境变量 JXWAF_SSH_PASSWORD（密码）或 --ssh-key <私钥路径>")
			}

			c, err := deploy.DialSSH(host, user, sshKey)
			if err != nil {
				return nil, err
			}
			defer c.Close()

			r := c.RunWithTimeout(cmdStr, time.Duration(timeoutSec)*time.Second)
			return map[string]any{
				"host":      host,
				"command":   cmdStr,
				"risky":     risky,
				"approved":  approve,
				"exit_code": r.Code,
				"stdout":    r.Stdout,
				"stderr":    r.Stderr,
			}, nil
		}),
	}
	cmd.Flags().StringVar(&host, "host", "", "目标服务器 IP（可带 SSH 端口，如 1.2.3.4:2222）")
	cmd.Flags().StringVar(&user, "user", "root", "SSH 用户（需 root 或免密 sudo）")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "SSH 私钥路径（密码认证改用环境变量 JXWAF_SSH_PASSWORD）")
	cmd.Flags().StringVar(&cmdStr, "cmd", "", "要执行的命令")
	cmd.Flags().BoolVar(&approve, "approve", false, "已审批执行风险命令（默认拒绝风险命令）")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 30, "命令执行超时秒数（0 表示不超时）")
	return cmd
}

// newDeployVersionCmd 查看当前镜像版本配置（versions.json）。
func newDeployVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "查看镜像版本配置（versions.json）",
		Long: `查看部署使用的镜像版本配置（项目目录 versions.json）。

镜像版本不再硬编码在代码里，而是外置到 versions.json。官方发布新版后，
由 AI 从官方 GitHub 仓库（jx-sec/jxwaf）各版本 compose 获取最新镜像 tag，
更新 versions.json 后重新部署即可（--image/--nft-image 等覆盖参数仍可单次临时指定）。`,
		RunE: runE(func(cmd *cobra.Command, args []string) (any, error) {
			v, err := deploy.LoadVersions()
			if err != nil {
				return nil, err
			}
			path, _ := deploy.VersionsPath()
			return map[string]any{
				"versions_path": path,
				"versions":      v,
				"hint":          "镜像版本来源为 versions.json；官方发布新版后，从 GitHub 仓库 jx-sec/jxwaf 各版本 compose 获取最新 tag 更新此文件",
			}, nil
		}),
	}
	return cmd
}

// resolveCompose 根据 --source 决定 compose 来源：
//   - "generate"（显式）：本地生成（compose.go 模板，版本来自 versions.json）
//   - "github"（默认）：多通道获取官方最新 compose —— 本机 raw.githubusercontent.com
//     → GitHub Contents API → 服务器 git clone；全失败直接报错（不再自动降级本地生成）
//   - "git"：服务器 git clone 官方仓库 → 失败直接报错
//
// 获取原则：以官方为准。任一通道失败会先尝试下一种方式重新获取，而不是没尝试就报失败；
// 所有官方通道都拿不到最新 compose 时直接返回失败，避免用本地旧模板静默兜底导致与官方不一致。
// 确需离线本地模板时显式 --source generate。
//
// c 为已建立的 SSH 连接（用于服务器 git clone 通道），可为 nil（此时跳过该通道）。
// 返回 compose 内容、实际来源（github/git/generate）、通道提示（本机通道失败改用其他官方通道时非空，仅说明，非版本降级）。
func resolveCompose(c *deploy.SSHClient, version, target, source string, inj deploy.InjectParams, gen func() (string, error)) (string, string, string, error) {
	if source == "generate" {
		y, err := gen()
		return y, "generate", "", err
	}

	if source == "git" {
		if c == nil {
			return "", "", "", fmt.Errorf("--source git 需要已建立的 SSH 连接（用于服务器 git clone）")
		}
		gy, err := deploy.GitCloneCompose(c, version, target, inj)
		if err != nil {
			return "", "", "", fmt.Errorf("服务器 git clone 官方 compose 失败: %v（可检查服务器到 github.com 的连通性，或改用默认 --source github 由本机多通道拉取）", err)
		}
		return gy, "git", "", nil
	}

	// source == "github"（默认）
	y, err := deploy.FetchCompose(version, target, inj)
	if err == nil {
		return y, "github", "", nil
	}
	// 本机官方通道（raw + GitHub Contents API）失败：改用服务器 git clone 重新获取（服务器网络可能可达 github.com）
	if c != nil {
		if gy, gerr := deploy.GitCloneCompose(c, version, target, inj); gerr == nil {
			return gy, "git", fmt.Sprintf("本机拉取官方 compose 失败（%v），已改用服务器 git clone 重新获取成功", err), nil
		}
		return "", "", "", fmt.Errorf("获取官方最新 compose 失败：本机 raw.githubusercontent.com、GitHub Contents API、服务器 git clone 均未成功（最后错误：%v）。请检查本机/服务器到 GitHub 的网络连通性后重试；CLI 默认不再降级本地旧模板，避免部署与官方版本不一致", err)
	}
	return "", "", "", fmt.Errorf("获取官方最新 compose 失败：本机 raw.githubusercontent.com、GitHub Contents API 均未成功（最后错误：%v）。请检查本机到 GitHub 的网络连通性后重试；CLI 默认不再降级本地旧模板，避免部署与官方版本不一致", err)
}
