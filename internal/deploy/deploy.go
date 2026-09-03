package deploy

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Options 一次部署的完整输入。
type Options struct {
	Host        string // 服务器 IP（或 host:port）
	User        string // SSH 用户（默认 root）
	SSHKey      string // SSH 私钥路径（与密码二选一；密码经 JXWAF_SSH_PASSWORD 环境变量）
	Compose     ComposeParams
	ComposeYAML string // 预生成的 compose 内容（CLI 层已解析，含官方拉取/参数注入；空则内部生成）
	SkipPortChk bool   // 跳过端口冲突检查（用户明确确认占用可忽略时）
	WaitSec     int    // 部署后等待节点启动的秒数（默认 15）
}

// Report 部署执行报告（dry-run 与实际执行共用结构）。
type Report struct {
	Host       string            `json:"host"`
	User       string            `json:"user"`
	Version    string            `json:"version"`
	Image      string            `json:"image"`
	WithNFT    bool              `json:"with_nft"`
	NFTImage   string            `json:"nft_image,omitempty"`
	ComposeAt  string            `json:"compose_path"`
	Steps      []StepResult      `json:"steps"`
	SysInfo    map[string]string `json:"sys_info,omitempty"`
	PortChecks []PortCheck       `json:"port_checks,omitempty"`
	Containers []ContainerStatus `json:"containers,omitempty"`
	NodeLogs   string            `json:"node_logs,omitempty"` // 部署后节点日志尾部（排障用）
	Applied    bool              `json:"applied"`             // false=预览
}

// StepResult 单个部署步骤的执行结果。
type StepResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok / skipped / failed
	Detail string `json:"detail,omitempty"`
}

// PortCheck 端口占用检查结果。
type PortCheck struct {
	Port    string `json:"port"`
	Busy    bool   `json:"busy"`
	Process string `json:"process,omitempty"` // 占用进程描述
}

// ContainerStatus 部署后容器状态。
type ContainerStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	State  string `json:"state"`
}

// Validate 校验必填参数，缺失时返回带指引的错误（供 CLI 层直接透出给用户）。
func (o Options) Validate() error {
	if o.Host == "" {
		return fmt.Errorf("缺少 --host：目标服务器 IP（可带端口，如 1.2.3.4 或 1.2.3.4:2222）")
	}
	if !ValidVersion(o.Compose.Version) {
		return fmt.Errorf("缺少或非法 --version：要部署的 WAF 版本，取值 standard/professional/cloud")
	}
	// standard 为单机全栈（控制台在本机），无需 --server；professional/cloud 为节点接入已有控制台
	if o.Compose.Version != VersionStandard {
		if _, err := NormalizeServerURL(o.Compose.ServerURL); err != nil {
			return fmt.Errorf("缺少或非法 --server：%v（该版本管理控制台的访问地址，如 http://your-admin-server，末尾不带 /）", err)
		}
	}
	if o.Compose.WafAuth == "" {
		return fmt.Errorf("缺少 --waf-auth：节点接入凭据（登录管理控制台，在 waf-auth/基础信息 页面查看；standard 版为自设的 UUID 值）")
	}
	if o.SSHKey == "" && !hasPassword() {
		return fmt.Errorf("缺少 SSH 认证：设置环境变量 JXWAF_SSH_PASSWORD（密码）或 --ssh-key <私钥路径>")
	}
	return nil
}

func hasPassword() bool { return strings.TrimSpace(os.Getenv(sshPasswordEnv)) != "" }

// Preflight 执行部署前置检查（SSH 连接 → 系统探测 → Docker 依赖 → 端口冲突），不产生变更。
// 返回探测到的系统信息；任一硬性阻断项失败即返回 error（含解决指引）。
func Preflight(c *SSHClient, opts Options) (*Report, error) {
	rep := &Report{
		Host:      c.Host(),
		User:      opts.User,
		Version:   opts.Compose.Version,
		Image:     opts.Compose.EffectiveNodeImage(),
		WithNFT:   opts.Compose.WithNFT && opts.Compose.Version != VersionStandard,
		ComposeAt: ComposePath,
	}
	rep.Steps = []StepResult{}

	// 1. 系统探测
	sys := map[string]string{}
	if out, err := c.RunCheck("cat /etc/os-release 2>/dev/null | head -5; uname -m; id -u"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "ID=") && sys["os"] == "" {
				sys["os"] = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				sys["os_version"] = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
			if line == "x86_64" || line == "aarch64" {
				sys["arch"] = line
			}
			if line == "0" {
				sys["is_root"] = "true"
			}
		}
	}
	if sys["is_root"] != "true" {
		// 非 root 尝试 sudo 免密
		if r := c.Run("sudo -n true 2>/dev/null"); r.Code == 0 {
			sys["sudo"] = "passwordless"
		} else {
			return rep, fmt.Errorf("SSH 用户 %s 非 root 且无免密 sudo：部署需要 root 权限（Docker 安装/privileged 容器），请用 root 登录或配置 sudo 免密", opts.User)
		}
	}
	rep.SysInfo = sys

	// 操作系统与资源配置检查（对齐官方环境要求：Debian 12.x / Ubuntu 20.04+，最低 4 核 8G；仅告警不阻断）
	osDetail := fmt.Sprintf("os=%s %s arch=%s", sys["os"], sys["os_version"], sys["arch"])
	if sys["os"] != "" && sys["os"] != "debian" && sys["os"] != "ubuntu" {
		rep.Steps = append(rep.Steps, StepResult{Name: "系统探测", Status: "ok",
			Detail: osDetail + "（注意：官方支持 Debian 12.x / Ubuntu 20.04+，其他系统未经官方验证）"})
	} else {
		rep.Steps = append(rep.Steps, StepResult{Name: "系统探测", Status: "ok", Detail: osDetail})
	}
	resWarn := checkResources(c)
	if resWarn != "" {
		rep.Steps = append(rep.Steps, StepResult{Name: "资源配置检查", Status: "ok", Detail: resWarn})
	}

	// 2. Docker 与 compose 依赖检查（缺失将自动安装，属可恢复项）
	dockerOK := c.Run("docker version >/dev/null 2>&1").Code == 0
	composeOK := c.Run("docker compose version >/dev/null 2>&1").Code == 0
	switch {
	case dockerOK && composeOK:
		rep.Steps = append(rep.Steps, StepResult{Name: "Docker 依赖", Status: "ok", Detail: "docker 与 compose 已安装"})
	case dockerOK && !composeOK:
		rep.Steps = append(rep.Steps, StepResult{Name: "Docker 依赖", Status: "ok", Detail: "docker 已装，compose 插件缺失（部署时自动补装 docker-compose-plugin）"})
	default:
		rep.Steps = append(rep.Steps, StepResult{Name: "Docker 依赖", Status: "ok",
			Detail: "docker 未安装（部署时按官方教程自动安装：curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun，使用阿里云镜像源）"})
	}

	// 3. 端口冲突检查（standard 全栈含控制台/MySQL/日志端口）
	if !opts.SkipPortChk {
		ports := CheckPorts(opts.Compose)
		for _, p := range ports {
			pc := checkPort(c, p)
			rep.PortChecks = append(rep.PortChecks, pc)
		}
		var busy []string
		for _, pc := range rep.PortChecks {
			if pc.Busy {
				busy = append(busy, fmt.Sprintf("端口 %s 被 %s 占用", pc.Port, pc.Process))
			}
		}
		if len(busy) > 0 {
			return rep, fmt.Errorf("端口冲突：%s。请换端口（--http-port/--https-port/--admin-port）或先在服务器上处理占用进程（本工具不会擅自 kill 进程）", strings.Join(busy, "；"))
		}
		rep.Steps = append(rep.Steps, StepResult{Name: "端口冲突检查", Status: "ok", Detail: fmt.Sprintf("端口 %v 空闲", ports)})
	} else {
		rep.Steps = append(rep.Steps, StepResult{Name: "端口冲突检查", Status: "skipped", Detail: "--skip-port-check"})
	}
	return rep, nil
}

// checkResources 检查 CPU/内存是否满足官方最低要求（4 核 8G），低于时返回告警描述。
func checkResources(c *SSHClient) string {
	cpuOut := c.Run("nproc 2>/dev/null").Stdout
	memOut := c.Run("free -m 2>/dev/null | awk '/^Mem:/{print $2}'").Stdout
	cpu := strings.TrimSpace(cpuOut)
	mem := strings.TrimSpace(memOut)
	if cpu == "" || mem == "" {
		return "无法读取 CPU/内存信息（跳过资源配置检查）"
	}
	var warns []string
	if n := parseInt(cpu); n > 0 && n < 4 {
		warns = append(warns, fmt.Sprintf("CPU %s 核（官方最低 4 核）", cpu))
	}
	if m := parseInt(mem); m > 0 && m < 8000 {
		warns = append(warns, fmt.Sprintf("内存 %sMB（官方最低 8G）", mem))
	}
	if len(warns) == 0 {
		return fmt.Sprintf("CPU %s 核 / 内存 %sMB，满足官方最低要求（4核8G）", cpu, mem)
	}
	return strings.Join(warns, "，") + "——低于官方推荐，可能影响防护性能"
}

func parseInt(s string) int {
	n := 0
	for _, ch := range strings.TrimSpace(s) {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// checkPort 探测远程端口占用（ss 优先，netstat 兜底），返回占用进程描述。
func checkPort(c *SSHClient, port string) PortCheck {
	// ss -tlnp 输出形如：LISTEN 0 511 *:80 *:* users:(("nginx",pid=1234,fd=6))
	cmd := fmt.Sprintf(
		"(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E '[:\\.]%s\\s' | head -3", port)
	r := c.Run(cmd)
	out := strings.TrimSpace(r.Stdout)
	if out == "" {
		return PortCheck{Port: port, Busy: false}
	}
	// 提取 users:(("name",pid=..)) 部分；无进程信息（无 root）时给出原始行
	desc := out
	if i := strings.Index(out, "users:"); i >= 0 {
		desc = out[i:]
	}
	return PortCheck{Port: port, Busy: true, Process: strings.Join(strings.Fields(desc), " ")}
}

// uniquePorts 汇总 HTTP/HTTPS 端口列表（多端口逗号分隔）。
func uniquePorts(portLists ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range portLists {
		for _, p := range strings.Split(list, ",") {
			if p = strings.TrimSpace(p); p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Deploy 执行实际部署：前置检查通过后安装依赖 → 上传 compose → 拉起 → 验证。
func Deploy(c *SSHClient, opts Options) (*Report, error) {
	rep, err := Preflight(c, opts)
	if err != nil {
		return rep, err
	}

	// 4. Docker 安装（如缺失）与启动——按官方教程命令（阿里云镜像源，适配国内网络环境）
	if err := ensureDocker(c, rep); err != nil {
		return rep, err
	}

	// 5. 生成 compose（0600，含凭据）并拉起验证；优先使用 CLI 层预生成的 compose（官方拉取）
	composeYAML := opts.ComposeYAML
	if composeYAML == "" {
		var err error
		composeYAML, err = GenerateCompose(opts.Compose)
		if err != nil {
			return rep, err
		}
	}
	rep, err = runStack(c, rep, ComposePath, composeYAML, opts.WaitSec, "节点")
	if err != nil {
		return rep, err
	}

	// 8. 节点启动日志尾部（排障参考；节点接入成功以管理端节点列表为准）
	// 容器名随版本不同（professional/cloud 为 jxwaf_base，standard 为 *jxwaf_node_standard-1），双过滤
	logs := c.Run("docker logs --tail 30 $(docker ps --filter name=jxwaf_base --filter name=jxwaf_node_standard --format '{{.Names}}' | head -1) 2>&1")
	rep.NodeLogs = strings.TrimSpace(logs.Stdout)
	wait := opts.WaitSec
	if wait <= 0 {
		wait = 15
	}
	detail := fmt.Sprintf("容器运行中；节点约 %d 秒内完成配置拉取，请到管理控制台节点状态页确认上线", wait)
	if opts.Compose.Version == VersionStandard {
		admin := opts.Compose.AdminPort
		if admin == "" {
			admin = "8000"
		}
		detail = fmt.Sprintf("标准版全栈运行中；浏览器访问 http://%s:%s 注册账号后即可使用（账号注册后建议开启 OTP）", hostOnly(opts.Host), admin)
	}
	rep.Steps = append(rep.Steps, StepResult{Name: "部署验证", Status: "ok", Detail: detail})
	return rep, nil
}

// AdminOptions 控制台部署输入。
type AdminOptions struct {
	Host        string
	User        string
	SSHKey      string
	Compose     AdminComposeParams
	ComposeYAML string // 预生成的 compose 内容（CLI 层已解析；空则内部生成）
	WaitSec     int
}

// ValidateAdmin 校验控制台部署必填参数。
func ValidateAdmin(o AdminOptions) error {
	if o.Host == "" {
		return fmt.Errorf("缺少 --host：目标服务器 IP")
	}
	if o.Compose.Version != VersionProfessional && o.Compose.Version != VersionCloud {
		return fmt.Errorf("缺少或非法 --version：控制台部署仅支持 professional/cloud（standard 为单机全栈，直接用 deploy 主体）")
	}
	if o.SSHKey == "" && !hasPassword() {
		return fmt.Errorf("缺少 SSH 认证：设置环境变量 JXWAF_SSH_PASSWORD（密码）或 --ssh-key <私钥路径>")
	}
	return nil
}

// PreflightStack 非节点组件（admin/jlog）的通用前置检查：探测 + Docker 依赖 + 指定端口冲突。
func PreflightStack(c *SSHClient, version, host, user string, ports []string) (*Report, error) {
	rep := &Report{Host: c.Host(), User: user, Version: version, ComposeAt: ""}
	rep.Steps = []StepResult{}

	sys := map[string]string{}
	if out, err := c.RunCheck("cat /etc/os-release 2>/dev/null | head -5; uname -m; id -u"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ID=") && sys["os"] == "" {
				sys["os"] = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				sys["os_version"] = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
			if line == "x86_64" || line == "aarch64" {
				sys["arch"] = line
			}
			if line == "0" {
				sys["is_root"] = "true"
			}
		}
	}
	if sys["is_root"] != "true" {
		if r := c.Run("sudo -n true 2>/dev/null"); r.Code != 0 {
			return rep, fmt.Errorf("SSH 用户 %s 非 root 且无免密 sudo：部署需要 root 权限，请用 root 登录或配置 sudo 免密", user)
		}
		sys["sudo"] = "passwordless"
	}
	rep.SysInfo = sys
	osDetail := fmt.Sprintf("os=%s %s arch=%s", sys["os"], sys["os_version"], sys["arch"])
	if sys["os"] != "" && sys["os"] != "debian" && sys["os"] != "ubuntu" {
		osDetail += "（注意：官方支持 Debian 12.x / Ubuntu 20.04+，其他系统未经官方验证）"
	}
	rep.Steps = append(rep.Steps, StepResult{Name: "系统探测", Status: "ok", Detail: osDetail})
	if w := checkResources(c); w != "" {
		rep.Steps = append(rep.Steps, StepResult{Name: "资源配置检查", Status: "ok", Detail: w})
	}

	dockerOK := c.Run("docker version >/dev/null 2>&1").Code == 0
	composeOK := c.Run("docker compose version >/dev/null 2>&1").Code == 0
	switch {
	case dockerOK && composeOK:
		rep.Steps = append(rep.Steps, StepResult{Name: "Docker 依赖", Status: "ok", Detail: "docker 与 compose 已安装"})
	case dockerOK:
		rep.Steps = append(rep.Steps, StepResult{Name: "Docker 依赖", Status: "ok", Detail: "docker 已装，compose 插件缺失（部署时自动补装）"})
	default:
		rep.Steps = append(rep.Steps, StepResult{Name: "Docker 依赖", Status: "ok", Detail: "docker 未安装（部署时按官方命令自动安装，--mirror Aliyun）"})
	}

	for _, p := range ports {
		pc := checkPort(c, p)
		rep.PortChecks = append(rep.PortChecks, pc)
	}
	var busy []string
	for _, pc := range rep.PortChecks {
		if pc.Busy {
			busy = append(busy, fmt.Sprintf("端口 %s 被 %s 占用", pc.Port, pc.Process))
		}
	}
	if len(busy) > 0 {
		return rep, fmt.Errorf("端口冲突：%s。请换端口（--admin-port 等）或先处理占用进程", strings.Join(busy, "；"))
	}
	rep.Steps = append(rep.Steps, StepResult{Name: "端口冲突检查", Status: "ok", Detail: fmt.Sprintf("端口 %v 空闲", ports)})
	return rep, nil
}

// DeployAdmin 执行控制台部署（prof/cloud 分离部署形态）。
func DeployAdmin(c *SSHClient, opts AdminOptions) (*Report, error) {
	rep, err := PreflightStack(c, opts.Compose.Version, opts.Host, opts.User, AdminCheckPorts(opts.Compose))
	if err != nil {
		return rep, err
	}
	if err := ensureDocker(c, rep); err != nil {
		return rep, err
	}
	composeYAML := opts.ComposeYAML
	if composeYAML == "" {
		var err error
		composeYAML, err = GenerateAdminCompose(opts.Compose)
		if err != nil {
			return rep, err
		}
	}
	rep, err = runStack(c, rep, AdminComposePath, composeYAML, opts.WaitSec, "控制台")
	if err != nil {
		return rep, err
	}
	rep.ComposeAt = AdminComposePath
	rep.Steps = append(rep.Steps, StepResult{Name: "部署验证", Status: "ok",
		Detail: fmt.Sprintf("控制台运行中；浏览器访问 http://%s:%s 注册账号（建议开启 OTP）。后续：注册后在系统管理→基础信息查看 waf_auth，用 `deploy --server http://%s:%s` 部署节点",
			hostOnly(opts.Host), opts.Compose.EffectiveAdminPort(), hostOnly(opts.Host), opts.Compose.EffectiveAdminPort())})
	return rep, nil
}

// JlogOptions jxlog 部署输入。
type JlogOptions struct {
	Host        string
	User        string
	SSHKey      string
	Compose     JlogComposeParams
	ComposeYAML string // 预生成的 compose 内容（CLI 层已解析；空则内部生成）
	WaitSec     int
}

// ValidateJlog 校验 jxlog 部署必填参数。
func ValidateJlog(o JlogOptions) error {
	if o.Host == "" {
		return fmt.Errorf("缺少 --host：目标服务器 IP")
	}
	if o.Compose.Version != VersionProfessional && o.Compose.Version != VersionCloud {
		return fmt.Errorf("缺少或非法 --version：jxlog 部署仅支持 professional/cloud（standard 日志走 MySQL，已含在全栈中）")
	}
	if o.SSHKey == "" && !hasPassword() {
		return fmt.Errorf("缺少 SSH 认证：设置环境变量 JXWAF_SSH_PASSWORD（密码）或 --ssh-key <私钥路径>")
	}
	return nil
}

// DeployJlog 执行 jxlog 日志系统部署。
func DeployJlog(c *SSHClient, opts JlogOptions) (*Report, error) {
	rep, err := PreflightStack(c, opts.Compose.Version, opts.Host, opts.User, JlogCheckPorts())
	if err != nil {
		return rep, err
	}
	if err := ensureDocker(c, rep); err != nil {
		return rep, err
	}
	composeYAML := opts.ComposeYAML
	if composeYAML == "" {
		var err error
		composeYAML, err = GenerateJlogCompose(opts.Compose)
		if err != nil {
			return rep, err
		}
	}
	rep, err = runStack(c, rep, JlogComposePath, composeYAML, opts.WaitSec, "jxlog")
	if err != nil {
		return rep, err
	}
	rep.ComposeAt = JlogComposePath
	rep.Steps = append(rep.Steps, StepResult{Name: "部署验证", Status: "ok",
		Detail: fmt.Sprintf("jxlog 运行中；到控制台完成对接：系统配置→日志传输配置填 %s:8877；日志查询配置填 %s:9004（用户 jxlog 密码 jxlog，库 jxwaf 表 jxlog）",
			hostOnly(opts.Host), hostOnly(opts.Host))})
	return rep, nil
}

// runStack 公共部署流程：上传 compose（0600）→ 拉取镜像 → 启动 → 等待 → 验证容器状态。
// 供节点/控制台/jxlog 三种部署复用。
func runStack(c *SSHClient, rep *Report, composePath, composeYAML string, waitSec int, label string) (*Report, error) {
	if err := c.WriteFile(composePath, []byte(composeYAML), 0o600); err != nil {
		return rep, fmt.Errorf("上传 %s 失败: %w", composePath, err)
	}
	dir := dirOf(composePath)
	rep.Steps = append(rep.Steps, StepResult{Name: "上传配置", Status: "ok", Detail: composePath + "（0600）"})

	pull := fmt.Sprintf("cd %s && docker compose pull 2>&1 | tail -5", dir)
	if out, err := c.RunCheck(pull); err != nil {
		return rep, fmt.Errorf("镜像拉取失败（确认服务器可访问镜像仓库，或用 --image 指定其他镜像）: %w\n%s", err, out)
	}
	if _, err := c.RunCheck(fmt.Sprintf("cd %s && docker compose up -d 2>&1", dir)); err != nil {
		return rep, fmt.Errorf("%s容器启动失败: %w", label, err)
	}
	rep.Steps = append(rep.Steps, StepResult{Name: "容器启动", Status: "ok"})

	if waitSec <= 0 {
		waitSec = 15
	}
	time.Sleep(time.Duration(waitSec) * time.Second)
	ps := c.Run(fmt.Sprintf("cd %s && docker compose ps --format '{{.Name}} {{.Status}}' 2>/dev/null", dir))
	for _, line := range strings.Split(strings.TrimSpace(ps.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		st := ContainerStatus{Name: parts[0], Status: parts[1]}
		if strings.Contains(parts[1], "Up") {
			st.State = "running"
		} else {
			st.State = "abnormal"
		}
		rep.Containers = append(rep.Containers, st)
	}
	if len(rep.Containers) == 0 {
		return rep, fmt.Errorf("未发现运行中的容器，请在服务器上执行 `docker ps -a` 排查")
	}
	for _, cs := range rep.Containers {
		if cs.State != "running" {
			return rep, fmt.Errorf("容器 %s 状态异常（%s），请 `docker logs %s` 排查", cs.Name, cs.Status, cs.Name)
		}
	}
	return rep, nil
}

// ensureDocker 安装缺失的 Docker 与 compose 插件并确保运行（官方命令：--mirror Aliyun）。
func ensureDocker(c *SSHClient, rep *Report) error {
	if c.Run("docker version >/dev/null 2>&1").Code != 0 {
		if _, err := c.RunCheck("curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun"); err != nil {
			return fmt.Errorf("Docker 安装失败（可重试，或在服务器手动执行官方命令后重新部署）: %w", err)
		}
		rep.Steps = append(rep.Steps, StepResult{Name: "Docker 安装", Status: "ok", Detail: "官方教程命令（--mirror Aliyun）"})
	}
	if c.Run("docker compose version >/dev/null 2>&1").Code != 0 {
		if c.Run("apt-get install -y docker-compose-plugin 2>/dev/null || yum install -y docker-compose-plugin 2>/dev/null").Code != 0 {
			return fmt.Errorf("docker compose 插件安装失败：请手动安装后重试")
		}
		rep.Steps = append(rep.Steps, StepResult{Name: "compose 插件安装", Status: "ok"})
	}
	if c.Run("docker info >/dev/null 2>&1").Code != 0 {
		_, _ = c.RunCheck("systemctl start docker 2>/dev/null || service docker start 2>/dev/null")
		if c.Run("docker info >/dev/null 2>&1").Code != 0 {
			return fmt.Errorf("Docker 服务启动失败：请在服务器上手动 `systemctl start docker` 后重试")
		}
	}
	return nil
}

// hostOnly 去掉 host 中的 SSH 端口部分（"1.2.3.4:2222" → "1.2.3.4"）。
func hostOnly(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

// RemoveOptions 卸载选项。
type RemoveOptions struct {
	Host   string // 服务器 IP（或 host:port）
	User   string // SSH 用户
	SSHKey string // SSH 私钥路径
	Target string // 卸载目标：node（默认）/ admin / jlog
	Purge  bool   // 同时删除数据目录（MySQL/ClickHouse 数据等，不可恢复）
}

// removeTargets 各卸载目标的目录与容器过滤词。
var removeTargets = map[string]struct{ dir, filter string }{
	"node":  {RemoteDir, "jxwaf"},
	"admin": {AdminRemoteDir, "jxwaf_admin_server"},
	"jlog":  {JlogRemoteDir, "jxlog"},
}

// ValidRemoveTarget 校验卸载目标取值。
func ValidRemoveTarget(t string) bool { _, ok := removeTargets[t]; return ok }

// TargetDir 返回卸载目标的部署目录（未知目标返回空）。
func TargetDir(t string) string {
	if tg, ok := removeTargets[t]; ok {
		return tg.dir
	}
	return ""
}

// RemoveReport 卸载执行报告。
type RemoveReport struct {
	Host    string            `json:"host"`
	Target  string            `json:"target"`
	Steps   []StepResult      `json:"steps"`
	SysInfo map[string]string `json:"sys_info,omitempty"`
	Applied bool              `json:"applied"`
}

// Remove 执行卸载（对齐官方教程"卸载系统"章节）：docker compose down 停止并移除容器；
// Purge 时额外删除数据目录。数据目录默认保留（重新部署可复用）。
// 三类部署分目录隔离（/opt/jxwaf_node、/opt/jxwaf_admin、/opt/jxwaf_jlog），单独卸载互不影响；
// 但 Purge 删除 /opt/jxwaf_data 时会连带其他组件的数据（同机部署时注意）。
func Remove(c *SSHClient, opts RemoveOptions) (*RemoveReport, error) {
	target := opts.Target
	if target == "" {
		target = "node"
	}
	tg, ok := removeTargets[target]
	if !ok {
		return nil, fmt.Errorf("未知卸载目标 %q（node/admin/jlog）", target)
	}
	rep := &RemoveReport{Host: c.Host(), Target: target, Applied: true}
	composePath := tg.dir + "/docker-compose.yml"

	// 探测部署目录是否存在
	if r := c.Run(fmt.Sprintf("test -f %s", composePath)); r.Code != 0 {
		return rep, fmt.Errorf("服务器上未找到部署配置 %s（可能未部署或非本工具部署），无需卸载", composePath)
	}

	// 1. 停止并移除容器（官方：docker compose down）
	if _, err := c.RunCheck(fmt.Sprintf("cd %s && docker compose down 2>&1", tg.dir)); err != nil {
		return rep, fmt.Errorf("容器停止失败: %w", err)
	}
	rep.Steps = append(rep.Steps, StepResult{Name: "停止并移除容器", Status: "ok"})

	// 2. 删除 compose 文件
	if _, err := c.RunCheck(fmt.Sprintf("rm -f %s && rmdir %s 2>/dev/null || true", composePath, tg.dir)); err != nil {
		return rep, fmt.Errorf("删除配置文件失败: %w", err)
	}
	rep.Steps = append(rep.Steps, StepResult{Name: "删除配置", Status: "ok", Detail: composePath})

	// 3. 可选：删除数据目录（不可恢复）
	if opts.Purge {
		if _, err := c.RunCheck("rm -rf /opt/jxwaf_data"); err != nil {
			return rep, fmt.Errorf("删除数据目录失败: %w", err)
		}
		rep.Steps = append(rep.Steps, StepResult{Name: "删除数据", Status: "ok", Detail: "/opt/jxwaf_data（不可恢复）"})
	} else {
		rep.Steps = append(rep.Steps, StepResult{Name: "保留数据目录", Status: "ok",
			Detail: "/opt/jxwaf_data（含各组件数据，重新部署可复用；彻底清除用 --purge-data）"})
	}

	// 4. 验证：该目标相关容器已移除
	left := c.Run(fmt.Sprintf("docker ps -a --filter name=%s --format '{{.Names}}' 2>/dev/null", tg.filter))
	if strings.TrimSpace(left.Stdout) != "" {
		return rep, fmt.Errorf("仍有残留容器: %s", strings.TrimSpace(left.Stdout))
	}
	rep.Steps = append(rep.Steps, StepResult{Name: "卸载验证", Status: "ok", Detail: "相关容器已全部移除"})
	return rep, nil
}
