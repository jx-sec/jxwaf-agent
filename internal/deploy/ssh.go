// Package deploy 实现远程 WAF 节点的自动化部署：SSH 连接 → 环境探测 →
// 依赖检查（Docker）→ 端口冲突检测 → 生成并上传 docker-compose → 拉起容器 → 验证。
//
// 凭据安全：SSH 密码仅经环境变量 JXWAF_SSH_PASSWORD 传入（不落盘、不进命令行参数）；
// 节点 waf_auth 必须写入远端 compose 文件（节点运行必需），文件权限 0600，本地不留存。
package deploy

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshPasswordEnv SSH 密码的环境变量名。
const sshPasswordEnv = "JXWAF_SSH_PASSWORD"

// SSHClient 封装到目标服务器的 SSH 会话。
type SSHClient struct {
	client *ssh.Client
	host   string
}

// DialSSH 建立到目标服务器的 SSH 连接（认证：私钥与密码二选一，都提供则都可用）。
// host 形如 "1.2.3.4"（默认 22 端口）或 "1.2.3.4:2222"。
func DialSSH(host, user, keyPath string) (*SSHClient, error) {
	var authMethods []ssh.AuthMethod
	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("读取 SSH 私钥失败 %s: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("解析 SSH 私钥失败（%s）: %w", keyPath, err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if pwd := os.Getenv(sshPasswordEnv); pwd != "" {
		authMethods = append(authMethods, ssh.Password(pwd))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("缺少 SSH 认证凭据：请用 --ssh-key 指定私钥路径，或设置环境变量 %s 提供密码", sshPasswordEnv)
	}
	if user == "" {
		user = "root"
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 部署目标是用户自己的服务器，不校验 known_hosts
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(host, "22")
	if _, _, err := net.SplitHostPort(host); err == nil {
		addr = host
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH 连接失败 %s（检查地址/账号/密码或密钥）: %w", addr, err)
	}
	return &SSHClient{client: client, host: host}, nil
}

// Close 关闭 SSH 会话。
func (c *SSHClient) Close() error { return c.client.Close() }

// Host 返回目标主机地址。
func (c *SSHClient) Host() string { return c.host }

// RunResult 一条远程命令的执行结果。
type RunResult struct {
	Cmd    string
	Stdout string
	Stderr string
	Code   int // 远程退出码；-1 表示会话层错误
}

// Run 在远程执行单条命令（每个 Run 独立会话，无状态残留）。
func (c *SSHClient) Run(cmd string) RunResult {
	session, err := c.client.NewSession()
	if err != nil {
		return RunResult{Cmd: cmd, Code: -1, Stderr: err.Error()}
	}
	defer session.Close()
	var out, errBuf strings.Builder
	session.Stdout = &out
	session.Stderr = &errBuf
	if err := session.Run(cmd); err != nil {
		code := -1
		if ee, ok := err.(*ssh.ExitError); ok {
			code = ee.ExitStatus()
		}
		return RunResult{Cmd: cmd, Stdout: out.String(), Stderr: errBuf.String(), Code: code}
	}
	return RunResult{Cmd: cmd, Stdout: out.String(), Stderr: errBuf.String(), Code: 0}
}

// RunCheck 执行命令，非零退出码时返回错误（stderr 优先）。
func (c *SSHClient) RunCheck(cmd string) (string, error) {
	r := c.Run(cmd)
	if r.Code != 0 {
		msg := strings.TrimSpace(r.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(r.Stdout)
		}
		return r.Stdout, fmt.Errorf("远程命令失败（exit=%d）: %s\n%s", r.Code, cmd, msg)
	}
	return r.Stdout, nil
}

// WriteFile 将内容写入远程路径（base64 管道传输避免转义问题），并设置权限位（如 0600）。
func (c *SSHClient) WriteFile(path string, content []byte, mode os.FileMode) error {
	b64 := base64.StdEncoding.EncodeToString(content)
	// heredoc 内 base64 纯字母数字+/= 无需转义；目录不存在时先创建
	r := c.Run(fmt.Sprintf("mkdir -p '%s' && base64 -d > '%s' <<'__JXWAF_B64__'\n%s\n__JXWAF_B64__\nchmod %o '%s'",
		dirOf(path), path, b64, mode, path))
	if r.Code != 0 {
		return fmt.Errorf("写入远程文件 %s 失败（exit=%d）: %s%s", path, r.Code, r.Stderr, r.Stdout)
	}
	// 校验内容完整性
	sum := c.Run(fmt.Sprintf("base64 -w0 '%s'", path))
	if strings.TrimSpace(sum.Stdout) != b64 {
		return fmt.Errorf("远程文件 %s 写入后校验不一致", path)
	}
	return nil
}

// dirOf 返回路径的目录部分（远程为 Linux，固定用 / 分隔）。
func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "/"
}
