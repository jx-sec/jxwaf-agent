// Package ssh 封装远程服务器 SSH 操作，用于自动部署
package ssh

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client SSH 客户端
type Client struct {
	host     string
	port     int
	user     string
	password string
	client   *ssh.Client
}

// ExecResult 命令执行结果
type ExecResult struct {
	Command  string `json:"command"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Success  bool   `json:"success"`
	Duration string `json:"duration"`
}

// NewClient 创建 SSH 客户端（未连接）
func NewClient(host string, port int, user, password string) *Client {
	if port == 0 {
		port = 22
	}
	return &Client{
		host:     host,
		port:     port,
		user:     user,
		password: password,
	}
}

// Connect 建立 SSH 连接
func (c *Client) Connect() error {
	config := &ssh.ClientConfig{
		User: c.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.password),
		},
		// 自动部署场景下用户已提供密码，接受首次连接的主机
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("SSH 连接失败 %s: %w", addr, err)
	}
	c.client = client
	return nil
}

// Close 关闭连接
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Exec 执行单条命令，返回完整结果
// timeout 为 0 时默认 120 秒
func (c *Client) Exec(command string, timeout time.Duration) (*ExecResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("SSH 未连接")
	}
	if timeout == 0 {
		timeout = 120 * time.Second
	}

	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建 SSH session 失败: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	var runErr error
	select {
	case err := <-done:
		runErr = err
	case <-time.After(timeout):
		return nil, fmt.Errorf("命令执行超时（%s）: %s", timeout, truncate(command, 100))
	}

	duration := time.Since(start)
	result := &ExecResult{
		Command:  command,
		Stdout:   strings.TrimRight(stdout.String(), "\n"),
		Stderr:   strings.TrimRight(stderr.String(), "\n"),
		ExitCode: 0,
		Success:  runErr == nil,
		Duration: duration.Round(time.Millisecond).String(),
	}

	// 提取退出码
	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			result.ExitCode = exitErr.ExitStatus()
		} else {
			return result, runErr
		}
	}

	return result, nil
}

// ExecBatch 依次执行多条命令，遇到失败停止
// 返回所有已执行结果和是否全部成功
func (c *Client) ExecBatch(commands []string, timeout time.Duration) ([]*ExecResult, bool) {
	results := make([]*ExecResult, 0, len(commands))
	allSuccess := true
	for _, cmd := range commands {
		result, err := c.Exec(cmd, timeout)
		if err != nil {
			results = append(results, &ExecResult{
				Command:  cmd,
				Stderr:   err.Error(),
				ExitCode: -1,
				Success:  false,
			})
			allSuccess = false
			break
		}
		results = append(results, result)
		if !result.Success {
			allSuccess = false
			break
		}
	}
	return results, allSuccess
}

// TestConnection 测试连接是否可用（执行 echo ok）
func (c *Client) TestConnection() error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	result, err := c.Exec("echo ok", 10*time.Second)
	if err != nil {
		return err
	}
	if !result.Success || result.Stdout != "ok" {
		return fmt.Errorf("连接测试失败: %s", result.Stderr)
	}
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
