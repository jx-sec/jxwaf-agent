package deploy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// VersionsFileName 镜像版本配置文件名（项目目录，与 config.json 同级；不含凭据，可提交仓库）。
const VersionsFileName = "versions.json"

// StackImages 某一版本的组件镜像集合。
type StackImages struct {
	Node  string `json:"node"`           // 流量节点镜像
	Admin string `json:"admin"`          // 管理控制台镜像
	NFT   string `json:"nft"`            // 网络封禁节点镜像
	Jlog  string `json:"jlog,omitempty"` // jxlog 日志镜像（standard 用 log_send_to_mysql，无此项）
}

// Versions 部署使用的镜像版本映射（versions.json 内容）。
// 镜像版本不再硬编码在代码里，而是外置到该配置文件：本地从官方 GitHub 仓库
// （jx-sec/jxwaf）各版本 compose 获取最新镜像 tag 后更新此文件，部署时读取。
type Versions struct {
	MySQL          string      `json:"mysql"`             // MySQL 8.0
	SSLCertService string      `json:"ssl_cert_service"`  // 泛域名证书服务（prof/cloud 控制台）
	Clickhouse     string      `json:"clickhouse"`        // jxlog 的 ClickHouse
	LogSendToMySQL string      `json:"log_send_to_mysql"` // standard 日志采集
	Standard       StackImages `json:"standard"`
	Professional   StackImages `json:"professional"`
	Cloud          StackImages `json:"cloud"`
}

// DefaultVersions 返回内置默认镜像版本（versions.json 缺失时的种子值）。
// 该值仅为初始兜底，部署以 versions.json 为准；官方发布新版后由 AI 从 GitHub 更新 versions.json。
func DefaultVersions() Versions {
	return Versions{
		MySQL:          "ccr.ccs.tencentyun.com/jxwaf/mysql:8.0",
		SSLCertService: "ccr.ccs.tencentyun.com/jxwaf/ssl_cert_service:6.2.2",
		Clickhouse:     "ccr.ccs.tencentyun.com/jxwaf/clickhouse-server:22.8.5-alpine",
		LogSendToMySQL: "ccr.ccs.tencentyun.com/jxwaf/log_send_to_mysql:v2",
		Standard: StackImages{
			Node:  "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_standard:6.1.7",
			Admin: "ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_standard:6.1.14",
			NFT:   "ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:7.0",
		},
		Professional: StackImages{
			Node:  "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_professional:6.1.0",
			Admin: "ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_professional:6.1.0",
			NFT:   "ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:6.0",
			Jlog:  "ccr.ccs.tencentyun.com/jxwaf/jxlog_professional:1.0",
		},
		Cloud: StackImages{
			Node:  "ccr.ccs.tencentyun.com/jxwaf/jxwaf_node_cloud:6.2.1",
			Admin: "ccr.ccs.tencentyun.com/jxwaf/jxwaf_admin_server_cloud:6.2.1",
			NFT:   "ccr.ccs.tencentyun.com/jxwaf/jxwaf_nft_node:6.0",
			Jlog:  "ccr.ccs.tencentyun.com/jxwaf/jxlog_cloud:1.0",
		},
	}
}

// Stack 返回指定版本的组件镜像集合（未知版本返回空集合）。
func (v Versions) Stack(version string) StackImages {
	switch version {
	case VersionStandard:
		return v.Standard
	case VersionProfessional:
		return v.Professional
	case VersionCloud:
		return v.Cloud
	}
	return StackImages{}
}

// IsZero 判断版本配置是否为零值（未设置，调用方需回退到 DefaultVersions）。
func (v Versions) IsZero() bool {
	return v.MySQL == "" && v.SSLCertService == "" && v.Clickhouse == "" &&
		v.LogSendToMySQL == "" && v.Standard == (StackImages{}) &&
		v.Professional == (StackImages{}) && v.Cloud == (StackImages{})
}

// VersionsPath 返回 versions.json 的路径（查找逻辑与 config.json 一致）。
func VersionsPath() (string, error) {
	if p := os.Getenv("JXWAF_CONFIG_PATH"); p != "" {
		return filepath.Join(filepath.Dir(p), VersionsFileName), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("无法定位当前目录: %w", err)
	}
	local := filepath.Join(wd, VersionsFileName)
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	if exe, err := os.Executable(); err == nil {
		exeV := filepath.Join(filepath.Dir(exe), VersionsFileName)
		if exeV != local {
			if _, err := os.Stat(exeV); err == nil {
				return exeV, nil
			}
		}
	}
	return local, nil
}

// LoadVersions 读取 versions.json；文件缺失或为空时写入内置默认并返回。
func LoadVersions() (Versions, error) {
	path, err := VersionsPath()
	if err != nil {
		return Versions{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return Versions{}, err
	}
	if len(data) == 0 {
		v := DefaultVersions()
		_ = SaveVersions(v)
		return v, nil
	}
	var v Versions
	if err := json.Unmarshal(data, &v); err != nil {
		return Versions{}, fmt.Errorf("versions.json 解析失败: %w", err)
	}
	return v, nil
}

// SaveVersions 原子写入 versions.json（权限 0644，不含凭据）。
func SaveVersions(v Versions) error {
	path, err := VersionsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".versions-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("设置临时文件权限失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("原子替换 versions.json 失败: %w", err)
	}
	return nil
}
