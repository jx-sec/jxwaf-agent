package deploy

import "testing"

func TestIsRiskyCommand(t *testing.T) {
	cases := []struct {
		cmd   string
		risky bool
	}{
		// 只读诊断命令：不判风险
		{"docker ps -a", false},
		{"docker logs jxwaf_base --tail 50", false},
		{"ss -tlnp", false},
		{"df -h", false},
		{"free -m", false},
		{"systemctl status docker", false},
		{"uptime", false},
		{"cat /etc/os-release", false},
		{"uname -a", false},
		// 风险命令：判风险
		{"kill 1234", true},
		{"pkill nginx", true},
		{"systemctl stop nginx", true},
		{"systemctl restart docker", true},
		{"service nginx stop", true},
		{"rm -rf /opt/jxwaf_data", true},
		{"rmdir /opt/old", true},
		{"docker compose down", true},
		{"docker stop jxwaf_base", true},
		{"docker rm -f abc", true},
		{"reboot", true},
		{"shutdown -h now", true},
		{"mkfs.ext4 /dev/sdb", true},
		{"dd if=/dev/zero of=/dev/sdb", true},
		{"iptables -A INPUT -j DROP", true},
		{"iptables -t nat -A POSTROUTING -j MASQUERADE", true},
		{"nft add rule inet filter input drop", true},
		{"systemctl reload nginx", true},
		{"echo x > /etc/hosts", true},
		{"cat /dev/null > /opt/jxwaf_data/x.log", true},
	}
	for _, c := range cases {
		risky, _ := IsRiskyCommand(c.cmd)
		if risky != c.risky {
			t.Errorf("IsRiskyCommand(%q) = %v, want %v", c.cmd, risky, c.risky)
		}
	}
}
