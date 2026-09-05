package cli

import (
	"strings"
	"testing"
)

func TestValidateHubPolicyContent(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		wantErr bool
		errText string
	}{
		{
			name: "合法包装结构",
			data: `{"web_rule_protection_data":{"block_crawler_ua":{"rule_name":"block_crawler_ua","rule_action":"block"}}}`,
		},
		{
			name: "多条目包装",
			data: `{"component_data":{"a":{"name":"a"},"b":{"name":"b"}}}`,
		},
		{
			name:    "扁平单规则对象（控制台加载会报 _data is nil）",
			data:    `{"rule_name":"block_crawler_ua","rule_action":"block"}`,
			wantErr: true,
			errText: "缺少控制台 hub-load 包装键",
		},
		{
			name:    "数组格式（load 导入格式，非 hub 策略格式）",
			data:    `[{"rule_name":"a"}]`,
			wantErr: true,
			errText: "需为 JSON 对象",
		},
		{
			name:    "包装键值为空对象",
			data:    `{"web_rule_protection_data":{}}`,
			wantErr: true,
			errText: "非空",
		},
		{
			name:    "包装键值为数组",
			data:    `{"web_rule_protection_data":[{"rule_name":"a"}]}`,
			wantErr: true,
			errText: "非空",
		},
		{
			name:    "包装键下单条目非对象",
			data:    `{"web_rule_protection_data":{"a":"str"}}`,
			wantErr: true,
			errText: "需为配置对象",
		},
		{
			name:    "非法 JSON",
			data:    `{"a":`,
			wantErr: true,
			errText: "需为 JSON 对象",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateHubPolicyContent([]byte(c.data))
			if c.wantErr {
				if err == nil {
					t.Fatalf("应报错但通过: %s", c.data)
				}
				if !strings.Contains(err.Error(), c.errText) {
					t.Fatalf("错误文本应含 %q，实际: %v", c.errText, err)
				}
			} else if err != nil {
				t.Fatalf("应通过但报错: %v", err)
			}
		})
	}
}
