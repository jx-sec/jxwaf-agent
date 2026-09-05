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
			name: "多条目包装（component_data 全字段，对齐 hub-export 导出结构）",
			data: `{"component_data":{"a":{"name":"a","detail":"d","code":"c","conf":"{}","status":"true","rule_order_time":"1720000000"},"b":{"name":"b","detail":"d","code":"c","conf":"{}","status":"false","rule_order_time":"1720000001"}}}`,
		},
		{
			name:    "component_data 缺 status/rule_order_time（控制台拼 SQL 会报 near ',)'）",
			data:    `{"component_data":{"cc_seq_dynamic_content":{"name":"cc_seq_dynamic_content","detail":"d","code":"c","conf":"{}"}}}`,
			wantErr: true,
			errText: "缺少控制台入库必需字段",
		},
		{
			name:    "component_data 缺 rule_order_time",
			data:    `{"component_data":{"a":{"name":"a","detail":"d","code":"c","conf":"{}","status":"true"}}}`,
			wantErr: true,
			errText: "缺少控制台入库必需字段",
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
