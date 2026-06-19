package function

import "encoding/json"

// jsonMarshal 序列化为 JSON 字节
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// jsonUnmarshal 从 JSON 字节反序列化
func jsonUnmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
