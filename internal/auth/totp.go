package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ValidateTOTP 验证 6 位 TOTP 验证码（兼容 Google Authenticator）
// secret 为 Base32 编码的密钥，code 为用户输入的 6 位数字
// 允许 ±30s 时间偏差（前后各一个时间窗口）
func ValidateTOTP(code string, secret string) bool {
	code = strings.TrimSpace(code)
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if len(code) != 6 || secret == "" {
		return false
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	timeStep := now / 30
	// 验证当前窗口和前后窗口（允许 ±30s 时间偏差）
	for offset := int64(-1); offset <= 1; offset++ {
		if validateTOTPAt(code, key, timeStep+offset) {
			return true
		}
	}
	return false
}

// validateTOTPAt 验证指定时间步的 TOTP
func validateTOTPAt(code string, key []byte, timeStep int64) bool {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(timeStep))
	h := hmac.New(sha1.New, key)
	h.Write(buf[:])
	hash := h.Sum(nil)
	// 动态截取
	offset := hash[len(hash)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	otp := truncated % 1000000
	expected := fmt.Sprintf("%06d", otp)
	return subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1
}
