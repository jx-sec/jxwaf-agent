// Package auth 实现用户注册、登录、令牌认证
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"jxwaf-agent-go/internal/config"
	"jxwaf-agent-go/internal/db"
)

// 令牌有效期 30 天
const tokenExpiry = 30 * 24 * time.Hour

// 哨兵错误
var (
	ErrUserExists         = errors.New("用户名已存在")
	ErrInvalidCredentials = errors.New("用户名或密码错误")
	ErrRegisterDisabled   = errors.New("注册已关闭")
	ErrInvalidOTP         = errors.New("OTP 验证码错误")
	ErrOTPRequired        = errors.New("需要 OTP 验证")
)

// context key 类型
type contextKey string

const (
	userContextKey  contextKey = "user"
	tokenContextKey contextKey = "token"
)

// GenerateToken 生成 32 字节随机 hex 令牌
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateOTPSecret 生成 20 字节随机 TOTP 密钥（Base32 编码，兼容 Google Authenticator）
func GenerateOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(b), nil
}

// Register 注册新用户：检查注册开关 → 可选绑定 OTP（验证码确认）→ bcrypt 哈希 → 创建用户 → 初始化空配置 → 生成令牌
// otpSecret 非空表示用户选择绑定 OTP，需验证 otpCode 正确后才绑定
func Register(database *db.DB, allowRegister bool, username, password, otpSecret, otpCode string) (string, error) {
	if !allowRegister {
		return "", ErrRegisterDisabled
	}
	// 用户选择绑定 OTP 时，验证 OTP 码
	if otpSecret != "" {
		if !ValidateTOTP(otpCode, otpSecret) {
			return "", ErrInvalidOTP
		}
	}
	// 检查用户名是否已存在
	if _, err := database.GetUserByUsername(username); err == nil {
		return "", ErrUserExists
	}
	// bcrypt 哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	// 创建用户（otpSecret 为空表示不绑定）
	userID, err := database.CreateUser(username, string(hash), otpSecret)
	if err != nil {
		return "", err
	}
	// 初始化空配置（用户注册后自行在配置页填写）
	if err := config.SetUserConfig(database, userID, config.DefaultConfig()); err != nil {
		return "", err
	}
	// 生成令牌
	token := GenerateToken()
	if err := database.SaveToken(token, userID, time.Now().Add(tokenExpiry)); err != nil {
		return "", err
	}
	return token, nil
}

// Login 验证密码。若用户绑定了 OTP，返回 ErrOTPRequired（调用方需再用 LoginWithOTP 完成）
func Login(database *db.DB, username, password string) (string, error) {
	user, err := database.GetUserByUsername(username)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}
	// 用户绑定了 OTP，需要二次验证
	if user.OTPSecret != "" {
		return "", ErrOTPRequired
	}
	token := GenerateToken()
	if err := database.SaveToken(token, user.ID, time.Now().Add(tokenExpiry)); err != nil {
		return "", err
	}
	return token, nil
}

// LoginWithOTP 验证密码 + OTP 码（用于已绑定 OTP 的用户登录）
func LoginWithOTP(database *db.DB, username, password, otpCode string) (string, error) {
	user, err := database.GetUserByUsername(username)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}
	if user.OTPSecret == "" {
		return "", ErrInvalidCredentials
	}
	if !ValidateTOTP(otpCode, user.OTPSecret) {
		return "", ErrInvalidOTP
	}
	token := GenerateToken()
	if err := database.SaveToken(token, user.ID, time.Now().Add(tokenExpiry)); err != nil {
		return "", err
	}
	return token, nil
}

// Logout 删除令牌
func Logout(database *db.DB, token string) error {
	return database.DeleteToken(token)
}

// ExtractToken 从 Cookie 或 Authorization header 提取令牌
func ExtractToken(r *http.Request) string {
	// Cookie
	if cookie, err := r.Cookie("jxwaf_auth_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	// Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// Middleware 认证中间件：验证令牌后注入 userID 和 username 到 context
func Middleware(database *db.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ExtractToken(r)
		if token == "" {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}
		info, err := database.GetToken(token)
		if err != nil {
			http.Error(w, "未认证", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, info)
		ctx = context.WithValue(ctx, tokenContextKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext 从请求 context 获取用户信息
func UserFromContext(r *http.Request) (userID int64, username string, ok bool) {
	info, ok := r.Context().Value(userContextKey).(*db.TokenInfo)
	if !ok {
		return 0, "", false
	}
	return info.UserID, info.Username, true
}

// TokenFromContext 从请求 context 获取令牌
func TokenFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(tokenContextKey).(string); ok {
		return v
	}
	return ""
}
