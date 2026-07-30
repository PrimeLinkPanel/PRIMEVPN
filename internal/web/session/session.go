package session

import (
	"encoding/gob"
	"net/http"
	"strings"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	loginUserKey        = "LOGIN_USER"
	loginEpochKey       = "LOGIN_EPOCH"
	apiAuthUserKey      = "api_auth_user"
	apiAuthPrincipalKey = "api_auth_principal"
	sessionCookieName   = "PRIMEVPN"
)

const APIAuthPrincipalKindMTLS = "mtls"

// APIAuthPrincipal describes how an API request was authenticated. It is held
// only in the Gin request context and never written to a browser session.
type APIAuthPrincipal struct {
	TokenId   int
	TokenName string
	Kind      string
	Scopes    []string
}

func init() {
	gob.Register(model.User{})
}

func SetLoginUser(c *gin.Context, user *model.User) error {
	if user == nil {
		return nil
	}
	s := sessions.Default(c)
	s.Set(loginUserKey, user.Id)
	s.Set(loginEpochKey, user.LoginEpoch)
	return s.Save()
}

func SetAPIAuthPrincipal(c *gin.Context, user *model.User, principal *APIAuthPrincipal) {
	if user == nil || principal == nil {
		return
	}
	c.Set(apiAuthUserKey, user)
	copyPrincipal := *principal
	copyPrincipal.Scopes = append([]string(nil), principal.Scopes...)
	c.Set(apiAuthPrincipalKey, &copyPrincipal)
}

// SetAPIAuthUser preserves the original helper for older tests and trusted
// internal callers. Such callers retain the legacy service-token semantics.
func SetAPIAuthUser(c *gin.Context, user *model.User) {
	SetAPIAuthPrincipal(c, user, &APIAuthPrincipal{
		Kind:   model.ApiTokenKindService,
		Scopes: []string{"*"},
	})
}

func GetAPIAuthPrincipal(c *gin.Context) *APIAuthPrincipal {
	if c == nil {
		return nil
	}
	value, ok := c.Get(apiAuthPrincipalKey)
	if !ok {
		return nil
	}
	principal, _ := value.(*APIAuthPrincipal)
	return principal
}

func IsDelegatedAPIAuth(c *gin.Context) bool {
	principal := GetAPIAuthPrincipal(c)
	return principal != nil && principal.Kind == model.ApiTokenKindDelegated
}

func IsServiceAPIAuth(c *gin.Context) bool {
	principal := GetAPIAuthPrincipal(c)
	if principal == nil {
		return false
	}
	return principal.Kind == model.ApiTokenKindService || principal.Kind == APIAuthPrincipalKindMTLS
}

// APIAuthScopeAllowed supports exact scopes plus resource wildcards for future
// service integrations. Delegated-token creation currently accepts exact scopes
// only; service and mTLS principals use the global wildcard.
func APIAuthScopeAllowed(c *gin.Context, required string) bool {
	principal := GetAPIAuthPrincipal(c)
	if principal == nil {
		return false
	}
	required = strings.ToLower(strings.TrimSpace(required))
	if required == "" {
		return false
	}
	for _, raw := range principal.Scopes {
		scope := strings.ToLower(strings.TrimSpace(raw))
		if scope == "*" || scope == required {
			return true
		}
		if strings.HasSuffix(scope, ":*") && strings.HasPrefix(required, strings.TrimSuffix(scope, "*")) {
			return true
		}
	}
	return false
}

func GetLoginUser(c *gin.Context) *model.User {
	if v, ok := c.Get(apiAuthUserKey); ok {
		if u, ok2 := v.(*model.User); ok2 {
			return u
		}
	}
	s := sessions.Default(c)
	obj := s.Get(loginUserKey)
	if obj == nil {
		return nil
	}
	userID, ok := sessionUserID(obj)
	if !ok {
		s.Delete(loginUserKey)
		s.Delete(loginEpochKey)
		if err := s.Save(); err != nil {
			logger.Warning("session: failed to drop stale user payload:", err)
		}
		return nil
	}
	if legacyUserID, ok := legacySessionUserID(obj); ok {
		s.Set(loginUserKey, legacyUserID)
		if err := s.Save(); err != nil {
			logger.Warning("session: failed to migrate legacy user payload:", err)
		}
	}
	user, err := getUserByID(userID)
	if err != nil {
		logger.Warning("session: failed to load user:", err)
		s.Delete(loginUserKey)
		s.Delete(loginEpochKey)
		if saveErr := s.Save(); saveErr != nil {
			logger.Warning("session: failed to drop missing user:", saveErr)
		}
		return nil
	}
	if !sessionEpochMatches(s.Get(loginEpochKey), user.LoginEpoch) {
		s.Delete(loginUserKey)
		s.Delete(loginEpochKey)
		if saveErr := s.Save(); saveErr != nil {
			logger.Warning("session: failed to drop stale epoch:", saveErr)
		}
		return nil
	}
	return user
}

func sessionEpochMatches(cookieVal any, userEpoch int64) bool {
	var got int64
	switch v := cookieVal.(type) {
	case nil:
	case int64:
		got = v
	case int:
		got = int64(v)
	case int32:
		got = int64(v)
	case float64:
		got = int64(v)
	default:
		return false
	}
	return got == userEpoch
}

func IsLogin(c *gin.Context) bool {
	return GetLoginUser(c) != nil
}

func sessionUserID(obj any) (int, bool) {
	switch v := obj.(type) {
	case int:
		return v, v > 0
	case int64:
		return int(v), v > 0
	case int32:
		return int(v), v > 0
	case float64:
		id := int(v)
		return id, v == float64(id) && id > 0
	case model.User:
		return v.Id, v.Id > 0
	case *model.User:
		if v == nil {
			return 0, false
		}
		return v.Id, v.Id > 0
	default:
		return 0, false
	}
}

func legacySessionUserID(obj any) (int, bool) {
	switch v := obj.(type) {
	case model.User:
		return v.Id, v.Id > 0
	case *model.User:
		if v == nil {
			return 0, false
		}
		return v.Id, v.Id > 0
	default:
		return 0, false
	}
}

func getUserByID(id int) (*model.User, error) {
	db := database.GetDB()
	if db == nil {
		return nil, http.ErrServerClosed
	}
	user := &model.User{}
	if err := db.Model(model.User{}).Where("id = ?", id).First(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func ClearSession(c *gin.Context) error {
	s := sessions.Default(c)
	s.Clear()
	cookiePath := c.GetString("base_path")
	if cookiePath == "" {
		cookiePath = "/"
	}
	secure := c.Request.TLS != nil
	s.Options(sessions.Options{
		Path:     cookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	if err := s.Save(); err != nil {
		return err
	}
	if cookiePath != "/" {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	return nil
}
