package controller

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	xuilogger "github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/session"
)

func newAdminSecurityTestEngine(t *testing.T) *gin.Engine {
	t.Helper()

	xuilogger.InitLogger(logging.ERROR)
	gin.SetMode(gin.TestMode)

	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	if err := database.InitDB(filepath.Join(dbDir, "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	db := database.GetDB()

	ownerRole := model.AdminRole{
		Name:            "security-test-owner",
		Slug:            "security-test-owner",
		OwnerRole:       true,
		PermissionsJSON: `{}`,
		LimitsJSON:      `{}`,
		FeaturesJSON:    `{}`,
		AccessJSON:      `{}`,
	}
	allowRole := model.AdminRole{
		Name:            "security-test-allow-admins-view",
		Slug:            "security-test-allow-admins-view",
		PermissionsJSON: `{"admins":{"view":true}}`,
		LimitsJSON:      `{}`,
		FeaturesJSON:    `{}`,
		AccessJSON:      `{}`,
	}
	denyRole := model.AdminRole{
		Name:            "security-test-deny-admins-view",
		Slug:            "security-test-deny-admins-view",
		PermissionsJSON: `{"admins":{"view":false}}`,
		LimitsJSON:      `{}`,
		FeaturesJSON:    `{}`,
		AccessJSON:      `{}`,
	}

	for _, role := range []*model.AdminRole{&ownerRole, &allowRole, &denyRole} {
		if err := db.Create(role).Error; err != nil {
			t.Fatalf("seed role %s: %v", role.Slug, err)
		}
	}

	users := []model.User{
		{
			Username: "security-owner",
			Password: "hash",
			Status:   model.AdminStatusActive,
			RoleId:   ownerRole.Id,
		},
		{
			Username: "security-allowed",
			Password: "hash",
			Status:   model.AdminStatusActive,
			RoleId:   allowRole.Id,
		},
		{
			Username: "security-denied",
			Password: "hash",
			Status:   model.AdminStatusActive,
			RoleId:   denyRole.Id,
		},
		{
			Username: "security-disabled",
			Password: "hash",
			Status:   model.AdminStatusDisabled,
			RoleId:   allowRole.Id,
		},
		{
			Username: "security-missing-role",
			Password: "hash",
			Status:   model.AdminStatusActive,
			RoleId:   999999,
		},
	}

	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("seed user %s: %v", users[i].Username, err)
		}
	}

	engine := gin.New()
	store := cookie.NewStore([]byte("admin-security-test-secret"))
	engine.Use(sessions.Sessions("PRIMEVPN", store))

	engine.GET("/test-login/:username", func(c *gin.Context) {
		var user model.User
		if err := database.GetDB().
			Where("username = ?", c.Param("username")).
			First(&user).
			Error; err != nil {
			c.Status(http.StatusNotFound)
			return
		}

		if err := session.SetLoginUser(c, &user); err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}

		c.Status(http.StatusNoContent)
	})

	engine.GET(
		"/protected/admins-view",
		requireAdminPermission("admins", "view"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	engine.GET(
		"/protected/api-authed/admins-view",
		func(c *gin.Context) {
			c.Set("api_authed", true)
		},
		requireAdminPermission("admins", "view"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	engine.GET(
		"/protected/owner-only",
		requireOwnerAdminMiddleware(),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	engine.GET(
		"/protected/api-authed/owner-only",
		func(c *gin.Context) {
			c.Set("api_authed", true)
		},
		requireOwnerAdminMiddleware(),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	return engine
}

func TestRequireAdminPermissionMiddleware(t *testing.T) {
	engine := newAdminSecurityTestEngine(t)
	ts := httptest.NewServer(engine)
	defer ts.Close()

	requestAs := func(username string, path string) int {
		t.Helper()

		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatalf("cookiejar: %v", err)
		}

		client := &http.Client{Jar: jar}

		if username != "" {
			loginResp, err := client.Get(ts.URL + "/test-login/" + username)
			if err != nil {
				t.Fatalf("login %s: %v", username, err)
			}
			loginResp.Body.Close()

			if loginResp.StatusCode != http.StatusNoContent {
				t.Fatalf("login %s status = %d, want %d", username, loginResp.StatusCode, http.StatusNoContent)
			}
		}

		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s as %s: %v", path, username, err)
		}
		resp.Body.Close()

		return resp.StatusCode
	}

	cases := []struct {
		name     string
		username string
		path     string
		want     int
	}{
		{
			name: "missing login is unauthorized",
			path: "/protected/admins-view",
			want: http.StatusUnauthorized,
		},
		{
			name:     "owner bypasses permission checks",
			username: "security-owner",
			path:     "/protected/admins-view",
			want:     http.StatusOK,
		},
		{
			name:     "admin with permission is allowed",
			username: "security-allowed",
			path:     "/protected/admins-view",
			want:     http.StatusOK,
		},
		{
			name:     "admin without permission is forbidden",
			username: "security-denied",
			path:     "/protected/admins-view",
			want:     http.StatusForbidden,
		},
		{
			name:     "disabled admin is forbidden",
			username: "security-disabled",
			path:     "/protected/admins-view",
			want:     http.StatusForbidden,
		},
		{
			name:     "admin with missing role is forbidden",
			username: "security-missing-role",
			path:     "/protected/admins-view",
			want:     http.StatusForbidden,
		},
		{
			name:     "api token authenticated admin route is forbidden",
			username: "security-owner",
			path:     "/protected/api-authed/admins-view",
			want:     http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestAs(tc.username, tc.path); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRequireOwnerAdminMiddleware(t *testing.T) {
	engine := newAdminSecurityTestEngine(t)
	ts := httptest.NewServer(engine)
	defer ts.Close()

	requestAs := func(username string, path string) int {
		t.Helper()

		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatalf("cookiejar: %v", err)
		}

		client := &http.Client{Jar: jar}

		if username != "" {
			loginResp, err := client.Get(ts.URL + "/test-login/" + username)
			if err != nil {
				t.Fatalf("login %s: %v", username, err)
			}
			loginResp.Body.Close()

			if loginResp.StatusCode != http.StatusNoContent {
				t.Fatalf("login %s status = %d, want %d", username, loginResp.StatusCode, http.StatusNoContent)
			}
		}

		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("owner-only request as %s: %v", username, err)
		}
		resp.Body.Close()

		return resp.StatusCode
	}

	cases := []struct {
		name     string
		username string
		path     string
		want     int
	}{
		{
			name: "missing login is unauthorized",
			path: "/protected/owner-only",
			want: http.StatusUnauthorized,
		},
		{
			name:     "owner is allowed",
			username: "security-owner",
			path:     "/protected/owner-only",
			want:     http.StatusOK,
		},
		{
			name:     "non-owner is forbidden",
			username: "security-allowed",
			path:     "/protected/owner-only",
			want:     http.StatusForbidden,
		},
		{
			name:     "disabled owner-like admin is forbidden before owner check",
			username: "security-disabled",
			path:     "/protected/owner-only",
			want:     http.StatusForbidden,
		},
		{
			name:     "api token authenticated owner route is forbidden",
			username: "security-owner",
			path:     "/protected/api-authed/owner-only",
			want:     http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestAs(tc.username, tc.path); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}
