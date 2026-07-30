package controller

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/session"
)

func addAPIAuthWhoAmIRoute(engine *gin.Engine, api *APIController) {
	engine.GET("/panel/api/whoami", api.checkAPIAuth, func(c *gin.Context) {
		user := session.GetLoginUser(c)
		principal := session.GetAPIAuthPrincipal(c)
		if user == nil || principal == nil {
			c.Status(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"id":       user.Id,
			"username": user.Username,
			"roleId":   user.RoleId,
			"kind":     principal.Kind,
			"scopes":   principal.Scopes,
		})
	})
}

func TestCheckAPIAuthDelegatedTokenUsesDynamicSubject(t *testing.T) {
	engine, api := newAPIAuthTestEngine(t)
	addAPIAuthWhoAmIRoute(engine, api)

	db := database.GetDB()
	var role model.AdminRole
	if err := db.Where("owner_role = ?", false).Order("id ASC").First(&role).Error; err != nil {
		t.Fatalf("load non-owner role: %v", err)
	}
	subject := &model.User{
		Username: "api-auth-delegated-subject",
		Password: "test-password-hash",
		Status:   model.AdminStatusActive,
		RoleId:   role.Id,
	}
	if err := db.Create(subject).Error; err != nil {
		t.Fatalf("create subject: %v", err)
	}
	tokenService := &panel.ApiTokenService{}
	view, err := tokenService.CreateWithOptions(panel.ApiTokenCreateOptions{
		Name:           "controller delegated token",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: subject.Id,
		Scopes: []string{
			panel.ApiTokenScopeClientsRead,
			panel.ApiTokenScopeClientsCreate,
		},
	})
	if err != nil {
		t.Fatalf("create delegated token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/panel/api/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+view.Token)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Id       int      `json:"id"`
		Username string   `json:"username"`
		RoleId   int      `json:"roleId"`
		Kind     string   `json:"kind"`
		Scopes   []string `json:"scopes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Id != subject.Id || body.Username != subject.Username || body.RoleId != role.Id {
		t.Fatalf("subject = %#v, want id=%d username=%q role=%d", body, subject.Id, subject.Username, role.Id)
	}
	if body.Kind != model.ApiTokenKindDelegated {
		t.Fatalf("principal kind = %q, want delegated", body.Kind)
	}

	if err := db.Model(&model.User{}).
		Where("id = ?", subject.Id).
		Update("status", model.AdminStatusDisabled).Error; err != nil {
		t.Fatalf("disable subject: %v", err)
	}
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req.Clone(req.Context()))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled subject status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestCheckAPIAuthInvalidBearerDoesNotFallBackToBrowserSession(t *testing.T) {
	engine, _ := newAPIAuthTestEngine(t)
	ts := httptest.NewServer(engine)
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}
	loginResponse, err := client.Get(ts.URL + "/test-login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", loginResponse.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/panel/api/ping", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer definitely-invalid")
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.StatusCode)
	}
}

func TestParseBearerCredentialIsStrictAndCaseInsensitive(t *testing.T) {
	tests := []struct {
		header string
		want   string
		ok     bool
	}{
		{header: "Bearer abc", want: "abc", ok: true},
		{header: "bearer abc", want: "abc", ok: true},
		{header: "  Bearer   abc  ", want: "abc", ok: true},
		{header: "Bearer", ok: false},
		{header: "Basic abc", ok: false},
		{header: "Bearer abc extra", ok: false},
	}
	for _, test := range tests {
		got, ok := parseBearerCredential(test.header)
		if got != test.want || ok != test.ok {
			t.Fatalf("parseBearerCredential(%q) = %q,%v; want %q,%v", test.header, got, ok, test.want, test.ok)
		}
	}
}
