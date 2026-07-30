package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
)

func addCustomPanelAuthTestRoute(engine *gin.Engine, api *APIController) {
	engine.POST("/api", api.checkCustomPanelAuth, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
}

func createCustomPanelTestSubject(t *testing.T) *model.User {
	t.Helper()
	db := database.GetDB()
	var role model.AdminRole
	if err := db.Where("owner_role = ?", false).Order("id ASC").First(&role).Error; err != nil {
		t.Fatalf("load non-owner role: %v", err)
	}
	subject := &model.User{
		Username: "custom-panel-subject",
		Password: "test-password-hash",
		Status:   model.AdminStatusActive,
		RoleId:   role.Id,
	}
	if err := db.Create(subject).Error; err != nil {
		t.Fatalf("create subject: %v", err)
	}
	return subject
}

func createCustomPanelTestToken(t *testing.T, options panel.ApiTokenCreateOptions) string {
	t.Helper()
	view, err := (&panel.ApiTokenService{}).CreateWithOptions(options)
	if err != nil {
		t.Fatalf("create API token: %v", err)
	}
	return view.Token
}

func customPanelAuthRequest(engine *gin.Engine, apiKey string, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func requireInvalidAPIKeyResponse(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != "error" || body.Message != "Invalid API Key" {
		t.Fatalf("response = %#v", body)
	}
}

func TestCustomPanelAuthAcceptsOnlyDelegatedScopedXAPIKey(t *testing.T) {
	engine, api := newAPIAuthTestEngine(t)
	addCustomPanelAuthTestRoute(engine, api)
	subject := createCustomPanelTestSubject(t)

	valid := createCustomPanelTestToken(t, panel.ApiTokenCreateOptions{
		Name:           "custom-panel-valid",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: subject.Id,
		Scopes:         []string{panel.ApiTokenScopeCustomPanelManage},
	})
	wrongScope := createCustomPanelTestToken(t, panel.ApiTokenCreateOptions{
		Name:           "custom-panel-wrong-scope",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: subject.Id,
		Scopes:         []string{panel.ApiTokenScopeClientsRead},
	})
	serviceToken := createCustomPanelTestToken(t, panel.ApiTokenCreateOptions{
		Name: "custom-panel-service",
		Kind: model.ApiTokenKindService,
	})

	response := customPanelAuthRequest(engine, valid, "")
	if response.Code != http.StatusOK || response.Body.String() != `{"ok":true}` {
		t.Fatalf("valid response = %d %s", response.Code, response.Body.String())
	}

	requireInvalidAPIKeyResponse(t, customPanelAuthRequest(engine, "", ""))
	requireInvalidAPIKeyResponse(t, customPanelAuthRequest(engine, "invalid", ""))
	requireInvalidAPIKeyResponse(t, customPanelAuthRequest(engine, wrongScope, ""))
	requireInvalidAPIKeyResponse(t, customPanelAuthRequest(engine, serviceToken, ""))
	requireInvalidAPIKeyResponse(t, customPanelAuthRequest(engine, valid, "Bearer another-token"))
}
