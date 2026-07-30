package controller

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/crypto"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/session"
)

type apiTokenManagementEnvelope struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

func mountAPITokenManagementTestRoutes(engine *gin.Engine, api *APIController) {
	group := engine.Group("/panel/api")
	group.Use(api.checkAPIAuth)
	group.Use(enforceDelegatedAPIScope())
	NewSettingController(group)

	engine.GET("/test-login-user/:id", func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		var user model.User
		if err := database.GetDB().Where("id = ?", id).First(&user).Error; err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		if err := session.SetLoginUser(c, &user); err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusNoContent)
	})
}

func apiTokenManagementClient(t *testing.T, serverURL string, loginPath string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}
	response, err := client.Get(serverURL + loginPath)
	if err != nil {
		t.Fatalf("login %s: %v", loginPath, err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		t.Fatalf("login status = %d", response.StatusCode)
	}
	return client
}

func apiTokenManagementRequest(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	payload any,
	bearer string,
) (int, apiTokenManagementEnvelope) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, url, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var envelope apiTokenManagementEnvelope
	if len(data) > 0 {
		_ = json.Unmarshal(data, &envelope)
	}
	return response.StatusCode, envelope
}

func TestAPITokenManagementIsOwnerBrowserOnly(t *testing.T) {
	engine, api := newAPIAuthTestEngine(t)
	mountAPITokenManagementTestRoutes(engine, api)
	db := database.GetDB()

	var ownerRole model.AdminRole
	if err := db.Where("owner_role = ?", true).First(&ownerRole).Error; err != nil {
		t.Fatalf("load owner role: %v", err)
	}
	var owner model.User
	if err := db.Where("role_id = ?", ownerRole.Id).Order("id ASC").First(&owner).Error; err != nil {
		t.Fatalf("load owner: %v", err)
	}
	var nonOwnerRole model.AdminRole
	if err := db.Where("owner_role = ?", false).Order("id ASC").First(&nonOwnerRole).Error; err != nil {
		t.Fatalf("load non-owner role: %v", err)
	}
	subject := &model.User{
		Username: "token-management-subject",
		Password: "test-password-hash",
		Status:   model.AdminStatusActive,
		RoleId:   nonOwnerRole.Id,
	}
	if err := db.Create(subject).Error; err != nil {
		t.Fatalf("create delegated subject: %v", err)
	}

	tokenService := &panel.ApiTokenService{}
	serviceToken, err := tokenService.Create("management service token")
	if err != nil {
		t.Fatalf("create service token: %v", err)
	}

	server := httptest.NewServer(engine)
	defer server.Close()
	ownerClient := apiTokenManagementClient(t, server.URL, "/test-login")
	nonOwnerClient := apiTokenManagementClient(t, server.URL, "/test-login-user/"+strconv.Itoa(subject.Id))
	plainClient := &http.Client{}

	managementRoutes := []struct {
		name    string
		method  string
		path    string
		payload any
	}{
		{name: "list", method: http.MethodGet, path: "/panel/api/setting/apiTokens"},
		{name: "subjects", method: http.MethodGet, path: "/panel/api/setting/apiTokens/subjects"},
		{name: "create", method: http.MethodPost, path: "/panel/api/setting/apiTokens/create", payload: map[string]any{"name": "must-not-create"}},
		{name: "delete", method: http.MethodPost, path: "/panel/api/setting/apiTokens/delete/999999"},
		{name: "set enabled", method: http.MethodPost, path: "/panel/api/setting/apiTokens/setEnabled/999999", payload: map[string]any{"enabled": false}},
	}
	for _, route := range managementRoutes {
		t.Run("non-owner cannot "+route.name, func(t *testing.T) {
			status, _ := apiTokenManagementRequest(
				t,
				nonOwnerClient,
				route.method,
				server.URL+route.path,
				route.payload,
				"",
			)
			if status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", status)
			}
		})
		t.Run("service token cannot "+route.name, func(t *testing.T) {
			status, _ := apiTokenManagementRequest(
				t,
				plainClient,
				route.method,
				server.URL+route.path,
				route.payload,
				serviceToken.Token,
			)
			if status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", status)
			}
		})
	}

	expiresAt := time.Now().Add(24 * time.Hour).Unix()
	status, envelope := apiTokenManagementRequest(
		t,
		ownerClient,
		http.MethodPost,
		server.URL+"/panel/api/setting/apiTokens/create",
		map[string]any{
			"name":             "owner delegated bot",
			"kind":             model.ApiTokenKindDelegated,
			"subjectAdminId":   subject.Id,
			"createdByAdminId": subject.Id,
			"scopes": []string{
				panel.ApiTokenScopeClientsRead,
				panel.ApiTokenScopeClientsCreate,
			},
			"expiresAt": expiresAt,
		},
		"",
	)
	if status != http.StatusOK || !envelope.Success {
		t.Fatalf("owner create status=%d success=%v msg=%q", status, envelope.Success, envelope.Msg)
	}
	var created panel.ApiTokenView
	if err := json.Unmarshal(envelope.Obj, &created); err != nil {
		t.Fatalf("decode created token: %v", err)
	}
	if created.Token == "" {
		t.Fatal("created token plaintext was not returned once")
	}

	var stored model.ApiToken
	if err := db.Where("id = ?", created.Id).First(&stored).Error; err != nil {
		t.Fatalf("load created token: %v", err)
	}
	if stored.Kind != model.ApiTokenKindDelegated {
		t.Fatalf("stored kind = %q, want delegated", stored.Kind)
	}
	if stored.SubjectAdminId == nil || *stored.SubjectAdminId != subject.Id {
		t.Fatalf("stored subject = %v, want %d", stored.SubjectAdminId, subject.Id)
	}
	if stored.CreatedByAdminId == nil || *stored.CreatedByAdminId != owner.Id {
		t.Fatalf("stored creator = %v, want owner %d", stored.CreatedByAdminId, owner.Id)
	}
	if stored.Token == created.Token || stored.Token != crypto.HashTokenSHA256(created.Token) {
		t.Fatal("controller did not preserve hash-at-rest token storage")
	}

	// Preserve the historical owner-only request shape used to mint trusted
	// remote-panel credentials. It must remain a service token, never inherit a
	// delegated subject, and still record the browser owner as creator.
	status, envelope = apiTokenManagementRequest(
		t,
		ownerClient,
		http.MethodPost,
		server.URL+"/panel/api/setting/apiTokens/create",
		map[string]any{"name": "legacy shape service token"},
		"",
	)
	if status != http.StatusOK || !envelope.Success {
		t.Fatalf("legacy service create status=%d success=%v msg=%q", status, envelope.Success, envelope.Msg)
	}
	var legacyCreated panel.ApiTokenView
	if err := json.Unmarshal(envelope.Obj, &legacyCreated); err != nil {
		t.Fatalf("decode legacy service token: %v", err)
	}
	var legacyStored model.ApiToken
	if err := db.Where("id = ?", legacyCreated.Id).First(&legacyStored).Error; err != nil {
		t.Fatalf("load legacy service token: %v", err)
	}
	if legacyStored.Kind != model.ApiTokenKindService || legacyStored.SubjectAdminId != nil {
		t.Fatalf("legacy request stored kind=%q subject=%v", legacyStored.Kind, legacyStored.SubjectAdminId)
	}
	if legacyStored.CreatedByAdminId == nil || *legacyStored.CreatedByAdminId != owner.Id {
		t.Fatalf("legacy service creator = %v, want owner %d", legacyStored.CreatedByAdminId, owner.Id)
	}

	status, _ = apiTokenManagementRequest(
		t,
		plainClient,
		http.MethodGet,
		server.URL+"/panel/api/setting/apiTokens",
		nil,
		created.Token,
	)
	if status != http.StatusForbidden {
		t.Fatalf("delegated-token management status = %d, want 403", status)
	}

	status, envelope = apiTokenManagementRequest(
		t,
		ownerClient,
		http.MethodGet,
		server.URL+"/panel/api/setting/apiTokens/subjects",
		nil,
		"",
	)
	if status != http.StatusOK || !envelope.Success {
		t.Fatalf("owner subject-list status=%d success=%v", status, envelope.Success)
	}
	var subjects []panel.ApiTokenSubjectView
	if err := json.Unmarshal(envelope.Obj, &subjects); err != nil {
		t.Fatalf("decode subject list: %v", err)
	}
	if len(subjects) != 1 || subjects[0].Id != subject.Id || subjects[0].RoleId != nonOwnerRole.Id {
		t.Fatalf("delegated subjects = %#v, want only %#v", subjects, subject)
	}

	status, envelope = apiTokenManagementRequest(
		t,
		ownerClient,
		http.MethodGet,
		server.URL+"/panel/api/setting/apiTokens",
		nil,
		"",
	)
	if status != http.StatusOK || !envelope.Success {
		t.Fatalf("owner token-list status=%d success=%v", status, envelope.Success)
	}
	var listed []panel.ApiTokenView
	if err := json.Unmarshal(envelope.Obj, &listed); err != nil {
		t.Fatalf("decode token list: %v", err)
	}
	for _, row := range listed {
		if row.Token != "" {
			t.Fatalf("list exposed plaintext for token %d", row.Id)
		}
	}
}
