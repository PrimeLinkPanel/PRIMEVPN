package controller

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
)

func mountDelegatedScopeTestRoutes(engine *gin.Engine, api *APIController) {
	group := engine.Group("/panel/api")
	group.Use(api.checkAPIAuth)
	group.Use(enforceDelegatedAPIScope())
	ok := func(c *gin.Context) { c.Status(http.StatusNoContent) }

	group.GET("/clients/list", ok)
	group.GET("/clients/get/:email", ok)
	group.POST("/clients/add", ok)
	group.POST("/clients/bulkCreate", ok)
	group.POST("/clients/update/:email", ok)
	group.GET("/clients/groups", ok)
	group.GET("/server/status", ok)
	group.POST("/inbounds/add", ok)
}

func mountDelegatedScopeBasePathTestRoute(engine *gin.Engine, api *APIController) {
	group := engine.Group("/randomized-base/panel/api")
	group.Use(api.checkAPIAuth)
	group.Use(enforceDelegatedAPIScope())
	group.GET("/clients/list", func(c *gin.Context) { c.Status(http.StatusNoContent) })
}

func seedDelegatedScopeSubject(t *testing.T) *model.User {
	t.Helper()
	db := database.GetDB()
	var role model.AdminRole
	if err := db.Where("owner_role = ?", false).Order("id ASC").First(&role).Error; err != nil {
		t.Fatalf("load non-owner role: %v", err)
	}
	user := &model.User{
		Username: "delegated-scope-subject",
		Password: "test-password-hash",
		Status:   model.AdminStatusActive,
		RoleId:   role.Id,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create delegated subject: %v", err)
	}
	return user
}

func requestDelegatedScopeRoute(t *testing.T, engine http.Handler, method string, path string, token string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)
	return recorder.Code
}

func TestDelegatedAPIScopeAllowlistIsDefaultDeny(t *testing.T) {
	engine, api := newAPIAuthTestEngine(t)
	mountDelegatedScopeTestRoutes(engine, api)
	mountDelegatedScopeBasePathTestRoute(engine, api)
	subject := seedDelegatedScopeSubject(t)
	service := &panel.ApiTokenService{}

	readView, err := service.CreateWithOptions(panel.ApiTokenCreateOptions{
		Name:           "scope read",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: subject.Id,
		Scopes:         []string{panel.ApiTokenScopeClientsRead},
	})
	if err != nil {
		t.Fatalf("create read token: %v", err)
	}
	createView, err := service.CreateWithOptions(panel.ApiTokenCreateOptions{
		Name:           "scope create",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: subject.Id,
		Scopes:         []string{panel.ApiTokenScopeClientsCreate},
	})
	if err != nil {
		t.Fatalf("create create token: %v", err)
	}
	serviceView, err := service.Create("scope service compatibility")
	if err != nil {
		t.Fatalf("create service token: %v", err)
	}

	tests := []struct {
		name   string
		token  string
		method string
		path   string
		want   int
	}{
		{name: "read token lists clients", token: readView.Token, method: http.MethodGet, path: "/panel/api/clients/list", want: http.StatusNoContent},
		{name: "read token works below randomized base path", token: readView.Token, method: http.MethodGet, path: "/randomized-base/panel/api/clients/list", want: http.StatusNoContent},
		{name: "read token reads one client", token: readView.Token, method: http.MethodGet, path: "/panel/api/clients/get/alice", want: http.StatusNoContent},
		{name: "read token cannot create", token: readView.Token, method: http.MethodPost, path: "/panel/api/clients/add", want: http.StatusForbidden},
		{name: "create token creates one", token: createView.Token, method: http.MethodPost, path: "/panel/api/clients/add", want: http.StatusNoContent},
		{name: "create token creates bulk", token: createView.Token, method: http.MethodPost, path: "/panel/api/clients/bulkCreate", want: http.StatusNoContent},
		{name: "create token cannot read", token: createView.Token, method: http.MethodGet, path: "/panel/api/clients/list", want: http.StatusForbidden},
		{name: "delegated token cannot update", token: createView.Token, method: http.MethodPost, path: "/panel/api/clients/update/alice", want: http.StatusForbidden},
		{name: "delegated token cannot administer groups", token: readView.Token, method: http.MethodGet, path: "/panel/api/clients/groups", want: http.StatusForbidden},
		{name: "delegated token cannot read server", token: readView.Token, method: http.MethodGet, path: "/panel/api/server/status", want: http.StatusForbidden},
		{name: "delegated token cannot create inbound", token: createView.Token, method: http.MethodPost, path: "/panel/api/inbounds/add", want: http.StatusForbidden},
		{name: "service token retains client update", token: serviceView.Token, method: http.MethodPost, path: "/panel/api/clients/update/alice", want: http.StatusNoContent},
		{name: "service token retains server access", token: serviceView.Token, method: http.MethodGet, path: "/panel/api/server/status", want: http.StatusNoContent},
		{name: "service token retains inbound access", token: serviceView.Token, method: http.MethodPost, path: "/panel/api/inbounds/add", want: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := requestDelegatedScopeRoute(t, engine, test.method, test.path, test.token); got != test.want {
				t.Fatalf("status = %d, want %d", got, test.want)
			}
		})
	}
}

func TestDelegatedAPIScopeGuardDoesNotRestrictBrowserSession(t *testing.T) {
	engine, api := newAPIAuthTestEngine(t)
	mountDelegatedScopeTestRoutes(engine, api)
	server := httptest.NewServer(engine)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}
	loginResponse, err := client.Get(server.URL + "/test-login")
	if err != nil {
		t.Fatalf("browser login: %v", err)
	}
	loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", loginResponse.StatusCode)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/panel/api/inbounds/add", nil)
	if err != nil {
		t.Fatalf("create browser request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("browser request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("browser status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
}
