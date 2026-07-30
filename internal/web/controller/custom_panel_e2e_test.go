package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/sub"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

const customPanelE2EUsername = "adapter-e2e-user"

type customPanelE2EHarness struct {
	engine  *gin.Engine
	apiKey  string
	subject *model.User
	inbound *model.Inbound
}

func newCustomPanelE2EHarness(t *testing.T, explicitInboundAccess bool) *customPanelE2EHarness {
	t.Helper()

	engine, api := newAPIAuthTestEngine(t)
	db := database.GetDB()

	var role model.AdminRole
	if err := db.Where("slug = ?", model.AdminRoleSlugAdministrator).First(&role).Error; err != nil {
		t.Fatalf("load administrator role: %v", err)
	}

	subject := &model.User{
		Username: "custom-panel-e2e-admin",
		Password: "test-password-hash",
		Status:   model.AdminStatusActive,
		RoleId:   role.Id,
	}
	if err := db.Create(subject).Error; err != nil {
		t.Fatalf("create subject: %v", err)
	}

	inbound := &model.Inbound{
		UserId:          subject.Id,
		Remark:          "custom-panel-e2e",
		SubSortIndex:    1,
		Enable:          false,
		TrafficReset:    "never",
		UsageMultiplier: 1,
		Port:            24443,
		Protocol:        model.VLESS,
		Settings:        `{"clients":[],"decryption":"none"}`,
		StreamSettings:  `{"network":"tcp","security":"none","tcpSettings":{"acceptProxyProtocol":false,"header":{"type":"none"}}}`,
		Sniffing:        `{"enabled":false,"destOverride":[],"metadataOnly":false,"routeOnly":false}`,
		Tag:             "custom-panel-e2e-inbound",
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	if explicitInboundAccess {
		role.AccessJSON = fmt.Sprintf(
			`{"allowAllGroups":true,"allowed_inbound_ids":[%d]}`,
			inbound.Id,
		)
		if err := db.Model(&model.AdminRole{}).
			Where("id = ?", role.Id).
			Update("access", role.AccessJSON).Error; err != nil {
			t.Fatalf("restrict role inbound access: %v", err)
		}
	}

	apiKey := createCustomPanelTestToken(t, panel.ApiTokenCreateOptions{
		Name:           "custom-panel-e2e-token",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: subject.Id,
		Scopes:         []string{panel.ApiTokenScopeCustomPanelManage},
	})

	service.RegisterSubLinkProvider(sub.NewLinkProvider())
	api.initCustomPanelRouter(engine.Group(""))

	return &customPanelE2EHarness{
		engine:  engine,
		apiKey:  apiKey,
		subject: subject,
		inbound: inbound,
	}
}

func customPanelE2ERequest(t *testing.T, engine *gin.Engine, apiKey string, payload any) map[string]any {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api", bytes.NewReader(body))
	req.Host = "panel.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}

	decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
	decoder.UseNumber()
	var decoded map[string]any
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode response %s: %v", response.Body.String(), err)
	}
	return decoded
}

func customPanelE2ERequireSuccess(t *testing.T, response map[string]any) {
	t.Helper()
	if got, _ := response["status"].(string); got != "success" {
		t.Fatalf("response status = %q, want success; response=%#v", got, response)
	}
}

func customPanelE2EInt64(t *testing.T, response map[string]any, field string) int64 {
	t.Helper()
	value, ok := response[field].(json.Number)
	if !ok {
		t.Fatalf("response field %q = %#v, want JSON number", field, response[field])
	}
	result, err := value.Int64()
	if err != nil {
		t.Fatalf("response field %q: %v", field, err)
	}
	return result
}

func customPanelE2ELoadClient(t *testing.T, email string) *model.ClientRecord {
	t.Helper()
	var record model.ClientRecord
	if err := database.GetDB().Where("email = ?", email).First(&record).Error; err != nil {
		t.Fatalf("load client %q: %v", email, err)
	}
	return &record
}

func TestCustomPanelAllActionsEndToEnd(t *testing.T) {
	harness := newCustomPanelE2EHarness(t, true)
	db := database.GetDB()

	count := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action": "count_users",
	})
	if got := customPanelE2EInt64(t, count, "count"); got != 0 {
		t.Fatalf("initial active count = %d, want 0", got)
	}

	const initialLimit = int64(10_737_418_240)
	const initialExpire = int64(1_900_000_000)
	create := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":     "create_user",
		"username":   customPanelE2EUsername,
		"data_limit": initialLimit,
		"expire":     initialExpire,
		"note":       "created through compatibility API",
	})
	customPanelE2ERequireSuccess(t, create)
	if create["username"] != customPanelE2EUsername {
		t.Fatalf("create username = %#v", create["username"])
	}
	createURL, _ := create["subscription_url"].(string)
	if !strings.HasPrefix(createURL, "http://panel.example.com:2096/sub/") {
		t.Fatalf("create subscription URL = %q", createURL)
	}
	if _, ok := create["configs"].([]any); !ok {
		t.Fatalf("create configs = %#v, want array", create["configs"])
	}

	record := customPanelE2ELoadClient(t, customPanelE2EUsername)
	if record.OwnerAdminId != harness.subject.Id || record.CreatedByAdminId != harness.subject.Id {
		t.Fatalf(
			"client ownership = owner:%d creator:%d, want %d",
			record.OwnerAdminId,
			record.CreatedByAdminId,
			harness.subject.Id,
		)
	}
	if record.TotalGB != initialLimit || record.ExpiryTime != initialExpire*1000 || !record.Enable {
		t.Fatalf("created client = %#v", record)
	}
	inboundIDs, err := (&service.ClientService{}).GetInboundIdsForRecord(record.Id)
	if err != nil {
		t.Fatalf("load client inbound IDs: %v", err)
	}
	if len(inboundIDs) != 1 || inboundIDs[0] != harness.inbound.Id {
		t.Fatalf("client inbound IDs = %#v, want [%d]", inboundIDs, harness.inbound.Id)
	}

	duplicate := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":     "create_user",
		"username":   customPanelE2EUsername,
		"data_limit": initialLimit,
		"expire":     initialExpire,
	})
	if duplicate["status"] != "error" || duplicate["message"] != "Username already exists" {
		t.Fatalf("duplicate response = %#v", duplicate)
	}

	if err := db.Model(&xray.ClientTraffic{}).
		Where("email = ?", customPanelE2EUsername).
		Updates(map[string]any{"up": int64(300), "down": int64(700)}).Error; err != nil {
		t.Fatalf("seed traffic: %v", err)
	}

	get := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "get_user",
		"username": customPanelE2EUsername,
	})
	customPanelE2ERequireSuccess(t, get)
	if customPanelE2EInt64(t, get, "data_limit") != initialLimit ||
		customPanelE2EInt64(t, get, "expire") != initialExpire ||
		customPanelE2EInt64(t, get, "used_traffic") != 1000 {
		t.Fatalf("get response = %#v", get)
	}
	if get["subscription_url"] != createURL {
		t.Fatalf("get subscription URL = %#v, want %q", get["subscription_url"], createURL)
	}
	if _, ok := get["links"].([]any); !ok {
		t.Fatalf("get links = %#v, want array", get["links"])
	}

	count = customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action": "count_users",
	})
	if got := customPanelE2EInt64(t, count, "count"); got != 1 {
		t.Fatalf("active count after create = %d, want 1", got)
	}

	disable := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "change_status",
		"username": customPanelE2EUsername,
		"status":   "disabled",
	})
	customPanelE2ERequireSuccess(t, disable)
	if customPanelE2ELoadClient(t, customPanelE2EUsername).Enable {
		t.Fatal("client remains enabled after change_status disabled")
	}
	count = customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action": "count_users",
	})
	if got := customPanelE2EInt64(t, count, "count"); got != 0 {
		t.Fatalf("active count after disable = %d, want 0", got)
	}

	const modifiedLimit = int64(21_474_836_480)
	const modifiedExpire = int64(1_910_000_000)
	modify := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "modify_user",
		"username": customPanelE2EUsername,
		"config": map[string]any{
			"status":     "active",
			"data_limit": modifiedLimit,
			"expire":     modifiedExpire,
			"note":       "modified through compatibility API",
		},
	})
	customPanelE2ERequireSuccess(t, modify)
	if _, ok := modify["data"].(map[string]any); !ok {
		t.Fatalf("modify data = %#v, want object", modify["data"])
	}
	record = customPanelE2ELoadClient(t, customPanelE2EUsername)
	if !record.Enable || record.TotalGB != modifiedLimit || record.ExpiryTime != modifiedExpire*1000 || record.Comment != "modified through compatibility API" {
		t.Fatalf("modified client = %#v", record)
	}

	if err := db.Model(&xray.ClientTraffic{}).
		Where("email = ?", customPanelE2EUsername).
		Updates(map[string]any{"up": int64(1234), "down": int64(5678)}).Error; err != nil {
		t.Fatalf("seed reset traffic: %v", err)
	}
	reset := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "reset_user",
		"username": customPanelE2EUsername,
	})
	customPanelE2ERequireSuccess(t, reset)
	var traffic xray.ClientTraffic
	if err := db.Where("email = ?", customPanelE2EUsername).First(&traffic).Error; err != nil {
		t.Fatalf("load reset traffic: %v", err)
	}
	if traffic.Up != 0 || traffic.Down != 0 || !traffic.Enable {
		t.Fatalf("traffic after reset = %#v", traffic)
	}

	const extendedLimit = int64(32_212_254_720)
	const extendedExpire = int64(1_920_000_000)
	extend := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":     "extend_user",
		"username":   customPanelE2EUsername,
		"data_limit": extendedLimit,
		"expire":     extendedExpire,
	})
	customPanelE2ERequireSuccess(t, extend)
	record = customPanelE2ELoadClient(t, customPanelE2EUsername)
	if record.TotalGB != extendedLimit || record.ExpiryTime != extendedExpire*1000 {
		t.Fatalf("extended client = %#v", record)
	}

	const extraBytes = int64(1_073_741_824)
	extraVolume := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "extra_volume",
		"username": customPanelE2EUsername,
		"volume":   extraBytes,
	})
	customPanelE2ERequireSuccess(t, extraVolume)
	record = customPanelE2ELoadClient(t, customPanelE2EUsername)
	if record.TotalGB != extendedLimit+extraBytes {
		t.Fatalf("total after extra_volume = %d", record.TotalGB)
	}

	const extraDays = int64(2)
	extraTime := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "extra_time",
		"username": customPanelE2EUsername,
		"time":     extraDays,
	})
	customPanelE2ERequireSuccess(t, extraTime)
	record = customPanelE2ELoadClient(t, customPanelE2EUsername)
	wantExpiry := extendedExpire*1000 + extraDays*customPanelMillisPerDay
	if record.ExpiryTime != wantExpiry {
		t.Fatalf("expiry after extra_time = %d, want %d", record.ExpiryTime, wantExpiry)
	}

	oldSubID := record.SubID
	revoke := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "revoke_sub",
		"username": customPanelE2EUsername,
	})
	customPanelE2ERequireSuccess(t, revoke)
	newURL, _ := revoke["subscription_url"].(string)
	if newURL == "" || newURL == createURL {
		t.Fatalf("revoke subscription URL = %q, old = %q", newURL, createURL)
	}
	if _, ok := revoke["configs"].([]any); !ok {
		t.Fatalf("revoke configs = %#v, want array", revoke["configs"])
	}
	record = customPanelE2ELoadClient(t, customPanelE2EUsername)
	if record.SubID == "" || record.SubID == oldSubID || !strings.HasSuffix(newURL, "/"+record.SubID) {
		t.Fatalf("subId after revoke = %q, URL = %q, old = %q", record.SubID, newURL, oldSubID)
	}

	remove := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":   "remove_user",
		"username": customPanelE2EUsername,
	})
	customPanelE2ERequireSuccess(t, remove)
	var remaining int64
	if err := db.Model(&model.ClientRecord{}).
		Where("email = ?", customPanelE2EUsername).
		Count(&remaining).Error; err != nil {
		t.Fatalf("count removed client: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("removed client count = %d, want 0", remaining)
	}
	if err := db.Model(&xray.ClientTraffic{}).
		Where("email = ?", customPanelE2EUsername).
		Count(&remaining).Error; err != nil {
		t.Fatalf("count removed traffic: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("removed traffic count = %d, want 0", remaining)
	}
	count = customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action": "count_users",
	})
	if got := customPanelE2EInt64(t, count, "count"); got != 0 {
		t.Fatalf("final active count = %d, want 0", got)
	}
}

func TestCustomPanelCrossAdminIsolation(t *testing.T) {
	harness := newCustomPanelE2EHarness(t, true)

	create := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":     "create_user",
		"username":   customPanelE2EUsername,
		"data_limit": int64(1024),
		"expire":     int64(1_900_000_000),
	})
	customPanelE2ERequireSuccess(t, create)

	db := database.GetDB()
	other := &model.User{
		Username: "custom-panel-other-admin",
		Password: "test-password-hash",
		Status:   model.AdminStatusActive,
		RoleId:   harness.subject.RoleId,
	}
	if err := db.Create(other).Error; err != nil {
		t.Fatalf("create other admin: %v", err)
	}
	otherKey := createCustomPanelTestToken(t, panel.ApiTokenCreateOptions{
		Name:           "custom-panel-other-token",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: other.Id,
		Scopes:         []string{panel.ApiTokenScopeCustomPanelManage},
	})

	get := customPanelE2ERequest(t, harness.engine, otherKey, map[string]any{
		"action":   "get_user",
		"username": customPanelE2EUsername,
	})
	if get["status"] != "error" || get["message"] != "User not found" {
		t.Fatalf("cross-admin get response = %#v", get)
	}

	count := customPanelE2ERequest(t, harness.engine, otherKey, map[string]any{
		"action": "count_users",
	})
	if got := customPanelE2EInt64(t, count, "count"); got != 0 {
		t.Fatalf("cross-admin count = %d, want 0", got)
	}
}

func TestCustomPanelCreateRequiresExplicitInboundAllowlist(t *testing.T) {
	harness := newCustomPanelE2EHarness(t, false)

	response := customPanelE2ERequest(t, harness.engine, harness.apiKey, map[string]any{
		"action":     "create_user",
		"username":   customPanelE2EUsername,
		"data_limit": int64(1024),
		"expire":     int64(1_900_000_000),
	})
	if response["status"] != "error" || response["message"] != "Custom panel administrator requires explicit inbound access" {
		t.Fatalf("unrestricted create response = %#v", response)
	}

	var record model.ClientRecord
	if err := database.GetDB().Where("email = ?", customPanelE2EUsername).First(&record).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("client created without explicit inbound allowlist: %v, %#v", err, record)
	}
}
