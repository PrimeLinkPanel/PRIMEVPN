package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/runtime"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

type orphanDeleteRuntime struct {
	deleted int
}

func (*orphanDeleteRuntime) Name() string                                     { return "orphan-delete-node" }
func (*orphanDeleteRuntime) AddInbound(context.Context, *model.Inbound) error { return nil }
func (*orphanDeleteRuntime) DelInbound(context.Context, *model.Inbound) error { return nil }
func (*orphanDeleteRuntime) UpdateInbound(context.Context, *model.Inbound, *model.Inbound) error {
	return nil
}
func (*orphanDeleteRuntime) AddUser(context.Context, *model.Inbound, map[string]any) error {
	return nil
}
func (*orphanDeleteRuntime) RemoveUser(context.Context, *model.Inbound, string) error { return nil }
func (*orphanDeleteRuntime) UpdateUser(context.Context, *model.Inbound, string, model.Client) error {
	return nil
}
func (*orphanDeleteRuntime) DeleteUser(context.Context, *model.Inbound, string) error { return nil }
func (*orphanDeleteRuntime) AddClient(context.Context, *model.Inbound, model.Client) error {
	return nil
}
func (*orphanDeleteRuntime) RestartXray(context.Context) error { return nil }
func (*orphanDeleteRuntime) ResetClientTraffic(context.Context, *model.Inbound, string) error {
	return nil
}
func (*orphanDeleteRuntime) ResetInboundTraffic(context.Context, *model.Inbound) error { return nil }
func (*orphanDeleteRuntime) ResetAllTraffics(context.Context) error                    { return nil }
func (*orphanDeleteRuntime) DeleteClient(context.Context, string) error                { return nil }
func (f *orphanDeleteRuntime) DeleteClientRecord(context.Context, string, bool) error {
	f.deleted++
	return nil
}
func (f *orphanDeleteRuntime) DeleteClientRecords(_ context.Context, emails []string, _ bool) error {
	f.deleted += len(emails)
	return nil
}

func TestClientDeleteAPIReachesNodeOnlyOrphanCleanup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	if err := database.InitDB(filepath.Join(t.TempDir(), "client-delete-orphan-controller.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	previousManager := runtime.GetManager()
	manager := runtime.NewManager(runtime.LocalDeps{
		APIPort:        func() int { return 0 },
		SetNeedRestart: func() {},
	})
	runtime.SetManager(manager)
	t.Cleanup(func() { runtime.SetManager(previousManager) })

	db := database.GetDB()
	node := &model.Node{
		Name:     "hk-test",
		Address:  "127.0.0.1",
		Port:     61187,
		ApiToken: "test-token",
		Enable:   true,
		Status:   "online",
	}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}

	fake := &orphanDeleteRuntime{}
	manager.SetRuntimeOverride(node.Id, fake)

	const email = "gogoli1"
	if err := db.Create(&model.NodeClientTraffic{NodeId: node.Id, Email: email}).Error; err != nil {
		t.Fatalf("create node traffic history: %v", err)
	}
	if err := db.Create(&xray.ClientTraffic{Email: email, Enable: true}).Error; err != nil {
		t.Fatalf("create central traffic orphan: %v", err)
	}

	router := gin.New()
	NewClientController(router.Group("/clients"))

	req := httptest.NewRequest(http.MethodPost, "/clients/del/"+email, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if !envelope.Success {
		t.Fatalf("delete response failed: %s body=%s", envelope.Msg, rec.Body.String())
	}
	if fake.deleted != 1 {
		t.Fatalf("remote full-delete calls = %d, want 1", fake.deleted)
	}

	var nodeRows, trafficRows int64
	if err := db.Model(&model.NodeClientTraffic{}).
		Where("node_id = ? AND email = ?", node.Id, email).
		Count(&nodeRows).Error; err != nil {
		t.Fatalf("count node history: %v", err)
	}
	if err := db.Model(&xray.ClientTraffic{}).
		Where("email = ?", email).
		Count(&trafficRows).Error; err != nil {
		t.Fatalf("count central traffic: %v", err)
	}
	if nodeRows != 0 || trafficRows != 0 {
		t.Fatalf("orphan rows remained: node=%d traffic=%d", nodeRows, trafficRows)
	}
}

func TestClientDeleteScopeAllowsOrphanCleanupOnlyForUnrestrictedAll(t *testing.T) {
	tests := []struct {
		name  string
		scope service.ClientAccessScope
		want  bool
	}{
		{name: "all", scope: service.ClientAccessScope{Mode: service.ClientAccessAll}, want: true},
		{name: "own", scope: service.ClientAccessScope{Mode: service.ClientAccessOwn, AdminID: 7}, want: false},
		{name: "none", scope: service.ClientAccessScope{Mode: service.ClientAccessNone}, want: false},
		{
			name: "all restricted inbound",
			scope: service.ClientAccessScope{
				Mode:              service.ClientAccessAll,
				RestrictInbounds:  true,
				AllowedInboundIDs: []int{17},
			},
			want: false,
		},
		{
			name: "all restricted group",
			scope: service.ClientAccessScope{
				Mode:           service.ClientAccessAll,
				RestrictGroups: true,
				AllowedGroups:  []string{"ops"},
			},
			want: false,
		},
		{
			name: "explicit all inbounds and groups",
			scope: service.ClientAccessScope{
				Mode:             service.ClientAccessAll,
				RestrictInbounds: true,
				AllowAllInbounds: true,
				RestrictGroups:   true,
				AllowAllGroups:   true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientDeleteScopeAllowsOrphanCleanup(tt.scope); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
