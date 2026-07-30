package service

import (
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func seedDepletedClient(t *testing.T, email string, port int) (*ClientService, *InboundService, *model.Inbound) {
	t.Helper()

	clientSvc := &ClientService{}
	inboundSvc := &InboundService{}
	client := model.Client{
		Email:  email,
		ID:     "11111111-1111-1111-1111-111111111111",
		SubID:  email,
		Enable: true,
	}
	inbound := mkInbound(t, port, model.VLESS, clientsSettings(t, []model.Client{client}))
	if err := clientSvc.SyncInbound(nil, inbound.Id, []model.Client{client}); err != nil {
		t.Fatalf("SyncInbound: %v", err)
	}
	mkTraffic(t, inbound.Id, email, 10, 0, 10, time.Now().Add(time.Hour).UnixMilli(), true)
	return clientSvc, inboundSvc, inbound
}

func TestDisableInvalidClientsMalformedSettingsRollsBackCanonicalState(t *testing.T) {
	setupBulkDB(t)
	clientSvc, _, inbound := seedDepletedClient(t, "bad-settings@x", 54101)

	if err := database.GetDB().Model(&model.Inbound{}).
		Where("id = ?", inbound.Id).
		Update("settings", "{not-json").Error; err != nil {
		t.Fatalf("corrupt settings: %v", err)
	}

	needRepair, disabled, _, err := (&InboundService{}).addTrafficLocked(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "settings JSON sync failed") {
		t.Fatalf("addTrafficLocked error = %v, want settings sync failure", err)
	}
	if !needRepair {
		t.Fatal("failed disable transaction must request runtime repair")
	}
	if disabled {
		t.Fatal("rolled-back transaction must not report committed disables")
	}
	if got := recordEnableOf(t, clientSvc, "bad-settings@x"); !got {
		t.Fatal("client record was disabled despite rollback")
	}
	if got := trafficOf(t, "bad-settings@x").Enable; !got {
		t.Fatal("client traffic was disabled despite rollback")
	}
}

func TestDisableInvalidClientsRecordWriteFailureRollsBackAllState(t *testing.T) {
	setupBulkDB(t)
	clientSvc, inboundSvc, inbound := seedDepletedClient(t, "record-write@x", 54102)

	if err := database.GetDB().Exec(`
		CREATE TRIGGER fail_client_enable_update
		BEFORE UPDATE OF enable ON clients
		WHEN NEW.email = 'record-write@x'
		BEGIN
			SELECT RAISE(ABORT, 'injected clients.enable failure');
		END;
	`).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	needRepair, disabled, _, err := (&InboundService{}).addTrafficLocked(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "update clients.enable") {
		t.Fatalf("addTrafficLocked error = %v, want clients.enable failure", err)
	}
	if !needRepair {
		t.Fatal("failed disable transaction must request runtime repair")
	}
	if disabled {
		t.Fatal("rolled-back transaction must not report committed disables")
	}
	if got := recordEnableOf(t, clientSvc, "record-write@x"); !got {
		t.Fatal("client record was disabled despite rollback")
	}
	if got := trafficOf(t, "record-write@x").Enable; !got {
		t.Fatal("client traffic was disabled despite rollback")
	}
	if got := jsonClientEnable(t, inboundSvc, inbound.Id, "record-write@x"); !got {
		t.Fatal("inbound settings were disabled despite rollback")
	}
}
