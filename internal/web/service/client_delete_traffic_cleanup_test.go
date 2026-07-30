package service

import (
	"fmt"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

func seedDetachedDeleteAccounting(t *testing.T, nodeID int, email string, port int) {
	t.Helper()
	db := database.GetDB()

	record := &model.ClientRecord{
		Email:  email,
		SubID:  fmt.Sprintf("sub-%d", port),
		Enable: true,
	}
	if err := db.Create(record).Error; err != nil {
		t.Fatalf("create client record %q: %v", email, err)
	}

	// Keep an inbound row only as the accounting identity. Deliberately do not
	// create client_inbounds or put the client in settings: this is the detached
	// shape that previously leaked client_inbound_traffics.
	inbound := mkInbound(t, port, model.VLESS, `{"clients":[]}`)

	rows := []any{
		&xray.ClientTraffic{InboundId: inbound.Id, Email: email, Enable: true, Up: 11, Down: 22},
		&model.ClientGlobalTraffic{MasterGuid: fmt.Sprintf("master-%d", port), Email: email, Up: 33, Down: 44},
		&model.ClientInboundTraffic{
			ClientID: record.Id, InboundID: inbound.Id, Email: email,
			StatEmail: fmt.Sprintf("stat-%d-%s", port, email), ActualUp: 55, ActualDown: 66,
		},
		&model.NodeClientTraffic{NodeId: nodeID, Email: email, Up: 77, Down: 88},
		&model.InboundClientIps{ClientEmail: email, Ips: `["192.0.2.1"]`},
	}
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("create accounting row %T for %q: %v", row, email, err)
		}
	}
}

func assertDeletedAccounting(t *testing.T, email string) {
	t.Helper()
	db := database.GetDB()

	checks := []struct {
		name  string
		model any
		where string
	}{
		{"clients", &model.ClientRecord{}, "email = ?"},
		{"client_traffics", &xray.ClientTraffic{}, "email = ?"},
		{"client_global_traffics", &model.ClientGlobalTraffic{}, "email = ?"},
		{"client_inbound_traffics", &model.ClientInboundTraffic{}, "email = ?"},
		{"node_client_traffics", &model.NodeClientTraffic{}, "email = ?"},
		{"inbound_client_ips", &model.InboundClientIps{}, "client_email = ?"},
	}
	for _, check := range checks {
		var count int64
		if err := db.Model(check.model).Where(check.where, email).Count(&count).Error; err != nil {
			t.Fatalf("count %s for %q: %v", check.name, email, err)
		}
		if count != 0 {
			t.Fatalf("%s rows for %q = %d, want 0", check.name, email, count)
		}
	}
}

func TestDeleteByEmailPurgesDetachedDetailedAccounting(t *testing.T) {
	setupBulkDB(t)
	nodeID, fake := setupNodeRuntime(t)
	email := "single-detached-delete@x"
	seedDetachedDeleteAccounting(t, nodeID, email, 31991)

	if _, err := (&ClientService{}).DeleteByEmail(&InboundService{}, email, false); err != nil {
		t.Fatalf("DeleteByEmail: %v", err)
	}
	if got := fake.deleteClient.Load(); got != 1 {
		t.Fatalf("remote full delete calls = %d, want 1", got)
	}
	assertDeletedAccounting(t, email)
}

func TestBulkDeletePurgesDetachedDetailedAccounting(t *testing.T) {
	setupBulkDB(t)
	nodeID, fake := setupNodeRuntime(t)
	emails := []string{"bulk-detached-a@x", "bulk-detached-b@x"}
	for i, email := range emails {
		seedDetachedDeleteAccounting(t, nodeID, email, 31992+i)
	}

	result, _, err := (&ClientService{}).BulkDelete(&InboundService{}, emails, false)
	if err != nil {
		t.Fatalf("BulkDelete: %v", err)
	}
	if result.Deleted != len(emails) || len(result.Skipped) != 0 {
		t.Fatalf("BulkDelete result = %+v, want deleted=%d and no skips", result, len(emails))
	}
	if got := fake.deleteClientBatch.Load(); got != 1 {
		t.Fatalf("remote bulk delete calls = %d, want 1", got)
	}
	for _, email := range emails {
		assertDeletedAccounting(t, email)
	}
}
