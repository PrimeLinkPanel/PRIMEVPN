package service

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

func TestAdminUsageLedgerDoesNotRefundWhenClientDeleted(t *testing.T) {
	db := initTrafficTestDB(t)

	admin := model.User{
		Username:  "ledger-reseller",
		DataLimit: 1024 * 1024 * 1024,
		UsedBytes: 0,
	}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}

	client := model.ClientRecord{
		Email:        "ledger-client@example.com",
		OwnerAdminId: admin.Id,
		Enable:       true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := db.Create(&xray.ClientTraffic{
		Email: "ledger-client@example.com",
		Up:    100,
		Down:  200,
	}).Error; err != nil {
		t.Fatalf("create traffic: %v", err)
	}

	usage, err := (&InboundService{}).SyncAdminUsedBytes()
	if err != nil {
		t.Fatalf("first SyncAdminUsedBytes: %v", err)
	}
	if got, want := usage[admin.Id], int64(300); got != want {
		t.Fatalf("first synced admin usage = %d, want %d", got, want)
	}

	var afterFirst model.User
	if err := db.First(&afterFirst, admin.Id).Error; err != nil {
		t.Fatalf("read admin after first sync: %v", err)
	}
	if got, want := afterFirst.UsedBytes, int64(300); got != want {
		t.Fatalf("admin used_bytes after first sync = %d, want %d", got, want)
	}

	if err := db.Where("email = ?", "ledger-client@example.com").Delete(&xray.ClientTraffic{}).Error; err != nil {
		t.Fatalf("delete client traffic: %v", err)
	}
	if err := db.Where("email = ?", "ledger-client@example.com").Delete(&model.ClientRecord{}).Error; err != nil {
		t.Fatalf("delete client record: %v", err)
	}

	usage, err = (&InboundService{}).SyncAdminUsedBytes()
	if err != nil {
		t.Fatalf("second SyncAdminUsedBytes: %v", err)
	}
	if got, want := usage[admin.Id], int64(300); got != want {
		t.Fatalf("admin usage after client delete = %d, want %d", got, want)
	}

	var afterDelete model.User
	if err := db.First(&afterDelete, admin.Id).Error; err != nil {
		t.Fatalf("read admin after delete: %v", err)
	}
	if got, want := afterDelete.UsedBytes, int64(300); got != want {
		t.Fatalf("admin used_bytes after client delete = %d, want %d", got, want)
	}
}

func TestAddAdminUsedBytesByClientEmailIncrementsOwnerLedger(t *testing.T) {
	db := initTrafficTestDB(t)

	admin := model.User{
		Username:  "ledger-increment-reseller",
		UsedBytes: 10,
	}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}

	client := model.ClientRecord{
		Email:        "ledger-increment@example.com",
		OwnerAdminId: admin.Id,
		Enable:       true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	if err := addAdminUsedBytesByClientEmail(database.GetDB(), client.Email, 512); err != nil {
		t.Fatalf("addAdminUsedBytesByClientEmail: %v", err)
	}

	var got model.User
	if err := db.First(&got, admin.Id).Error; err != nil {
		t.Fatalf("read admin: %v", err)
	}
	if got.UsedBytes != 522 {
		t.Fatalf("admin used_bytes = %d, want 522", got.UsedBytes)
	}
}

func TestNodeTrafficDeltaIncrementsAdminLedgerAfterDeletedClientHistory(t *testing.T) {
	db := initTrafficTestDB(t)

	admin := model.User{
		Username:  "node-ledger-reseller",
		DataLimit: 5 * 1024 * 1024 * 1024,
		UsedBytes: 3200,
	}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}

	const email = "node-ledger-new-client@example.com"

	client := model.ClientRecord{
		Email:        email,
		OwnerAdminId: admin.Id,
		Enable:       true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	createNodeInboundWithClient(t, db, 1, "n1-ledger", 41991, email)

	svc := &InboundService{}

	// First node snapshot becomes the node baseline and must not import old
	// historical node counters into the reseller ledger.
	syncNode(t, svc, 1, "n1-ledger", xray.ClientTraffic{
		Email:  email,
		Up:     500,
		Down:   600,
		Enable: true,
	})

	var afterBaseline model.User
	if err := db.First(&afterBaseline, admin.Id).Error; err != nil {
		t.Fatalf("read admin after baseline: %v", err)
	}
	if got, want := afterBaseline.UsedBytes, int64(3200); got != want {
		t.Fatalf("admin used_bytes after node baseline = %d, want %d", got, want)
	}

	// New node traffic must increment the historical admin ledger immediately,
	// even when the client's current live usage is still below the reseller's
	// previous deleted-client history.
	syncNode(t, svc, 1, "n1-ledger", xray.ClientTraffic{
		Email:  email,
		Up:     1000,
		Down:   1600,
		Enable: true,
	})

	var afterDelta model.User
	if err := db.First(&afterDelta, admin.Id).Error; err != nil {
		t.Fatalf("read admin after delta: %v", err)
	}

	// Delta = (1000-500) + (1600-600) = 1500.
	if got, want := afterDelta.UsedBytes, int64(4700); got != want {
		t.Fatalf("admin used_bytes after node delta = %d, want %d", got, want)
	}
}
