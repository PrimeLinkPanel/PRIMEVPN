package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientActivityRemoteMergeIsIdempotentAndVisible(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "activity-node-sync.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	db := database.GetDB()
	client := model.ClientRecord{Email: "activity-node-client", Enable: true}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	setting := model.ClientActivitySetting{
		ClientID: client.Id, Enabled: true, Generation: 4, DataEpoch: 2,
	}
	if err := db.Create(&setting).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}
	local := model.ClientActivityDestination{
		ClientID: client.Id, DataEpoch: 2,
		SourceIP: "203.0.113.10", Destination: "example.com",
		UploadBytes: 10, DownloadBytes: 20, LastSeen: time.Now().UnixMilli(),
	}
	if err := db.Create(&local).Error; err != nil {
		t.Fatalf("create local row: %v", err)
	}

	response := &model.ClientActivitySyncResponse{
		Items: []model.ClientActivitySyncItem{{
			OriginGUID: "node-guid", Email: client.Email, DataEpoch: 2,
			SourceIP: "203.0.113.10", Destination: "example.com",
			UploadBytes: 100, DownloadBytes: 200, LastSeen: time.Now().UnixMilli(),
		}},
	}
	activity := &ClientActivityService{}
	if err := activity.MergeNodeActivity("mother-guid", response); err != nil {
		t.Fatalf("first merge: %v", err)
	}
	if err := activity.MergeNodeActivity("mother-guid", response); err != nil {
		t.Fatalf("retry merge: %v", err)
	}

	list, err := activity.ListByClientID(client.Id, 1, 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.Total != 1 || len(list.Items) != 1 {
		t.Fatalf("unexpected list: %+v", list)
	}
	if list.Items[0].UploadBytes != 110 || list.Items[0].DownloadBytes != 220 {
		t.Fatalf("remote retry double-counted or was not aggregated: %+v", list.Items[0])
	}

	if _, err := activity.ResetByClientID(client.Id); err != nil {
		t.Fatalf("reset: %v", err)
	}
	var remoteCount int64
	if err := db.Model(&model.ClientActivityRemoteDestination{}).
		Where("client_id = ?", client.Id).Count(&remoteCount).Error; err != nil {
		t.Fatalf("count remote rows: %v", err)
	}
	if remoteCount != 0 {
		t.Fatalf("reset left %d remote rows", remoteCount)
	}
}

func TestApplyAuthoritativeNodeStateUsesCanonicalEmail(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "activity-node-state.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	db := database.GetDB()
	client := model.ClientRecord{Email: "canonical-client", Enable: true}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	activity := &ClientActivityService{}
	_, err := activity.ApplyNodeSyncAndExport("node-guid", &model.ClientActivitySyncRequest{
		States: []model.ClientActivitySyncState{{
			Email: client.Email, Enabled: true, Generation: 7, DataEpoch: 3,
		}},
	})
	if err != nil {
		t.Fatalf("apply state: %v", err)
	}

	status, err := activity.StatusByClientID(client.Id)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Enabled || status.Generation != 7 || status.DataEpoch != 3 {
		t.Fatalf("unexpected authoritative status: %+v", status)
	}
}
