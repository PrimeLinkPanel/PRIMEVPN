package service

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

func inboundHasClientEmail(t *testing.T, inboundSvc *InboundService, inboundID int, email string) bool {
	t.Helper()
	ib, err := inboundSvc.GetInbound(inboundID)
	if err != nil {
		t.Fatalf("GetInbound(%d): %v", inboundID, err)
	}
	clients, err := inboundSvc.GetClients(ib)
	if err != nil {
		t.Fatalf("GetClients(%d): %v", inboundID, err)
	}
	for _, client := range clients {
		if client.Email == email {
			return true
		}
	}
	return false
}

func TestDeleteByEmailPropagatesFullDeleteToNode(t *testing.T) {
	setupBulkDB(t)
	nodeID, fake := setupNodeRuntime(t)
	email := "global-delete@x"
	client := model.Client{
		ID:     uuid.NewString(),
		Email:  email,
		SubID:  "global-delete",
		Enable: true,
	}
	ib := nodeInbound(t, nodeID, 31001, []model.Client{client})

	clientSvc := &ClientService{}
	inboundSvc := &InboundService{}
	if _, err := clientSvc.DeleteByEmail(inboundSvc, email, false); err != nil {
		t.Fatalf("DeleteByEmail: %v", err)
	}

	if got := fake.deleteClient.Load(); got != 1 {
		t.Fatalf("full node delete calls = %d, want 1", got)
	}
	if got := fake.deleteUser.Load(); got != 0 {
		t.Fatalf("inbound detach calls = %d, want 0 after full node delete", got)
	}
	if inboundHasClientEmail(t, inboundSvc, ib.Id, email) {
		t.Fatal("client remained in central inbound settings")
	}
	if _, err := clientSvc.GetRecordByEmail(nil, email); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("central ClientRecord error = %v, want record not found", err)
	}
}

func TestDeleteByEmailRemoteFailureIsFailClosed(t *testing.T) {
	setupBulkDB(t)
	nodeID, fake := setupNodeRuntime(t)
	fake.deleteClientErr = errors.New("remote delete failed")
	email := "delete-fail-closed@x"
	client := model.Client{
		ID:     uuid.NewString(),
		Email:  email,
		SubID:  "delete-fail-closed",
		Enable: true,
	}
	ib := nodeInbound(t, nodeID, 31002, []model.Client{client})

	clientSvc := &ClientService{}
	inboundSvc := &InboundService{}
	if _, err := clientSvc.DeleteByEmail(inboundSvc, email, false); err == nil {
		t.Fatal("DeleteByEmail succeeded despite remote full-delete failure")
	}

	if got := fake.deleteClient.Load(); got != 1 {
		t.Fatalf("full node delete calls = %d, want 1", got)
	}
	if got := fake.deleteUser.Load(); got != 0 {
		t.Fatalf("detach calls = %d, want 0 before remote full delete succeeds", got)
	}
	if !inboundHasClientEmail(t, inboundSvc, ib.Id, email) {
		t.Fatal("central inbound changed despite remote full-delete failure")
	}
	if _, err := clientSvc.GetRecordByEmail(nil, email); err != nil {
		t.Fatalf("central ClientRecord was removed on failed delete: %v", err)
	}
}

func TestDeleteByEmailCleansNodeOnlyOrphanFromTrafficHistory(t *testing.T) {
	setupBulkDB(t)
	nodeID, fake := setupNodeRuntime(t)
	email := "node-only-orphan@x"
	db := database.GetDB()

	if err := db.Create(&model.NodeClientTraffic{
		NodeId: nodeID,
		Email:  email,
	}).Error; err != nil {
		t.Fatalf("create node traffic history: %v", err)
	}
	if err := db.Create(&xray.ClientTraffic{
		Email:  email,
		Enable: true,
	}).Error; err != nil {
		t.Fatalf("create central traffic orphan: %v", err)
	}

	if _, err := (&ClientService{}).DeleteByEmail(&InboundService{}, email, false); err != nil {
		t.Fatalf("DeleteByEmail orphan retry: %v", err)
	}
	if got := fake.deleteClient.Load(); got != 1 {
		t.Fatalf("full node delete calls = %d, want 1", got)
	}

	var nodeRows int64
	if err := db.Model(&model.NodeClientTraffic{}).
		Where("node_id = ? AND email = ?", nodeID, email).
		Count(&nodeRows).Error; err != nil {
		t.Fatalf("count node traffic rows: %v", err)
	}
	if nodeRows != 0 {
		t.Fatalf("node traffic history rows = %d, want 0", nodeRows)
	}
	var trafficRows int64
	if err := db.Model(&xray.ClientTraffic{}).
		Where("email = ?", email).
		Count(&trafficRows).Error; err != nil {
		t.Fatalf("count central traffic rows: %v", err)
	}
	if trafficRows != 0 {
		t.Fatalf("central traffic orphan rows = %d, want 0", trafficRows)
	}
}

func TestBulkDeletePropagatesFullDeleteToNode(t *testing.T) {
	setupBulkDB(t)
	nodeID, fake := setupNodeRuntime(t)
	clients := []model.Client{
		{ID: uuid.NewString(), Email: "bulk-global-a@x", SubID: "bulk-a", Enable: true},
		{ID: uuid.NewString(), Email: "bulk-global-b@x", SubID: "bulk-b", Enable: true},
	}
	nodeInbound(t, nodeID, 31003, clients)

	result, _, err := (&ClientService{}).BulkDelete(
		&InboundService{},
		[]string{clients[0].Email, clients[1].Email},
		false,
	)
	if err != nil {
		t.Fatalf("BulkDelete: %v", err)
	}
	if result.Deleted != 2 {
		t.Fatalf("BulkDelete deleted = %d, want 2; skipped=%v", result.Deleted, result.Skipped)
	}
	if got := fake.deleteClient.Load(); got != 2 {
		t.Fatalf("full node deletes = %d, want 2", got)
	}
	if got := fake.deleteClientBatch.Load(); got != 1 {
		t.Fatalf("bulk node delete RPCs = %d, want 1", got)
	}
}
