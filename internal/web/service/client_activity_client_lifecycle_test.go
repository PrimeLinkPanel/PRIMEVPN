package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientActivityFollowsClientLifecycle(t *testing.T) {
	dbPath := filepath.Join(
		t.TempDir(),
		"client-activity-lifecycle.db",
	)

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	db := database.GetDB()
	clientService := &ClientService{}
	inboundService := &InboundService{}

	createClientWithActivity := func(
		email string,
		generation int64,
		epoch int64,
	) model.ClientRecord {
		t.Helper()

		client := model.ClientRecord{
			Email:  email,
			Enable: true,
		}
		if err := db.Create(&client).Error; err != nil {
			t.Fatalf("create client %q: %v", email, err)
		}

		setting := model.ClientActivitySetting{
			ClientID:   client.Id,
			Enabled:    true,
			Generation: generation,
			DataEpoch:  epoch,
		}
		if err := db.Create(&setting).Error; err != nil {
			t.Fatalf(
				"create Activity setting for %q: %v",
				email,
				err,
			)
		}

		destination := model.ClientActivityDestination{
			ClientID:      client.Id,
			DataEpoch:     epoch,
			SourceIP:      "203.0.113.10",
			Destination:   email + ".example",
			UploadBytes:   100,
			DownloadBytes: 200,
			LastSeen:      time.Now().UnixMilli(),
		}
		if err := db.Create(&destination).Error; err != nil {
			t.Fatalf(
				"create Activity destination for %q: %v",
				email,
				err,
			)
		}

		return client
	}

	assertActivityCounts := func(
		clientID int,
		wantSettings int64,
		wantDestinations int64,
	) {
		t.Helper()

		var settings int64
		if err := db.
			Model(&model.ClientActivitySetting{}).
			Where("client_id = ?", clientID).
			Count(&settings).
			Error; err != nil {
			t.Fatalf("count Activity settings: %v", err)
		}

		var destinations int64
		if err := db.
			Model(&model.ClientActivityDestination{}).
			Where("client_id = ?", clientID).
			Count(&destinations).
			Error; err != nil {
			t.Fatalf("count Activity destinations: %v", err)
		}

		if settings != wantSettings ||
			destinations != wantDestinations {
			t.Fatalf(
				"client %d Activity counts = settings:%d destinations:%d, want settings:%d destinations:%d",
				clientID,
				settings,
				destinations,
				wantSettings,
				wantDestinations,
			)
		}
	}

	t.Run("rename preserves history and bumps generation", func(t *testing.T) {
		client := createClientWithActivity(
			"activity-rename-old",
			7,
			3,
		)

		updated := *client.ToClient()
		updated.Email = "activity-rename-new"

		if _, err := clientService.Update(
			inboundService,
			client.Id,
			updated,
		); err != nil {
			t.Fatalf("rename client: %v", err)
		}

		var renamed model.ClientRecord
		if err := db.First(&renamed, client.Id).Error; err != nil {
			t.Fatalf("load renamed client: %v", err)
		}
		if renamed.Email != updated.Email {
			t.Fatalf(
				"renamed email = %q, want %q",
				renamed.Email,
				updated.Email,
			)
		}

		var setting model.ClientActivitySetting
		if err := db.
			Where("client_id = ?", client.Id).
			First(&setting).
			Error; err != nil {
			t.Fatalf("load renamed Activity setting: %v", err)
		}

		if setting.Generation != 8 {
			t.Fatalf(
				"generation after rename = %d, want 8",
				setting.Generation,
			)
		}
		if setting.DataEpoch != 3 {
			t.Fatalf(
				"data epoch after rename = %d, want 3",
				setting.DataEpoch,
			)
		}

		assertActivityCounts(client.Id, 1, 1)
	})

	t.Run("single delete removes Activity even when traffic is kept", func(t *testing.T) {
		client := createClientWithActivity(
			"activity-single-delete",
			2,
			1,
		)

		if _, err := clientService.Delete(
			inboundService,
			client.Id,
			true,
		); err != nil {
			t.Fatalf("single delete: %v", err)
		}

		assertActivityCounts(client.Id, 0, 0)
	})

	t.Run("bulk delete removes only successful client Activity", func(t *testing.T) {
		first := createClientWithActivity(
			"activity-bulk-first",
			1,
			1,
		)
		second := createClientWithActivity(
			"activity-bulk-second",
			4,
			2,
		)

		result, _, err := clientService.BulkDelete(
			inboundService,
			[]string{
				first.Email,
				second.Email,
				"activity-bulk-missing",
			},
			true,
		)
		if err != nil {
			t.Fatalf("bulk delete: %v", err)
		}

		if result.Deleted != 2 {
			t.Fatalf(
				"bulk deleted = %d, want 2",
				result.Deleted,
			)
		}

		assertActivityCounts(first.Id, 0, 0)
		assertActivityCounts(second.Id, 0, 0)
	})
}
