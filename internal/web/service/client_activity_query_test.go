package service

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientActivityListByClientID(t *testing.T) {
	dbPath := filepath.Join(
		t.TempDir(),
		"client-activity-query.db",
	)

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	db := database.GetDB()

	client := model.ClientRecord{
		Email:  "activity-query-client",
		Enable: true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	setting := model.ClientActivitySetting{
		ClientID:   client.Id,
		Enabled:    true,
		Generation: 6,
		DataEpoch:  3,
	}
	if err := db.Create(&setting).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}

	rows := []model.ClientActivityDestination{
		{
			ClientID:      client.Id,
			DataEpoch:     3,
			SourceIP:      "203.0.113.10",
			Destination:   "newest.example",
			UploadBytes:   300,
			DownloadBytes: 600,
			LastSeen:      3000,
		},
		{
			ClientID:      client.Id,
			DataEpoch:     3,
			SourceIP:      "203.0.113.11",
			Destination:   "older.example",
			UploadBytes:   100,
			DownloadBytes: 200,
			LastSeen:      2000,
		},
		{
			ClientID:      client.Id,
			DataEpoch:     2,
			SourceIP:      "203.0.113.12",
			Destination:   "stale-epoch.example",
			UploadBytes:   9999,
			DownloadBytes: 9999,
			LastSeen:      4000,
		},
	}

	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("create destinations: %v", err)
	}

	service := &ClientActivityService{}

	firstPage, err := service.ListByClientID(
		client.Id,
		1,
		1,
	)
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}

	if !firstPage.Enabled ||
		firstPage.Generation != 6 ||
		firstPage.DataEpoch != 3 ||
		firstPage.Total != 2 ||
		firstPage.Page != 1 ||
		firstPage.PageSize != 1 ||
		len(firstPage.Items) != 1 {
		t.Fatalf(
			"unexpected first page: %+v",
			firstPage,
		)
	}

	if firstPage.Items[0].Destination != "newest.example" ||
		firstPage.Items[0].SourceIP != "203.0.113.10" ||
		firstPage.Items[0].UploadBytes != 300 ||
		firstPage.Items[0].DownloadBytes != 600 {
		t.Fatalf(
			"unexpected first item: %+v",
			firstPage.Items[0],
		)
	}

	secondPage, err := service.ListByClientID(
		client.Id,
		2,
		1,
	)
	if err != nil {
		t.Fatalf("list second page: %v", err)
	}

	if len(secondPage.Items) != 1 ||
		secondPage.Items[0].Destination != "older.example" {
		t.Fatalf(
			"unexpected second page: %+v",
			secondPage,
		)
	}
}

func TestClientActivityListDefaultsWhenNotConfigured(
	t *testing.T,
) {
	dbPath := filepath.Join(
		t.TempDir(),
		"client-activity-empty.db",
	)

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	result, err := (&ClientActivityService{}).
		ListByClientID(999, 0, 9999)
	if err != nil {
		t.Fatalf("list unconfigured client: %v", err)
	}

	if result.Enabled ||
		result.Generation != 0 ||
		result.DataEpoch != 1 ||
		result.Total != 0 ||
		result.Page != 1 ||
		result.PageSize != maxClientActivityPageSize ||
		len(result.Items) != 0 {
		t.Fatalf(
			"unexpected default response: %+v",
			result,
		)
	}
}
