package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientActivityLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "activity-test.db")

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	db := database.GetDB()

	client := model.ClientRecord{
		Email:  "activity-test-client",
		Enable: true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	if !db.Migrator().HasTable(&model.ClientActivitySetting{}) {
		t.Fatal("client_activity_settings table was not migrated")
	}
	if !db.Migrator().HasTable(&model.ClientActivityDestination{}) {
		t.Fatal("client_activity_destinations table was not migrated")
	}

	activity := &ClientActivityService{}

	initial, err := activity.StatusByEmail(client.Email)
	if err != nil {
		t.Fatalf("initial status: %v", err)
	}
	if initial.Enabled {
		t.Fatal("monitoring must be disabled by default")
	}
	if initial.Generation != 0 || initial.DataEpoch != 1 {
		t.Fatalf("unexpected initial state: %+v", initial)
	}

	started, err := activity.SetMonitoringByEmail(client.Email, true)
	if err != nil {
		t.Fatalf("start monitoring: %v", err)
	}
	if !started.Enabled || started.Generation != 1 || started.DataEpoch != 1 {
		t.Fatalf("unexpected started state: %+v", started)
	}

	startedAgain, err := activity.SetMonitoringByEmail(client.Email, true)
	if err != nil {
		t.Fatalf("repeat start monitoring: %v", err)
	}
	if !startedAgain.Enabled ||
		startedAgain.Generation != 1 ||
		startedAgain.DataEpoch != 1 {
		t.Fatalf("repeat start changed state: %+v", startedAgain)
	}

	destination := model.ClientActivityDestination{
		ClientID:      client.Id,
		DataEpoch:     started.DataEpoch,
		SourceIP:      "203.0.113.10",
		Destination:   "example.com",
		UploadBytes:   123,
		DownloadBytes: 456,
		LastSeen:      time.Now().UnixMilli(),
	}
	if err := db.Create(&destination).Error; err != nil {
		t.Fatalf("create activity destination: %v", err)
	}

	reset, err := activity.ResetByEmail(client.Email)
	if err != nil {
		t.Fatalf("reset activity: %v", err)
	}
	if !reset.Enabled {
		t.Fatal("reset must not disable monitoring")
	}
	if reset.Generation != 2 || reset.DataEpoch != 2 {
		t.Fatalf("unexpected reset state: %+v", reset)
	}

	var count int64
	if err := db.
		Model(&model.ClientActivityDestination{}).
		Where("client_id = ?", client.Id).
		Count(&count).
		Error; err != nil {
		t.Fatalf("count activity destinations: %v", err)
	}
	if count != 0 {
		t.Fatalf("reset left %d destination rows", count)
	}

	stopped, err := activity.SetMonitoringByEmail(client.Email, false)
	if err != nil {
		t.Fatalf("stop monitoring: %v", err)
	}
	if stopped.Enabled || stopped.Generation != 3 || stopped.DataEpoch != 2 {
		t.Fatalf("unexpected stopped state: %+v", stopped)
	}

	stoppedAgain, err := activity.SetMonitoringByEmail(client.Email, false)
	if err != nil {
		t.Fatalf("repeat stop monitoring: %v", err)
	}
	if stoppedAgain.Enabled ||
		stoppedAgain.Generation != 3 ||
		stoppedAgain.DataEpoch != 2 {
		t.Fatalf("repeat stop changed state: %+v", stoppedAgain)
	}

	restarted, err := activity.SetMonitoringByEmail(client.Email, true)
	if err != nil {
		t.Fatalf("restart monitoring: %v", err)
	}
	if !restarted.Enabled ||
		restarted.Generation != 4 ||
		restarted.DataEpoch != 2 {
		t.Fatalf("unexpected restarted state: %+v", restarted)
	}
}
