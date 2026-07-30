package job

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientActivityCollectorPersistsValidatedDatagrams(
	t *testing.T,
) {
	dbPath := filepath.Join(
		t.TempDir(),
		"client-activity-collector.db",
	)

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	db := database.GetDB()

	client := model.ClientRecord{
		Email:  "activity-collector-client",
		Enable: true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	setting := model.ClientActivitySetting{
		ClientID:   client.Id,
		Enabled:    true,
		Generation: 5,
		DataEpoch:  2,
	}
	if err := db.Create(&setting).Error; err != nil {
		t.Fatalf("create Activity setting: %v", err)
	}

	socketPath := filepath.Join(
		t.TempDir(),
		"client-activity.sock",
	)

	collector := newClientActivityCollector(
		socketPath,
		20*time.Millisecond,
		64,
	)

	if err := collector.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	t.Cleanup(collector.Stop)

	address := &net.UnixAddr{
		Name: socketPath,
		Net:  "unixgram",
	}

	connection, err := net.DialUnix(
		"unixgram",
		nil,
		address,
	)
	if err != nil {
		t.Fatalf("dial collector: %v", err)
	}
	defer connection.Close()

	send := func(event clientActivityEvent) {
		t.Helper()

		data, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}

		if _, err := connection.Write(data); err != nil {
			t.Fatalf("send event: %v", err)
		}
	}

	now := time.Now().UnixMilli()

	baseEvent := clientActivityEvent{
		Version:       1,
		ClientID:      client.Id,
		Email:         client.Email,
		Generation:    5,
		DataEpoch:     2,
		SourceIP:      "203.0.113.20",
		Destination:   "Example.COM.",
		UploadBytes:   100,
		DownloadBytes: 200,
		ObservedAt:    now,
	}

	send(baseEvent)

	secondEvent := baseEvent
	secondEvent.UploadBytes = 30
	secondEvent.DownloadBytes = 60
	secondEvent.ObservedAt = now + 1
	send(secondEvent)

	staleEvent := baseEvent
	staleEvent.Generation = 4
	staleEvent.UploadBytes = 5000
	staleEvent.DownloadBytes = 5000
	send(staleEvent)

	deadline := time.Now().Add(3 * time.Second)

	for {
		var row model.ClientActivityDestination

		err := db.
			Where(
				"client_id = ? AND data_epoch = ? AND source_ip = ? AND destination = ?",
				client.Id,
				2,
				"203.0.113.20",
				"example.com",
			).
			First(&row).
			Error

		if err == nil &&
			row.UploadBytes == 130 &&
			row.DownloadBytes == 260 {
			if row.LastSeen != now+1 {
				t.Fatalf(
					"last seen = %d, want %d",
					row.LastSeen,
					now+1,
				)
			}
			break
		}

		if time.Now().After(deadline) {
			t.Fatalf(
				"collector did not persist expected aggregation; row=%+v err=%v",
				row,
				err,
			)
		}

		time.Sleep(20 * time.Millisecond)
	}

	var count int64
	if err := db.
		Model(&model.ClientActivityDestination{}).
		Where("client_id = ?", client.Id).
		Count(&count).
		Error; err != nil {
		t.Fatalf("count destination rows: %v", err)
	}

	if count != 1 {
		t.Fatalf(
			"destination row count = %d, want 1",
			count,
		)
	}
}

func TestClientActivityCollectorRejectsNonSocketCollision(
	t *testing.T,
) {
	path := filepath.Join(
		t.TempDir(),
		"client-activity.sock",
	)

	if err := os.WriteFile(
		path,
		[]byte("protected"),
		0o600,
	); err != nil {
		t.Fatalf("create collision file: %v", err)
	}

	collector := newClientActivityCollector(
		path,
		20*time.Millisecond,
		8,
	)

	if err := collector.Start(); err == nil {
		collector.Stop()
		t.Fatal(
			"collector replaced a non-socket filesystem entry",
		)
	}
}
