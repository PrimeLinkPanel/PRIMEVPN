package job

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientActivityRowsPerClientIsOneHundredThousand(
	t *testing.T,
) {
	if clientActivityRowsPerClient != 100000 {
		t.Fatalf(
			"clientActivityRowsPerClient = %d, want 100000",
			clientActivityRowsPerClient,
		)
	}
}

func TestCapClientActivityRowsKeepsNewestRowsPerClient(
	t *testing.T,
) {
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)

	if err := database.InitDB(
		filepath.Join(dbDir, "primevpn.db"),
	); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	db := database.GetDB()

	const (
		firstClientID     = 700001
		secondClientID    = 700002
		untouchedClientID = 700003
	)

	for _, clientID := range []int{
		firstClientID,
		secondClientID,
		untouchedClientID,
	} {
		rows := make(
			[]model.ClientActivityDestination,
			0,
			5,
		)

		for ordinal := 1; ordinal <= 5; ordinal++ {
			rows = append(
				rows,
				model.ClientActivityDestination{
					ClientID:  clientID,
					DataEpoch: 1,
					SourceIP: fmt.Sprintf(
						"198.51.100.%d",
						ordinal,
					),
					Destination: fmt.Sprintf(
						"destination-%d.example",
						ordinal,
					),
					UploadBytes: int64(ordinal),
					DownloadBytes: int64(
						ordinal * 10,
					),
					LastSeen: int64(ordinal),
				},
			)
		}

		if err := db.Create(&rows).Error; err != nil {
			t.Fatalf(
				"create rows for client %d: %v",
				clientID,
				err,
			)
		}
	}

	if err := capClientActivityRowsToLimit(
		db,
		[]int{
			firstClientID,
			secondClientID,
		},
		3,
	); err != nil {
		t.Fatalf(
			"capClientActivityRowsToLimit: %v",
			err,
		)
	}

	for _, clientID := range []int{
		firstClientID,
		secondClientID,
	} {
		var rows []model.ClientActivityDestination

		if err := db.
			Where("client_id = ?", clientID).
			Order("last_seen DESC").
			Order("id DESC").
			Find(&rows).
			Error; err != nil {
			t.Fatalf(
				"read rows for client %d: %v",
				clientID,
				err,
			)
		}

		if len(rows) != 3 {
			t.Fatalf(
				"client %d retained %d rows, want 3",
				clientID,
				len(rows),
			)
		}

		expected := []int64{5, 4, 3}

		for index, want := range expected {
			if rows[index].LastSeen != want {
				t.Fatalf(
					"client %d row %d lastSeen = %d, want %d",
					clientID,
					index,
					rows[index].LastSeen,
					want,
				)
			}
		}
	}

	var untouchedCount int64

	if err := db.
		Model(&model.ClientActivityDestination{}).
		Where("client_id = ?", untouchedClientID).
		Count(&untouchedCount).
		Error; err != nil {
		t.Fatalf(
			"count untouched rows: %v",
			err,
		)
	}

	if untouchedCount != 5 {
		t.Fatalf(
			"untouched client retained %d rows, want 5",
			untouchedCount,
		)
	}
}
