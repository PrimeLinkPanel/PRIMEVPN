package job

import (
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestClientActivityUpsertGeneratesPostgresSafeSQL(
	t *testing.T,
) {
	db, err := gorm.Open(
		postgres.New(postgres.Config{
			DSN: "host=127.0.0.1 user=secx_test " +
				"dbname=secx_test sslmode=disable",
			PreferSimpleProtocol: true,
		}),
		&gorm.Config{
			DisableAutomaticPing: true,
		},
	)
	if err != nil {
		t.Fatalf(
			"open PostgreSQL SQL generator: %v",
			err,
		)
	}

	row := model.ClientActivityDestination{
		ClientID:      1,
		DataEpoch:     1,
		SourceIP:      "203.0.113.10",
		Destination:   "example.com",
		UploadBytes:   100,
		DownloadBytes: 200,
		LastSeen:      1_700_000_000_000,
	}

	sql := db.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.
			Clauses(clientActivityUpsertClause(tx)).
			Create(&row)
	})

	if strings.TrimSpace(sql) == "" {
		t.Fatal("GORM generated empty PostgreSQL SQL")
	}

	t.Logf("generated PostgreSQL SQL:\n%s", sql)

	lowerSQL := strings.ToLower(sql)

	requiredFragments := []string{
		"insert into",
		"on conflict",
		"do update set",
		"client_activity_destinations.upload_bytes + excluded.upload_bytes",
		"client_activity_destinations.download_bytes + excluded.download_bytes",
		"client_activity_destinations.last_seen > excluded.last_seen",
		"then client_activity_destinations.last_seen",
		"else excluded.last_seen end",
	}

	for _, fragment := range requiredFragments {
		if !strings.Contains(lowerSQL, fragment) {
			t.Fatalf(
				"generated PostgreSQL SQL is missing %q:\n%s",
				fragment,
				sql,
			)
		}
	}

	ambiguousFragments := []string{
		"upload_bytes + excluded.upload_bytes",
		"download_bytes + excluded.download_bytes",
		"case when last_seen > excluded.last_seen",
	}

	for _, fragment := range ambiguousFragments {
		qualified := "client_activity_destinations." + fragment

		if strings.Contains(lowerSQL, fragment) &&
			!strings.Contains(lowerSQL, qualified) {
			t.Fatalf(
				"generated PostgreSQL SQL contains ambiguous expression %q:\n%s",
				fragment,
				sql,
			)
		}
	}
}

func TestStopClientActivityCollectorIsIdempotent(
	t *testing.T,
) {
	StopClientActivityCollector()
	StopClientActivityCollector()
}
