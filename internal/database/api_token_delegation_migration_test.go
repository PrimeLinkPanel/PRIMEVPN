package database

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestApiTokenDelegationMigrationPreservesLegacyRows(t *testing.T) {
	originalDB := db
	t.Cleanup(func() { db = originalDB })

	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := testDB.Exec(`
		CREATE TABLE api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			token TEXT NOT NULL,
			enabled NUMERIC DEFAULT 1,
			created_at INTEGER
		)
	`).Error; err != nil {
		t.Fatalf("create legacy api_tokens: %v", err)
	}
	if err := testDB.Exec(`CREATE UNIQUE INDEX idx_api_tokens_name ON api_tokens(name)`).Error; err != nil {
		t.Fatalf("create legacy token name index: %v", err)
	}
	if err := testDB.Exec(
		`INSERT INTO api_tokens(name, token, enabled, created_at) VALUES (?, ?, ?, ?)`,
		"legacy-node", "legacy-hash", true, int64(1_782_485_394),
	).Error; err != nil {
		t.Fatalf("insert legacy token: %v", err)
	}

	db = testDB
	if err := migrateApiTokenDelegationSchema(); err != nil {
		t.Fatalf("migrate delegated token columns: %v", err)
	}
	if err := migrateApiTokenDelegationSchema(); err != nil {
		t.Fatalf("repeat delegated token migration: %v", err)
	}
	var row model.ApiToken
	if err := testDB.Where("name = ?", "legacy-node").First(&row).Error; err != nil {
		t.Fatalf("load migrated legacy token: %v", err)
	}
	if row.Token != "legacy-hash" || !row.Enabled || row.CreatedAt != 1_782_485_394 {
		t.Fatalf("legacy token changed during migration: %#v", row)
	}
	if row.Kind != model.ApiTokenKindService {
		t.Fatalf("legacy kind = %q, want %q", row.Kind, model.ApiTokenKindService)
	}
	if row.SubjectAdminId != nil || row.CreatedByAdminId != nil || row.ExpiresAt != 0 {
		t.Fatalf("legacy token gained delegated metadata: %#v", row)
	}
	indexes := []string{
		"idx_api_tokens_name",
		"idx_api_tokens_token_hash",
		"idx_api_tokens_kind",
		"idx_api_tokens_subject_admin_id",
		"idx_api_tokens_created_by_admin_id",
		"idx_api_tokens_expires_at",
	}
	for _, index := range indexes {
		if !testDB.Migrator().HasIndex(&model.ApiToken{}, index) {
			t.Fatalf("index %q missing after migration", index)
		}
	}
}
