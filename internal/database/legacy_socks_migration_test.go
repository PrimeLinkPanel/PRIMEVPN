package database

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMigrateLegacySocksInboundsToMixed(t *testing.T) {
	previousDB := db
	t.Cleanup(func() { db = previousDB })

	testDB, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "migration.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open temporary sqlite database: %v", err)
	}
	db = testDB
	if err := db.AutoMigrate(&model.Inbound{}); err != nil {
		t.Fatalf("migrate temporary inbound schema: %v", err)
	}

	rows := []*model.Inbound{
		{Tag: "legacy-socks", Port: 1080, Protocol: model.Protocol("socks")},
		{Tag: "already-mixed", Port: 1081, Protocol: model.Mixed},
		{Tag: "unrelated-vless", Port: 443, Protocol: model.VLESS},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed protocol rows: %v", err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := migrateLegacySocksInboundsToMixed(); err != nil {
			t.Fatalf("migration attempt %d: %v", attempt, err)
		}
	}

	var got []model.Inbound
	if err := db.Order("id ASC").Find(&got).Error; err != nil {
		t.Fatalf("load migrated rows: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("row count = %d, want 3", len(got))
	}
	want := []model.Protocol{model.Mixed, model.Mixed, model.VLESS}
	for i := range want {
		if got[i].Protocol != want[i] {
			t.Errorf("row %d protocol = %q, want %q", i, got[i].Protocol, want[i])
		}
	}
}
