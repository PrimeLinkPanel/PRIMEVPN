package database

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestBackfillLegacyClientsToOwnerAssignsOnlyUnowned(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	var owner model.User
	if err := db.Table("users AS u").
		Select("u.*").
		Joins("JOIN admin_roles AS r ON r.id = u.role_id").
		Where("r.owner_role = ?", true).
		Order("u.id ASC").
		First(&owner).Error; err != nil {
		t.Fatalf("find owner: %v", err)
	}
	if owner.Id <= 0 {
		t.Fatalf("owner id not resolved")
	}

	var adminRole model.AdminRole
	if err := db.Where("slug = ?", model.AdminRoleSlugAdministrator).First(&adminRole).Error; err != nil {
		t.Fatalf("find administrator role: %v", err)
	}

	admin := model.User{
		Username: "administrator",
		Status:   model.AdminStatusActive,
		RoleId:   adminRole.Id,
	}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("create administrator: %v", err)
	}

	legacy := model.ClientRecord{
		Email:            "legacy@example.com",
		Enable:           true,
		OwnerAdminId:     0,
		CreatedByAdminId: 0,
	}
	owned := model.ClientRecord{
		Email:            "owned@example.com",
		Enable:           true,
		OwnerAdminId:     admin.Id,
		CreatedByAdminId: admin.Id,
	}

	if err := db.Create(&legacy).Error; err != nil {
		t.Fatalf("create legacy client: %v", err)
	}
	if err := db.Create(&owned).Error; err != nil {
		t.Fatalf("create owned client: %v", err)
	}

	if err := backfillLegacyClientsToOwner(); err != nil {
		t.Fatalf("backfill first run: %v", err)
	}

	var total int64
	if err := db.Model(&model.ClientRecord{}).Count(&total).Error; err != nil {
		t.Fatalf("count clients: %v", err)
	}
	if total != 2 {
		t.Fatalf("client count changed: got %d want 2", total)
	}

	var gotLegacy model.ClientRecord
	if err := db.Where("email = ?", legacy.Email).First(&gotLegacy).Error; err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	if gotLegacy.OwnerAdminId != owner.Id {
		t.Fatalf("legacy owner_admin_id = %d, want owner %d", gotLegacy.OwnerAdminId, owner.Id)
	}
	if gotLegacy.CreatedByAdminId != owner.Id {
		t.Fatalf("legacy created_by_admin_id = %d, want owner %d", gotLegacy.CreatedByAdminId, owner.Id)
	}

	var gotOwned model.ClientRecord
	if err := db.Where("email = ?", owned.Email).First(&gotOwned).Error; err != nil {
		t.Fatalf("load owned: %v", err)
	}
	if gotOwned.OwnerAdminId != admin.Id {
		t.Fatalf("owned owner_admin_id changed: got %d want %d", gotOwned.OwnerAdminId, admin.Id)
	}
	if gotOwned.CreatedByAdminId != admin.Id {
		t.Fatalf("owned created_by_admin_id changed: got %d want %d", gotOwned.CreatedByAdminId, admin.Id)
	}

	if err := backfillLegacyClientsToOwner(); err != nil {
		t.Fatalf("backfill second run: %v", err)
	}

	var unowned int64
	if err := db.Model(&model.ClientRecord{}).
		Where("owner_admin_id IS NULL OR owner_admin_id = ?", 0).
		Count(&unowned).Error; err != nil {
		t.Fatalf("count unowned: %v", err)
	}
	if unowned != 0 {
		t.Fatalf("unowned clients after second run = %d, want 0", unowned)
	}

	var totalAfter int64
	if err := db.Model(&model.ClientRecord{}).Count(&totalAfter).Error; err != nil {
		t.Fatalf("count clients after second run: %v", err)
	}
	if totalAfter != 2 {
		t.Fatalf("client count after second run changed: got %d want 2", totalAfter)
	}
}
