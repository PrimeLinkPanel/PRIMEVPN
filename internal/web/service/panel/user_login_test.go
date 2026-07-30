package panel

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/crypto"

	"gorm.io/gorm"
)

func seedLoginTestUser(t *testing.T, username, password, status string) {
	t.Helper()

	hash, err := crypto.HashPasswordAsBcrypt(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if err := database.GetDB().Create(&model.User{
		Username: username,
		Password: hash,
		Status:   status,
	}).Error; err != nil {
		t.Fatalf("create test user %q: %v", username, err)
	}
}

func TestCheckUserAllowsActiveAdmin(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	const username = "active-admin-login-test"
	const password = "correct-password"

	seedLoginTestUser(t, username, password, model.AdminStatusActive)

	user, err := (&UserService{}).CheckUser(username, password, "")
	if err != nil {
		t.Fatalf("CheckUser active admin returned error: %v", err)
	}
	if user == nil {
		t.Fatal("CheckUser active admin returned nil user")
	}
	if user.Username != username {
		t.Fatalf("Username = %q, want %q", user.Username, username)
	}
}

func TestCheckUserRejectsDisabledAdmin(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	const username = "disabled-admin-login-test"
	const password = "correct-password"

	seedLoginTestUser(t, username, password, model.AdminStatusDisabled)

	user, err := (&UserService{}).CheckUser(username, password, "")
	if user != nil {
		t.Fatalf("CheckUser disabled admin returned user: %#v", user)
	}
	if err == nil {
		t.Fatal("CheckUser disabled admin returned nil error")
	}
	if err.Error() != "admin account is disabled" {
		t.Fatalf("error = %q, want disabled-account error", err.Error())
	}
}

func TestCheckUserRejectsUnknownAdmin(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	user, err := (&UserService{}).CheckUser("missing-admin-login-test", "password", "")
	if user != nil {
		t.Fatalf("CheckUser unknown admin returned user: %#v", user)
	}
	if err == nil {
		t.Fatal("CheckUser unknown admin returned nil error")
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("CheckUser leaked gorm not-found error: %v", err)
	}
}

func TestCheckUserRejectsLimitedAdminWhenBlockFeatureEnabled(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	const username = "limited-admin-login-test"
	const password = "correct-password"

	role := model.AdminRole{
		Name:            "limited-login-role",
		Slug:            "limited-login-role",
		PermissionsJSON: `{}`,
		LimitsJSON:      `{}`,
		FeaturesJSON:    `{"blockLimitedAdmins":true}`,
		AccessJSON:      `{}`,
	}
	if err := database.GetDB().Create(&role).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}

	hash, err := crypto.HashPasswordAsBcrypt(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if err := database.GetDB().Create(&model.User{
		Username:  username,
		Password:  hash,
		Status:    model.AdminStatusActive,
		RoleId:    role.Id,
		DataLimit: 100,
		UsedBytes: 100,
	}).Error; err != nil {
		t.Fatalf("create limited user: %v", err)
	}

	user, err := (&UserService{}).CheckUser(username, password, "")
	if user != nil {
		t.Fatalf("CheckUser limited admin returned user: %#v", user)
	}
	if err == nil {
		t.Fatal("CheckUser limited admin returned nil error")
	}
	if err.Error() != "admin account is limited" {
		t.Fatalf("error = %q, want limited-account error", err.Error())
	}
}
