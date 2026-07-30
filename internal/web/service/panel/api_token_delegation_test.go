package panel

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/crypto"
)

func initDelegatedAPITokenTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	if err := database.InitDB(filepath.Join(dir, "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })
}

func seedDelegatedAPITokenSubject(t *testing.T, username string) (*model.User, *model.AdminRole) {
	t.Helper()
	db := database.GetDB()
	var role model.AdminRole
	if err := db.Where("owner_role = ?", false).Order("id ASC").First(&role).Error; err != nil {
		t.Fatalf("load non-owner role: %v", err)
	}
	user := &model.User{
		Username: username,
		Password: "test-password-hash",
		Status:   model.AdminStatusActive,
		RoleId:   role.Id,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create delegated subject: %v", err)
	}
	return user, &role
}

func TestApiTokenServiceCreateAndAuthenticateDelegated(t *testing.T) {
	initDelegatedAPITokenTestDB(t)
	subject, role := seedDelegatedAPITokenSubject(t, "delegated-token-operator")

	service := &ApiTokenService{}
	expiresAt := time.Now().Add(2 * time.Hour).Unix()
	view, err := service.CreateWithOptions(ApiTokenCreateOptions{
		Name:             "telegram automation",
		Kind:             model.ApiTokenKindDelegated,
		SubjectAdminId:   subject.Id,
		CreatedByAdminId: 1,
		Scopes: []string{
			ApiTokenScopeClientsRead,
			ApiTokenScopeClientsCreate,
			ApiTokenScopeClientsRead,
		},
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("CreateWithOptions: %v", err)
	}
	if !strings.HasPrefix(view.Token, "hmd_d_") {
		t.Fatalf("token prefix = %q, want hmd_d_", view.Token)
	}
	if view.SubjectAdminId == nil || *view.SubjectAdminId != subject.Id {
		t.Fatalf("subject = %v, want %d", view.SubjectAdminId, subject.Id)
	}
	if view.SubjectUsername != subject.Username || view.SubjectRoleName != role.Name {
		t.Fatalf("subject metadata = %q/%q, want %q/%q", view.SubjectUsername, view.SubjectRoleName, subject.Username, role.Name)
	}
	wantScopes := []string{ApiTokenScopeClientsCreate, ApiTokenScopeClientsRead}
	if !reflect.DeepEqual(view.Scopes, wantScopes) {
		t.Fatalf("scopes = %#v, want %#v", view.Scopes, wantScopes)
	}

	var stored model.ApiToken
	if err := database.GetDB().Where("id = ?", view.Id).First(&stored).Error; err != nil {
		t.Fatalf("load stored token: %v", err)
	}
	if stored.Token == view.Token || stored.Token != crypto.HashTokenSHA256(view.Token) {
		t.Fatalf("token was not stored as its SHA-256 digest")
	}

	auth, err := service.Authenticate(view.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if auth.Kind != model.ApiTokenKindDelegated || auth.Subject == nil || auth.Subject.Id != subject.Id {
		t.Fatalf("authentication = kind %q subject %#v", auth.Kind, auth.Subject)
	}
	if !reflect.DeepEqual(auth.Scopes, wantScopes) {
		t.Fatalf("authenticated scopes = %#v, want %#v", auth.Scopes, wantScopes)
	}

	rows, err := service.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 || rows[0].Token != "" || rows[0].SubjectUsername != subject.Username {
		t.Fatalf("list view unexpectedly exposed or lost metadata: %#v", rows)
	}
}

func TestApiTokenServiceDelegatedSubjectStateIsDynamic(t *testing.T) {
	initDelegatedAPITokenTestDB(t)
	subject, _ := seedDelegatedAPITokenSubject(t, "delegated-token-dynamic")
	service := &ApiTokenService{}
	view, err := service.CreateWithOptions(ApiTokenCreateOptions{
		Name:           "dynamic subject",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: subject.Id,
		Scopes:         []string{ApiTokenScopeClientsCreate},
	})
	if err != nil {
		t.Fatalf("CreateWithOptions: %v", err)
	}
	if _, err := service.Authenticate(view.Token); err != nil {
		t.Fatalf("initial Authenticate: %v", err)
	}

	if err := database.GetDB().Model(&model.User{}).
		Where("id = ?", subject.Id).
		Update("status", model.AdminStatusDisabled).Error; err != nil {
		t.Fatalf("disable subject: %v", err)
	}
	if _, err := service.Authenticate(view.Token); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("disabled subject error = %v, want ErrInvalidAPIToken", err)
	}

	var ownerRole model.AdminRole
	if err := database.GetDB().Where("owner_role = ?", true).First(&ownerRole).Error; err != nil {
		t.Fatalf("load owner role: %v", err)
	}
	if err := database.GetDB().Model(&model.User{}).
		Where("id = ?", subject.Id).
		Updates(map[string]any{
			"status":  model.AdminStatusActive,
			"role_id": ownerRole.Id,
		}).Error; err != nil {
		t.Fatalf("promote delegated subject to owner: %v", err)
	}
	if _, err := service.Authenticate(view.Token); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("promoted owner subject error = %v, want ErrInvalidAPIToken", err)
	}
}

func TestApiTokenServiceRejectsExpiredAndOwnerDelegation(t *testing.T) {
	initDelegatedAPITokenTestDB(t)
	service := &ApiTokenService{}

	var ownerRole model.AdminRole
	if err := database.GetDB().Where("owner_role = ?", true).First(&ownerRole).Error; err != nil {
		t.Fatalf("load owner role: %v", err)
	}
	var owner model.User
	if err := database.GetDB().Where("role_id = ?", ownerRole.Id).First(&owner).Error; err != nil {
		t.Fatalf("load owner: %v", err)
	}
	if _, err := service.CreateWithOptions(ApiTokenCreateOptions{
		Name:           "owner delegation forbidden",
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: owner.Id,
		Scopes:         []string{ApiTokenScopeClientsCreate},
	}); err == nil {
		t.Fatal("owner delegated token creation succeeded, want rejection")
	}

	const plaintext = "expired-delegated-token"
	subject, _ := seedDelegatedAPITokenSubject(t, "expired-token-subject")
	scopesJSON := `["clients:create"]`
	row := &model.ApiToken{
		Name:           "expired delegated",
		Token:          crypto.HashTokenSHA256(plaintext),
		Kind:           model.ApiTokenKindDelegated,
		SubjectAdminId: &subject.Id,
		ScopesJSON:     scopesJSON,
		ExpiresAt:      time.Now().Add(-time.Minute).Unix(),
		Enabled:        true,
	}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed expired token: %v", err)
	}
	if _, err := service.Authenticate(plaintext); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("expired token error = %v, want ErrInvalidAPIToken", err)
	}
}

func TestApiTokenServiceLegacyServiceCompatibilityAndIndex(t *testing.T) {
	initDelegatedAPITokenTestDB(t)
	service := &ApiTokenService{}
	const plaintext = "legacy-service-token"
	row := &model.ApiToken{
		Name:    "legacy service",
		Token:   crypto.HashTokenSHA256(plaintext),
		Enabled: true,
	}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed legacy service token: %v", err)
	}
	// Simulate a row created before the kind column existed. AutoMigrate assigns
	// the service default to real legacy rows; blank remains accepted defensively.
	if err := database.GetDB().Model(&model.ApiToken{}).
		Where("id = ?", row.Id).
		UpdateColumn("kind", "").Error; err != nil {
		t.Fatalf("blank legacy kind: %v", err)
	}

	auth, err := service.Authenticate(plaintext)
	if err != nil {
		t.Fatalf("Authenticate legacy service token: %v", err)
	}
	if auth.Kind != model.ApiTokenKindService || auth.Subject != nil || !reflect.DeepEqual(auth.Scopes, []string{"*"}) {
		t.Fatalf("legacy auth = %#v", auth)
	}
	if !database.GetDB().Migrator().HasIndex(&model.ApiToken{}, "idx_api_tokens_token_hash") {
		t.Fatal("token hash lookup index is missing")
	}
}

func TestApiTokenServiceRejectsAmbiguousDigest(t *testing.T) {
	initDelegatedAPITokenTestDB(t)
	const plaintext = "manually-duplicated-token"
	hash := crypto.HashTokenSHA256(plaintext)
	rows := []model.ApiToken{
		{Name: "duplicate-a", Token: hash, Kind: model.ApiTokenKindService, Enabled: true},
		{Name: "duplicate-b", Token: hash, Kind: model.ApiTokenKindService, Enabled: true},
	}
	if err := database.GetDB().Create(&rows).Error; err != nil {
		t.Fatalf("seed duplicate digests: %v", err)
	}
	if _, err := (&ApiTokenService{}).Authenticate(plaintext); !errors.Is(err, ErrInvalidAPIToken) {
		t.Fatalf("duplicate digest error = %v, want ErrInvalidAPIToken", err)
	}
}

func TestApiTokenServiceListsOnlyActiveNonOwnerSubjects(t *testing.T) {
	initDelegatedAPITokenTestDB(t)
	active, role := seedDelegatedAPITokenSubject(t, "subject-active")
	disabled := &model.User{
		Username: "subject-disabled",
		Password: "test-password-hash",
		Status:   model.AdminStatusDisabled,
		RoleId:   role.Id,
	}
	if err := database.GetDB().Create(disabled).Error; err != nil {
		t.Fatalf("create disabled subject: %v", err)
	}

	rows, err := (&ApiTokenService{}).ListDelegatedSubjects()
	if err != nil {
		t.Fatalf("ListDelegatedSubjects: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("subject count = %d, want 1: %#v", len(rows), rows)
	}
	if rows[0].Id != active.Id || rows[0].Username != active.Username || rows[0].RoleId != role.Id || rows[0].RoleName != role.Name {
		t.Fatalf("subject row = %#v, want active non-owner %d", rows[0], active.Id)
	}
}
