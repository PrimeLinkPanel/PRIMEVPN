package panel

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustEqual[T comparable](t *testing.T, want T, got T) {
	t.Helper()
	if want != got {
		t.Fatalf("want %#v, got %#v", want, got)
	}
}

func mustEqualAny(t *testing.T, want any, got any) {
	t.Helper()
	if want != got {
		t.Fatalf("want %#v, got %#v", want, got)
	}
}

func mustTrue(t *testing.T, ok bool, msg string) {
	t.Helper()
	if !ok {
		t.Fatal(msg)
	}
}

func initAdminRoleTestDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	db := database.GetDB()
	if db == nil {
		t.Fatal("database.GetDB returned nil")
	}

	mustNoErr(t, db.Exec("DELETE FROM users").Error)
	mustNoErr(t, db.Exec("DELETE FROM admin_roles").Error)

	for _, role := range model.DefaultAdminRoles() {
		row := role
		mustNoErr(t, db.Create(&row).Error)
	}
}

func TestAdminRoleServiceCreateDefaultsAllOperatorRoleMaps(t *testing.T) {
	initAdminRoleTestDB(t)

	svc := &AdminRoleService{}
	role, err := svc.Create(AdminRolePayload{Name: "Support Operator"})
	mustNoErr(t, err)

	if role == nil {
		t.Fatal("expected role, got nil")
	}
	mustEqual(t, "Support Operator", role.Name)

	permissions, ok := role.Permissions.(map[string]any)
	mustTrue(t, ok, "permissions must be map[string]any")

	limits, ok := role.Limits.(map[string]any)
	mustTrue(t, ok, "limits must be map[string]any")

	features, ok := role.Features.(map[string]any)
	mustTrue(t, ok, "features must be map[string]any")

	access, ok := role.Access.(map[string]any)
	mustTrue(t, ok, "access must be map[string]any")

	mustTrue(t, len(permissions) > 0, "permissions must not be empty")
	mustTrue(t, len(limits) > 0, "limits must not be empty")
	mustTrue(t, len(features) > 0, "features must not be empty")
	mustTrue(t, len(access) > 0, "access must not be empty")

	if _, ok := permissions["users"]; !ok {
		t.Fatal("permissions must contain users")
	}
	if _, ok := access["allowAllGroups"]; !ok {
		t.Fatal("access must contain allowAllGroups")
	}
}

func TestAdminRoleServiceUpdatePersistsRoleMaps(t *testing.T) {
	initAdminRoleTestDB(t)

	svc := &AdminRoleService{}
	role, err := svc.Create(AdminRolePayload{Name: "Limited Support"})
	mustNoErr(t, err)

	if role == nil {
		t.Fatal("expected role, got nil")
	}

	updated, err := svc.Update(role.Id, AdminRolePayload{
		Name: "Limited Support Plus",
		Permissions: map[string]any{
			"users": map[string]any{
				"view":   "own",
				"create": "none",
				"update": "own",
				"delete": "none",
			},
			"groups": map[string]any{
				"viewSimple": true,
			},
		},
		Limits: map[string]any{
			"maxUsers":      float64(25),
			"maxDataLimit":  float64(100),
			"maxExpireDays": float64(30),
			"minExpireDays": float64(1),
		},
		Features: map[string]any{
			"blockLimitedAdmins":          true,
			"disconnectUsersWhenLimited":  true,
			"disconnectUsersWhenDisabled": true,
			"useResetStrategy":            true,
			"useNextPlan":                 false,
		},
		Access: map[string]any{
			"allowAllGroups": false,
			"allowedGroups":  []any{"vip", "support"},
		},
	})
	mustNoErr(t, err)

	if updated == nil {
		t.Fatal("expected updated role, got nil")
	}
	mustEqual(t, "Limited Support Plus", updated.Name)

	fetched, err := svc.Get(role.Id)
	mustNoErr(t, err)
	mustEqual(t, "Limited Support Plus", fetched.Name)

	permissions, ok := fetched.Permissions.(map[string]any)
	mustTrue(t, ok, "permissions must be map[string]any")

	users, ok := permissions["users"].(map[string]any)
	mustTrue(t, ok, "users permissions must be map[string]any")

	mustEqualAny(t, "own", users["view"])
	mustEqualAny(t, "none", users["create"])

	limits, ok := fetched.Limits.(map[string]any)
	mustTrue(t, ok, "limits must be map[string]any")

	mustEqualAny(t, float64(25), limits["maxUsers"])
	mustEqualAny(t, float64(100), limits["maxDataLimit"])

	features, ok := fetched.Features.(map[string]any)
	mustTrue(t, ok, "features must be map[string]any")

	mustEqualAny(t, true, features["blockLimitedAdmins"])
	mustEqualAny(t, false, features["useNextPlan"])

	access, ok := fetched.Access.(map[string]any)
	mustTrue(t, ok, "access must be map[string]any")

	mustEqualAny(t, false, access["allowAllGroups"])

	allowedGroups, ok := access["allowedGroups"].([]any)
	mustTrue(t, ok, "allowedGroups must be []any")
	mustEqual(t, 2, len(allowedGroups))
}
