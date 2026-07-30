package controller

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func testRoleWithPermissions(permissions string) *model.AdminRole {
	return &model.AdminRole{PermissionsJSON: permissions}
}

func TestRoleAllowsPermissionCanonicalAliases(t *testing.T) {
	role := testRoleWithPermissions(`{
		"inbounds": {
			"read_simple": {"scope": 2},
			"reset_usage": true
		},
		"admin_roles": {
			"read": true
		},
		"users": {
			"read": {"scope": 1}
		}
	}`)

	if !roleAllowsPermission(role, "inbounds", "viewSimple") {
		t.Fatal("expected inbounds.read_simple to allow inbounds.viewSimple")
	}
	if !roleAllowsPermission(role, "inbounds", "resetUsage") {
		t.Fatal("expected inbounds.reset_usage to allow inbounds.resetUsage")
	}
	if !roleAllowsPermission(role, "roles", "view") {
		t.Fatal("expected admin_roles.read to allow roles.view")
	}
	if !roleAllowsPermission(role, "users", "view") {
		t.Fatal("expected scoped users.read to allow users.view")
	}
}

func TestRoleAllowsPermissionDoesNotInferInboundAccessFromUsers(t *testing.T) {
	role := testRoleWithPermissions(`{
		"users": {
			"create": true,
			"update": {"scope": 2}
		}
	}`)

	if roleAllowsPermission(role, "inbounds", "viewSimple") {
		t.Fatal("users.create/update must not implicitly grant inbounds.viewSimple")
	}
}
