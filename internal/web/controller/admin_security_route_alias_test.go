package controller

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestRoleAllowsPermissionViewGeneralAlias(t *testing.T) {
	role := &model.AdminRole{PermissionsJSON: `{"settings":{"read_general":true}}`}
	if !roleAllowsPermission(role, "settings", "viewGeneral") {
		t.Fatal("expected settings.read_general to allow settings.viewGeneral")
	}
}

func TestRoleAllowsAnyPermission(t *testing.T) {
	role := &model.AdminRole{PermissionsJSON: `{"routing":{"read":true}}`}
	if !roleAllowsAnyPermission(role,
		panelPermissionRequirement{Section: "outbounds", Permission: "view"},
		panelPermissionRequirement{Section: "routing", Permission: "view"},
	) {
		t.Fatal("expected routing.read to satisfy any-permission requirement")
	}
	if roleAllowsAnyPermission(role, panelPermissionRequirement{Section: "settings", Permission: "update"}) {
		t.Fatal("did not expect unrelated permission to satisfy any-permission requirement")
	}
}
