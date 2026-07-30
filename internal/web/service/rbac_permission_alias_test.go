package service

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientAccessModeFromScopedPermission(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want ClientAccessMode
	}{
		{name: "scope all", in: map[string]any{"scope": float64(2)}, want: ClientAccessAll},
		{name: "scope own", in: map[string]any{"scope": float64(1)}, want: ClientAccessOwn},
		{name: "scope none", in: map[string]any{"scope": float64(0)}, want: ClientAccessNone},
		{name: "string all", in: "all", want: ClientAccessAll},
		{name: "bool true", in: true, want: ClientAccessAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientAccessModeFromPermission(tt.in); got != tt.want {
				t.Fatalf("clientAccessModeFromPermission(%#v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestInboundRolePermissionAliases(t *testing.T) {
	role := &model.AdminRole{PermissionsJSON: `{
		"inbounds": {
			"read_simple": {"scope": 2},
			"reset_usage": true
		}
	}`}

	if !roleJSONPermissionAllowed(role, "inbounds", "viewSimple") {
		t.Fatal("expected inbounds.read_simple to allow inbounds.viewSimple")
	}
	if !roleJSONPermissionAllowed(role, "inbounds", "resetUsage") {
		t.Fatal("expected inbounds.reset_usage to allow inbounds.resetUsage")
	}
}

func TestInboundRolePermissionDoesNotUseUserPermissions(t *testing.T) {
	role := &model.AdminRole{PermissionsJSON: `{
		"users": {
			"create": true,
			"update": {"scope": 2}
		}
	}`}

	if roleJSONPermissionAllowed(role, "inbounds", "viewSimple") {
		t.Fatal("users.create/update must not implicitly grant inbound visibility")
	}
}
