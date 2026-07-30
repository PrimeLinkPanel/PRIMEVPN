package service

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientRecordAllowedAppliesAllowedGroups(t *testing.T) {
	svc := ClientService{}

	scope := ClientAccessScope{
		AdminID:        7,
		Mode:           ClientAccessAll,
		RestrictGroups: true,
		AllowedGroups:  []string{"VIP", "Resellers"},
	}

	if !svc.ClientRecordAllowed(scope, &model.ClientRecord{Email: "vip@example.com", Group: "vip"}) {
		t.Fatal("expected client in allowed group to be visible")
	}

	if svc.ClientRecordAllowed(scope, &model.ClientRecord{Email: "public@example.com", Group: "public"}) {
		t.Fatal("expected client outside allowed group to be denied")
	}

	ownScope := ClientAccessScope{
		AdminID:        7,
		Mode:           ClientAccessOwn,
		RestrictGroups: true,
		AllowedGroups:  []string{"vip"},
	}

	if !svc.ClientRecordAllowed(ownScope, &model.ClientRecord{Email: "own@example.com", Group: "vip", OwnerAdminId: 7}) {
		t.Fatal("expected own client in allowed group to be visible")
	}

	if svc.ClientRecordAllowed(ownScope, &model.ClientRecord{Email: "other@example.com", Group: "vip", OwnerAdminId: 8}) {
		t.Fatal("expected other admin's client to be denied")
	}

	if svc.ClientRecordAllowed(ownScope, &model.ClientRecord{Email: "own-public@example.com", Group: "public", OwnerAdminId: 7}) {
		t.Fatal("expected own client outside allowed group to be denied")
	}
}

func TestClientGroupAllowedForScopeDefaultsToUnrestricted(t *testing.T) {
	if !ClientGroupAllowedForScope(ClientAccessScope{Mode: ClientAccessAll}, "any-group") {
		t.Fatal("bare all scope should remain unrestricted for legacy internal callers")
	}
}

func TestClientGroupAllowedForScopeDeniesEmptyRestrictedGroups(t *testing.T) {
	scope := ClientAccessScope{
		Mode:           ClientAccessAll,
		RestrictGroups: true,
		AllowAllGroups: false,
		AllowedGroups:  nil,
	}

	if ClientGroupAllowedForScope(scope, "vip") {
		t.Fatal("restricted scope with no allowed groups should deny all groups")
	}
}
