package service

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestRoleGroupAccessScopeSnakeCaseNullAllowsAll(t *testing.T) {
	role := &model.AdminRole{AccessJSON: `{"allowed_group_ids": null}`}

	restrict, allowAll, groups := roleGroupAccessScope(role)
	if !restrict || !allowAll || len(groups) != 0 {
		t.Fatalf("roleGroupAccessScope() = restrict=%v allowAll=%v groups=%v, want restricted allow-all with no groups", restrict, allowAll, groups)
	}
}

func TestRoleGroupAccessScopeSnakeCaseEmptyAllowsAll(t *testing.T) {
	role := &model.AdminRole{AccessJSON: `{"allowed_group_ids": []}`}

	restrict, allowAll, groups := roleGroupAccessScope(role)
	if !restrict || !allowAll || len(groups) != 0 {
		t.Fatalf("roleGroupAccessScope() = restrict=%v allowAll=%v groups=%v, want restricted allow-all with no groups", restrict, allowAll, groups)
	}
}

func TestRoleGroupAccessScopeLegacyAllowAll(t *testing.T) {
	role := &model.AdminRole{AccessJSON: `{"allowAllGroups": true, "allowedGroups": []}`}

	restrict, allowAll, groups := roleGroupAccessScope(role)
	if !restrict || !allowAll || len(groups) != 0 {
		t.Fatalf("roleGroupAccessScope() = restrict=%v allowAll=%v groups=%v, want legacy allow-all", restrict, allowAll, groups)
	}
}

func TestRoleGroupAccessScopeLegacyRestrictedNames(t *testing.T) {
	role := &model.AdminRole{AccessJSON: `{"allowAllGroups": false, "allowedGroups": ["VIP", " support "]}`}

	restrict, allowAll, groups := roleGroupAccessScope(role)
	if !restrict || allowAll {
		t.Fatalf("roleGroupAccessScope() = restrict=%v allowAll=%v groups=%v, want restricted groups", restrict, allowAll, groups)
	}
	if len(groups) != 2 || groups[0] != "vip" || groups[1] != "support" {
		t.Fatalf("groups = %#v, want normalized vip/support", groups)
	}
}

func TestRoleGroupAccessScopeMissingAccessDefaultsToAllowAll(t *testing.T) {
	role := &model.AdminRole{AccessJSON: `{}`}

	restrict, allowAll, groups := roleGroupAccessScope(role)
	if !restrict || !allowAll || len(groups) != 0 {
		t.Fatalf("roleGroupAccessScope() = restrict=%v allowAll=%v groups=%v, want default allow-all", restrict, allowAll, groups)
	}
}
