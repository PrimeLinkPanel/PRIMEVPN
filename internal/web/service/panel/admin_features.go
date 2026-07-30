package panel

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	core "github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"

	"gorm.io/gorm"
)

func AdminIsLimited(user *model.User) bool {
	return user != nil && user.DataLimit > 0 && user.UsedBytes >= user.DataLimit
}

func adminRoleForFeatures(db *gorm.DB, roleID int) (*model.AdminRole, error) {
	if db == nil || roleID <= 0 {
		return nil, gorm.ErrRecordNotFound
	}

	var role model.AdminRole
	if err := db.Where("id = ?", roleID).First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

func roleFeatureBoolValue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "1", "on", "enabled", "all":
			return true
		}
	case float64:
		return t != 0
	case int:
		return t != 0
	}
	return false
}

func AdminRoleFeatureEnabled(role *model.AdminRole, key string) bool {
	if role == nil || strings.TrimSpace(key) == "" {
		return false
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(role.FeaturesJSON), &root); err != nil {
		return false
	}

	return roleFeatureBoolValue(root[key])
}

func adminRoleFeatureEnabledByID(db *gorm.DB, roleID int, key string) bool {
	role, err := adminRoleForFeatures(db, roleID)
	if err != nil {
		return false
	}
	return AdminRoleFeatureEnabled(role, key)
}

func EnforceLimitedAdminFeatures(user *model.User) error {
	if !AdminIsLimited(user) {
		return nil
	}

	db := database.GetDB()
	role, err := adminRoleForFeatures(db, user.RoleId)
	if err != nil {
		return nil
	}

	if role.OwnerRole {
		return nil
	}

	if AdminRoleFeatureEnabled(role, "disconnectUsersWhenLimited") {
		needRestart, _, disErr := (&core.InboundService{}).DisableClientsByOwnerAdminID(user.Id)
		if disErr != nil {
			return disErr
		}
		if needRestart {
			(&core.XrayService{}).SetToNeedRestart()
		}
	}

	if AdminRoleFeatureEnabled(role, "blockLimitedAdmins") {
		return errors.New("admin account is limited")
	}

	return nil
}
