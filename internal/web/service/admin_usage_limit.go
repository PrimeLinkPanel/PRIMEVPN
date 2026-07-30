package service

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"

	"gorm.io/gorm"
)

type adminUsageByOwnerRow struct {
	AdminID   int   `gorm:"column:admin_id"`
	UsedBytes int64 `gorm:"column:used_bytes"`
}

func adminUsageByOwnerID(db *gorm.DB) (map[int]int64, error) {
	out := map[int]int64{}
	if db == nil {
		return out, errors.New("database is not initialized")
	}

	var rows []adminUsageByOwnerRow
	if err := db.Table("clients AS c").
		Select("c.owner_admin_id AS admin_id, COALESCE(SUM(COALESCE(ct.up, 0) + COALESCE(ct.down, 0)), 0) AS used_bytes").
		Joins("LEFT JOIN client_traffics AS ct ON ct.email = c.email").
		Where("c.owner_admin_id > 0").
		Group("c.owner_admin_id").
		Scan(&rows).Error; err != nil {
		return out, err
	}

	for _, row := range rows {
		if row.AdminID > 0 {
			out[row.AdminID] = row.UsedBytes
		}
	}
	return out, nil
}

func addAdminUsedBytesByClientEmail(tx *gorm.DB, email string, delta int64) error {
	if tx == nil || delta <= 0 || strings.TrimSpace(email) == "" {
		return nil
	}

	return tx.Exec(
		`UPDATE users
		 SET used_bytes = COALESCE(used_bytes, 0) + ?
		 WHERE id = (
			 SELECT owner_admin_id
			 FROM clients
			 WHERE email = ? AND owner_admin_id > 0
			 LIMIT 1
		 )`,
		delta, strings.TrimSpace(email),
	).Error
}

func (s *InboundService) SyncAdminUsedBytes() (map[int]int64, error) {
	db := database.GetDB()
	if db == nil {
		return nil, errors.New("database is not initialized")
	}

	usageByAdmin, err := adminUsageByOwnerID(db)
	if err != nil {
		return nil, err
	}

	var users []model.User
	if err := db.Model(&model.User{}).Select("id", "used_bytes").Find(&users).Error; err != nil {
		return nil, err
	}

	for _, user := range users {
		used := user.UsedBytes
		if currentLiveUsed := usageByAdmin[user.Id]; currentLiveUsed > used {
			used = currentLiveUsed
		}
		if used < 0 {
			used = 0
		}
		usageByAdmin[user.Id] = used
		if user.UsedBytes == used {
			continue
		}
		if err := db.Model(&model.User{}).
			Where("id = ?", user.Id).
			Update("used_bytes", used).Error; err != nil {
			return nil, err
		}
	}

	return usageByAdmin, nil
}

func (s *InboundService) SyncAndEnforceAdminUsageLimits() (bool, bool, error) {
	db := database.GetDB()
	if db == nil {
		return false, false, errors.New("database is not initialized")
	}

	if _, err := s.SyncAdminUsedBytes(); err != nil {
		return false, false, err
	}

	var limitedUsers []model.User
	if err := db.Model(&model.User{}).
		Where("data_limit > 0 AND used_bytes >= data_limit").
		Find(&limitedUsers).Error; err != nil {
		return false, false, err
	}
	if len(limitedUsers) == 0 {
		return false, false, nil
	}

	roleIDs := make([]int, 0, len(limitedUsers))
	seenRoleIDs := map[int]struct{}{}
	for _, user := range limitedUsers {
		if user.RoleId <= 0 {
			continue
		}
		if _, seen := seenRoleIDs[user.RoleId]; seen {
			continue
		}
		seenRoleIDs[user.RoleId] = struct{}{}
		roleIDs = append(roleIDs, user.RoleId)
	}

	rolesByID := map[int]model.AdminRole{}
	if len(roleIDs) > 0 {
		var roles []model.AdminRole
		if err := db.Model(&model.AdminRole{}).Where("id IN ?", roleIDs).Find(&roles).Error; err != nil {
			return false, false, err
		}
		for _, role := range roles {
			rolesByID[role.Id] = role
		}
	}

	needRestart := false
	clientsDisabled := false
	for _, user := range limitedUsers {
		role, ok := rolesByID[user.RoleId]
		if !ok || role.OwnerRole {
			continue
		}

		if adminUsageRoleFeatureEnabled(&role, "disconnectUsersWhenLimited") {
			restart, disabled, err := s.DisableClientsByOwnerAdminID(user.Id)
			if err != nil {
				return needRestart, clientsDisabled, err
			}
			if disabled > 0 {
				clientsDisabled = true
				logger.Warning("Admin usage limit reached; disabled owned clients for admin:", user.Username, "disabled:", disabled)
			}
			if restart {
				needRestart = true
			}
		}

		if adminUsageRoleFeatureEnabled(&role, "blockLimitedAdmins") && user.Status != model.AdminStatusDisabled {
			if err := db.Model(&model.User{}).
				Where("id = ?", user.Id).
				Updates(map[string]any{
					"status":      model.AdminStatusDisabled,
					"login_epoch": gorm.Expr("login_epoch + 1"),
				}).Error; err != nil {
				return needRestart, clientsDisabled, err
			}
			logger.Warning("Admin usage limit reached; disabled admin account:", user.Username)
		}
	}

	return needRestart, clientsDisabled, nil
}

func adminUsageRoleFeatureEnabled(role *model.AdminRole, key string) bool {
	if role == nil || strings.TrimSpace(role.FeaturesJSON) == "" {
		return false
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(role.FeaturesJSON), &root); err != nil {
		return false
	}

	return adminUsageBoolish(root[key])
}

func adminUsageBoolish(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		return err == nil && parsed
	case float64:
		return value != 0
	case int:
		return value != 0
	case int64:
		return value != 0
	case json.Number:
		i, err := value.Int64()
		return err == nil && i != 0
	default:
		return false
	}
}
