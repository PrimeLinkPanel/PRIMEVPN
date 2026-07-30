package panel

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/common"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/crypto"
	core "github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"

	"gorm.io/gorm"
)

type AdminService struct{}

type AdminPayload struct {
	Username                 string         `json:"username" form:"username"`
	Password                 string         `json:"password" form:"password"`
	RoleId                   int            `json:"roleId" form:"roleId"`
	Status                   string         `json:"status" form:"status"`
	DataLimit                int64          `json:"dataLimit" form:"dataLimit"`
	TelegramID               string         `json:"telegramId" form:"telegramId"`
	DiscordWebhook           string         `json:"discordWebhook" form:"discordWebhook"`
	SupportURL               string         `json:"supportUrl" form:"supportUrl"`
	ProfileTitle             string         `json:"profileTitle" form:"profileTitle"`
	SubscriptionDomain       string         `json:"subscriptionDomain" form:"subscriptionDomain"`
	SubscriptionTemplatePath string         `json:"subscriptionTemplatePath" form:"subscriptionTemplatePath"`
	Note                     string         `json:"note" form:"note"`
	NotificationFilters      map[string]any `json:"notificationFilters" form:"notificationFilters"`
	PermissionOverrides      map[string]any `json:"permissionOverrides" form:"permissionOverrides"`
}

type AdminView struct {
	Id                       int    `json:"id"`
	Username                 string `json:"username"`
	RoleId                   int    `json:"roleId"`
	RoleName                 string `json:"roleName"`
	RoleSlug                 string `json:"roleSlug"`
	Status                   string `json:"status"`
	DataLimit                int64  `json:"dataLimit"`
	UsedBytes                int64  `json:"usedBytes"`
	TotalUsers               int64  `json:"totalUsers"`
	TelegramID               string `json:"telegramId"`
	DiscordWebhook           string `json:"discordWebhook"`
	SupportURL               string `json:"supportUrl"`
	ProfileTitle             string `json:"profileTitle"`
	SubscriptionDomain       string `json:"subscriptionDomain"`
	SubscriptionTemplatePath string `json:"subscriptionTemplatePath"`
	Note                     string `json:"note"`
	NotificationFilters      any    `json:"notificationFilters"`
	PermissionOverrides      any    `json:"permissionOverrides"`
	CreatedAt                int64  `json:"createdAt"`
	UpdatedAt                int64  `json:"updatedAt"`
}

type AdminStats struct {
	TotalAdmins    int64 `json:"totalAdmins"`
	ActiveAdmins   int64 `json:"activeAdmins"`
	DisabledAdmins int64 `json:"disabledAdmins"`
	LimitedAdmins  int64 `json:"limitedAdmins"`
}

func marshalAdminMap(v map[string]any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeAdminJSON(raw string) any {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]any{}
	}
	return out
}

func validAdminStatus(status string) bool {
	return status == model.AdminStatusActive || status == model.AdminStatusDisabled
}

func normalizeAdminStatus(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	if status == "" {
		return model.AdminStatusActive
	}
	return status
}

func adminToView(user *model.User, role *model.AdminRole, totalUsers int64) *AdminView {
	roleName := ""
	roleSlug := ""
	if role != nil {
		roleName = role.Name
		roleSlug = role.Slug
	}
	return &AdminView{
		Id:                       user.Id,
		Username:                 user.Username,
		RoleId:                   user.RoleId,
		RoleName:                 roleName,
		RoleSlug:                 roleSlug,
		Status:                   user.Status,
		DataLimit:                user.DataLimit,
		UsedBytes:                user.UsedBytes,
		TotalUsers:               totalUsers,
		TelegramID:               user.TelegramID,
		DiscordWebhook:           user.DiscordWebhook,
		SupportURL:               user.SupportURL,
		ProfileTitle:             user.ProfileTitle,
		SubscriptionDomain:       user.SubscriptionDomain,
		SubscriptionTemplatePath: user.SubscriptionTemplatePath,
		Note:                     user.Note,
		NotificationFilters:      decodeAdminJSON(user.NotificationFiltersJSON),
		PermissionOverrides:      decodeAdminJSON(user.PermissionOverridesJSON),
		CreatedAt:                user.CreatedAt,
		UpdatedAt:                user.UpdatedAt,
	}
}

func (s *AdminService) roleByID(tx *gorm.DB, roleID int) (*model.AdminRole, error) {
	if roleID <= 0 {
		return nil, common.NewError("role is required")
	}
	var role model.AdminRole
	if err := tx.Where("id = ?", roleID).First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

func (s *AdminService) ownerRoleID(tx *gorm.DB) (int, error) {
	var role model.AdminRole
	if err := tx.Where("slug = ?", model.AdminRoleSlugOwner).First(&role).Error; err != nil {
		return 0, err
	}
	return role.Id, nil
}

func (s *AdminService) adminUsageByUserID(tx *gorm.DB, adminIDs []int) (map[int]int64, error) {
	out := make(map[int]int64, len(adminIDs))
	if len(adminIDs) == 0 {
		return out, nil
	}

	var users []model.User
	if err := tx.Model(&model.User{}).
		Select("id", "used_bytes").
		Where("id IN ?", adminIDs).
		Find(&users).Error; err != nil {
		return nil, err
	}

	for _, user := range users {
		out[user.Id] = user.UsedBytes
	}
	return out, nil
}

func (s *AdminService) List() ([]*AdminView, error) {
	db := database.GetDB()
	var users []model.User
	if err := db.Order("id ASC").Find(&users).Error; err != nil {
		return nil, err
	}

	roleIDs := make([]int, 0, len(users))
	adminIDs := make([]int, 0, len(users))
	for _, user := range users {
		roleIDs = append(roleIDs, user.RoleId)
		adminIDs = append(adminIDs, user.Id)
	}

	roles := map[int]model.AdminRole{}
	if len(roleIDs) > 0 {
		var rows []model.AdminRole
		if err := db.Where("id IN ?", roleIDs).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			roles[row.Id] = row
		}
	}

	userCounts := map[int]int64{}
	if len(adminIDs) > 0 {
		type countRow struct {
			OwnerAdminId int
			Count        int64
		}
		var grouped []countRow
		if err := db.Model(&model.ClientRecord{}).
			Select("owner_admin_id, COUNT(*) AS count").
			Where("owner_admin_id IN ?", adminIDs).
			Group("owner_admin_id").
			Scan(&grouped).Error; err != nil {
			return nil, err
		}
		for _, row := range grouped {
			userCounts[row.OwnerAdminId] = row.Count
		}
	}

	usageByAdmin := map[int]int64{}
	if len(adminIDs) > 0 {
		var usageErr error
		usageByAdmin, usageErr = s.adminUsageByUserID(db, adminIDs)
		if usageErr != nil {
			return nil, usageErr
		}
	}

	out := make([]*AdminView, 0, len(users))
	for i := range users {
		role, ok := roles[users[i].RoleId]
		var rolePtr *model.AdminRole
		if ok {
			rolePtr = &role
		}
		view := adminToView(&users[i], rolePtr, userCounts[users[i].Id])
		if used, ok := usageByAdmin[users[i].Id]; ok {
			view.UsedBytes = used
		}
		out = append(out, view)
	}
	return out, nil
}

func (s *AdminService) Stats() (*AdminStats, error) {
	db := database.GetDB()
	var stats AdminStats
	if err := db.Model(&model.User{}).Count(&stats.TotalAdmins).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.User{}).Where("status = ?", model.AdminStatusActive).Count(&stats.ActiveAdmins).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.User{}).Where("status = ?", model.AdminStatusDisabled).Count(&stats.DisabledAdmins).Error; err != nil {
		return nil, err
	}
	if err := db.Raw(`
		SELECT COUNT(*)
		FROM users AS u
		WHERE u.data_limit > 0
		  AND COALESCE(u.used_bytes, 0) >= u.data_limit
	`).Scan(&stats.LimitedAdmins).Error; err != nil {
		return nil, err
	}
	return &stats, nil
}

func (s *AdminService) Get(id int) (*AdminView, error) {
	if id <= 0 {
		return nil, common.NewError("invalid admin id")
	}
	db := database.GetDB()
	var user model.User
	if err := db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}
	var role model.AdminRole
	_ = db.Where("id = ?", user.RoleId).First(&role).Error
	var totalUsers int64
	if err := db.Model(&model.ClientRecord{}).Where("owner_admin_id = ?", id).Count(&totalUsers).Error; err != nil {
		return nil, err
	}
	view := adminToView(&user, &role, totalUsers)
	usageByAdmin, err := s.adminUsageByUserID(db, []int{id})
	if err != nil {
		return nil, err
	}
	if used, ok := usageByAdmin[id]; ok {
		view.UsedBytes = used
	}
	return view, nil
}

func (s *AdminService) Create(payload AdminPayload) (*AdminView, error) {
	username := strings.TrimSpace(payload.Username)
	if username == "" {
		return nil, common.NewError("username is required")
	}
	if len(username) > 64 {
		return nil, common.NewError("username must be 64 characters or fewer")
	}
	if payload.Password == "" {
		return nil, common.NewError("password is required")
	}

	status := normalizeAdminStatus(payload.Status)
	if !validAdminStatus(status) {
		return nil, common.NewError("invalid admin status")
	}

	db := database.GetDB()
	role, err := s.roleByID(db, payload.RoleId)
	if err != nil {
		return nil, err
	}
	if role.OwnerRole {
		return nil, common.NewError("owner role cannot be assigned here")
	}

	var count int64
	if err := db.Model(&model.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, common.NewError("username already exists")
	}

	hash, err := crypto.HashPasswordAsBcrypt(payload.Password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Username:                 username,
		Password:                 hash,
		RoleId:                   payload.RoleId,
		Status:                   status,
		DataLimit:                payload.DataLimit,
		TelegramID:               strings.TrimSpace(payload.TelegramID),
		DiscordWebhook:           strings.TrimSpace(payload.DiscordWebhook),
		SupportURL:               strings.TrimSpace(payload.SupportURL),
		ProfileTitle:             strings.TrimSpace(payload.ProfileTitle),
		SubscriptionDomain:       strings.TrimSpace(payload.SubscriptionDomain),
		SubscriptionTemplatePath: strings.TrimSpace(payload.SubscriptionTemplatePath),
		Note:                     strings.TrimSpace(payload.Note),
		NotificationFiltersJSON:  marshalAdminMap(payload.NotificationFilters),
		PermissionOverridesJSON:  marshalAdminMap(payload.PermissionOverrides),
	}

	if err := db.Create(user).Error; err != nil {
		return nil, err
	}
	return adminToView(user, role, 0), nil
}

func (s *AdminService) Update(id int, payload AdminPayload) (*AdminView, error) {
	if id <= 0 {
		return nil, common.NewError("invalid admin id")
	}
	db := database.GetDB()
	var existing model.User
	if err := db.Where("id = ?", id).First(&existing).Error; err != nil {
		return nil, err
	}

	role, err := s.roleByID(db, payload.RoleId)
	if err != nil {
		return nil, err
	}
	ownerRoleID, err := s.ownerRoleID(db)
	if err != nil {
		return nil, err
	}
	if existing.RoleId == ownerRoleID {
		return nil, common.NewError("owner admin cannot be modified here")
	}
	if role.OwnerRole {
		return nil, common.NewError("owner role cannot be assigned here")
	}

	username := strings.TrimSpace(payload.Username)
	if username == "" {
		return nil, common.NewError("username is required")
	}
	if len(username) > 64 {
		return nil, common.NewError("username must be 64 characters or fewer")
	}
	status := normalizeAdminStatus(payload.Status)
	if !validAdminStatus(status) {
		return nil, common.NewError("invalid admin status")
	}

	var count int64
	if err := db.Model(&model.User{}).
		Where("username = ? AND id <> ?", username, id).
		Count(&count).Error; err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, common.NewError("username already exists")
	}

	updates := map[string]any{
		"username":                   username,
		"role_id":                    payload.RoleId,
		"status":                     status,
		"data_limit":                 payload.DataLimit,
		"telegram_id":                strings.TrimSpace(payload.TelegramID),
		"discord_webhook":            strings.TrimSpace(payload.DiscordWebhook),
		"support_url":                strings.TrimSpace(payload.SupportURL),
		"profile_title":              strings.TrimSpace(payload.ProfileTitle),
		"subscription_domain":        strings.TrimSpace(payload.SubscriptionDomain),
		"subscription_template_path": strings.TrimSpace(payload.SubscriptionTemplatePath),
		"note":                       strings.TrimSpace(payload.Note),
		"notification_filters":       marshalAdminMap(payload.NotificationFilters),
		"permission_overrides":       marshalAdminMap(payload.PermissionOverrides),
	}

	if payload.Password != "" {
		hash, hashErr := crypto.HashPasswordAsBcrypt(payload.Password)
		if hashErr != nil {
			return nil, hashErr
		}
		updates["password"] = hash
		updates["login_epoch"] = gorm.Expr("login_epoch + 1")
	}

	if err := db.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, err
	}

	if payload.DataLimit != existing.DataLimit && status == model.AdminStatusActive {
		inboundSvc := &core.InboundService{}
		usageByAdmin, usageErr := inboundSvc.SyncAdminUsedBytes()
		if usageErr != nil {
			return nil, usageErr
		}
		usedBytes := usageByAdmin[id]
		if payload.DataLimit <= 0 || usedBytes < payload.DataLimit {
			needRestart, enabledCount, enableErr := inboundSvc.EnableEligibleClientsByOwnerAdminID(id)
			if enableErr != nil {
				return nil, enableErr
			}
			if enabledCount > 0 && needRestart {
				xraySvc := &core.XrayService{}
				if restartErr := xraySvc.RestartXray(true); restartErr != nil {
					xraySvc.SetToNeedRestart()
				}
			}
		}
	}
	return s.Get(id)
}

func (s *AdminService) Delete(id int) error {
	if id <= 0 {
		return common.NewError("invalid admin id")
	}
	db := database.GetDB()
	var existing model.User
	if err := db.Where("id = ?", id).First(&existing).Error; err != nil {
		return err
	}

	ownerRoleID, err := s.ownerRoleID(db)
	if err != nil {
		return err
	}
	if existing.RoleId == ownerRoleID {
		return common.NewError("owner admin cannot be deleted")
	}

	var ownedClients int64
	if err := db.Model(&model.ClientRecord{}).Where("owner_admin_id = ?", id).Count(&ownedClients).Error; err != nil {
		return err
	}
	if ownedClients > 0 {
		return common.NewError("admin owns clients and cannot be deleted")
	}

	res := db.Where("id = ?", id).Delete(&model.User{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("admin not found")
	}
	return nil
}

func (s *AdminService) SetEnabled(id int, enabled bool) error {
	if id <= 0 {
		return common.NewError("invalid admin id")
	}
	db := database.GetDB()
	var existing model.User
	if err := db.Where("id = ?", id).First(&existing).Error; err != nil {
		return err
	}
	ownerRoleID, err := s.ownerRoleID(db)
	if err != nil {
		return err
	}
	if existing.RoleId == ownerRoleID {
		return common.NewError("owner admin cannot be disabled")
	}

	status := model.AdminStatusDisabled
	if enabled {
		status = model.AdminStatusActive
	}
	res := db.Model(&model.User{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":      status,
			"login_epoch": gorm.Expr("login_epoch + 1"),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("admin not found")
	}

	if adminRoleFeatureEnabledByID(db, existing.RoleId, "disconnectUsersWhenDisabled") {
		if !enabled {
			needRestart, _, disErr := (&core.InboundService{}).DisableClientsByDisabledOwnerAdminID(id)
			if disErr != nil {
				return disErr
			}
			if needRestart {
				(&core.XrayService{}).SetToNeedRestart()
			}
		} else {
			needRestart, _, enableErr := (&core.InboundService{}).EnableClientsDisabledByOwnerAdminID(id)
			if enableErr != nil {
				return enableErr
			}
			if needRestart {
				(&core.XrayService{}).SetToNeedRestart()
			}
		}
	}

	return nil
}

func (s *AdminService) ensureAdminExists(tx *gorm.DB, id int) error {
	if id <= 0 {
		return common.NewError("invalid admin id")
	}
	var existing model.User
	if err := tx.Where("id = ?", id).First(&existing).Error; err != nil {
		return err
	}
	return nil
}

func (s *AdminService) clientEmailsByAdminID(tx *gorm.DB, id int, enabled *bool) ([]string, error) {
	if err := s.ensureAdminExists(tx, id); err != nil {
		return nil, err
	}

	query := tx.Model(&model.ClientRecord{}).Where("owner_admin_id = ?", id)
	if enabled != nil {
		query = query.Where("enable = ?", *enabled)
	}

	var rawEmails []string
	if err := query.Pluck("email", &rawEmails).Error; err != nil {
		return nil, err
	}
	return core.FilterVisibleClientEmails(rawEmails), nil
}

func (s *AdminService) ResetUsage(id int) error {
	if id <= 0 {
		return common.NewError("invalid admin id")
	}
	db := database.GetDB()
	emails, err := s.clientEmailsByAdminID(db, id, nil)
	if err != nil {
		return err
	}

	if len(emails) > 0 {
		affected, resetErr := (&core.ClientService{}).BulkResetTraffic(&core.InboundService{}, emails)
		if resetErr != nil {
			return resetErr
		}
		if affected > 0 {
			(&core.XrayService{}).SetToNeedRestart()
		}
	}

	res := db.Model(&model.User{}).Where("id = ?", id).Update("used_bytes", 0)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("admin not found")
	}
	return nil
}

func (s *AdminService) DisableAllActiveUsers(id int) (int64, error) {
	db := database.GetDB()
	if err := s.ensureAdminExists(db, id); err != nil {
		return 0, err
	}

	needRestart, count, err := (&core.InboundService{}).DisableClientsByOwnerAdminID(id)
	if err != nil {
		return count, err
	}
	if needRestart {
		(&core.XrayService{}).SetToNeedRestart()
	}
	return count, nil
}

func (s *AdminService) ActivateAllDisabledUsers(id int) (int64, error) {
	db := database.GetDB()
	disabled := false
	emails, err := s.clientEmailsByAdminID(db, id, &disabled)
	if err != nil {
		return 0, err
	}

	var affected int64
	needRestart := false
	var firstErr error

	clientSvc := &core.ClientService{}
	inboundSvc := &core.InboundService{}

	for _, email := range emails {
		changed, restart, err := clientSvc.SetClientEnableByEmail(inboundSvc, email, true)
		if restart {
			needRestart = true
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if changed {
			affected++
		}
	}

	if needRestart {
		(&core.XrayService{}).SetToNeedRestart()
	}
	if firstErr != nil && affected == 0 {
		return affected, firstErr
	}
	return affected, nil
}

func (s *AdminService) RemoveAllUsers(id int) (int, error) {
	db := database.GetDB()
	emails, err := s.clientEmailsByAdminID(db, id, nil)
	if err != nil {
		return 0, err
	}
	if len(emails) == 0 {
		return 0, nil
	}

	result, needRestart, err := (&core.ClientService{}).BulkDelete(&core.InboundService{}, emails, false)
	if err != nil {
		return result.Deleted, err
	}
	if needRestart {
		(&core.XrayService{}).SetToNeedRestart()
	}
	return result.Deleted, nil
}
