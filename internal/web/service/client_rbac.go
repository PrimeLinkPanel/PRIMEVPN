package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/common"

	"gorm.io/gorm"
)

type ClientAccessMode string

const (
	ClientAccessAll  ClientAccessMode = "all"
	ClientAccessOwn  ClientAccessMode = "own"
	ClientAccessNone ClientAccessMode = "none"
)

type ClientAccessScope struct {
	AdminID           int              `json:"-"`
	Mode              ClientAccessMode `json:"-"`
	RestrictGroups    bool             `json:"-"`
	AllowAllGroups    bool             `json:"-"`
	AllowedGroups     []string         `json:"-"`
	RestrictInbounds  bool             `json:"-"`
	AllowAllInbounds  bool             `json:"-"`
	AllowedInboundIDs []int            `json:"-"`
}

func normalizeAllowedClientGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(groups))
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		key := strings.ToLower(strings.TrimSpace(group))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func normalizeAllowedInboundIDs(ids []int) []int {
	if len(ids) == 0 {
		return nil
	}

	seen := make(map[int]struct{}, len(ids))
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func normalizeClientAccessScope(scope ClientAccessScope) ClientAccessScope {
	if scope.Mode == "" {
		scope.Mode = ClientAccessAll
	}
	if scope.Mode == ClientAccessOwn && scope.AdminID <= 0 {
		scope.Mode = ClientAccessNone
	}
	if scope.RestrictGroups {
		scope.AllowedGroups = normalizeAllowedClientGroups(scope.AllowedGroups)
		if scope.AllowAllGroups {
			scope.AllowedGroups = nil
		}
	}
	if scope.RestrictInbounds {
		scope.AllowedInboundIDs = normalizeAllowedInboundIDs(scope.AllowedInboundIDs)
		if scope.AllowAllInbounds {
			scope.AllowedInboundIDs = nil
		}
	}
	return scope
}

func clientGroupAllowed(scope ClientAccessScope, group string) bool {
	scope = normalizeClientAccessScope(scope)
	if !scope.RestrictGroups || scope.AllowAllGroups {
		return true
	}
	if len(scope.AllowedGroups) == 0 {
		return false
	}

	key := strings.ToLower(strings.TrimSpace(group))
	for _, allowed := range scope.AllowedGroups {
		if key == allowed {
			return true
		}
	}
	return false
}

func applyClientGroupAccessScope(db *gorm.DB, scope ClientAccessScope) *gorm.DB {
	scope = normalizeClientAccessScope(scope)
	if !scope.RestrictGroups || scope.AllowAllGroups {
		return db
	}
	if len(scope.AllowedGroups) == 0 {
		return db.Where("1 = 0")
	}
	return db.Where("LOWER(group_name) IN ?", scope.AllowedGroups)
}

func clientInboundsAllowed(scope ClientAccessScope, inboundIds []int) bool {
	scope = normalizeClientAccessScope(scope)
	if !scope.RestrictInbounds || scope.AllowAllInbounds {
		return true
	}
	if len(scope.AllowedInboundIDs) == 0 || len(inboundIds) == 0 {
		return false
	}

	allowed := make(map[int]struct{}, len(scope.AllowedInboundIDs))
	for _, id := range scope.AllowedInboundIDs {
		allowed[id] = struct{}{}
	}
	for _, id := range inboundIds {
		if id <= 0 {
			return false
		}
		if _, ok := allowed[id]; !ok {
			return false
		}
	}
	return true
}

// ClientInboundsAllowedForScope reports whether a scoped client operation may use
// the requested inbound ids. Missing access config means allow all for backward
// compatibility; explicit empty allowed_inbound_ids means allow all too.
func ClientInboundsAllowedForScope(scope ClientAccessScope, inboundIds []int) bool {
	scope = normalizeClientAccessScope(scope)
	if scope.Mode == ClientAccessNone {
		return false
	}
	return clientInboundsAllowed(scope, inboundIds)
}

// ClientGroupAllowedForScope reports whether a scoped client operation may touch
// a client group. Bare scopes used by legacy tests and internal trusted callers
// remain unrestricted unless RestrictGroups is explicitly set.
func ClientGroupAllowedForScope(scope ClientAccessScope, group string) bool {
	scope = normalizeClientAccessScope(scope)
	if scope.Mode == ClientAccessNone {
		return false
	}
	return clientGroupAllowed(scope, group)
}

func (s *ClientService) adminRoleForUser(user *model.User) (*model.AdminRole, error) {
	if user == nil || user.Id <= 0 {
		return nil, gorm.ErrRecordNotFound
	}
	if user.Status != "" && user.Status != model.AdminStatusActive {
		return nil, gorm.ErrRecordNotFound
	}
	if user.RoleId <= 0 {
		return nil, gorm.ErrRecordNotFound
	}

	var role model.AdminRole
	if err := database.GetDB().Where("id = ?", user.RoleId).First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

func roleUserPermissionValue(role *model.AdminRole, key string) any {
	if role == nil {
		return nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(role.PermissionsJSON), &root); err != nil {
		return nil
	}

	users, ok := root["users"].(map[string]any)
	if !ok {
		return nil
	}

	for _, candidate := range roleUserPermissionKeys(key) {
		if value, ok := users[candidate]; ok {
			return value
		}
	}

	return nil
}

func roleUserPermissionKeys(key string) []string {
	switch key {
	case "view":
		return []string{"view", "read"}
	case "viewSimpleList":
		return []string{"viewSimpleList", "viewSimple", "read_simple"}
	case "resetUsage":
		return []string{"resetUsage", "reset_usage"}
	case "revokeSubscription":
		return []string{"revokeSubscription", "revoke_sub"}
	case "activateNextPlan":
		return []string{"activateNextPlan", "activate_next_plan"}
	case "adminFilter":
		return []string{"adminFilter", "admin_filter"}
	case "setOwner":
		return []string{"setOwner", "set_owner"}
	default:
		return []string{key}
	}
}

func clientAccessModeFromPermission(v any) ClientAccessMode {
	switch t := v.(type) {
	case map[string]any:
		return clientAccessModeFromPermission(t["scope"])
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "all", "2":
			return ClientAccessAll
		case "own", "1":
			return ClientAccessOwn
		case "none", "0":
			return ClientAccessNone
		}
	case bool:
		if t {
			return ClientAccessAll
		}
		return ClientAccessNone
	case float64:
		switch int(t) {
		case 2:
			return ClientAccessAll
		case 1:
			return ClientAccessOwn
		}
	case int:
		switch t {
		case 2:
			return ClientAccessAll
		case 1:
			return ClientAccessOwn
		}
	}

	return ClientAccessNone
}

func roleUserBoolPermission(role *model.AdminRole, key string) bool {
	switch t := roleUserPermissionValue(role, key).(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "all", "own":
			return true
		}
	}
	return false
}

func roleAccessBoolValue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "1", "all":
			return true
		}
	case float64:
		return t != 0
	case int:
		return t != 0
	}
	return false
}

func roleAccessStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return normalizeAllowedClientGroups(t)
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return normalizeAllowedClientGroups(out)
	}
	return nil
}

func roleAccessIntSlice(v any) []int {
	switch t := v.(type) {
	case []int:
		out := make([]int, 0, len(t))
		for _, id := range t {
			if id > 0 {
				out = append(out, id)
			}
		}
		return out
	case []any:
		out := make([]int, 0, len(t))
		for _, item := range t {
			switch v := item.(type) {
			case float64:
				if int(v) > 0 {
					out = append(out, int(v))
				}
			case int:
				if v > 0 {
					out = append(out, v)
				}
			}
		}
		return out
	}
	return nil
}

func roleAccessValue(root map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := root[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func roleGroupNamesByIDs(ids []int) []string {
	if len(ids) == 0 {
		return nil
	}

	db := database.GetDB()
	if db == nil {
		return nil
	}

	var names []string
	if err := db.Model(&model.ClientGroup{}).
		Where("id IN ?", ids).
		Order("id ASC").
		Pluck("name", &names).Error; err != nil {
		return nil
	}

	return normalizeAllowedClientGroups(names)
}

func roleGroupAccessScope(role *model.AdminRole) (restrictGroups bool, allowAllGroups bool, allowedGroups []string) {
	if role == nil {
		return true, false, nil
	}
	if role.OwnerRole {
		return true, true, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(role.AccessJSON), &root); err != nil {
		return true, false, nil
	}

	if value, ok := roleAccessValue(root, "allowAllGroups", "allow_all_groups"); ok && roleAccessBoolValue(value) {
		return true, true, nil
	}

	if value, ok := roleAccessValue(root, "allowed_group_ids", "allowedGroupIds"); ok {
		ids := roleAccessIntSlice(value)
		if len(ids) == 0 {
			return true, true, nil
		}
		groups := roleGroupNamesByIDs(ids)
		return true, false, groups
	}

	if value, ok := roleAccessValue(root, "allowedGroups", "allowed_groups"); ok {
		groups := roleAccessStringSlice(value)
		if len(groups) == 0 {
			if allowValue, hasAllowValue := roleAccessValue(root, "allowAllGroups", "allow_all_groups"); hasAllowValue && !roleAccessBoolValue(allowValue) {
				return true, false, nil
			}
			return true, true, nil
		}
		return true, false, groups
	}

	return true, true, nil
}

func roleInboundAccessScope(role *model.AdminRole) (restrictInbounds bool, allowAllInbounds bool, allowedInboundIDs []int) {
	if role == nil {
		return true, false, nil
	}
	if role.OwnerRole {
		return true, true, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(role.AccessJSON), &root); err != nil {
		return true, false, nil
	}

	if value, ok := roleAccessValue(root, "allowAllInbounds", "allow_all_inbounds"); ok && roleAccessBoolValue(value) {
		return true, true, nil
	}

	if value, ok := roleAccessValue(root, "allowed_inbound_ids", "allowedInboundIds"); ok {
		ids := normalizeAllowedInboundIDs(roleAccessIntSlice(value))
		if len(ids) == 0 {
			return true, true, nil
		}
		return true, false, ids
	}

	return true, true, nil
}

func (s *ClientService) ClientAccessScopeForAdmin(user *model.User, permission string) ClientAccessScope {
	role, err := s.adminRoleForUser(user)
	if err != nil {
		return ClientAccessScope{Mode: ClientAccessNone, RestrictGroups: true}
	}

	restrictGroups, allowAllGroups, allowedGroups := roleGroupAccessScope(role)
	restrictInbounds, allowAllInbounds, allowedInboundIDs := roleInboundAccessScope(role)

	if role.OwnerRole {
		return normalizeClientAccessScope(ClientAccessScope{
			AdminID:           user.Id,
			Mode:              ClientAccessAll,
			RestrictGroups:    restrictGroups,
			AllowAllGroups:    allowAllGroups,
			AllowedGroups:     allowedGroups,
			RestrictInbounds:  restrictInbounds,
			AllowAllInbounds:  allowAllInbounds,
			AllowedInboundIDs: allowedInboundIDs,
		})
	}

	mode := clientAccessModeFromPermission(roleUserPermissionValue(role, permission))
	// Only the owner role may receive cross-owner client access. Non-owner
	// roles can keep full CRUD permissions, but client visibility and client
	// actions are constrained to clients owned by the logged-in admin.
	if mode == ClientAccessAll {
		mode = ClientAccessOwn
	}
	return normalizeClientAccessScope(ClientAccessScope{
		AdminID:           user.Id,
		Mode:              mode,
		RestrictGroups:    restrictGroups,
		AllowAllGroups:    allowAllGroups,
		AllowedGroups:     allowedGroups,
		RestrictInbounds:  restrictInbounds,
		AllowAllInbounds:  allowAllInbounds,
		AllowedInboundIDs: allowedInboundIDs,
	})
}

func (s *ClientService) CanCreateClientForAdmin(user *model.User) bool {
	role, err := s.adminRoleForUser(user)
	if err != nil {
		return false
	}

	if role.OwnerRole {
		return true
	}

	return roleUserBoolPermission(role, "create")
}

func (s *ClientService) CanFilterClientOwnersForAdmin(user *model.User) bool {
	role, err := s.adminRoleForUser(user)
	if err != nil {
		return false
	}

	if role.OwnerRole {
		return true
	}

	return roleUserBoolPermission(role, "adminFilter")
}

func (s *ClientService) ClientRecordAllowed(scope ClientAccessScope, rec *model.ClientRecord) bool {
	scope = normalizeClientAccessScope(scope)
	if rec == nil {
		return false
	}
	if IsHiddenClientEmail(rec.Email) {
		return false
	}
	if !clientGroupAllowed(scope, rec.Group) {
		return false
	}

	switch scope.Mode {
	case ClientAccessAll:
		return true
	case ClientAccessOwn:
		return rec.OwnerAdminId > 0 && rec.OwnerAdminId == scope.AdminID
	default:
		return false
	}
}

func applyClientAccessScope(db *gorm.DB, scope ClientAccessScope, emailColumn string) *gorm.DB {
	scope = normalizeClientAccessScope(scope)

	if emailColumn != "" {
		db = applyVisibleClientEmailScope(db, emailColumn)
	}

	db = applyClientGroupAccessScope(db, scope)

	switch scope.Mode {
	case ClientAccessAll:
		return db
	case ClientAccessOwn:
		return db.Where("owner_admin_id = ?", scope.AdminID)
	default:
		return db.Where("1 = 0")
	}
}

func (s *ClientService) FilterClientEmailsForScope(scope ClientAccessScope, emails []string) []string {
	emails = FilterVisibleClientEmails(emails)
	if len(emails) == 0 {
		return emails
	}

	scope = normalizeClientAccessScope(scope)
	if scope.Mode == ClientAccessNone {
		return []string{}
	}

	allowed := make(map[string]struct{}, len(emails))
	for _, batch := range chunkStrings(emails, sqlInChunk) {
		var rows []string
		query := applyClientAccessScope(
			database.GetDB().Model(&model.ClientRecord{}),
			scope,
			"email",
		).Where("email IN ?", batch)
		if err := query.Pluck("email", &rows).Error; err != nil {
			return []string{}
		}
		for _, email := range rows {
			allowed[strings.ToLower(email)] = struct{}{}
		}
	}

	out := make([]string, 0, len(emails))
	seen := map[string]struct{}{}
	for _, email := range emails {
		key := strings.ToLower(strings.TrimSpace(email))
		if key == "" {
			continue
		}
		if _, ok := allowed[key]; !ok {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, email)
	}
	return out
}

func (s *ClientService) RequireClientForScopeByEmail(scope ClientAccessScope, email string) (*model.ClientRecord, error) {
	if IsHiddenClientEmail(email) {
		return nil, gorm.ErrRecordNotFound
	}

	row := &model.ClientRecord{}
	err := applyClientAccessScope(
		database.GetDB().Where("email = ?", email),
		scope,
		"email",
	).First(row).Error
	if err != nil {
		return nil, err
	}

	return row, nil
}

func (s *ClientService) RequireClientForScopeBySubID(scope ClientAccessScope, subID string) (*model.ClientRecord, error) {
	subID = strings.TrimSpace(subID)
	if subID == "" {
		return nil, gorm.ErrRecordNotFound
	}

	row := &model.ClientRecord{}
	err := applyClientAccessScope(
		database.GetDB().Where("sub_id = ?", subID),
		scope,
		"email",
	).First(row).Error
	if err != nil {
		return nil, err
	}

	return row, nil
}

type adminRoleClientLimits struct {
	MaxUsersSet          bool
	MaxUsers             int64
	MinDataLimitSet      bool
	MinDataLimitGB       int64
	MinDataLimitBytesSet bool
	MinDataLimitBytes    int64
	MaxDataLimitSet      bool
	MaxDataLimitGB       int64
	MaxDataLimitBytesSet bool
	MaxDataLimitBytes    int64
	MinExpireDaysSet     bool
	MinExpireDays        int64
	MaxExpireDaysSet     bool
	MaxExpireDays        int64
	MinOnHoldTimeoutSet  bool
	MinOnHoldTimeoutDays int64
	MaxOnHoldTimeoutSet  bool
	MaxOnHoldTimeoutDays int64

	MinDownloadMbpsSet bool
	MinDownloadMbps    int64
	MaxDownloadMbpsSet bool
	MaxDownloadMbps    int64
	MinUploadMbpsSet   bool
	MinUploadMbps      int64
	MaxUploadMbpsSet   bool
	MaxUploadMbps      int64
}

func positiveInt64RoleLimit(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		if t > 0 {
			return int64(t), true
		}
	case int:
		if t > 0 {
			return int64(t), true
		}
	case int64:
		if t > 0 {
			return t, true
		}
	case string:
		t = strings.TrimSpace(t)
		if t == "" {
			return 0, false
		}
		var n int64
		for _, r := range t {
			if r < '0' || r > '9' {
				return 0, false
			}
			n = n*10 + int64(r-'0')
		}
		if n > 0 {
			return n, true
		}
	}
	return 0, false
}

func roleClientLimits(role *model.AdminRole) adminRoleClientLimits {
	var limits adminRoleClientLimits
	if role == nil || strings.TrimSpace(role.LimitsJSON) == "" {
		return limits
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(role.LimitsJSON), &root); err != nil {
		return limits
	}

	limits.MaxUsers, limits.MaxUsersSet = positiveInt64RoleLimit(firstRoleLimitValue(root, "maxUsers", "max_users"))

	// Legacy role limits use GB/days.
	limits.MinDataLimitGB, limits.MinDataLimitSet = positiveInt64RoleLimit(root["minDataLimit"])
	limits.MaxDataLimitGB, limits.MaxDataLimitSet = positiveInt64RoleLimit(root["maxDataLimit"])
	limits.MinExpireDays, limits.MinExpireDaysSet = positiveInt64RoleLimit(root["minExpireDays"])
	limits.MaxExpireDays, limits.MaxExpireDaysSet = positiveInt64RoleLimit(root["maxExpireDays"])

	// New UI-style limits use bytes/seconds.
	if n, ok := positiveInt64RoleLimit(root["data_limit_min"]); ok {
		limits.MinDataLimitBytes = n
		limits.MinDataLimitBytesSet = true
	}
	if n, ok := positiveInt64RoleLimit(root["data_limit_max"]); ok {
		limits.MaxDataLimitBytes = n
		limits.MaxDataLimitBytesSet = true
	}
	if n, ok := positiveInt64RoleLimit(root["expire_min"]); ok {
		limits.MinExpireDays = secondsToRoleLimitDays(n)
		limits.MinExpireDaysSet = true
	}
	if n, ok := positiveInt64RoleLimit(root["expire_max"]); ok {
		limits.MaxExpireDays = secondsToRoleLimitDays(n)
		limits.MaxExpireDaysSet = true
	}

	limits.MinOnHoldTimeoutDays, limits.MinOnHoldTimeoutSet = positiveInt64RoleLimit(root["minOnHoldTimeoutDays"])
	limits.MaxOnHoldTimeoutDays, limits.MaxOnHoldTimeoutSet = positiveInt64RoleLimit(root["maxOnHoldTimeoutDays"])

	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "download_mbps_min", "minDownloadMbps", "downloadMbpsMin")); ok {
		limits.MinDownloadMbps = n
		limits.MinDownloadMbpsSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "download_mbps_max", "maxDownloadMbps", "downloadMbpsMax")); ok {
		limits.MaxDownloadMbps = n
		limits.MaxDownloadMbpsSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "upload_mbps_min", "minUploadMbps", "uploadMbpsMin")); ok {
		limits.MinUploadMbps = n
		limits.MinUploadMbpsSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "upload_mbps_max", "maxUploadMbps", "uploadMbpsMax")); ok {
		limits.MaxUploadMbps = n
		limits.MaxUploadMbpsSet = true
	}

	return limits
}

func applyAdminPermissionOverrides(limits adminRoleClientLimits, user *model.User) adminRoleClientLimits {
	if user == nil || strings.TrimSpace(user.PermissionOverridesJSON) == "" {
		return limits
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(user.PermissionOverridesJSON), &root); err != nil {
		return limits
	}

	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "max_users", "maxUsers")); ok {
		limits.MaxUsers = n
		limits.MaxUsersSet = true
	}

	// Legacy override keys use GB/days.
	if n, ok := positiveInt64RoleLimit(root["minDataLimit"]); ok {
		limits.MinDataLimitGB = n
		limits.MinDataLimitSet = true
	}
	if n, ok := positiveInt64RoleLimit(root["maxDataLimit"]); ok {
		limits.MaxDataLimitGB = n
		limits.MaxDataLimitSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "expire_days_min", "minExpireDays")); ok {
		limits.MinExpireDays = n
		limits.MinExpireDaysSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "expire_days_max", "maxExpireDays")); ok {
		limits.MaxExpireDays = n
		limits.MaxExpireDaysSet = true
	}

	// Admin modal override keys use bytes/seconds.
	if n, ok := positiveInt64RoleLimit(root["data_limit_min"]); ok {
		limits.MinDataLimitBytes = n
		limits.MinDataLimitBytesSet = true
	}
	if n, ok := positiveInt64RoleLimit(root["data_limit_max"]); ok {
		limits.MaxDataLimitBytes = n
		limits.MaxDataLimitBytesSet = true
	}
	if n, ok := positiveInt64RoleLimit(root["expire_min"]); ok {
		limits.MinExpireDays = secondsToRoleLimitDays(n)
		limits.MinExpireDaysSet = true
	}
	if n, ok := positiveInt64RoleLimit(root["expire_max"]); ok {
		limits.MaxExpireDays = secondsToRoleLimitDays(n)
		limits.MaxExpireDaysSet = true
	}

	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "on_hold_timeout_days_min", "minOnHoldTimeoutDays")); ok {
		limits.MinOnHoldTimeoutDays = n
		limits.MinOnHoldTimeoutSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "on_hold_timeout_days_max", "maxOnHoldTimeoutDays")); ok {
		limits.MaxOnHoldTimeoutDays = n
		limits.MaxOnHoldTimeoutSet = true
	}

	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "download_mbps_min", "minDownloadMbps", "downloadMbpsMin")); ok {
		limits.MinDownloadMbps = n
		limits.MinDownloadMbpsSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "download_mbps_max", "maxDownloadMbps", "downloadMbpsMax")); ok {
		limits.MaxDownloadMbps = n
		limits.MaxDownloadMbpsSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "upload_mbps_min", "minUploadMbps", "uploadMbpsMin")); ok {
		limits.MinUploadMbps = n
		limits.MinUploadMbpsSet = true
	}
	if n, ok := positiveInt64RoleLimit(firstRoleLimitValue(root, "upload_mbps_max", "maxUploadMbps", "uploadMbpsMax")); ok {
		limits.MaxUploadMbps = n
		limits.MaxUploadMbpsSet = true
	}

	return limits
}

func firstRoleLimitValue(root map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := root[key]; ok {
			return value
		}
	}
	return nil
}

func (l adminRoleClientLimits) hasDataLimit() bool {
	return l.MinDataLimitSet || l.MaxDataLimitSet || l.MinDataLimitBytesSet || l.MaxDataLimitBytesSet
}

func (l adminRoleClientLimits) hasExpireLimit() bool {
	return l.MinExpireDaysSet || l.MaxExpireDaysSet
}

const (
	roleLimitBytesPerGB int64 = 1024 * 1024 * 1024
	roleLimitDayMillis  int64 = 24 * 60 * 60 * 1000
)

func secondsToRoleLimitDays(seconds int64) int64 {
	if seconds <= 0 {
		return 0
	}
	const daySeconds int64 = 24 * 60 * 60
	return (seconds + daySeconds - 1) / daySeconds
}

func clientRoleLimitDurationMillis(expiryTime int64, nowMs int64) (int64, bool) {
	if expiryTime > 0 {
		durationMillis := expiryTime - nowMs
		return durationMillis, durationMillis > 0
	}
	if expiryTime < 0 {
		// Start-after-first-use clients store the configured duration as a
		// negative expiry value. Validate the duration, not an absolute date.
		return -expiryTime, true
	}
	return 0, false
}

func roleLimitGBToBytes(gb int64) int64 {
	if gb <= 0 {
		return 0
	}
	return gb * roleLimitBytesPerGB
}

func roleLimitMinDataBytes(limits adminRoleClientLimits) (int64, bool) {
	var min int64
	var ok bool
	if limits.MinDataLimitSet {
		min = roleLimitGBToBytes(limits.MinDataLimitGB)
		ok = min > 0
	}
	if limits.MinDataLimitBytesSet && limits.MinDataLimitBytes > 0 {
		if !ok || limits.MinDataLimitBytes > min {
			min = limits.MinDataLimitBytes
			ok = true
		}
	}
	return min, ok
}

func roleLimitMaxDataBytes(limits adminRoleClientLimits) (int64, bool) {
	var max int64
	var ok bool
	if limits.MaxDataLimitSet {
		max = roleLimitGBToBytes(limits.MaxDataLimitGB)
		ok = max > 0
	}
	if limits.MaxDataLimitBytesSet && limits.MaxDataLimitBytes > 0 {
		if !ok || limits.MaxDataLimitBytes < max {
			max = limits.MaxDataLimitBytes
			ok = true
		}
	}
	return max, ok
}

func roleLimitMinExpireDays(limits adminRoleClientLimits) (int64, bool) {
	if limits.MinExpireDaysSet && limits.MinExpireDays > 0 {
		return limits.MinExpireDays, true
	}
	return 0, false
}

func roleLimitMaxExpireDays(limits adminRoleClientLimits) (int64, bool) {
	if limits.MaxExpireDaysSet && limits.MaxExpireDays > 0 {
		return limits.MaxExpireDays, true
	}
	return 0, false
}

func clientDataLimitRequiredMessage(minBytes int64, hasMin bool, maxBytes int64, hasMax bool) string {
	switch {
	case hasMin && hasMax:
		return fmt.Sprintf("برای این حساب، حجم ترافیک کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست. بازه مجاز حجم برای هر کلاینت از %s تا %s است.", formatRoleLimitBytes(minBytes), formatRoleLimitBytes(maxBytes))
	case hasMin:
		return fmt.Sprintf("برای این حساب، حجم ترافیک کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست. حداقل حجم مجاز برای هر کلاینت %s است.", formatRoleLimitBytes(minBytes))
	case hasMax:
		return fmt.Sprintf("برای این حساب، حجم ترافیک کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست. حداکثر حجم مجاز برای هر کلاینت %s است.", formatRoleLimitBytes(maxBytes))
	default:
		return "برای این حساب، حجم ترافیک کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست."
	}
}

func clientExpiryRequiredMessage(minDays int64, hasMin bool, maxDays int64, hasMax bool) string {
	switch {
	case hasMin && hasMax:
		return fmt.Sprintf("برای این حساب، مدت اعتبار کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست. بازه مجاز مدت اعتبار برای هر کلاینت از %s تا %s است.", formatRoleLimitDays(minDays), formatRoleLimitDays(maxDays))
	case hasMin:
		return fmt.Sprintf("برای این حساب، مدت اعتبار کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست. حداقل مدت مجاز برای هر کلاینت %s است.", formatRoleLimitDays(minDays))
	case hasMax:
		return fmt.Sprintf("برای این حساب، مدت اعتبار کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست. حداکثر مدت مجاز برای هر کلاینت %s است.", formatRoleLimitDays(maxDays))
	default:
		return "برای این حساب، مدت اعتبار کلاینت باید محدود باشد. مقدار Unlimited مجاز نیست."
	}
}

func formatRoleLimitBytes(bytes int64) string {
	if bytes <= 0 {
		return "Unlimited"
	}

	units := []struct {
		size int64
		name string
	}{
		{1024 * 1024 * 1024 * 1024, "ترابایت"},
		{1024 * 1024 * 1024, "گیگابایت"},
		{1024 * 1024, "مگابایت"},
		{1024, "کیلوبایت"},
	}

	for _, unit := range units {
		if bytes >= unit.size {
			value := float64(bytes) / float64(unit.size)
			if bytes%unit.size == 0 {
				return fmt.Sprintf("%d %s", bytes/unit.size, unit.name)
			}
			return fmt.Sprintf("%.2f %s", value, unit.name)
		}
	}
	return fmt.Sprintf("%d بایت", bytes)
}

func formatRoleLimitDays(days int64) string {
	return fmt.Sprintf("%d روز", days)
}

func formatRoleLimitDurationMillis(ms int64) string {
	if ms <= 0 {
		return "0 روز"
	}
	if ms%roleLimitDayMillis == 0 {
		return formatRoleLimitDays(ms / roleLimitDayMillis)
	}
	return fmt.Sprintf("%.2f روز", float64(ms)/float64(roleLimitDayMillis))
}

func validateClientAgainstRoleLimits(limits adminRoleClientLimits, client model.Client, nowMs int64) error {
	if limits.hasDataLimit() {
		minBytes, hasMinBytes := roleLimitMinDataBytes(limits)
		maxBytes, hasMaxBytes := roleLimitMaxDataBytes(limits)

		if client.TotalGB <= 0 {
			return common.NewError(clientDataLimitRequiredMessage(minBytes, hasMinBytes, maxBytes, hasMaxBytes))
		}
		if hasMinBytes && client.TotalGB < minBytes {
			return common.NewErrorf("حجم ترافیک انتخاب‌شده برای این کلاینت کمتر از حداقل مجاز است. حداقل حجم مجاز برای این حساب %s است، اما مقدار واردشده %s است.", formatRoleLimitBytes(minBytes), formatRoleLimitBytes(client.TotalGB))
		}
		if hasMaxBytes && client.TotalGB > maxBytes {
			return common.NewErrorf("حجم ترافیک انتخاب‌شده برای این کلاینت بیشتر از حداکثر مجاز است. حداکثر حجم مجاز برای این حساب %s است، اما مقدار واردشده %s است.", formatRoleLimitBytes(maxBytes), formatRoleLimitBytes(client.TotalGB))
		}
	}

	if limits.hasExpireLimit() {
		minDays, hasMinDays := roleLimitMinExpireDays(limits)
		maxDays, hasMaxDays := roleLimitMaxExpireDays(limits)

		durationMillis, ok := clientRoleLimitDurationMillis(client.ExpiryTime, nowMs)
		if !ok {
			return common.NewError(clientExpiryRequiredMessage(minDays, hasMinDays, maxDays, hasMaxDays))
		}
		if hasMinDays && durationMillis < minDays*roleLimitDayMillis {
			return common.NewErrorf("مدت اعتبار انتخاب‌شده برای این کلاینت کمتر از حداقل مجاز است. حداقل مدت مجاز برای این حساب %s است، اما مقدار واردشده %s است.", formatRoleLimitDays(minDays), formatRoleLimitDurationMillis(durationMillis))
		}
		if hasMaxDays && durationMillis > maxDays*roleLimitDayMillis {
			return common.NewErrorf("مدت اعتبار انتخاب‌شده برای این کلاینت بیشتر از حداکثر مجاز است. حداکثر مدت مجاز برای این حساب %s است، اما مقدار واردشده %s است.", formatRoleLimitDays(maxDays), formatRoleLimitDurationMillis(durationMillis))
		}
	}

	// On-hold timeout limits are intentionally not enforced here yet because the
	// client/client record models currently do not expose an on-hold timeout
	// field. The limits are preserved in role JSON for forward compatibility.
	if err := validateClientSpeedLimits(client, limits); err != nil {
		return err
	}

	return nil
}

func (s *ClientService) ValidateClientLimitsForAdmin(user *model.User, client model.Client, checkMaxUsers bool) error {
	// Legacy controller unit tests mount routes without session middleware. Those
	// callers are already outside production auth and should remain unrestricted.
	if user == nil {
		return nil
	}

	role, err := s.adminRoleForUser(user)
	if err != nil {
		return common.NewError("active admin role required")
	}

	if role.OwnerRole {
		return nil
	}

	limits := applyAdminPermissionOverrides(roleClientLimits(role), user)
	if checkMaxUsers && limits.MaxUsersSet {
		var count int64
		if err := database.GetDB().
			Model(&model.ClientRecord{}).
			Where("owner_admin_id = ?", user.Id).
			Count(&count).Error; err != nil {
			return err
		}
		if count >= limits.MaxUsers {
			return common.NewErrorf("سقف ساخت کلاینت برای این حساب %d عدد است. اکنون %d کلاینت ثبت شده دارید و امکان ساخت کلاینت جدید وجود ندارد.", limits.MaxUsers, count)
		}
	}

	return validateClientAgainstRoleLimits(limits, client, time.Now().UnixMilli())
}

func (s *ClientService) BulkAdjustForAdmin(inboundSvc *InboundService, emails []string, addDays int, addBytes int64, flow string, user *model.User) (BulkAdjustResult, bool, error) {
	if user == nil {
		return s.BulkAdjust(inboundSvc, emails, addDays, addBytes, flow)
	}

	result := BulkAdjustResult{}
	emails = FilterVisibleClientEmails(emails)
	if len(emails) == 0 {
		return result, false, nil
	}

	addExpiryMs := int64(addDays) * roleLimitDayMillis

	db := database.GetDB()
	recordsByEmail := make(map[string]*model.ClientRecord, len(emails))
	for _, batch := range chunkStrings(emails, sqlInChunk) {
		var rows []model.ClientRecord
		if err := db.Where("email IN ?", batch).Find(&rows).Error; err != nil {
			return result, false, err
		}
		for i := range rows {
			recordsByEmail[rows[i].Email] = &rows[i]
		}
	}

	allowedEmails := make([]string, 0, len(emails))
	for _, email := range emails {
		rec, ok := recordsByEmail[email]
		if !ok {
			allowedEmails = append(allowedEmails, email)
			continue
		}

		next := model.Client{
			Email:      rec.Email,
			TotalGB:    rec.TotalGB,
			ExpiryTime: rec.ExpiryTime,
			Group:      rec.Group,
		}

		willChange := false
		if addDays != 0 {
			switch {
			case rec.ExpiryTime > 0:
				next.ExpiryTime = rec.ExpiryTime + addExpiryMs
				willChange = next.ExpiryTime > 0
			case rec.ExpiryTime < 0:
				next.ExpiryTime = rec.ExpiryTime - addExpiryMs
				willChange = next.ExpiryTime < 0
			}
		}
		if addBytes != 0 && rec.TotalGB != 0 {
			next.TotalGB = max(rec.TotalGB+addBytes, 0)
			willChange = true
		}

		if willChange {
			if err := s.ValidateClientLimitsForAdmin(user, next, false); err != nil {
				result.Skipped = append(result.Skipped, BulkAdjustReport{Email: email, Reason: err.Error()})
				continue
			}
		}

		allowedEmails = append(allowedEmails, email)
	}

	delegate, needRestart, err := s.BulkAdjust(inboundSvc, allowedEmails, addDays, addBytes, flow)
	if err != nil {
		return result, needRestart, err
	}
	result.Adjusted += delegate.Adjusted
	result.Skipped = append(result.Skipped, delegate.Skipped...)
	return result, needRestart, nil
}

func (s *ClientService) BulkCreateForAdmin(inboundSvc *InboundService, payloads []ClientCreatePayload, user *model.User) (BulkCreateResult, bool, error) {
	if user == nil {
		return s.BulkCreate(inboundSvc, payloads)
	}

	result := BulkCreateResult{}
	needRestart := false

	for i := range payloads {
		payload := payloads[i]
		if IsHiddenClientEmail(payload.Client.Email) {
			continue
		}

		nr, err := s.CreateForAdmin(inboundSvc, &payload, user)
		if err != nil {
			email := strings.TrimSpace(payload.Client.Email)
			if email == "" {
				email = "(missing email)"
			}
			result.Skipped = append(result.Skipped, BulkCreateReport{Email: email, Reason: err.Error()})
			continue
		}

		result.Created++
		if nr {
			needRestart = true
		}
	}

	return result, needRestart, nil
}

func (s *ClientService) ClientGroupAllowedForAdmin(user *model.User, permission string, group string) bool {
	return ClientGroupAllowedForScope(s.ClientAccessScopeForAdmin(user, permission), group)
}

func (s *ClientService) ClientInboundsAllowedForAdmin(user *model.User, permission string, inboundIds []int) bool {
	return ClientInboundsAllowedForScope(s.ClientAccessScopeForAdmin(user, permission), inboundIds)
}

func (s *ClientService) ValidateInboundAccessForAdmin(user *model.User, permission string, inboundIds []int) error {
	if user == nil {
		return nil
	}
	if s.ClientInboundsAllowedForAdmin(user, permission, inboundIds) {
		return nil
	}
	return common.NewError("inbound access denied")
}

// RestrictedInboundIDsForAdmin returns the concrete inbound allow-list for a role.
// The second return value is meaningful only when restricted is true.
// nil/empty allowed_inbound_ids keeps backward-compatible "allow all" behavior.

func roleAdminFeatureBool(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "yes", "1", "on", "enabled", "all":
			return true
		}
	case float64:
		return value != 0
	case int:
		return value != 0
	case int64:
		return value != 0
	case json.Number:
		i, err := value.Int64()
		return err == nil && i != 0
	}
	return false
}

func roleAdminFeatureEnabled(role *model.AdminRole, key string) bool {
	if role == nil || strings.TrimSpace(key) == "" {
		return false
	}
	if role.OwnerRole {
		return true
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(role.FeaturesJSON), &root); err != nil {
		return false
	}

	return roleAdminFeatureBool(root[key])
}

func (s *ClientService) AdminRoleFeatureEnabledForAdmin(user *model.User, key string) bool {
	if user == nil {
		return false
	}

	role, err := s.adminRoleForUser(user)
	if err != nil {
		return false
	}

	return roleAdminFeatureEnabled(role, key)
}

func (s *ClientService) ValidateAdminRoleFeatureForAdmin(user *model.User, key string) error {
	if s.AdminRoleFeatureEnabledForAdmin(user, key) {
		return nil
	}
	return common.NewError("feature not allowed")
}

func (s *ClientService) RestrictedInboundIDsForAdmin(user *model.User) (restricted bool, allowedInboundIDs []int) {
	role, err := s.adminRoleForUser(user)
	if err != nil {
		return true, nil
	}

	restrictInbounds, allowAllInbounds, ids := roleInboundAccessScope(role)
	if !restrictInbounds || allowAllInbounds {
		return false, nil
	}

	ids = normalizeAllowedInboundIDs(ids)
	if len(ids) == 0 {
		return false, nil
	}

	return true, ids
}

func (s *ClientService) CreateForAdmin(inboundSvc *InboundService, payload *ClientCreatePayload, user *model.User) (bool, error) {
	if payload == nil {
		return false, common.NewError("empty payload")
	}
	if !s.CanCreateClientForAdmin(user) {
		return false, common.NewError("client create permission required")
	}
	if !s.ClientGroupAllowedForAdmin(user, "create", payload.Client.Group) {
		return false, common.NewError("client group access denied")
	}
	if err := s.ValidateInboundAccessForAdmin(user, "create", payload.InboundIds); err != nil {
		return false, err
	}

	email := strings.TrimSpace(payload.Client.Email)
	checkMaxUsers := true
	if email != "" {
		existing, err := s.GetRecordByEmail(nil, email)
		if err == nil {
			checkMaxUsers = false
			scope := s.ClientAccessScopeForAdmin(user, "update")
			if !s.ClientRecordAllowed(scope, existing) {
				return false, gorm.ErrRecordNotFound
			}
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			checkMaxUsers = true
		} else {
			return false, err
		}
	}
	if err := s.ValidateClientLimitsForAdmin(user, payload.Client, checkMaxUsers); err != nil {
		return false, err
	}

	needRestart, err := s.Create(inboundSvc, payload)
	if err != nil {
		return needRestart, err
	}

	if user != nil && user.Id > 0 && email != "" {
		if err := database.GetDB().
			Model(&model.ClientRecord{}).
			Where("email = ? AND owner_admin_id = 0", email).
			Updates(map[string]any{
				"owner_admin_id":      user.Id,
				"created_by_admin_id": user.Id,
			}).Error; err != nil {
			return needRestart, err
		}
	}

	return needRestart, nil
}

func validateClientSpeedLimits(client model.Client, limits adminRoleClientLimits) error {
	if limits.MinDownloadMbpsSet || limits.MaxDownloadMbpsSet {
		if client.DownloadMbps <= 0 {
			if limits.MinDownloadMbpsSet {
				return fmt.Errorf("unlimited download speed is not allowed; minimum download limit is %d Mbps", limits.MinDownloadMbps)
			}
			return fmt.Errorf("unlimited download speed is not allowed")
		}
		downloadMbps := int64(client.DownloadMbps)
		if limits.MinDownloadMbpsSet && downloadMbps < limits.MinDownloadMbps {
			return fmt.Errorf("minimum download limit is %d Mbps", limits.MinDownloadMbps)
		}
		if limits.MaxDownloadMbpsSet && downloadMbps > limits.MaxDownloadMbps {
			return fmt.Errorf("maximum download limit is %d Mbps", limits.MaxDownloadMbps)
		}
	}

	if limits.MinUploadMbpsSet || limits.MaxUploadMbpsSet {
		if client.UploadMbps <= 0 {
			if limits.MinUploadMbpsSet {
				return fmt.Errorf("unlimited upload speed is not allowed; minimum upload limit is %d Mbps", limits.MinUploadMbps)
			}
			return fmt.Errorf("unlimited upload speed is not allowed")
		}
		uploadMbps := int64(client.UploadMbps)
		if limits.MinUploadMbpsSet && uploadMbps < limits.MinUploadMbps {
			return fmt.Errorf("minimum upload limit is %d Mbps", limits.MinUploadMbps)
		}
		if limits.MaxUploadMbpsSet && uploadMbps > limits.MaxUploadMbps {
			return fmt.Errorf("maximum upload limit is %d Mbps", limits.MaxUploadMbps)
		}
	}

	return nil
}
