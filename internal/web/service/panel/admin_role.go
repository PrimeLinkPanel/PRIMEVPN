package panel

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/common"
)

type AdminRoleService struct{}

type AdminRolePayload struct {
	Name        string         `json:"name" form:"name"`
	Permissions map[string]any `json:"permissions" form:"permissions"`
	Limits      map[string]any `json:"limits" form:"limits"`
	Features    map[string]any `json:"features" form:"features"`
	Access      map[string]any `json:"access" form:"access"`
}

type AdminRoleView struct {
	Id          int    `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	BuiltIn     bool   `json:"builtIn"`
	OwnerRole   bool   `json:"ownerRole"`
	Permissions any    `json:"permissions"`
	Limits      any    `json:"limits"`
	Features    any    `json:"features"`
	Access      any    `json:"access"`
	AdminCount  int64  `json:"adminCount"`
	CreatedAt   int64  `json:"createdAt"`
	UpdatedAt   int64  `json:"updatedAt"`
}

func normalizeRoleSlug(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-'
		if !ok {
			if !lastDash {
				b.WriteRune('-')
				lastDash = true
			}
			continue
		}
		if r == '-' {
			if lastDash {
				continue
			}
			lastDash = true
		} else {
			lastDash = false
		}
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

func marshalAnyMap(v map[string]any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeJSONView(raw string) any {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]any{}
	}
	return out
}

func roleToView(row *model.AdminRole, adminCount int64) *AdminRoleView {
	if row == nil {
		return nil
	}
	return &AdminRoleView{
		Id:          row.Id,
		Name:        row.Name,
		Slug:        row.Slug,
		BuiltIn:     row.BuiltIn,
		OwnerRole:   row.OwnerRole,
		Permissions: decodeJSONView(row.PermissionsJSON),
		Limits:      decodeJSONView(row.LimitsJSON),
		Features:    decodeJSONView(row.FeaturesJSON),
		Access:      decodeJSONView(row.AccessJSON),
		AdminCount:  adminCount,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}

func (s *AdminRoleService) List() ([]*AdminRoleView, error) {
	db := database.GetDB()
	var rows []*model.AdminRole
	if err := db.Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}

	roleIDs := make([]int, 0, len(rows))
	for _, row := range rows {
		roleIDs = append(roleIDs, row.Id)
	}

	counts := map[int]int64{}
	if len(roleIDs) > 0 {
		type countRow struct {
			RoleId int
			Count  int64
		}
		var grouped []countRow
		if err := db.Model(&model.User{}).
			Select("role_id, COUNT(*) AS count").
			Where("role_id IN ?", roleIDs).
			Group("role_id").
			Scan(&grouped).Error; err != nil {
			return nil, err
		}
		for _, row := range grouped {
			counts[row.RoleId] = row.Count
		}
	}

	out := make([]*AdminRoleView, 0, len(rows))
	for _, row := range rows {
		out = append(out, roleToView(row, counts[row.Id]))
	}
	return out, nil
}

func (s *AdminRoleService) Get(id int) (*AdminRoleView, error) {
	if id <= 0 {
		return nil, common.NewError("invalid role id")
	}
	db := database.GetDB()
	var row model.AdminRole
	if err := db.Where("id = ?", id).First(&row).Error; err != nil {
		return nil, err
	}
	var count int64
	if err := db.Model(&model.User{}).Where("role_id = ?", id).Count(&count).Error; err != nil {
		return nil, err
	}
	return roleToView(&row, count), nil
}

func (s *AdminRoleService) Create(payload AdminRolePayload) (*AdminRoleView, error) {
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		return nil, common.NewError("role name is required")
	}
	if len(name) > 64 {
		return nil, common.NewError("role name must be 64 characters or fewer")
	}
	slug := normalizeRoleSlug(name)
	if slug == "" {
		return nil, common.NewError("role slug is invalid")
	}

	db := database.GetDB()
	var count int64
	if err := db.Model(&model.AdminRole{}).
		Where("name = ? OR slug = ?", name, slug).
		Count(&count).Error; err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, common.NewError("role already exists")
	}

	defaultPermissions, defaultLimits, defaultFeatures, defaultAccess := defaultOperatorRoleMaps()

	row := &model.AdminRole{
		Name:            name,
		Slug:            slug,
		BuiltIn:         false,
		OwnerRole:       false,
		PermissionsJSON: marshalAnyMap(nonEmptyOrDefault(payload.Permissions, defaultPermissions)),
		LimitsJSON:      marshalAnyMap(nonEmptyOrDefault(payload.Limits, defaultLimits)),
		FeaturesJSON:    marshalAnyMap(nonEmptyOrDefault(payload.Features, defaultFeatures)),
		AccessJSON:      marshalAnyMap(nonEmptyOrDefault(payload.Access, defaultAccess)),
	}
	if err := db.Create(row).Error; err != nil {
		return nil, err
	}
	return roleToView(row, 0), nil
}

func (s *AdminRoleService) Update(id int, payload AdminRolePayload) (*AdminRoleView, error) {
	if id <= 0 {
		return nil, common.NewError("invalid role id")
	}
	db := database.GetDB()
	var row model.AdminRole
	if err := db.Where("id = ?", id).First(&row).Error; err != nil {
		return nil, err
	}
	if row.OwnerRole {
		return nil, common.NewError("owner role is read-only")
	}

	updates := map[string]any{
		"permissions": marshalAnyMap(payload.Permissions),
		"limits":      marshalAnyMap(payload.Limits),
		"features":    marshalAnyMap(payload.Features),
		"access":      marshalAnyMap(payload.Access),
	}

	if !row.BuiltIn {
		name := strings.TrimSpace(payload.Name)
		if name == "" {
			return nil, common.NewError("role name is required")
		}
		if len(name) > 64 {
			return nil, common.NewError("role name must be 64 characters or fewer")
		}
		slug := normalizeRoleSlug(name)
		if slug == "" {
			return nil, common.NewError("role slug is invalid")
		}
		var count int64
		if err := db.Model(&model.AdminRole{}).
			Where("(name = ? OR slug = ?) AND id <> ?", name, slug, id).
			Count(&count).Error; err != nil {
			return nil, err
		}
		if count > 0 {
			return nil, common.NewError("role already exists")
		}
		updates["name"] = name
		updates["slug"] = slug
	}

	if err := db.Model(&model.AdminRole{}).
		Where("id = ?", id).
		Updates(updates).
		Error; err != nil {
		return nil, err
	}
	return s.Get(id)
}

func (s *AdminRoleService) Duplicate(id int) (*AdminRoleView, error) {
	if id <= 0 {
		return nil, common.NewError("invalid role id")
	}
	db := database.GetDB()
	var src model.AdminRole
	if err := db.Where("id = ?", id).First(&src).Error; err != nil {
		return nil, err
	}

	baseName := strings.TrimSpace(src.Name) + " (copy)"
	name := baseName
	for i := 2; ; i++ {
		slug := normalizeRoleSlug(name)
		var count int64
		if err := db.Model(&model.AdminRole{}).
			Where("name = ? OR slug = ?", name, slug).
			Count(&count).Error; err != nil {
			return nil, err
		}
		if count == 0 {
			row := &model.AdminRole{
				Name:            name,
				Slug:            slug,
				BuiltIn:         false,
				OwnerRole:       false,
				PermissionsJSON: src.PermissionsJSON,
				LimitsJSON:      src.LimitsJSON,
				FeaturesJSON:    src.FeaturesJSON,
				AccessJSON:      src.AccessJSON,
			}
			if err := db.Create(row).Error; err != nil {
				return nil, err
			}
			return roleToView(row, 0), nil
		}
		name = baseName + " " + strconv.Itoa(i)
	}
}

func (s *AdminRoleService) Delete(id int) error {
	if id <= 0 {
		return common.NewError("invalid role id")
	}
	db := database.GetDB()
	var row model.AdminRole
	if err := db.Where("id = ?", id).First(&row).Error; err != nil {
		return err
	}
	if row.OwnerRole {
		return common.NewError("owner role cannot be deleted")
	}
	if row.BuiltIn {
		return common.NewError("built-in roles cannot be deleted")
	}

	var count int64
	if err := db.Model(&model.User{}).Where("role_id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return common.NewError("role is assigned to admins")
	}

	res := db.Where("id = ?", id).Delete(&model.AdminRole{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("role not found")
	}
	return nil
}

// PermissionsJSONToMap is intentionally not exported on model.AdminRole. This
// local fallback keeps custom role creation minimal until the full permission UI
// starts sending complete maps.
func nonEmptyOrDefault(v map[string]any, fallback map[string]any) map[string]any {
	if len(v) > 0 {
		return v
	}
	return fallback
}

func decodeDefaultRoleMap(raw string) map[string]any {
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]any{}
	}
	return out
}

func defaultOperatorRoleMaps() (map[string]any, map[string]any, map[string]any, map[string]any) {
	defaults := model.DefaultAdminRoles()[2]
	return decodeDefaultRoleMap(defaults.PermissionsJSON),
		decodeDefaultRoleMap(defaults.LimitsJSON),
		decodeDefaultRoleMap(defaults.FeaturesJSON),
		decodeDefaultRoleMap(defaults.AccessJSON)
}
