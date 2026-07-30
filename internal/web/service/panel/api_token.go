package panel

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/common"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/crypto"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/random"
)

type ApiTokenService struct{}

const (
	apiTokenLength             = 48
	maxPresentedAPITokenLength = 256

	ApiTokenScopeClientsRead       = "clients:read"
	ApiTokenScopeClientsCreate     = "clients:create"
	ApiTokenScopeCustomPanelManage = "custom-panel:manage"
)

var (
	ErrInvalidAPIToken      = errors.New("invalid API token")
	delegatedAPITokenScopes = map[string]struct{}{
		ApiTokenScopeClientsRead:       {},
		ApiTokenScopeClientsCreate:     {},
		ApiTokenScopeCustomPanelManage: {},
	}
)

// ApiTokenCreateOptions is the trusted service-layer input used by the
// owner-only controller. SubjectAdminId is mandatory for delegated tokens and
// forbidden for service tokens.
type ApiTokenCreateOptions struct {
	Name             string
	Kind             string
	SubjectAdminId   int
	CreatedByAdminId int
	Scopes           []string
	ExpiresAt        int64
}

// ApiTokenAuthentication contains request-local identity metadata. It never
// contains the plaintext bearer token or its stored hash.
type ApiTokenAuthentication struct {
	TokenId   int
	TokenName string
	Kind      string
	Scopes    []string
	Subject   *model.User
}

type ApiTokenView struct {
	Id               int      `json:"id" example:"2"`
	Name             string   `json:"name" example:"telegram-bot-a"`
	Token            string   `json:"token,omitempty" example:"hmd_d_new-token-string"`
	Kind             string   `json:"kind" example:"delegated"`
	SubjectAdminId   *int     `json:"subjectAdminId,omitempty" example:"3"`
	SubjectUsername  string   `json:"subjectUsername,omitempty" example:"operator-a"`
	SubjectRoleName  string   `json:"subjectRoleName,omitempty" example:"Operator"`
	CreatedByAdminId *int     `json:"createdByAdminId,omitempty" example:"1"`
	Scopes           []string `json:"scopes" example:"[\"clients:read\",\"clients:create\"]"`
	ExpiresAt        int64    `json:"expiresAt" example:"1767536000"`
	Expired          bool     `json:"expired" example:"false"`
	Enabled          bool     `json:"enabled" example:"true"`
	CreatedAt        int64    `json:"createdAt" example:"1736000000"`
}

type ApiTokenSubjectView struct {
	Id       int    `json:"id" gorm:"column:id" example:"3"`
	Username string `json:"username" gorm:"column:username" example:"operator-a"`
	RoleId   int    `json:"roleId" gorm:"column:role_id" example:"2"`
	RoleName string `json:"roleName" gorm:"column:role_name" example:"Operator"`
}

func apiTokenCreatedAtSeconds(createdAt int64) int64 {
	if createdAt >= model.ApiTokenUnixMillisecondsThreshold {
		return createdAt / 1000
	}
	return createdAt
}

func normalizedAPITokenKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		// Rows created before delegated tokens existed are trusted service tokens.
		return model.ApiTokenKindService
	}
	return kind
}

func normalizeDelegatedAPITokenScopes(scopes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, raw := range scopes {
		scope := strings.ToLower(strings.TrimSpace(raw))
		if scope == "" {
			continue
		}
		if _, allowed := delegatedAPITokenScopes[scope]; !allowed {
			return nil, common.NewErrorf("unsupported API token scope: %s", scope)
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	if len(out) == 0 {
		return nil, common.NewError("at least one delegated API token scope is required")
	}
	sort.Strings(out)
	return out, nil
}

func storedAPITokenScopes(row *model.ApiToken) ([]string, error) {
	if row == nil {
		return nil, ErrInvalidAPIToken
	}
	if normalizedAPITokenKind(row.Kind) == model.ApiTokenKindService {
		return []string{"*"}, nil
	}
	if strings.TrimSpace(row.ScopesJSON) == "" {
		return nil, ErrInvalidAPIToken
	}
	var scopes []string
	if err := json.Unmarshal([]byte(row.ScopesJSON), &scopes); err != nil {
		return nil, ErrInvalidAPIToken
	}
	normalized, err := normalizeDelegatedAPITokenScopes(scopes)
	if err != nil {
		return nil, ErrInvalidAPIToken
	}
	return normalized, nil
}

func toView(row *model.ApiToken, subject *model.User, role *model.AdminRole) *ApiTokenView {
	kind := normalizedAPITokenKind(row.Kind)
	scopes, err := storedAPITokenScopes(row)
	if err != nil {
		scopes = []string{}
	}
	view := &ApiTokenView{
		Id:               row.Id,
		Name:             row.Name,
		Kind:             kind,
		SubjectAdminId:   row.SubjectAdminId,
		CreatedByAdminId: row.CreatedByAdminId,
		Scopes:           scopes,
		ExpiresAt:        row.ExpiresAt,
		Expired:          row.ExpiresAt > 0 && row.ExpiresAt <= time.Now().Unix(),
		Enabled:          row.Enabled,
		CreatedAt:        apiTokenCreatedAtSeconds(row.CreatedAt),
	}
	if subject != nil {
		view.SubjectUsername = subject.Username
	}
	if role != nil {
		view.SubjectRoleName = role.Name
	}
	return view
}

// List resolves subject and role labels in two batched lookups, avoiding an
// N+1 query pattern as the number of tokens grows.
func (s *ApiTokenService) List() ([]*ApiTokenView, error) {
	db := database.GetDB()
	var rows []*model.ApiToken
	if err := db.Model(model.ApiToken{}).Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}

	subjectIDs := make([]int, 0, len(rows))
	seenSubjectIDs := make(map[int]struct{}, len(rows))
	for _, row := range rows {
		if row.SubjectAdminId == nil || *row.SubjectAdminId <= 0 {
			continue
		}
		if _, seen := seenSubjectIDs[*row.SubjectAdminId]; seen {
			continue
		}
		seenSubjectIDs[*row.SubjectAdminId] = struct{}{}
		subjectIDs = append(subjectIDs, *row.SubjectAdminId)
	}

	usersByID := make(map[int]*model.User, len(subjectIDs))
	rolesByID := make(map[int]*model.AdminRole)
	if len(subjectIDs) > 0 {
		var users []model.User
		if err := db.Where("id IN ?", subjectIDs).Find(&users).Error; err != nil {
			return nil, err
		}
		roleIDs := make([]int, 0, len(users))
		seenRoleIDs := make(map[int]struct{}, len(users))
		for i := range users {
			user := &users[i]
			usersByID[user.Id] = user
			if user.RoleId <= 0 {
				continue
			}
			if _, seen := seenRoleIDs[user.RoleId]; seen {
				continue
			}
			seenRoleIDs[user.RoleId] = struct{}{}
			roleIDs = append(roleIDs, user.RoleId)
		}
		if len(roleIDs) > 0 {
			var roles []model.AdminRole
			if err := db.Where("id IN ?", roleIDs).Find(&roles).Error; err != nil {
				return nil, err
			}
			for i := range roles {
				rolesByID[roles[i].Id] = &roles[i]
			}
		}
	}

	out := make([]*ApiTokenView, 0, len(rows))
	for _, row := range rows {
		var subject *model.User
		var role *model.AdminRole
		if row.SubjectAdminId != nil {
			subject = usersByID[*row.SubjectAdminId]
			if subject != nil {
				role = rolesByID[subject.RoleId]
			}
		}
		out = append(out, toView(row, subject, role))
	}
	return out, nil
}

// ListDelegatedSubjects returns the minimum metadata needed by the owner token
// form. The join filters inactive and owner accounts in the database and avoids
// exposing passwords, limits, contact settings, or other administrator data.
func (s *ApiTokenService) ListDelegatedSubjects() ([]*ApiTokenSubjectView, error) {
	db := database.GetDB()
	if db == nil {
		return nil, common.NewError("database is not initialized")
	}
	rows := make([]*ApiTokenSubjectView, 0)
	err := db.Table("users AS u").
		Select("u.id AS id, u.username AS username, u.role_id AS role_id, r.name AS role_name").
		Joins("JOIN admin_roles AS r ON r.id = u.role_id").
		Where("u.status = ? AND r.owner_role = ?", model.AdminStatusActive, false).
		Order("LOWER(u.username) ASC").
		Order("u.id ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Create preserves the original service-token API for trusted internal callers
// and backward-compatible tests. Browser token creation uses CreateWithOptions
// through an owner-only controller.
func (s *ApiTokenService) Create(name string) (*ApiTokenView, error) {
	return s.CreateWithOptions(ApiTokenCreateOptions{
		Name: name,
		Kind: model.ApiTokenKindService,
	})
}

func (s *ApiTokenService) validateDelegatedSubject(subjectAdminID int) (*model.User, *model.AdminRole, error) {
	if subjectAdminID <= 0 {
		return nil, nil, common.NewError("delegated token subject is required")
	}
	db := database.GetDB()
	var subject model.User
	if err := db.Where("id = ? AND status = ?", subjectAdminID, model.AdminStatusActive).First(&subject).Error; err != nil {
		return nil, nil, common.NewError("active delegated token subject not found")
	}
	var role model.AdminRole
	if err := db.Where("id = ?", subject.RoleId).First(&role).Error; err != nil {
		return nil, nil, common.NewError("delegated token subject role not found")
	}
	if role.OwnerRole {
		return nil, nil, common.NewError("owner cannot be a delegated token subject")
	}
	return &subject, &role, nil
}

func (s *ApiTokenService) CreateWithOptions(opts ApiTokenCreateOptions) (*ApiTokenView, error) {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return nil, common.NewError("token name is required")
	}
	if utf8.RuneCountInString(name) > 64 {
		return nil, common.NewError("token name must be 64 characters or fewer")
	}

	kind := normalizedAPITokenKind(opts.Kind)
	if kind != model.ApiTokenKindService && kind != model.ApiTokenKindDelegated {
		return nil, common.NewError("unsupported API token kind")
	}
	if opts.ExpiresAt < 0 || (opts.ExpiresAt > 0 && opts.ExpiresAt <= time.Now().Unix()) {
		return nil, common.NewError("token expiry must be in the future")
	}

	var subject *model.User
	var role *model.AdminRole
	var subjectID *int
	var scopes []string
	var err error
	if kind == model.ApiTokenKindDelegated {
		subject, role, err = s.validateDelegatedSubject(opts.SubjectAdminId)
		if err != nil {
			return nil, err
		}
		scopes, err = normalizeDelegatedAPITokenScopes(opts.Scopes)
		if err != nil {
			return nil, err
		}
		id := subject.Id
		subjectID = &id
	} else {
		if opts.SubjectAdminId != 0 {
			return nil, common.NewError("service tokens cannot have a delegated subject")
		}
		scopes = []string{"*"}
	}

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, err
	}
	db := database.GetDB()
	var count int64
	if err := db.Model(model.ApiToken{}).Where("name = ?", name).Count(&count).Error; err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, common.NewError("a token with that name already exists")
	}

	prefix := "hmd_s_"
	if kind == model.ApiTokenKindDelegated {
		prefix = "hmd_d_"
	}
	plaintext := prefix + random.Seq(apiTokenLength)
	var createdByID *int
	if opts.CreatedByAdminId > 0 {
		id := opts.CreatedByAdminId
		createdByID = &id
	}
	row := &model.ApiToken{
		Name:             name,
		Token:            crypto.HashTokenSHA256(plaintext),
		Kind:             kind,
		SubjectAdminId:   subjectID,
		CreatedByAdminId: createdByID,
		ScopesJSON:       string(scopesJSON),
		ExpiresAt:        opts.ExpiresAt,
		Enabled:          true,
	}
	if err := db.Create(row).Error; err != nil {
		return nil, err
	}
	view := toView(row, subject, role)
	view.Token = plaintext
	return view, nil
}

func (s *ApiTokenService) Delete(id int) error {
	if id <= 0 {
		return common.NewError("invalid token id")
	}
	db := database.GetDB()
	return db.Where("id = ?", id).Delete(model.ApiToken{}).Error
}

func (s *ApiTokenService) SetEnabled(id int, enabled bool) error {
	if id <= 0 {
		return common.NewError("invalid token id")
	}
	db := database.GetDB()
	res := db.Model(model.ApiToken{}).Where("id = ?", id).Update("enabled", enabled)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return errors.New("token not found")
	}
	return nil
}

// Authenticate performs a single indexed lookup by SHA-256 digest. API tokens
// carry at least 48 random characters, so direct digest equality is resistant
// to offline guessing while avoiding the previous O(n) full-table scan.
func (s *ApiTokenService) Authenticate(presented string) (*ApiTokenAuthentication, error) {
	if presented == "" || len(presented) > maxPresentedAPITokenLength {
		return nil, ErrInvalidAPIToken
	}
	db := database.GetDB()
	if db == nil {
		return nil, ErrInvalidAPIToken
	}
	hash := crypto.HashTokenSHA256(presented)
	var matches []model.ApiToken
	if err := db.Where("token = ? AND enabled = ?", hash, true).Limit(2).Find(&matches).Error; err != nil {
		return nil, err
	}
	// A duplicate digest should be practically impossible. Treating an
	// ambiguous credential as invalid is safer than choosing an arbitrary row
	// if a database was manually modified or imported from a broken source.
	if len(matches) != 1 {
		return nil, ErrInvalidAPIToken
	}
	row := matches[0]
	if row.ExpiresAt > 0 && row.ExpiresAt <= time.Now().Unix() {
		return nil, ErrInvalidAPIToken
	}

	kind := normalizedAPITokenKind(row.Kind)
	scopes, err := storedAPITokenScopes(&row)
	if err != nil {
		return nil, ErrInvalidAPIToken
	}
	auth := &ApiTokenAuthentication{
		TokenId:   row.Id,
		TokenName: row.Name,
		Kind:      kind,
		Scopes:    scopes,
	}
	if kind == model.ApiTokenKindService {
		return auth, nil
	}
	if kind != model.ApiTokenKindDelegated || row.SubjectAdminId == nil {
		return nil, ErrInvalidAPIToken
	}

	subject, role, err := s.validateDelegatedSubject(*row.SubjectAdminId)
	if err != nil || subject == nil || role == nil {
		return nil, ErrInvalidAPIToken
	}
	if err := EnforceLimitedAdminFeatures(subject); err != nil {
		return nil, ErrInvalidAPIToken
	}
	auth.Subject = subject
	return auth, nil
}

// Match remains as a compatibility wrapper for trusted internal callers.
func (s *ApiTokenService) Match(presented string) bool {
	_, err := s.Authenticate(presented)
	return err == nil
}
