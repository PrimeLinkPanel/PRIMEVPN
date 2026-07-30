package service

import (
	"os"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"

	"gorm.io/gorm"
)

const hiddenClientEmailsEnv = "XUI_HIDDEN_CLIENT_EMAILS"

func hiddenClientEmailRules() []string {
	raw := strings.TrimSpace(os.Getenv(hiddenClientEmailsEnv))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	rules := make([]string, 0, len(parts))

	for _, part := range parts {
		rule := strings.ToLower(strings.TrimSpace(part))
		if rule != "" {
			rules = append(rules, rule)
		}
	}

	return rules
}

// IsHiddenClientEmail supports exact matches and prefix wildcards:
//
//	XUI_HIDDEN_CLIENT_EMAILS=client1,system-*,tunnel-*
func IsHiddenClientEmail(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}

	for _, rule := range hiddenClientEmailRules() {
		if rule == email {
			return true
		}

		if strings.HasSuffix(rule, "*") {
			prefix := strings.TrimSuffix(rule, "*")
			if prefix != "" && strings.HasPrefix(email, prefix) {
				return true
			}
		}
	}

	return false
}

func filterVisibleClientRows(rows []ClientWithAttachments) []ClientWithAttachments {
	if len(rows) == 0 || len(hiddenClientEmailRules()) == 0 {
		return rows
	}

	visible := make([]ClientWithAttachments, 0, len(rows))

	for _, row := range rows {
		if IsHiddenClientEmail(row.Email) {
			continue
		}

		visible = append(visible, row)
	}

	return visible
}

func FilterVisibleClientEmails(emails []string) []string {
	if len(emails) == 0 || len(hiddenClientEmailRules()) == 0 {
		return emails
	}

	visible := make([]string, 0, len(emails))

	for _, email := range emails {
		if IsHiddenClientEmail(email) {
			continue
		}

		visible = append(visible, email)
	}

	return visible
}

// RequireVisibleClientByEmail prevents direct API access to hidden clients.
func (s *ClientService) RequireVisibleClientByEmail(email string) (*model.ClientRecord, error) {
	if IsHiddenClientEmail(email) {
		return nil, gorm.ErrRecordNotFound
	}

	return s.GetRecordByEmail(nil, email)
}

// RequireVisibleClientBySubID prevents subscription-link access through a
// hidden client's subscription identifier.
func (s *ClientService) RequireVisibleClientBySubID(subID string) (*model.ClientRecord, error) {
	subID = strings.TrimSpace(subID)
	if subID == "" {
		return nil, gorm.ErrRecordNotFound
	}

	row := &model.ClientRecord{}
	err := database.GetDB().
		Where("sub_id = ?", subID).
		First(row).
		Error
	if err != nil {
		return nil, err
	}

	if IsHiddenClientEmail(row.Email) {
		return nil, gorm.ErrRecordNotFound
	}

	return row, nil
}

func applyVisibleClientEmailScope(db *gorm.DB, column string) *gorm.DB {
	if db == nil || len(hiddenClientEmailRules()) == 0 {
		return db
	}

	for _, rule := range hiddenClientEmailRules() {
		if strings.HasSuffix(rule, "*") {
			prefix := strings.TrimSuffix(rule, "*")
			if prefix != "" {
				db = db.Where("LOWER("+column+") NOT LIKE ?", prefix+"%")
			}
			continue
		}

		db = db.Where("LOWER("+column+") <> ?", rule)
	}

	return db
}
