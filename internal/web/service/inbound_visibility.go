package service

import (
	"os"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"

	"gorm.io/gorm"
)

const hiddenInboundRemarksEnv = "XUI_HIDDEN_INBOUND_REMARKS"

var defaultHiddenInboundRemarkRules = []string{
	"s1",
	"s2",
	"s3",
	"s4",
	"s5",
	"s6",
}

func hiddenInboundRemarkRules() []string {
	raw := strings.TrimSpace(os.Getenv(hiddenInboundRemarksEnv))
	if raw == "" {
		return defaultHiddenInboundRemarkRules
	}

	parts := strings.Split(raw, ",")
	rules := make([]string, 0, len(parts))

	for _, part := range parts {
		rule := strings.ToLower(strings.TrimSpace(part))
		if rule == "" {
			continue
		}
		rules = append(rules, rule)
	}

	if len(rules) == 0 {
		return defaultHiddenInboundRemarkRules
	}

	return rules
}

func isHiddenInboundRemark(remark string) bool {
	remark = strings.ToLower(strings.TrimSpace(remark))
	if remark == "" {
		return false
	}

	for _, rule := range hiddenInboundRemarkRules() {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if rule == "" {
			continue
		}

		if strings.HasSuffix(rule, "*") {
			prefix := strings.TrimSuffix(rule, "*")
			if prefix != "" && strings.HasPrefix(remark, prefix) {
				return true
			}
			continue
		}

		if remark == rule {
			return true
		}
	}

	return false
}

func isHiddenInbound(inbound *model.Inbound) bool {
	if inbound == nil {
		return false
	}

	return isHiddenInboundRemark(inbound.Remark)
}

func filterVisibleInbounds(inbounds []*model.Inbound) []*model.Inbound {
	if len(inbounds) == 0 {
		return inbounds
	}

	visible := inbounds[:0]
	for _, inbound := range inbounds {
		if isHiddenInbound(inbound) {
			continue
		}
		visible = append(visible, inbound)
	}

	return visible
}

// RequireVisibleInbound returns gorm.ErrRecordNotFound for hidden inbounds.
// This intentionally behaves like the inbound does not exist, so callers do
// not leak that an internal/tunnel inbound is present.
func (s *InboundService) RequireVisibleInbound(id int) (*model.Inbound, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}

	if err := db.Model(model.Inbound{}).First(inbound, id).Error; err != nil {
		return nil, err
	}

	if isHiddenInbound(inbound) {
		return nil, gorm.ErrRecordNotFound
	}

	return inbound, nil
}
