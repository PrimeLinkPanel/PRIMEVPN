package outbound

import (
	"os"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

const hiddenOutboundTagsEnv = "XUI_HIDDEN_OUTBOUND_TAGS"

func isHiddenOutboundTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return false
	}
	for _, raw := range strings.Split(os.Getenv(hiddenOutboundTagsEnv), ",") {
		rule := strings.TrimSpace(raw)
		if rule == "" {
			continue
		}
		if rule == tag {
			return true
		}
		if strings.HasSuffix(rule, "*") {
			prefix := strings.TrimSuffix(rule, "*")
			if prefix != "" && strings.HasPrefix(tag, prefix) {
				return true
			}
		}
	}
	return false
}

func filterVisibleOutboundTraffics(traffics []*model.OutboundTraffics) []*model.OutboundTraffics {
	visible := make([]*model.OutboundTraffics, 0, len(traffics))
	for _, traffic := range traffics {
		if traffic != nil && isHiddenOutboundTag(traffic.Tag) {
			continue
		}
		visible = append(visible, traffic)
	}
	return visible
}
