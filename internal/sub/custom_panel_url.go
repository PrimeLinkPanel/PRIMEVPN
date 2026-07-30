package sub

import (
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/common"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
)

func BuildSubscriptionURL(host string, subID string) (string, error) {
	subID = strings.TrimSpace(subID)
	if subID == "" {
		return "", common.NewError("client subId is required")
	}

	settingService := service.SettingService{}
	subPath, err := settingService.GetSubPath()
	if err != nil {
		return "", err
	}

	svc := NewSubService("")
	svc.PrepareForRequest(host)
	subURL, _, _ := svc.BuildURLs(subPath, "", "", subID)
	if subURL == "" {
		return "", common.NewError("subscription URL is unavailable")
	}
	return subURL, nil
}
