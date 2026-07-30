package service

import (
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestValidateClientAgainstRoleLimitsDataLimit(t *testing.T) {
	limits := adminRoleClientLimits{
		MinDataLimitSet: true,
		MinDataLimitGB:  10,
		MaxDataLimitSet: true,
		MaxDataLimitGB:  100,
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 50 * roleLimitBytesPerGB}, 0); err != nil {
		t.Fatalf("expected data limit inside range to pass: %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 0}, 0); err == nil {
		t.Fatal("expected unlimited traffic to be denied when data limits are configured")
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 5 * roleLimitBytesPerGB}, 0); err == nil {
		t.Fatal("expected data limit below minimum to be denied")
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 101 * roleLimitBytesPerGB}, 0); err == nil {
		t.Fatal("expected data limit above maximum to be denied")
	}
}

func TestValidateClientAgainstRoleLimitsExpiryLimit(t *testing.T) {
	now := int64(1_700_000_000_000)
	limits := adminRoleClientLimits{
		MinExpireDaysSet: true,
		MinExpireDays:    1,
		MaxExpireDaysSet: true,
		MaxExpireDays:    30,
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{ExpiryTime: now + 7*roleLimitDayMillis}, now); err != nil {
		t.Fatalf("expected expiry inside range to pass: %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{ExpiryTime: 0}, now); err == nil {
		t.Fatal("expected unlimited expiry to be denied when expiry limits are configured")
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{ExpiryTime: now + 12*60*60*1000}, now); err == nil {
		t.Fatal("expected expiry below minimum to be denied")
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{ExpiryTime: now + 31*roleLimitDayMillis}, now); err == nil {
		t.Fatal("expected expiry above maximum to be denied")
	}
}

func TestRoleClientLimitsParsesPositiveValuesOnly(t *testing.T) {
	role := &model.AdminRole{
		LimitsJSON: `{"maxUsers":5,"minDataLimit":0,"maxDataLimit":"100","minExpireDays":"bad","maxExpireDays":30}`,
	}

	limits := roleClientLimits(role)

	if !limits.MaxUsersSet || limits.MaxUsers != 5 {
		t.Fatalf("maxUsers = (%v,%d), want set 5", limits.MaxUsersSet, limits.MaxUsers)
	}
	if limits.MinDataLimitSet {
		t.Fatal("zero minDataLimit should disable the limit")
	}
	if !limits.MaxDataLimitSet || limits.MaxDataLimitGB != 100 {
		t.Fatalf("maxDataLimit = (%v,%d), want set 100", limits.MaxDataLimitSet, limits.MaxDataLimitGB)
	}
	if limits.MinExpireDaysSet {
		t.Fatal("invalid minExpireDays should disable the limit")
	}
	if !limits.MaxExpireDaysSet || limits.MaxExpireDays != 30 {
		t.Fatalf("maxExpireDays = (%v,%d), want set 30", limits.MaxExpireDaysSet, limits.MaxExpireDays)
	}
}

func TestApplyAdminPermissionOverrides(t *testing.T) {
	role := &model.AdminRole{
		LimitsJSON: `{"maxUsers":10,"minDataLimit":5,"maxDataLimit":100,"minExpireDays":1,"maxExpireDays":30}`,
	}
	user := &model.User{
		PermissionOverridesJSON: `{"max_users":1,"data_limit_max":2147483648,"expire_max":604800}`,
	}

	limits := applyAdminPermissionOverrides(roleClientLimits(role), user)

	if !limits.MaxUsersSet || limits.MaxUsers != 1 {
		t.Fatalf("maxUsers override = (%v,%d), want set 1", limits.MaxUsersSet, limits.MaxUsers)
	}
	if !limits.MaxDataLimitBytesSet || limits.MaxDataLimitBytes != 2147483648 {
		t.Fatalf("maxDataLimit override bytes = (%v,%d), want set 2147483648", limits.MaxDataLimitBytesSet, limits.MaxDataLimitBytes)
	}
	if !limits.MaxExpireDaysSet || limits.MaxExpireDays != 7 {
		t.Fatalf("maxExpireDays override = (%v,%d), want set 7", limits.MaxExpireDaysSet, limits.MaxExpireDays)
	}
	if !limits.MinDataLimitSet || limits.MinDataLimitGB != 5 {
		t.Fatalf("minDataLimit should inherit role value, got (%v,%d)", limits.MinDataLimitSet, limits.MinDataLimitGB)
	}
}

func TestPermissionOverrideBytesValidation(t *testing.T) {
	limits := applyAdminPermissionOverrides(adminRoleClientLimits{}, &model.User{
		PermissionOverridesJSON: `{"data_limit_min":1073741824,"data_limit_max":10737418240,"expire_min":86400,"expire_max":2592000}`,
	})

	if err := validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 3 * roleLimitBytesPerGB, ExpiryTime: roleLimitDayMillis * 10}, 0); err != nil {
		t.Fatalf("expected 3GB/10d to pass byte-second overrides: %v", err)
	}
	if err := validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 512 * 1024 * 1024, ExpiryTime: roleLimitDayMillis * 10}, 0); err == nil {
		t.Fatal("expected 512MB to fail 1GB minimum")
	}
}

func TestValidateClientAgainstRoleLimitsStartAfterFirstUseExpiry(t *testing.T) {
	limits := adminRoleClientLimits{
		MinExpireDaysSet: true,
		MinExpireDays:    1,
		MaxExpireDaysSet: true,
		MaxExpireDays:    30,
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{ExpiryTime: -20 * roleLimitDayMillis}, 0); err != nil {
		t.Fatalf("expected start-after-first-use 20d to pass 1..30d limit: %v", err)
	}
	if err := validateClientAgainstRoleLimits(limits, model.Client{ExpiryTime: -12 * 60 * 60 * 1000}, 0); err == nil {
		t.Fatal("expected start-after-first-use 12h to fail 1d minimum")
	}
	if err := validateClientAgainstRoleLimits(limits, model.Client{ExpiryTime: -40 * roleLimitDayMillis}, 0); err == nil {
		t.Fatal("expected start-after-first-use 40d to fail 30d maximum")
	}
}

func TestValidateClientAgainstRoleLimitsDetailedMessages(t *testing.T) {
	limits := adminRoleClientLimits{
		MinDataLimitBytesSet: true,
		MinDataLimitBytes:    5 * roleLimitBytesPerGB,
		MaxDataLimitBytesSet: true,
		MaxDataLimitBytes:    10 * roleLimitBytesPerGB,
		MinExpireDaysSet:     true,
		MinExpireDays:        7,
		MaxExpireDaysSet:     true,
		MaxExpireDays:        30,
	}

	err := validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 2 * roleLimitBytesPerGB, ExpiryTime: 10 * roleLimitDayMillis}, 0)
	if err == nil || !strings.Contains(err.Error(), "حداقل حجم مجاز") || !strings.Contains(err.Error(), "5 گیگابایت") || !strings.Contains(err.Error(), "2 گیگابایت") {
		t.Fatalf("below-min data error = %v", err)
	}

	err = validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 12 * roleLimitBytesPerGB, ExpiryTime: 10 * roleLimitDayMillis}, 0)
	if err == nil || !strings.Contains(err.Error(), "حداکثر حجم مجاز") || !strings.Contains(err.Error(), "10 گیگابایت") || !strings.Contains(err.Error(), "12 گیگابایت") {
		t.Fatalf("above-max data error = %v", err)
	}

	err = validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 6 * roleLimitBytesPerGB, ExpiryTime: 3 * roleLimitDayMillis}, 0)
	if err == nil || !strings.Contains(err.Error(), "حداقل مدت مجاز") || !strings.Contains(err.Error(), "7 روز") || !strings.Contains(err.Error(), "3 روز") {
		t.Fatalf("below-min expiry error = %v", err)
	}

	err = validateClientAgainstRoleLimits(limits, model.Client{TotalGB: 6 * roleLimitBytesPerGB, ExpiryTime: 40 * roleLimitDayMillis}, 0)
	if err == nil || !strings.Contains(err.Error(), "حداکثر مدت مجاز") || !strings.Contains(err.Error(), "30 روز") || !strings.Contains(err.Error(), "40 روز") {
		t.Fatalf("above-max expiry error = %v", err)
	}
}

func TestValidateClientAgainstRoleLimitsSpeedLimits(t *testing.T) {
	limits := adminRoleClientLimits{
		MinDownloadMbpsSet: true,
		MinDownloadMbps:    10,
		MaxDownloadMbpsSet: true,
		MaxDownloadMbps:    100,
		MinUploadMbpsSet:   true,
		MinUploadMbps:      5,
		MaxUploadMbpsSet:   true,
		MaxUploadMbps:      50,
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 50, UploadMbps: 20}, 0); err != nil {
		t.Fatalf("expected download/upload speeds inside range to pass: %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 0, UploadMbps: 20}, 0); err == nil || !strings.Contains(err.Error(), "unlimited download speed") {
		t.Fatalf("expected unlimited download speed to fail, got %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 9, UploadMbps: 20}, 0); err == nil || !strings.Contains(err.Error(), "minimum download limit is 10 Mbps") {
		t.Fatalf("expected download speed below min to fail, got %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 101, UploadMbps: 20}, 0); err == nil || !strings.Contains(err.Error(), "maximum download limit is 100 Mbps") {
		t.Fatalf("expected download speed above max to fail, got %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 50, UploadMbps: 0}, 0); err == nil || !strings.Contains(err.Error(), "unlimited upload speed") {
		t.Fatalf("expected unlimited upload speed to fail, got %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 50, UploadMbps: 4}, 0); err == nil || !strings.Contains(err.Error(), "minimum upload limit is 5 Mbps") {
		t.Fatalf("expected upload speed below min to fail, got %v", err)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 50, UploadMbps: 51}, 0); err == nil || !strings.Contains(err.Error(), "maximum upload limit is 50 Mbps") {
		t.Fatalf("expected upload speed above max to fail, got %v", err)
	}
}

func TestRoleClientLimitsParsesSpeedLimits(t *testing.T) {
	role := &model.AdminRole{
		LimitsJSON: `{"download_mbps_min":10,"download_mbps_max":100,"upload_mbps_min":5,"upload_mbps_max":50}`,
	}

	limits := roleClientLimits(role)

	if !limits.MinDownloadMbpsSet || limits.MinDownloadMbps != 10 {
		t.Fatalf("min download = (%v,%d), want set 10", limits.MinDownloadMbpsSet, limits.MinDownloadMbps)
	}
	if !limits.MaxDownloadMbpsSet || limits.MaxDownloadMbps != 100 {
		t.Fatalf("max download = (%v,%d), want set 100", limits.MaxDownloadMbpsSet, limits.MaxDownloadMbps)
	}
	if !limits.MinUploadMbpsSet || limits.MinUploadMbps != 5 {
		t.Fatalf("min upload = (%v,%d), want set 5", limits.MinUploadMbpsSet, limits.MinUploadMbps)
	}
	if !limits.MaxUploadMbpsSet || limits.MaxUploadMbps != 50 {
		t.Fatalf("max upload = (%v,%d), want set 50", limits.MaxUploadMbpsSet, limits.MaxUploadMbps)
	}
}

func TestApplyAdminPermissionOverridesSpeedLimits(t *testing.T) {
	role := &model.AdminRole{
		LimitsJSON: `{"download_mbps_min":10,"download_mbps_max":100,"upload_mbps_min":5,"upload_mbps_max":50}`,
	}
	user := &model.User{
		PermissionOverridesJSON: `{"download_mbps_min":20,"download_mbps_max":80,"upload_mbps_min":10,"upload_mbps_max":40}`,
	}

	limits := applyAdminPermissionOverrides(roleClientLimits(role), user)

	if limits.MinDownloadMbps != 20 || limits.MaxDownloadMbps != 80 || limits.MinUploadMbps != 10 || limits.MaxUploadMbps != 40 {
		t.Fatalf("speed overrides not applied: %+v", limits)
	}

	if err := validateClientAgainstRoleLimits(limits, model.Client{DownloadMbps: 15, UploadMbps: 20}, 0); err == nil || !strings.Contains(err.Error(), "minimum download limit is 20 Mbps") {
		t.Fatalf("expected overridden min download to be enforced, got %v", err)
	}
}
