package service

import (
	"math"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestUpdateInbound_PersistsUsageMultiplier(t *testing.T) {
	setupConflictDB(t)

	existing := model.Inbound{
		UserId:          1,
		Tag:             "in-45678-tcp",
		Enable:          true,
		Listen:          "0.0.0.0",
		Port:            45678,
		Protocol:        model.VLESS,
		StreamSettings:  `{"network":"tcp","security":"none"}`,
		Settings:        `{"clients":[],"decryption":"none","encryption":"none"}`,
		UsageMultiplier: 1,
	}
	if err := database.GetDB().Create(&existing).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	update := existing
	update.UsageMultiplier = 7.5
	got, _, err := (&InboundService{}).UpdateInbound(&update)
	if err != nil {
		t.Fatalf("UpdateInbound: %v", err)
	}

	var reloaded model.Inbound
	if err := database.GetDB().First(&reloaded, existing.Id).Error; err != nil {
		t.Fatalf("reload inbound: %v", err)
	}

	if math.Abs(reloaded.UsageMultiplier-7.5) > 0.0001 {
		t.Fatalf("persisted usage multiplier = %v, want 7.5", reloaded.UsageMultiplier)
	}
	if math.Abs(got.UsageMultiplier-7.5) > 0.0001 {
		t.Fatalf("returned usage multiplier = %v, want 7.5", got.UsageMultiplier)
	}
}

func TestAddInbound_NormalizesUsageMultiplierDefault(t *testing.T) {
	setupConflictDB(t)

	inbound := &model.Inbound{
		UserId:         1,
		Tag:            "in-45679-tcp",
		Enable:         true,
		Listen:         "0.0.0.0",
		Port:           45679,
		Protocol:       model.VLESS,
		StreamSettings: `{"network":"tcp","security":"none"}`,
		Settings:       `{"clients":[],"decryption":"none","encryption":"none"}`,
	}

	got, _, err := (&InboundService{}).AddInbound(inbound)
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	var reloaded model.Inbound
	if err := database.GetDB().First(&reloaded, got.Id).Error; err != nil {
		t.Fatalf("reload inbound: %v", err)
	}

	if reloaded.UsageMultiplier != 1 {
		t.Fatalf("default usage multiplier = %v, want 1", reloaded.UsageMultiplier)
	}
}
