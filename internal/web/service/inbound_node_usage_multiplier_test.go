package service

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestAdoptedWireFingerprintTracksUsageMultiplier(t *testing.T) {
	central := &model.Inbound{
		Settings:        `{"clients":[]}`,
		UsageMultiplier: 1,
	}

	snapshot := *central
	snapshot.UsageMultiplier = 2.5

	if !adoptedWireChanged(
		central,
		&snapshot,
		central.Settings,
	) {
		t.Fatal(
			"usage multiplier change was omitted " +
				"from adopted wire fingerprint",
		)
	}

	adopted := adoptedWireInbound(
		central,
		&snapshot,
		central.Settings,
	)

	if adopted.UsageMultiplier != 2.5 {
		t.Fatalf(
			"adopted multiplier = %v, want 2.5",
			adopted.UsageMultiplier,
		)
	}

	if central.UsageMultiplier != 1 {
		t.Fatalf(
			"adoption mutated source multiplier: %v",
			central.UsageMultiplier,
		)
	}
}

func TestAdoptedWireFingerprintNormalizesDefaultMultiplier(
	t *testing.T,
) {
	central := &model.Inbound{
		Settings:        `{"clients":[]}`,
		UsageMultiplier: 1,
	}

	snapshot := *central
	snapshot.UsageMultiplier = 0

	if adoptedWireChanged(
		central,
		&snapshot,
		central.Settings,
	) {
		t.Fatal(
			"wire-equivalent multipliers 0 and 1 " +
				"were reported as changed",
		)
	}
}
