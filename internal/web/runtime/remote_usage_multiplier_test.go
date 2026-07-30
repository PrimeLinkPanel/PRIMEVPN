package runtime

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestWireInboundIncludesUsageMultiplier(t *testing.T) {
	values := wireInbound(&model.Inbound{
		Remark:          "node factor test",
		UsageMultiplier: 9,
	}, 0)

	if got := values.Get("usageMultiplier"); got != "9" {
		t.Fatalf("usageMultiplier payload = %q, want 9", got)
	}
}

func TestWireInboundDefaultsUsageMultiplier(t *testing.T) {
	values := wireInbound(&model.Inbound{
		Remark:          "node factor default test",
		UsageMultiplier: 0,
	}, 0)

	if got := values.Get("usageMultiplier"); got != "1" {
		t.Fatalf("default usageMultiplier payload = %q, want 1", got)
	}
}
