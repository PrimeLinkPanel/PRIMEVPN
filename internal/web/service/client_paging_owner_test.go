package service

import (
	"reflect"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

func TestOwnerSummaryBaseSegmentsClients(t *testing.T) {
	rows := []ClientWithAttachments{
		{ClientRecord: model.ClientRecord{Email: "owner@x", OwnerAdminId: 1}},
		{ClientRecord: model.ClientRecord{Email: "gogoli@x", OwnerAdminId: 2}},
		{ClientRecord: model.ClientRecord{Email: "king@x", OwnerAdminId: 3}},
	}

	emails := func(items []ClientWithAttachments) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			out = append(out, item.Email)
		}
		return out
	}

	tests := []struct {
		name           string
		owner          string
		currentAdminID int
		want           []string
	}{
		{name: "empty means all", owner: "", currentAdminID: 1, want: []string{"owner@x", "gogoli@x", "king@x"}},
		{name: "all means all", owner: "all", currentAdminID: 1, want: []string{"owner@x", "gogoli@x", "king@x"}},
		{name: "me means current admin", owner: "me", currentAdminID: 1, want: []string{"owner@x"}},
		{name: "admin id filters owner", owner: "2", currentAdminID: 1, want: []string{"gogoli@x"}},
		{name: "invalid owner returns empty", owner: "nope", currentAdminID: 1, want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := emails(ownerSummaryBase(rows, tt.owner, tt.currentAdminID))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ownerSummaryBase(%q, %d) = %v, want %v", tt.owner, tt.currentAdminID, got, tt.want)
			}
		})
	}
}

func TestBuildClientsSummaryTrafficTotals(t *testing.T) {
	rows := []ClientWithAttachments{
		{
			ClientRecord: model.ClientRecord{Email: "limited@x", OwnerAdminId: 1, Enable: true, TotalGB: 1000},
			Traffic:      &xray.ClientTraffic{Up: 100, Down: 250},
		},
		{
			ClientRecord: model.ClientRecord{Email: "unlimited@x", OwnerAdminId: 1, Enable: true, TotalGB: 0},
			Traffic:      &xray.ClientTraffic{Up: 10, Down: 40},
		},
		{
			ClientRecord: model.ClientRecord{Email: "over@x", OwnerAdminId: 1, Enable: true, TotalGB: 200},
			Traffic:      &xray.ClientTraffic{Up: 150, Down: 100},
		},
	}

	got := buildClientsSummary(rows, map[string]struct{}{}, 0, 0, 0)

	if got.TrafficUp != 260 {
		t.Fatalf("TrafficUp = %d, want 260", got.TrafficUp)
	}
	if got.TrafficDown != 390 {
		t.Fatalf("TrafficDown = %d, want 390", got.TrafficDown)
	}
	if got.TrafficUsed != 650 {
		t.Fatalf("TrafficUsed = %d, want 650", got.TrafficUsed)
	}
	if got.TrafficTotal != 1200 {
		t.Fatalf("TrafficTotal = %d, want 1200", got.TrafficTotal)
	}
	if got.TrafficRemaining != 650 {
		t.Fatalf("TrafficRemaining = %d, want 650", got.TrafficRemaining)
	}
}

func TestSummaryQuotaAdminID(t *testing.T) {
	tests := []struct {
		name   string
		scope  ClientAccessScope
		owner  string
		wantID int
		wantOK bool
	}{
		{
			name:   "own scope uses current admin",
			scope:  ClientAccessScope{Mode: ClientAccessOwn, AdminID: 7},
			owner:  "",
			wantID: 7,
			wantOK: true,
		},
		{
			name:   "owner me uses current owner",
			scope:  ClientAccessScope{Mode: ClientAccessAll, AdminID: 1},
			owner:  "me",
			wantID: 1,
			wantOK: true,
		},
		{
			name:   "owner admin id selects that admin",
			scope:  ClientAccessScope{Mode: ClientAccessAll, AdminID: 1},
			owner:  "2",
			wantID: 2,
			wantOK: true,
		},
		{
			name:   "owner all has no single quota",
			scope:  ClientAccessScope{Mode: ClientAccessAll, AdminID: 1},
			owner:  "all",
			wantID: 0,
			wantOK: false,
		},
		{
			name:   "owner empty has no single quota",
			scope:  ClientAccessScope{Mode: ClientAccessAll, AdminID: 1},
			owner:  "",
			wantID: 0,
			wantOK: false,
		},
		{
			name:   "invalid owner has no quota",
			scope:  ClientAccessScope{Mode: ClientAccessAll, AdminID: 1},
			owner:  "nope",
			wantID: 0,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotOK := summaryQuotaAdminID(tt.scope, tt.owner)
			if gotID != tt.wantID || gotOK != tt.wantOK {
				t.Fatalf("summaryQuotaAdminID() = (%d, %v), want (%d, %v)", gotID, gotOK, tt.wantID, tt.wantOK)
			}
		})
	}
}

func TestApplyAdminTrafficQuotaOverridesClientQuota(t *testing.T) {
	summary := ClientsSummary{
		TrafficUsed:      350,
		TrafficTotal:     1200,
		TrafficRemaining: 850,
	}

	applyAdminTrafficQuota(&summary, 1000)

	if summary.TrafficTotal != 1000 {
		t.Fatalf("TrafficTotal = %d, want 1000", summary.TrafficTotal)
	}
	if summary.TrafficRemaining != 650 {
		t.Fatalf("TrafficRemaining = %d, want 650", summary.TrafficRemaining)
	}

	overused := ClientsSummary{TrafficUsed: 1200, TrafficTotal: 9999, TrafficRemaining: 9999}
	applyAdminTrafficQuota(&overused, 1000)
	if overused.TrafficTotal != 1000 {
		t.Fatalf("overused TrafficTotal = %d, want 1000", overused.TrafficTotal)
	}
	if overused.TrafficRemaining != 0 {
		t.Fatalf("overused TrafficRemaining = %d, want 0", overused.TrafficRemaining)
	}
}
