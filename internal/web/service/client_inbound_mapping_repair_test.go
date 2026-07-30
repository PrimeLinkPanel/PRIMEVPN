package service

import (
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func seedClientInboundMappingRepairClient(
	t *testing.T,
	email string,
	port int,
) (*InboundService, *model.Inbound, *model.ClientRecord) {
	t.Helper()

	initAccurateBillingTestDB(t)

	db := database.GetDB()
	svc := &InboundService{}

	inbound := &model.Inbound{
		UserId:   1,
		Tag:      "mapping-repair",
		Enable:   true,
		Port:     port,
		Protocol: model.VLESS,
		Settings: `{"clients":[]}`,
	}

	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	client := model.Client{
		Email:  email,
		ID:     "11111111-1111-4111-8111-111111111111",
		SubID:  "sub-mapping-repair",
		Enable: true,
	}

	if err := svc.clientService.SyncInbound(
		nil,
		inbound.Id,
		[]model.Client{client},
	); err != nil {
		t.Fatalf("SyncInbound: %v", err)
	}

	var record model.ClientRecord
	if err := db.
		Where("email = ?", email).
		First(&record).
		Error; err != nil {
		t.Fatalf("load canonical client: %v", err)
	}

	if err := db.
		Where("inbound_id = ?", inbound.Id).
		Delete(&model.ClientInboundTraffic{}).
		Error; err != nil {
		t.Fatalf("clear initial mappings: %v", err)
	}

	return svc, inbound, &record
}

func TestEnsureClientInboundTrafficMappingsRebindsLegacyGhost(
	t *testing.T,
) {
	const email = "recreated-ghost@x"

	svc, inbound, current := seedClientInboundMappingRepairClient(
		t,
		email,
		45101,
	)

	db := database.GetDB()
	statEmail := clientInboundStatEmail(
		email,
		inbound.Id,
	)

	ghost := &model.ClientInboundTraffic{
		ClientID:     current.Id + 100000,
		InboundID:    inbound.Id,
		Email:        email,
		StatEmail:    statEmail,
		ActualUp:     101,
		ActualDown:   202,
		BillableUp:   303,
		BillableDown: 404,
		LastOnline:   505,
		CreatedAt:    10,
		UpdatedAt:    20,
	}

	if err := db.Create(ghost).Error; err != nil {
		t.Fatalf("create legacy ghost: %v", err)
	}

	for pass := 1; pass <= 2; pass++ {
		if err := svc.
			EnsureClientInboundTrafficMappingsForInbound(
				inbound.Id,
			); err != nil {
			t.Fatalf(
				"repair pass %d failed: %v",
				pass,
				err,
			)
		}
	}

	var rows []model.ClientInboundTraffic
	if err := db.
		Where("inbound_id = ?", inbound.Id).
		Find(&rows).
		Error; err != nil {
		t.Fatalf("read repaired mappings: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf(
			"mapping rows = %d, want 1",
			len(rows),
		)
	}

	got := rows[0]

	if got.ClientID != current.Id {
		t.Fatalf(
			"client_id = %d, want %d",
			got.ClientID,
			current.Id,
		)
	}

	if got.StatEmail != statEmail {
		t.Fatalf(
			"stat_email = %q, want %q",
			got.StatEmail,
			statEmail,
		)
	}

	if got.ActualUp != 101 ||
		got.ActualDown != 202 ||
		got.BillableUp != 303 ||
		got.BillableDown != 404 ||
		got.LastOnline != 505 {
		t.Fatalf(
			"traffic was not preserved: %#v",
			got,
		)
	}
}

func TestEnsureClientInboundTrafficMappingsMergesPairAndStatRows(
	t *testing.T,
) {
	const email = "duplicate-mapping@x"

	svc, inbound, current := seedClientInboundMappingRepairClient(
		t,
		email,
		45102,
	)

	db := database.GetDB()
	expectedStatEmail := clientInboundStatEmail(
		email,
		inbound.Id,
	)

	pairRow := &model.ClientInboundTraffic{
		ClientID:     current.Id,
		InboundID:    inbound.Id,
		Email:        email,
		StatEmail:    "legacy-pair-stat-email",
		ActualUp:     10,
		ActualDown:   20,
		BillableUp:   30,
		BillableDown: 40,
		LastOnline:   100,
		CreatedAt:    20,
		UpdatedAt:    30,
	}

	statRow := &model.ClientInboundTraffic{
		ClientID:     current.Id + 100000,
		InboundID:    inbound.Id,
		Email:        email,
		StatEmail:    expectedStatEmail,
		ActualUp:     1,
		ActualDown:   2,
		BillableUp:   3,
		BillableDown: 4,
		LastOnline:   200,
		CreatedAt:    10,
		UpdatedAt:    40,
	}

	if err := db.Create(pairRow).Error; err != nil {
		t.Fatalf("create pair row: %v", err)
	}

	if err := db.Create(statRow).Error; err != nil {
		t.Fatalf("create stat row: %v", err)
	}

	if err := svc.
		EnsureClientInboundTrafficMappingsForInbound(
			inbound.Id,
		); err != nil {
		t.Fatalf("repair duplicate mappings: %v", err)
	}

	var rows []model.ClientInboundTraffic
	if err := db.
		Where("inbound_id = ?", inbound.Id).
		Find(&rows).
		Error; err != nil {
		t.Fatalf("read merged mapping: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf(
			"mapping rows = %d, want 1",
			len(rows),
		)
	}

	got := rows[0]

	if got.ClientID != current.Id {
		t.Fatalf(
			"client_id = %d, want %d",
			got.ClientID,
			current.Id,
		)
	}

	if got.StatEmail != expectedStatEmail {
		t.Fatalf(
			"stat_email = %q, want %q",
			got.StatEmail,
			expectedStatEmail,
		)
	}

	if got.ActualUp != 11 ||
		got.ActualDown != 22 ||
		got.BillableUp != 33 ||
		got.BillableDown != 44 {
		t.Fatalf(
			"merged traffic = %#v",
			got,
		)
	}

	if got.LastOnline != 200 {
		t.Fatalf(
			"last_online = %d, want 200",
			got.LastOnline,
		)
	}

	if got.CreatedAt != 10 {
		t.Fatalf(
			"created_at = %d, want 10",
			got.CreatedAt,
		)
	}
}

func TestMigrationRepairClientInboundTrafficMappingsIsIdempotent(
	t *testing.T,
) {
	const email = "migration-ghost@x"

	svc, inbound, current := seedClientInboundMappingRepairClient(
		t,
		email,
		45103,
	)

	db := database.GetDB()
	statEmail := clientInboundStatEmail(
		email,
		inbound.Id,
	)

	ghost := &model.ClientInboundTraffic{
		ClientID:   current.Id + 100000,
		InboundID:  inbound.Id,
		Email:      email,
		StatEmail:  statEmail,
		ActualUp:   77,
		ActualDown: 88,
		CreatedAt:  10,
		UpdatedAt:  20,
	}

	missingInbound := &model.ClientInboundTraffic{
		ClientID:   current.Id + 200000,
		InboundID:  999999,
		Email:      "missing-inbound@x",
		StatEmail:  "hmstat_999999_aaaaaaaaaaaaaaaa",
		ActualUp:   99,
		ActualDown: 111,
		CreatedAt:  10,
		UpdatedAt:  20,
	}

	if err := db.Create(ghost).Error; err != nil {
		t.Fatalf("create migration ghost: %v", err)
	}

	if err := db.Create(missingInbound).Error; err != nil {
		t.Fatalf(
			"create missing-inbound row: %v",
			err,
		)
	}

	svc.MigrationRepairClientInboundTrafficMappings()
	svc.MigrationRepairClientInboundTrafficMappings()

	var rows []model.ClientInboundTraffic
	if err := db.
		Order("id ASC").
		Find(&rows).
		Error; err != nil {
		t.Fatalf("read migration result: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf(
			"mapping rows = %d, want 1",
			len(rows),
		)
	}

	got := rows[0]

	if got.ClientID != current.Id ||
		got.InboundID != inbound.Id ||
		got.StatEmail != statEmail {
		t.Fatalf(
			"wrong repaired mapping: %#v",
			got,
		)
	}

	if got.ActualUp != 77 ||
		got.ActualDown != 88 {
		t.Fatalf(
			"migration lost traffic: %#v",
			got,
		)
	}
}
