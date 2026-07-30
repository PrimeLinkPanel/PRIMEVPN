package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

func initAccurateBillingTestDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "primevpn.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
}

func seedAccurateBillingClient(t *testing.T, svc *InboundService, email string, multiplier float64) *model.Inbound {
	t.Helper()

	db := database.GetDB()
	ib := &model.Inbound{
		UserId:          1,
		Tag:             "accurate-" + email,
		Enable:          true,
		Port:            45001,
		Protocol:        model.VLESS,
		Settings:        `{"clients":[]}`,
		UsageMultiplier: multiplier,
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	client := model.Client{
		Email:      email,
		ID:         "11111111-1111-4111-8111-111111111111",
		SubID:      "sub-" + email,
		Enable:     true,
		TotalGB:    10 * 1024 * 1024 * 1024,
		ExpiryTime: 0,
	}

	if err := svc.clientService.SyncInbound(nil, ib.Id, []model.Client{client}); err != nil {
		t.Fatalf("SyncInbound: %v", err)
	}
	if err := svc.AddClientStat(db, ib.Id, &client); err != nil {
		t.Fatalf("AddClientStat: %v", err)
	}
	if err := svc.EnsureClientInboundTrafficMappingsForInbound(ib.Id); err != nil {
		t.Fatalf("EnsureClientInboundTrafficMappingsForInbound: %v", err)
	}

	return ib
}

func TestAccurateClientInboundBillingRuntimeStatEmail(t *testing.T) {
	initAccurateBillingTestDB(t)

	svc := &InboundService{}
	email := "accurate@x"
	ib := seedAccurateBillingClient(t, svc, email, 3)

	statEmail := clientInboundStatEmail(email, ib.Id)
	if statEmail == "" || statEmail == email {
		t.Fatalf("bad stat email: %q", statEmail)
	}

	if _, _, _, err := svc.addTrafficLocked(nil, []*xray.ClientTraffic{{
		Email: statEmail,
		Up:    100,
		Down:  50,
	}}); err != nil {
		t.Fatalf("addTrafficLocked: %v", err)
	}

	db := database.GetDB()

	var rollup xray.ClientTraffic
	if err := db.Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read rollup: %v", err)
	}
	if rollup.Up != 300 || rollup.Down != 150 {
		t.Fatalf("rollup usage = up:%d down:%d, want up:300 down:150", rollup.Up, rollup.Down)
	}
	if rollup.LastOnline == 0 {
		t.Fatalf("rollup last_online was not bumped")
	}

	var detail model.ClientInboundTraffic
	if err := db.Model(&model.ClientInboundTraffic{}).Where("stat_email = ?", statEmail).First(&detail).Error; err != nil {
		t.Fatalf("read detail: %v", err)
	}
	if detail.Email != email || detail.InboundID != ib.Id {
		t.Fatalf("wrong mapping: %#v", detail)
	}
	if detail.ActualUp != 100 || detail.ActualDown != 50 || detail.BillableUp != 300 || detail.BillableDown != 150 {
		t.Fatalf("detail usage = actual:%d/%d billable:%d/%d, want actual:100/50 billable:300/150",
			detail.ActualUp, detail.ActualDown, detail.BillableUp, detail.BillableDown)
	}
}

func TestAccurateBillingKeepsLegacyEmailFallbackRaw(t *testing.T) {
	initAccurateBillingTestDB(t)

	svc := &InboundService{}
	email := "legacy@x"
	seedAccurateBillingClient(t, svc, email, 3)

	if _, _, _, err := svc.addTrafficLocked(nil, []*xray.ClientTraffic{{
		Email: email,
		Up:    100,
		Down:  50,
	}}); err != nil {
		t.Fatalf("addTrafficLocked legacy: %v", err)
	}

	var rollup xray.ClientTraffic
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read rollup: %v", err)
	}
	if rollup.Up != 100 || rollup.Down != 50 {
		t.Fatalf("legacy rollup usage = up:%d down:%d, want raw up:100 down:50", rollup.Up, rollup.Down)
	}
}

func TestAccurateBillingBumpLastOnlineResolvesRuntimeEmail(t *testing.T) {
	initAccurateBillingTestDB(t)

	svc := &InboundService{}
	email := "online@x"
	ib := seedAccurateBillingClient(t, svc, email, 2)
	statEmail := clientInboundStatEmail(email, ib.Id)

	if err := svc.BumpClientsLastOnline([]string{statEmail}); err != nil {
		t.Fatalf("BumpClientsLastOnline: %v", err)
	}

	var rollup xray.ClientTraffic
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read rollup: %v", err)
	}
	if rollup.LastOnline == 0 {
		t.Fatal("rollup last_online not bumped")
	}

	var detail model.ClientInboundTraffic
	if err := database.GetDB().Model(&model.ClientInboundTraffic{}).Where("stat_email = ?", statEmail).First(&detail).Error; err != nil {
		t.Fatalf("read detail: %v", err)
	}
	if detail.LastOnline == 0 {
		t.Fatal("detail last_online not bumped")
	}
}

func TestRuntimeUserMapForInboundTagRewritesStandardInbound(t *testing.T) {
	initAccurateBillingTestDB(t)

	db := database.GetDB()
	svc := &InboundService{}
	ib := &model.Inbound{
		UserId:          1,
		Tag:             "tag-runtime-helper",
		Enable:          true,
		Port:            45003,
		Protocol:        model.VLESS,
		Settings:        `{"clients":[]}`,
		UsageMultiplier: 2,
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	raw := map[string]any{"email": "helper@x", "id": "11111111-1111-4111-8111-111111111111"}
	got := svc.runtimeUserMapForInboundTag(ib.Tag, raw)
	email, _ := got["email"].(string)

	if email == "helper@x" {
		t.Fatalf("expected runtime stat email, got logical email")
	}
	if want := clientInboundStatEmail("helper@x", ib.Id); email != want {
		t.Fatalf("runtime email = %q, want %q", email, want)
	}
	if raw["email"] != "helper@x" {
		t.Fatalf("input map was mutated: %#v", raw)
	}
}

func TestRuntimeUserMapForInboundTagKeepsWireGuard(t *testing.T) {
	initAccurateBillingTestDB(t)

	db := database.GetDB()
	svc := &InboundService{}
	ib := &model.Inbound{
		UserId:   1,
		Tag:      "tag-runtime-wg",
		Enable:   true,
		Port:     45004,
		Protocol: model.WireGuard,
		Settings: `{"peers":[]}`,
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	got := svc.runtimeUserMapForInboundTag(ib.Tag, map[string]any{"email": "wg@x"})
	if got["email"] != "wg@x" {
		t.Fatalf("wireguard email must stay logical, got %#v", got["email"])
	}
}

func seedDelayedAccurateBillingInbound(
	t *testing.T,
	svc *InboundService,
	email string,
	tag string,
	port int,
	multiplier float64,
	duration int64,
	addRollup bool,
) (*model.Inbound, model.Client) {
	t.Helper()

	client := model.Client{
		Email:      email,
		ID:         "22222222-2222-4222-8222-222222222222",
		SubID:      "sub-" + email,
		Enable:     true,
		TotalGB:    10 * 1024 * 1024 * 1024,
		ExpiryTime: -duration,
	}
	inbound := &model.Inbound{
		UserId:          1,
		Tag:             tag,
		Enable:          true,
		Port:            port,
		Protocol:        model.VLESS,
		Settings:        clientsSettings(t, []model.Client{client}),
		UsageMultiplier: multiplier,
	}

	db := database.GetDB()
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create delayed inbound: %v", err)
	}
	if err := svc.clientService.SyncInbound(db, inbound.Id, []model.Client{client}); err != nil {
		t.Fatalf("SyncInbound delayed client: %v", err)
	}
	if addRollup {
		if err := svc.AddClientStat(db, inbound.Id, &client); err != nil {
			t.Fatalf("AddClientStat delayed client: %v", err)
		}
	}
	if err := svc.EnsureClientInboundTrafficMappingsForInbound(inbound.Id); err != nil {
		t.Fatalf("EnsureClientInboundTrafficMappingsForInbound delayed client: %v", err)
	}

	return inbound, client
}

func assertDelayedExpiryState(
	t *testing.T,
	svc *InboundService,
	email string,
	inboundIDs []int,
	want int64,
) {
	t.Helper()

	db := database.GetDB()

	var rollup xray.ClientTraffic
	if err := db.Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read rollup %q: %v", email, err)
	}
	if rollup.ExpiryTime != want {
		t.Fatalf("rollup expiry = %d, want %d", rollup.ExpiryTime, want)
	}

	var record model.ClientRecord
	if err := db.Where("email = ?", email).First(&record).Error; err != nil {
		t.Fatalf("read client record %q: %v", email, err)
	}
	if record.ExpiryTime != want {
		t.Fatalf("client record expiry = %d, want %d", record.ExpiryTime, want)
	}

	for _, inboundID := range inboundIDs {
		inbound, err := svc.GetInbound(inboundID)
		if err != nil {
			t.Fatalf("GetInbound(%d): %v", inboundID, err)
		}
		clients, err := svc.GetClients(inbound)
		if err != nil {
			t.Fatalf("GetClients(%d): %v", inboundID, err)
		}
		if len(clients) != 1 {
			t.Fatalf("inbound %d clients = %d, want 1", inboundID, len(clients))
		}
		if clients[0].Email != email {
			t.Fatalf("inbound %d email = %q, want %q", inboundID, clients[0].Email, email)
		}
		if clients[0].ExpiryTime != want {
			t.Fatalf("inbound %d expiry = %d, want %d", inboundID, clients[0].ExpiryTime, want)
		}
	}
}

func TestAccurateBillingActivatesDelayedStart(t *testing.T) {
	initAccurateBillingTestDB(t)

	const oneDay = int64(24 * 60 * 60 * 1000)
	const email = "accurate-delayed@x"

	svc := &InboundService{}
	inbound, _ := seedDelayedAccurateBillingInbound(
		t,
		svc,
		email,
		"accurate-delayed",
		45005,
		2,
		oneDay,
		true,
	)
	statEmail := clientInboundStatEmail(email, inbound.Id)

	// A zero-delta poll is not a first use and must not start the timer.
	if _, _, _, err := svc.addTrafficLocked(nil, []*xray.ClientTraffic{{Email: statEmail}}); err != nil {
		t.Fatalf("zero-delta addTrafficLocked: %v", err)
	}
	assertDelayedExpiryState(t, svc, email, []int{inbound.Id}, -oneDay)

	before := time.Now().UnixMilli()
	if _, _, _, err := svc.addTrafficLocked(nil, []*xray.ClientTraffic{{
		Email: statEmail,
		Up:    100,
		Down:  50,
	}}); err != nil {
		t.Fatalf("first-use addTrafficLocked: %v", err)
	}

	var rollup xray.ClientTraffic
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read activated rollup: %v", err)
	}
	if rollup.ExpiryTime < before+oneDay-5000 || rollup.ExpiryTime > before+oneDay+5000 {
		t.Fatalf("activated expiry = %d, want ~%d", rollup.ExpiryTime, before+oneDay)
	}
	if rollup.Up != 200 || rollup.Down != 100 {
		t.Fatalf("activated rollup usage = %d/%d, want 200/100", rollup.Up, rollup.Down)
	}
	firstDeadline := rollup.ExpiryTime
	assertDelayedExpiryState(t, svc, email, []int{inbound.Id}, firstDeadline)

	var detail model.ClientInboundTraffic
	if err := database.GetDB().Where("stat_email = ?", statEmail).First(&detail).Error; err != nil {
		t.Fatalf("read activated detail: %v", err)
	}
	if detail.ActualUp != 100 || detail.ActualDown != 50 || detail.BillableUp != 200 || detail.BillableDown != 100 {
		t.Fatalf(
			"detail usage = actual:%d/%d billable:%d/%d, want actual:100/50 billable:200/100",
			detail.ActualUp,
			detail.ActualDown,
			detail.BillableUp,
			detail.BillableDown,
		)
	}

	// Later traffic must add usage without moving the first-use deadline.
	if _, _, _, err := svc.addTrafficLocked(nil, []*xray.ClientTraffic{{
		Email: statEmail,
		Up:    7,
		Down:  11,
	}}); err != nil {
		t.Fatalf("second addTrafficLocked: %v", err)
	}
	assertDelayedExpiryState(t, svc, email, []int{inbound.Id}, firstDeadline)

	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read second rollup: %v", err)
	}
	if rollup.Up != 214 || rollup.Down != 122 {
		t.Fatalf("second rollup usage = %d/%d, want 214/122", rollup.Up, rollup.Down)
	}
}

func TestAccurateBillingDelayedStartSharedAcrossInbounds(t *testing.T) {
	initAccurateBillingTestDB(t)

	const oneDay = int64(24 * 60 * 60 * 1000)
	const email = "accurate-delayed-shared@x"

	svc := &InboundService{}
	first, _ := seedDelayedAccurateBillingInbound(
		t,
		svc,
		email,
		"accurate-delayed-shared-1",
		45006,
		2,
		oneDay,
		true,
	)
	second, _ := seedDelayedAccurateBillingInbound(
		t,
		svc,
		email,
		"accurate-delayed-shared-2",
		45007,
		3,
		oneDay,
		true,
	)

	before := time.Now().UnixMilli()
	if _, _, _, err := svc.addTrafficLocked(nil, []*xray.ClientTraffic{
		{Email: clientInboundStatEmail(email, first.Id), Up: 10, Down: 20},
		{Email: clientInboundStatEmail(email, second.Id), Up: 30, Down: 40},
	}); err != nil {
		t.Fatalf("shared addTrafficLocked: %v", err)
	}

	var rollup xray.ClientTraffic
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read shared rollup: %v", err)
	}
	if rollup.ExpiryTime < before+oneDay-5000 || rollup.ExpiryTime > before+oneDay+5000 {
		t.Fatalf("shared expiry = %d, want ~%d", rollup.ExpiryTime, before+oneDay)
	}
	if rollup.Up != 110 || rollup.Down != 160 {
		t.Fatalf("shared rollup usage = %d/%d, want 110/160", rollup.Up, rollup.Down)
	}
	assertDelayedExpiryState(t, svc, email, []int{first.Id, second.Id}, rollup.ExpiryTime)
}

func TestAccurateBillingDelayedStartRepairsMissingRollup(t *testing.T) {
	initAccurateBillingTestDB(t)

	const oneDay = int64(24 * 60 * 60 * 1000)
	const email = "accurate-delayed-missing-rollup@x"

	svc := &InboundService{}
	inbound, _ := seedDelayedAccurateBillingInbound(
		t,
		svc,
		email,
		"accurate-delayed-missing-rollup",
		45008,
		2,
		oneDay,
		false,
	)

	before := time.Now().UnixMilli()
	if _, _, _, err := svc.addTrafficLocked(nil, []*xray.ClientTraffic{{
		Email: clientInboundStatEmail(email, inbound.Id),
		Up:    5,
		Down:  6,
	}}); err != nil {
		t.Fatalf("missing-rollup addTrafficLocked: %v", err)
	}

	var rollup xray.ClientTraffic
	if err := database.GetDB().Model(xray.ClientTraffic{}).Where("email = ?", email).First(&rollup).Error; err != nil {
		t.Fatalf("read repaired rollup: %v", err)
	}
	if rollup.ExpiryTime < before+oneDay-5000 || rollup.ExpiryTime > before+oneDay+5000 {
		t.Fatalf("repaired expiry = %d, want ~%d", rollup.ExpiryTime, before+oneDay)
	}
	if rollup.Up != 10 || rollup.Down != 12 {
		t.Fatalf("repaired rollup usage = %d/%d, want 10/12", rollup.Up, rollup.Down)
	}
	assertDelayedExpiryState(t, svc, email, []int{inbound.Id}, rollup.ExpiryTime)
}

func TestAggregateCanonicalClientTrafficDeltas(t *testing.T) {
	runtimeA := clientInboundStatEmail(
		"alice@example.com",
		10,
	)
	runtimeB := clientInboundStatEmail(
		"alice@example.com",
		20,
	)
	unknownRuntime := clientInboundStatEmail(
		"ghost@example.com",
		30,
	)

	got := aggregateCanonicalClientTrafficDeltas(
		[]*xray.ClientTraffic{
			{
				Email: runtimeA,
				Up:    100,
				Down:  200,
			},
			{
				Email: runtimeB,
				Up:    300,
				Down:  400,
			},
			{
				Email: "bob@example.com",
				Up:    50,
				Down:  60,
			},
			{
				Email: unknownRuntime,
				Up:    700,
				Down:  800,
			},
			nil,
		},
		map[string]string{
			runtimeA: "alice@example.com",
			runtimeB: "alice@example.com",
		},
	)

	if len(got) != 2 {
		t.Fatalf(
			"canonical rows = %d, want 2: %#v",
			len(got),
			got,
		)
	}

	byEmail := make(
		map[string]*xray.ClientTraffic,
		len(got),
	)

	for _, row := range got {
		if row != nil {
			byEmail[row.Email] = row
		}
	}

	alice := byEmail["alice@example.com"]
	if alice == nil {
		t.Fatal("alice canonical row missing")
	}

	if alice.Up != 400 || alice.Down != 600 {
		t.Fatalf(
			"alice delta = up:%d down:%d, want up:400 down:600",
			alice.Up,
			alice.Down,
		)
	}

	bob := byEmail["bob@example.com"]
	if bob == nil {
		t.Fatal("legacy bob row missing")
	}

	if bob.Up != 50 || bob.Down != 60 {
		t.Fatalf(
			"bob delta = up:%d down:%d, want up:50 down:60",
			bob.Up,
			bob.Down,
		)
	}

	if _, found := byEmail[unknownRuntime]; found {
		t.Fatal(
			"unresolved runtime email leaked into canonical output",
		)
	}
}

func TestCanonicalClientTrafficDeltasResolvesDatabaseMapping(
	t *testing.T,
) {
	initAccurateBillingTestDB(t)

	svc := &InboundService{}
	email := "speed-display@example.com"

	inbound := seedAccurateBillingClient(
		t,
		svc,
		email,
		3,
	)

	statEmail := clientInboundStatEmail(
		email,
		inbound.Id,
	)

	got, err := svc.CanonicalClientTrafficDeltas(
		[]*xray.ClientTraffic{
			{
				Email: statEmail,
				Up:    125,
				Down:  375,
			},
		},
	)
	if err != nil {
		t.Fatalf(
			"CanonicalClientTrafficDeltas: %v",
			err,
		)
	}

	if len(got) != 1 {
		t.Fatalf(
			"canonical rows = %d, want 1",
			len(got),
		)
	}

	if got[0].Email != email {
		t.Fatalf(
			"canonical email = %q, want %q",
			got[0].Email,
			email,
		)
	}

	if got[0].Up != 125 || got[0].Down != 375 {
		t.Fatalf(
			"canonical raw delta = up:%d down:%d, want up:125 down:375",
			got[0].Up,
			got[0].Down,
		)
	}
}
