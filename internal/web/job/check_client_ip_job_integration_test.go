package job

import (
	"encoding/json"
	"log"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/op/go-logging"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	xuilogger "github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
)

// PRIMEVPN logger must be initialised once before any code path that can
// log a warning. otherwise log.Warningf panics on a nil logger.
var loggerInitOnce sync.Once

// setupIntegrationDB wires a temp sqlite db and log folder so
// updateInboundClientIps can run end to end. closes the db before
// TempDir cleanup so windows doesn't complain about the file being in
// use.
func setupIntegrationDB(t *testing.T) {
	t.Helper()

	loggerInitOnce.Do(func() {
		xuilogger.InitLogger(logging.ERROR)
	})

	dbDir := t.TempDir()
	logDir := t.TempDir()

	t.Setenv("XUI_DB_FOLDER", dbDir)
	t.Setenv("XUI_LOG_FOLDER", logDir)

	// updateInboundClientIps calls log.SetOutput on the package global,
	// which would leak to other tests in the same binary.
	origLogWriter := log.Writer()
	origLogFlags := log.Flags()
	t.Cleanup(func() {
		log.SetOutput(origLogWriter)
		log.SetFlags(origLogFlags)
	})

	if err := database.InitDB(filepath.Join(dbDir, "x-ui.db")); err != nil {
		t.Fatalf("database.InitDB failed: %v", err)
	}
	// LIFO cleanup order: this runs before t.TempDir's own cleanup.
	t.Cleanup(func() {
		if err := database.CloseDB(); err != nil {
			t.Logf("database.CloseDB warning: %v", err)
		}
	})
}

// seed an inbound whose settings json has a single client with the
// given email and ip limit.
func seedInboundWithClient(t *testing.T, tag, email string, limitIp int) {
	t.Helper()
	seedInboundOnlyWithClient(t, tag, email, limitIp)
}

func seedInboundOnlyWithClient(t *testing.T, tag, email string, limitIp int) *model.Inbound {
	t.Helper()
	settings := map[string]any{
		"clients": []map[string]any{
			{
				"email":   email,
				"limitIp": limitIp,
				"enable":  true,
			},
		},
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		Tag:      tag,
		Enable:   true,
		Protocol: model.VLESS,
		Port:     4321,
		Settings: string(settingsJSON),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	return inbound
}

func seedLinkedInboundWithClient(t *testing.T, tag, email string, limitIp int) *model.Inbound {
	t.Helper()
	inbound := seedInboundOnlyWithClient(t, tag, email, limitIp)
	client := &model.ClientRecord{Email: email}
	if err := database.GetDB().Create(client).Error; err != nil {
		t.Fatalf("seed client record: %v", err)
	}
	link := &model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}
	if err := database.GetDB().Create(link).Error; err != nil {
		t.Fatalf("seed client inbound link: %v", err)
	}
	return inbound
}

// seed an InboundClientIps row with the given blob.
func seedClientIps(t *testing.T, email string, ips []IPWithTimestamp) *model.InboundClientIps {
	t.Helper()
	blob, err := json.Marshal(ips)
	if err != nil {
		t.Fatalf("marshal ips: %v", err)
	}
	row := &model.InboundClientIps{
		ClientEmail: email,
		Ips:         string(blob),
	}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("seed InboundClientIps: %v", err)
	}
	return row
}

// read the persisted blob and parse it back.
func readClientIps(t *testing.T, email string) []IPWithTimestamp {
	t.Helper()
	row := &model.InboundClientIps{}
	if err := database.GetDB().Where("client_email = ?", email).First(row).Error; err != nil {
		t.Fatalf("read InboundClientIps for %s: %v", email, err)
	}
	if row.Ips == "" {
		return nil
	}
	var out []IPWithTimestamp
	if err := json.Unmarshal([]byte(row.Ips), &out); err != nil {
		t.Fatalf("unmarshal Ips blob %q: %v", row.Ips, err)
	}
	return out
}

// make a lookup map so asserts don't depend on slice order.
func ipSet(entries []IPWithTimestamp) map[string]int64 {
	out := make(map[string]int64, len(entries))
	for _, e := range entries {
		out[e.IP] = e.Timestamp
	}
	return out
}

// With the access-log fallback removed, an unavailable online-stats API (xray
// down, as in this unit test) must make Run a clean no-op: no legacy enforcement side effects and no
// inbound_client_ips rows — never a crash or partial work.
func TestProcessObserved_CollectsIpsWithoutLimit(t *testing.T) {
	setupIntegrationDB(t)

	const email = "no-limit-user"
	seedInboundWithClient(t, "inbound-no-limit", email, 0) // limitIp = 0

	observed := map[string]map[string]int64{
		email: {"203.0.113.10": time.Now().Unix()},
	}
	NewCheckClientIpJob().processObserved(observed, true)

	ips := readClientIps(t, email)
	if len(ips) != 1 || ips[0].IP != "203.0.113.10" {
		t.Fatalf("expected the observed IP to be collected without a limit, got %v", ips)
	}

}

// #4963: an observed IP for a renamed/deleted client (its email no longer maps
// to any inbound) must not create or resurrect an inbound_client_ips row, and
// must drop any orphan left behind — instead of erroring every run.
func TestProcessObserved_StaleEmailIsSkippedAndOrphanDropped(t *testing.T) {
	setupIntegrationDB(t)

	const staleEmail = "renamed-away"
	// No inbound references staleEmail. Pre-seed an orphan tracking row to
	// confirm the job removes it rather than leaving it to error forever.
	seedClientIps(t, staleEmail, []IPWithTimestamp{{IP: "203.0.113.5", Timestamp: time.Now().Unix()}})

	observed := map[string]map[string]int64{
		staleEmail: {"203.0.113.5": time.Now().Unix()},
	}
	NewCheckClientIpJob().processObserved(observed, true)

	var count int64
	if err := database.GetDB().Model(&model.InboundClientIps{}).Where("client_email = ?", staleEmail).Count(&count).Error; err != nil {
		t.Fatalf("count InboundClientIps: %v", err)
	}
	if count != 0 {
		t.Fatalf("stale-email orphan row should be deleted, got %d row(s)", count)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// the exact clients/client_inbounds relation must win over the substring scan,
// so a client is resolved to its own inbound even when another inbound holds a
// superstring email.
func TestGetInboundByEmailUsesClientInboundLink(t *testing.T) {
	setupIntegrationDB(t)

	want := seedLinkedInboundWithClient(t, "linked-inbound", "exact@example.com", 1)
	seedInboundOnlyWithClient(t, "other-inbound", "not-exact@example.com", 1)

	got, err := (&CheckClientIpJob{}).getInboundByEmail("exact@example.com")
	if err != nil {
		t.Fatalf("getInboundByEmail returned error: %v", err)
	}
	if got.Id != want.Id {
		t.Fatalf("getInboundByEmail returned inbound %d, want %d", got.Id, want.Id)
	}
}

// the substring fallback must still verify the exact email inside settings, so
// "ann@example.com" does not match an inbound holding "joann@example.com".
func TestGetInboundByEmailRejectsSubstringFallbackMatch(t *testing.T) {
	setupIntegrationDB(t)

	seedInboundOnlyWithClient(t, "substring-only", "joann@example.com", 1)

	if got, err := (&CheckClientIpJob{}).getInboundByEmail("ann@example.com"); err == nil {
		t.Fatalf("substring email matched inbound %d; want no exact match", got.Id)
	}
}
