package job

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/runtime"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"

	"gorm.io/gorm"
)

const diagnosticSharedEmail = "diagnostic-job-shared@example.invalid"

type diagnosticNodeEndpoint struct {
	tag          string
	email        string
	rejectUpdate bool
	listDelay    time.Duration
	counter      atomic.Int64
	listCalls    atomic.Int64
	updateCalls  atomic.Int64
}

func diagnosticEnvelope(w http.ResponseWriter, obj any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"msg":     "",
		"obj":     obj,
	})
}

func (e *diagnosticNodeEndpoint) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/panel/api/inbounds/list":
		if e.listDelay > 0 {
			time.Sleep(e.listDelay)
		}
		e.listCalls.Add(1)
		up := e.counter.Load()
		diagnosticEnvelope(w, []map[string]any{{
			"id":             1,
			"tag":            e.tag,
			"enable":         true,
			"port":           443,
			"protocol":       "vless",
			"settings":       fmt.Sprintf(`{"clients":[{"email":%q,"enable":true}]}`, e.email),
			"streamSettings": `{"network":"tcp","security":"none"}`,
			"sniffing":       `{"enabled":false}`,
			"clientStats": []map[string]any{{
				"email":  e.email,
				"up":     up,
				"down":   up * 2,
				"enable": true,
			}},
		}})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/panel/api/inbounds/update/"):
		e.updateCalls.Add(1)
		if e.rejectUpdate {
			http.Error(w, "diagnostic reconcile rejection", http.StatusBadRequest)
			return
		}
		diagnosticEnvelope(w, nil)
	case r.Method == http.MethodPost && r.URL.Path == "/panel/api/clients/onlinesByGuid":
		diagnosticEnvelope(w, map[string][]string{})
	case r.Method == http.MethodPost && r.URL.Path == "/panel/api/clients/onlines":
		diagnosticEnvelope(w, []string{})
	case r.Method == http.MethodPost && r.URL.Path == "/panel/api/clients/lastOnline":
		diagnosticEnvelope(w, map[string]int64{})
	default:
		http.NotFound(w, r)
	}
}

func initDiagnosticNodeJobDB(t *testing.T) *gorm.DB {
	t.Helper()
	t.Setenv("XUI_DB_TYPE", "sqlite")
	t.Setenv("XUI_DB_DSN", "")
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	if err := database.InitDB(filepath.Join(dbDir, "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	service.StartTrafficWriter()
	t.Cleanup(func() {
		service.StopTrafficWriter()
		_ = database.CloseDB()
	})
	return database.GetDB()
}

func addDiagnosticHTTPNode(
	t *testing.T,
	db *gorm.DB,
	ordinal int,
	dirty bool,
	rejectUpdate bool,
) (*model.Node, *diagnosticNodeEndpoint) {
	t.Helper()
	tag := fmt.Sprintf("diagnostic-job-node-%02d", ordinal)
	endpoint := &diagnosticNodeEndpoint{
		tag:          tag,
		email:        diagnosticSharedEmail,
		rejectUpdate: rejectUpdate,
	}
	endpoint.counter.Store(int64(ordinal * 1000))

	server := httptest.NewServer(http.HandlerFunc(endpoint.serveHTTP))
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split test server host: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}

	node := &model.Node{
		Name:                fmt.Sprintf("diagnostic-node-%02d", ordinal),
		Scheme:              "http",
		Address:             host,
		Port:                port,
		BasePath:            "/",
		ApiToken:            "diagnostic-token",
		Enable:              true,
		AllowPrivateAddress: true,
		TlsVerifyMode:       "verify",
		InboundSyncMode:     "all",
		Guid:                fmt.Sprintf("diagnostic-guid-%02d", ordinal),
		Status:              "online",
		ConfigDirty:         dirty,
		ConfigDirtyAt:       time.Now().UnixMilli(),
	}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("create diagnostic node %d: %v", ordinal, err)
	}

	nodeID := node.Id
	settings := fmt.Sprintf(`{"clients":[{"email":%q,"enable":true}]}`, diagnosticSharedEmail)
	inbound := &model.Inbound{
		UserId:          1,
		NodeID:          &nodeID,
		Tag:             tag,
		Enable:          true,
		Port:            43000 + ordinal,
		Protocol:        model.VLESS,
		Settings:        settings,
		StreamSettings:  `{"network":"tcp","security":"none"}`,
		Sniffing:        `{"enabled":false}`,
		UsageMultiplier: 1,
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("create diagnostic inbound %d: %v", ordinal, err)
	}
	return node, endpoint
}

func newDiagnosticTrafficJob(t *testing.T) *NodeTrafficSyncJob {
	t.Helper()
	previous := runtime.GetManager()
	mgr := runtime.NewManager(runtime.LocalDeps{})
	runtime.SetManager(mgr)
	t.Cleanup(func() { runtime.SetManager(previous) })

	job := NewNodeTrafficSyncJob()
	// Keep this diagnostic focused on the traffic snapshot/merge path. IP sync
	// and the 30-second reverse global push are independently tested features.
	job.lastIpSync = time.Now().Unix()
	job.lastGlobalPush = time.Now().Unix()
	return job
}

func readDiagnosticTraffic(t *testing.T, db *gorm.DB) xray.ClientTraffic {
	t.Helper()
	var row xray.ClientTraffic
	if err := db.Where("email = ?", diagnosticSharedEmail).First(&row).Error; err != nil {
		t.Fatalf("read diagnostic client traffic: %v", err)
	}
	return row
}

// TestDiagnosticTenHealthyNodesAggregateTraffic confirms that the production
// job reaches and merges ten healthy nodes. It rules out a hard-coded "first
// node only" loop/index bug and verifies the concurrency limiter's second wave.
func TestDiagnosticTenHealthyNodesAggregateTraffic(t *testing.T) {
	db := initDiagnosticNodeJobDB(t)
	endpoints := make([]*diagnosticNodeEndpoint, 0, 10)
	for ordinal := 1; ordinal <= 10; ordinal++ {
		_, endpoint := addDiagnosticHTTPNode(t, db, ordinal, false, false)
		endpoints = append(endpoints, endpoint)
	}

	job := newDiagnosticTrafficJob(t)
	job.Run()

	var baselines int64
	if err := db.Model(&model.NodeClientTraffic{}).
		Where("email = ?", diagnosticSharedEmail).
		Count(&baselines).Error; err != nil {
		t.Fatalf("count initial baselines: %v", err)
	}
	if baselines != 10 {
		t.Fatalf("healthy-node baselines = %d, want 10", baselines)
	}
	initial := readDiagnosticTraffic(t, db)
	if initial.Up != 0 || initial.Down != 0 {
		t.Fatalf("initial traffic = %d/%d, want 0/0 baselines", initial.Up, initial.Down)
	}

	for ordinal, endpoint := range endpoints {
		endpoint.counter.Add(int64((ordinal + 1) * 10))
	}
	job.Run()

	got := readDiagnosticTraffic(t, db)
	if got.Up != 550 || got.Down != 1100 {
		t.Fatalf("ten-node job delta = %d/%d, want 550/1100", got.Up, got.Down)
	}
	for ordinal, endpoint := range endpoints {
		if calls := endpoint.listCalls.Load(); calls != 2 {
			t.Errorf("healthy node %d inbound-list calls = %d, want 2", ordinal+1, calls)
		}
	}
}

// TestDiagnosticOneCleanNineDirtyNodesStillSyncTraffic protects the reported
// 1-of-10 pattern. A config reconcile error must leave ConfigDirty set for a
// retry, but it must NOT suppress the independent traffic snapshot.
func TestDiagnosticOneCleanNineDirtyNodesStillSyncTraffic(t *testing.T) {
	db := initDiagnosticNodeJobDB(t)
	endpoints := make([]*diagnosticNodeEndpoint, 0, 10)
	for ordinal := 1; ordinal <= 10; ordinal++ {
		dirty := ordinal > 1
		_, endpoint := addDiagnosticHTTPNode(t, db, ordinal, dirty, dirty)
		if ordinal == 1 {
			// Force the clean node to create the shared traffic row
			// after all dirty nodes have reported. Every dirty node
			// must already have established its own baseline.
			endpoint.listDelay = 250 * time.Millisecond
		}
		endpoints = append(endpoints, endpoint)
	}

	job := newDiagnosticTrafficJob(t)
	job.Run()

	var baselines int64
	if err := db.Model(&model.NodeClientTraffic{}).
		Where("email = ?", diagnosticSharedEmail).
		Count(&baselines).Error; err != nil {
		t.Fatalf("count dirty-node baselines: %v", err)
	}
	if baselines != 10 {
		calls := make([]string, 0, len(endpoints))
		for ordinal, endpoint := range endpoints {
			calls = append(calls, fmt.Sprintf(
				"n%d:list=%d/update=%d",
				ordinal+1,
				endpoint.listCalls.Load(),
				endpoint.updateCalls.Load(),
			))
		}
		t.Fatalf(
			"BUG_REPRODUCED_RECONCILE_STARVES_TRAFFIC: baselines=%d want=10 calls=[%s]",
			baselines,
			strings.Join(calls, " "),
		)
	}

	var dirtyNodes int64
	if err := db.Model(&model.Node{}).Where("config_dirty = ?", true).Count(&dirtyNodes).Error; err != nil {
		t.Fatalf("count nodes still dirty after rejected reconcile: %v", err)
	}
	if dirtyNodes != 9 {
		t.Fatalf("dirty nodes after rejected reconcile = %d, want 9", dirtyNodes)
	}
	for ordinal, endpoint := range endpoints {
		if ordinal == 0 {
			if updates := endpoint.updateCalls.Load(); updates != 0 {
				t.Errorf("clean node update calls = %d, want 0", updates)
			}
			continue
		}
		if updates := endpoint.updateCalls.Load(); updates != 1 {
			t.Errorf("dirty node %d update calls = %d, want 1", ordinal+1, updates)
		}
		if lists := endpoint.listCalls.Load(); lists != 2 {
			t.Errorf("dirty node %d inbound-list calls = %d, want 2 (reconcile + traffic)", ordinal+1, lists)
		}
	}

	for ordinal, endpoint := range endpoints {
		endpoint.counter.Add(int64((ordinal + 1) * 10))
	}
	job.Run()

	got := readDiagnosticTraffic(t, db)
	if got.Up != 550 || got.Down != 1100 {
		t.Fatalf("dirty-node job delta = %d/%d, want 550/1100", got.Up, got.Down)
	}
	if err := db.Model(&model.Node{}).Where("config_dirty = ?", true).Count(&dirtyNodes).Error; err != nil {
		t.Fatalf("recount nodes still dirty: %v", err)
	}
	if dirtyNodes != 9 {
		t.Fatalf("dirty nodes after retry = %d, want 9", dirtyNodes)
	}
}
