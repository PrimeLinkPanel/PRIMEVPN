package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/runtime"
)

// One rejected inbound must not abort reconciliation of the remaining
// inbounds or the stale-tag sweep. The joined error still identifies the
// rejected tag so the caller keeps ConfigDirty set and retries later.
func TestReconcileNode_ContinuesPastFailedInbound(t *testing.T) {
	setupConflictDB(t)

	var mu sync.Mutex
	updated := map[int]int{}
	var deleted []int
	tagToID := map[string]int{"legacy": 1, "healthy": 2, "gone": 3}
	writeOK := func(w http.ResponseWriter, obj any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "msg": "", "obj": obj})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/panel/api/inbounds/list", func(w http.ResponseWriter, _ *http.Request) {
		type row struct {
			Id  int    `json:"id"`
			Tag string `json:"tag"`
		}
		rows := make([]row, 0, len(tagToID))
		for tag, id := range tagToID {
			rows = append(rows, row{Id: id, Tag: tag})
		}
		writeOK(w, rows)
	})
	mux.HandleFunc("/panel/api/inbounds/update/", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/panel/api/inbounds/update/"))
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		if id == tagToID["legacy"] {
			http.Error(w, "request body failed validation", http.StatusBadRequest)
			return
		}
		mu.Lock()
		updated[id]++
		mu.Unlock()
		writeOK(w, nil)
	})
	mux.HandleFunc("/panel/api/inbounds/del/", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/panel/api/inbounds/del/"))
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		mu.Lock()
		deleted = append(deleted, id)
		mu.Unlock()
		writeOK(w, nil)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	node := reconcileTestNode(t, ts, "half-broken-node", "all", nil)
	seedInboundConflictNode(t, "legacy", "", 1080, model.Protocol("socks"), `{}`, `{"auth":"noauth"}`, &node.Id)
	seedInboundConflictNode(t, "healthy", "", 443, model.VLESS, `{"network":"tcp"}`, `{"clients":[]}`, &node.Id)

	svc := InboundService{}
	err := svc.ReconcileNode(context.Background(), runtime.NewRemote(node, nil), node)
	if err == nil {
		t.Fatal("ReconcileNode: want an error naming the rejected inbound, got nil")
	}
	if !strings.Contains(err.Error(), `reconcile inbound "legacy"`) {
		t.Fatalf("ReconcileNode error = %q, want it to name inbound legacy", err)
	}

	mu.Lock()
	healthyPushes := updated[tagToID["healthy"]]
	gotDeleted := append([]int(nil), deleted...)
	mu.Unlock()
	if healthyPushes != 1 {
		t.Fatalf("healthy inbound pushed %d times, want 1", healthyPushes)
	}
	sort.Ints(gotDeleted)
	if len(gotDeleted) != 1 || gotDeleted[0] != tagToID["gone"] {
		t.Fatalf("deleted remote ids = %v, want [%d]", gotDeleted, tagToID["gone"])
	}
}
