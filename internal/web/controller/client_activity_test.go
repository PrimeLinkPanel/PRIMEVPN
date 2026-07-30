package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

type activityAPIEnvelope struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

func TestClientActivityControlAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(
		t.TempDir(),
		"client-activity-controller.db",
	)

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	db := database.GetDB()

	client := model.ClientRecord{
		Email:  "activity-api-client",
		Enable: true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := gin.New()
	group := router.Group("/clients")
	NewClientController(group)

	request := func(
		method string,
		path string,
	) activityAPIEnvelope {
		t.Helper()

		req := httptest.NewRequest(method, path, nil)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf(
				"%s %s status = %d, body = %s",
				method,
				path,
				rec.Code,
				rec.Body.String(),
			)
		}

		var envelope activityAPIEnvelope
		if err := json.Unmarshal(
			rec.Body.Bytes(),
			&envelope,
		); err != nil {
			t.Fatalf(
				"decode %s %s response: %v; body=%s",
				method,
				path,
				err,
				rec.Body.String(),
			)
		}

		return envelope
	}

	decodeStatus := func(
		envelope activityAPIEnvelope,
	) *struct {
		ClientID   int   `json:"clientId"`
		Enabled    bool  `json:"enabled"`
		Generation int64 `json:"generation"`
		DataEpoch  int64 `json:"dataEpoch"`
	} {
		t.Helper()

		if !envelope.Success {
			t.Fatalf(
				"API response failed: %s",
				envelope.Msg,
			)
		}

		var status struct {
			ClientID   int   `json:"clientId"`
			Enabled    bool  `json:"enabled"`
			Generation int64 `json:"generation"`
			DataEpoch  int64 `json:"dataEpoch"`
		}

		if err := json.Unmarshal(
			envelope.Obj,
			&status,
		); err != nil {
			t.Fatalf(
				"decode Activity status: %v; obj=%s",
				err,
				string(envelope.Obj),
			)
		}

		return &status
	}

	base := "/clients/" + client.Email + "/activity"

	initial := decodeStatus(request(
		http.MethodGet,
		base+"/status",
	))
	if initial.ClientID != client.Id ||
		initial.Enabled ||
		initial.Generation != 0 ||
		initial.DataEpoch != 1 {
		t.Fatalf(
			"unexpected initial status: %+v",
			initial,
		)
	}

	started := decodeStatus(request(
		http.MethodPost,
		base+"/start",
	))
	if !started.Enabled ||
		started.Generation != 1 ||
		started.DataEpoch != 1 {
		t.Fatalf(
			"unexpected started status: %+v",
			started,
		)
	}

	startedAgain := decodeStatus(request(
		http.MethodPost,
		base+"/start",
	))
	if !startedAgain.Enabled ||
		startedAgain.Generation != 1 ||
		startedAgain.DataEpoch != 1 {
		t.Fatalf(
			"duplicate start was not idempotent: %+v",
			startedAgain,
		)
	}

	destination := model.ClientActivityDestination{
		ClientID:      client.Id,
		DataEpoch:     started.DataEpoch,
		SourceIP:      "203.0.113.20",
		Destination:   "example.com",
		UploadBytes:   100,
		DownloadBytes: 200,
		LastSeen:      time.Now().UnixMilli(),
	}
	if err := db.Create(&destination).Error; err != nil {
		t.Fatalf("create destination: %v", err)
	}

	reset := decodeStatus(request(
		http.MethodPost,
		base+"/reset",
	))
	if !reset.Enabled ||
		reset.Generation != 2 ||
		reset.DataEpoch != 2 {
		t.Fatalf(
			"unexpected reset status: %+v",
			reset,
		)
	}

	var destinationCount int64
	if err := db.
		Model(&model.ClientActivityDestination{}).
		Where("client_id = ?", client.Id).
		Count(&destinationCount).
		Error; err != nil {
		t.Fatalf("count destinations after reset: %v", err)
	}
	if destinationCount != 0 {
		t.Fatalf(
			"reset left %d destination rows",
			destinationCount,
		)
	}

	stopped := decodeStatus(request(
		http.MethodPost,
		base+"/stop",
	))
	if stopped.Enabled ||
		stopped.Generation != 3 ||
		stopped.DataEpoch != 2 {
		t.Fatalf(
			"unexpected stopped status: %+v",
			stopped,
		)
	}

	stoppedAgain := decodeStatus(request(
		http.MethodPost,
		base+"/stop",
	))
	if stoppedAgain.Enabled ||
		stoppedAgain.Generation != 3 ||
		stoppedAgain.DataEpoch != 2 {
		t.Fatalf(
			"duplicate stop was not idempotent: %+v",
			stoppedAgain,
		)
	}

	finalStatus := decodeStatus(request(
		http.MethodGet,
		base+"/status",
	))
	if finalStatus.Enabled ||
		finalStatus.Generation != 3 ||
		finalStatus.DataEpoch != 2 {
		t.Fatalf(
			"unexpected final status: %+v",
			finalStatus,
		)
	}

}

func TestClientActivityRoutesRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	NewClientController(router.Group("/clients"))

	expected := map[string]string{
		"GET /clients/:email/activity/status": "",
		"POST /clients/activity/node-sync":    "",
		"POST /clients/:email/activity/start": "",
		"POST /clients/:email/activity/stop":  "",
		"POST /clients/:email/activity/reset": "",
	}

	for _, route := range router.Routes() {
		key := route.Method + " " + route.Path
		if _, found := expected[key]; found {
			expected[key] = route.Handler
		}
	}

	for route, handler := range expected {
		if handler == "" {
			t.Fatalf(
				"Activity route was not registered: %s",
				route,
			)
		}
	}
}
