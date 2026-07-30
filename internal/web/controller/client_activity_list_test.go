package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestClientActivityListAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(
		t.TempDir(),
		"client-activity-list-api.db",
	)

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})

	db := database.GetDB()

	client := model.ClientRecord{
		Email:  "activity-list-api-client",
		Enable: true,
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}

	setting := model.ClientActivitySetting{
		ClientID:   client.Id,
		Enabled:    true,
		Generation: 4,
		DataEpoch:  2,
	}
	if err := db.Create(&setting).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}

	rows := []model.ClientActivityDestination{
		{
			ClientID:      client.Id,
			DataEpoch:     2,
			SourceIP:      "203.0.113.20",
			Destination:   "first.example",
			UploadBytes:   10,
			DownloadBytes: 20,
			LastSeen:      200,
		},
		{
			ClientID:      client.Id,
			DataEpoch:     2,
			SourceIP:      "203.0.113.21",
			Destination:   "second.example",
			UploadBytes:   30,
			DownloadBytes: 40,
			LastSeen:      100,
		},
	}

	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("create rows: %v", err)
	}

	router := gin.New()
	NewClientController(router.Group("/clients"))

	request := httptest.NewRequest(
		http.MethodGet,
		"/clients/"+client.Email+
			"/activity?page=1&pageSize=1",
		nil,
	)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"status = %d body=%s",
			recorder.Code,
			recorder.Body.String(),
		)
	}

	var envelope struct {
		Success bool `json:"success"`
		Obj     struct {
			Enabled    bool  `json:"enabled"`
			Generation int64 `json:"generation"`
			DataEpoch  int64 `json:"dataEpoch"`
			Total      int64 `json:"total"`
			Page       int   `json:"page"`
			PageSize   int   `json:"pageSize"`
			Items      []struct {
				Destination   string `json:"destination"`
				SourceIP      string `json:"sourceIp"`
				UploadBytes   int64  `json:"uploadBytes"`
				DownloadBytes int64  `json:"downloadBytes"`
			} `json:"items"`
		} `json:"obj"`
	}

	if err := json.Unmarshal(
		recorder.Body.Bytes(),
		&envelope,
	); err != nil {
		t.Fatalf(
			"decode response: %v body=%s",
			err,
			recorder.Body.String(),
		)
	}

	if !envelope.Success ||
		!envelope.Obj.Enabled ||
		envelope.Obj.Generation != 4 ||
		envelope.Obj.DataEpoch != 2 ||
		envelope.Obj.Total != 2 ||
		envelope.Obj.Page != 1 ||
		envelope.Obj.PageSize != 1 ||
		len(envelope.Obj.Items) != 1 {
		t.Fatalf(
			"unexpected response: %+v",
			envelope,
		)
	}

	item := envelope.Obj.Items[0]

	if item.Destination != "first.example" ||
		item.SourceIP != "203.0.113.20" ||
		item.UploadBytes != 10 ||
		item.DownloadBytes != 20 {
		t.Fatalf("unexpected item: %+v", item)
	}
}
