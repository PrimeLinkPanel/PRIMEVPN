package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"

	xuilogger "github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
)

func TestServerControllerInstallXrayDisabledForPRIMEVPN(t *testing.T) {
	xuilogger.InitLogger(logging.ERROR)
	gin.SetMode(gin.TestMode)

	router := gin.New()
	controller := &ServerController{}
	router.POST("/server/installXray/:version", controller.installXray)

	req := httptest.NewRequest(http.MethodPost, "/server/installXray/v26.6.22", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var envelope struct {
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}

	if envelope.Success {
		t.Fatalf("installXray response success = true, want false; body=%s", rec.Body.String())
	}

	if !strings.Contains(strings.ToLower(envelope.Msg), "heimdall") ||
		!strings.Contains(strings.ToLower(envelope.Msg), "disabled") {
		t.Fatalf("response msg = %q, want PRIMEVPN disabled message", envelope.Msg)
	}
}
