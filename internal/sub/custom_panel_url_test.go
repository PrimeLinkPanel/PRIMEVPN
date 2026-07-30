package sub

import (
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestBuildSubscriptionURLUsesPanelSubscriptionSettings(t *testing.T) {
	initSubDB(t)

	url, err := BuildSubscriptionURL("panel.example.com", "ABC")
	if err != nil {
		t.Fatalf("default URL: %v", err)
	}
	if url != "http://panel.example.com:2096/sub/ABC" {
		t.Fatalf("default URL = %q", url)
	}

	if err := database.GetDB().Create(&model.Setting{
		Key:   "subURI",
		Value: "https://subscriptions.example/custom/",
	}).Error; err != nil {
		t.Fatalf("set subURI: %v", err)
	}
	url, err = BuildSubscriptionURL("ignored.example.com", "ABC")
	if err != nil {
		t.Fatalf("configured URL: %v", err)
	}
	if url != "https://subscriptions.example/custom/ABC" {
		t.Fatalf("configured URL = %q", url)
	}
}

func TestBuildSubscriptionURLRejectsEmptySubID(t *testing.T) {
	initSubDB(t)
	if _, err := BuildSubscriptionURL("panel.example.com", "  "); err == nil || !strings.Contains(err.Error(), "subId") {
		t.Fatalf("empty subId error = %v", err)
	}
}
