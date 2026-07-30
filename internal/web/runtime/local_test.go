package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestLocalRuntimeUserMapRewritesStandardInboundEmail(t *testing.T) {
	ib := &model.Inbound{Id: 42, Protocol: model.VLESS}
	raw := map[string]any{"email": "Alice@Example.COM", "id": "11111111-1111-4111-8111-111111111111"}

	got := localRuntimeUserMap(ib, raw)

	email, _ := got["email"].(string)
	if !strings.HasPrefix(email, model.ClientInboundStatEmailPrefix+"_42_") {
		t.Fatalf("runtime email was not rewritten: %q", email)
	}
	if raw["email"] != "Alice@Example.COM" {
		t.Fatalf("input map was mutated: %#v", raw)
	}
}

func TestLocalRuntimeUserMapKeepsWireGuardEmail(t *testing.T) {
	ib := &model.Inbound{Id: 42, Protocol: model.WireGuard}
	got := localRuntimeUserMap(ib, map[string]any{"email": "wg-user"})
	if got["email"] != "wg-user" {
		t.Fatalf("wireguard email must stay logical, got %#v", got["email"])
	}
}

func TestLocalRuntimeInboundTransformsStandardClientsOnly(t *testing.T) {
	ib := &model.Inbound{
		Id:       42,
		Protocol: model.VLESS,
		Settings: `{"clients":[{"email":"alice","id":"11111111-1111-4111-8111-111111111111"}],"decryption":"none"}`,
	}

	runtimeInbound := localRuntimeInbound(ib)
	if runtimeInbound == ib {
		t.Fatalf("expected transformed inbound copy")
	}
	if strings.Contains(runtimeInbound.Settings, `"email":"alice"`) {
		t.Fatalf("runtime settings still contains logical email: %s", runtimeInbound.Settings)
	}
	if !strings.Contains(ib.Settings, `"email":"alice"`) {
		t.Fatalf("original inbound settings must stay logical: %s", ib.Settings)
	}

	var settings map[string]any
	if err := json.Unmarshal([]byte(runtimeInbound.Settings), &settings); err != nil {
		t.Fatalf("runtime settings json: %v", err)
	}
	clients := settings["clients"].([]any)
	email := clients[0].(map[string]any)["email"].(string)
	if !strings.HasPrefix(email, model.ClientInboundStatEmailPrefix+"_42_") {
		t.Fatalf("unexpected runtime email: %q", email)
	}
}
