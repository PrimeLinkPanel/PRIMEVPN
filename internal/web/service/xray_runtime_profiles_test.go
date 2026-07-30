package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

func runtimeProfileTestParent() *model.Inbound {
	return &model.Inbound{
		Id:       7,
		Listen:   "0.0.0.0",
		Port:     22937,
		Protocol: model.VLESS,
		Tag:      "in-22937-tcp",
		Settings: `{"clients":[{"id":"00000000-0000-0000-0000-000000000001","email":"hmstat_parent"}],"decryption":"none"}`,
		StreamSettings: `{
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}}
		}`,
		Sniffing: `{"enabled":false}`,
	}
}

func TestCompileRuntimeProfileInboundsDirectGRPC(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(2087),
			"network":  "grpc",
			"security": "none",
			"grpcSettings": map[string]any{
				"serviceName": "mobile",
			},
			"runtime": map[string]any{},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d synthetic inbounds, want 1", len(got))
	}
	if got[0].Port != 2087 || got[0].Tag != "hm-profile-7-auto-profile-1" {
		t.Fatalf("unexpected synthetic endpoint: port=%d tag=%q", got[0].Port, got[0].Tag)
	}
	var stream map[string]any
	if err := json.Unmarshal(got[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	if stream["network"] != "grpc" || stream["security"] != "none" {
		t.Fatalf("unexpected stream: %#v", stream)
	}
	if strings.Contains(string(got[0].StreamSettings), "externalProxy") {
		t.Fatalf("runtime config leaked externalProxy: %s", got[0].StreamSettings)
	}
	if !strings.Contains(string(got[0].Settings), "hmstat_parent") {
		t.Fatalf("synthetic inbound did not reuse parent runtime client identity: %s", got[0].Settings)
	}
}

func TestCompileRuntimeProfileInboundsLegacyProfileStaysSubscriptionOnly(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{map[string]any{
			"dest":     "cdn.example.test",
			"port":     float64(443),
			"forceTls": "tls",
			"sni":      "origin.example.test",
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("legacy profile unexpectedly became runtime listener: %#v", got)
	}
}

func TestCompileRuntimeProfileInboundsMarkerlessStructuredProfileStaysSubscriptionOnly(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"enabled": true,
			"port":    float64(1995),
			"network": "grpc",
			"grpcSettings": map[string]any{
				"serviceName": "pre-automatic-topology",
			},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("markerless structured profile unexpectedly became runtime listener: %#v", got)
	}
}

func TestCompileRuntimeProfileInboundsRuntimeDisabledCannotDisableAutomaticListener(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"port":    float64(2087),
			"network": "grpc",
			"runtime": map[string]any{
				"enabled": false,
				"id":      "automatic-grpc",
			},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != 2087 || got[0].Tag != "hm-profile-7-automatic-grpc" {
		t.Fatalf("automatic runtime listener = %#v", got)
	}
}

func TestCompileRuntimeProfileInboundsDisabledProfileDoesNotListen(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"enabled": false,
			"port":    float64(2087),
			"network": "grpc",
			"runtime": map[string]any{
				"enabled": true,
				"id":      "disabled-grpc",
			},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("disabled profile unexpectedly became runtime listener: %#v", got)
	}
}

func TestCompileRuntimeProfileInboundsSameSocketDifferentTransportUsesFrontMux(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"port":     float64(22937),
			"network":  "grpc",
			"security": "none",
			"runtime": map[string]any{
				"enabled": true,
				"id":      "same-port-grpc",
				"mode":    "direct",
			},
		}},
	}
	topology, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.SharedPlan.Groups) != 1 || len(topology.SharedPlan.Groups[0].Routes) != 2 {
		t.Fatalf("unexpected shared topology: %+v", topology.SharedPlan)
	}
	if topology.Parent.Port == parent.Port || len(topology.Synthetic) != 1 || topology.Synthetic[0].Port == parent.Port {
		t.Fatalf("shared endpoints were not moved to private backends: parent=%d synthetic=%+v", topology.Parent.Port, topology.Synthetic)
	}
}

func TestCompileRuntimeProfileInboundsTCPAndKCPMaySharePort(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{map[string]any{
			"port":     float64(22937),
			"network":  "kcp",
			"security": "none",
			"runtime": map[string]any{
				"enabled": true,
				"id":      "udp-kcp",
			},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != parent.Port {
		t.Fatalf("TCP and KCP should coexist on one numeric port: %#v", got)
	}
}

func TestCompileRuntimeProfileInboundsSameListenerAliasNeedsNoSynthetic(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"port":     float64(22937),
			"network":  "same",
			"security": "same",
			"runtime":  map[string]any{},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("exact parent alias must not create another listener: %#v", got)
	}
}

func TestCompileRuntimeProfileInboundsTLSRequiresServerSettings(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{map[string]any{
			"port":     float64(443),
			"network":  "ws",
			"security": "tls",
			"runtime": map[string]any{
				"enabled": true,
				"id":      "ws-tls",
				"mode":    "direct",
			},
		}},
	}
	_, err := compileRuntimeProfileInbounds(parent, raw)
	if err == nil || !strings.Contains(err.Error(), "requires runtime.tlsSettings") {
		t.Fatalf("got error %v, want missing TLS server settings", err)
	}
}

func TestCompileRuntimeProfileInboundsDuplicateRuntimeIDRejected(t *testing.T) {
	parent := runtimeProfileTestParent()
	profile := func(port float64) map[string]any {
		return map[string]any{
			"port":    port,
			"network": "grpc",
			"runtime": map[string]any{"enabled": true, "id": "duplicate"},
		}
	}
	raw := map[string]any{
		"network":       "tcp",
		"externalProxy": []any{profile(2087), profile(2088)},
	}
	_, err := compileRuntimeProfileInbounds(parent, raw)
	if err == nil || !strings.Contains(err.Error(), "duplicates runtime.id") {
		t.Fatalf("got error %v, want duplicate runtime.id", err)
	}
}

func TestCompileRuntimeProfileInboundsIgnoresLegacyRuntimePort(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"port":    float64(2087),
			"network": "grpc",
			"runtime": map[string]any{
				"id":   "profile-port-wins",
				"port": 2087.5,
			},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != 2087 {
		t.Fatalf("legacy runtime.port affected topology: %#v", got)
	}
}

func TestCompileRuntimeProfileInboundsIgnoresLegacyRuntimeListen(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"port":    float64(2087),
			"network": "grpc",
			"runtime": map[string]any{
				"id":     "parent-listen-wins",
				"listen": "edge.example.com",
			},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Listen) != `"0.0.0.0"` {
		t.Fatalf("legacy runtime.listen affected topology: %#v", got)
	}
}

func TestNormalizeAutomaticRuntimeProfilesIsStableAndStripsTopologyControls(t *testing.T) {
	raw := map[string]any{
		"externalProxy": []any{
			map[string]any{
				"network": "grpc",
				"runtime": map[string]any{
					"enabled": false,
					"mode":    "shared",
					"listen":  "127.0.0.1",
					"port":    float64(9443),
				},
			},
			map[string]any{
				"network": "kcp",
				"runtime": map[string]any{"id": "auto-profile-1"},
			},
			map[string]any{
				"enabled": false,
				"network": "grpc",
				"runtime": "unfinished-draft",
			},
			map[string]any{
				"dest": "legacy.example.test",
				"port": float64(443),
			},
		},
	}

	first, changed, err := normalizeAutomaticRuntimeProfiles(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("automatic runtime metadata was not materialized")
	}
	profiles := first["externalProxy"].([]any)
	firstRuntime := profiles[0].(map[string]any)["runtime"].(map[string]any)
	if firstRuntime["id"] != "auto-profile-1-2" {
		t.Fatalf("generated id = %#v", firstRuntime["id"])
	}
	for _, key := range automaticRuntimeTopologyFields {
		if _, exists := firstRuntime[key]; exists {
			t.Fatalf("obsolete topology key %q survived: %#v", key, firstRuntime)
		}
	}
	if profiles[1].(map[string]any)["runtime"].(map[string]any)["id"] != "auto-profile-1" {
		t.Fatal("explicit runtime id was not preserved")
	}
	if profiles[2].(map[string]any)["runtime"] != "unfinished-draft" {
		t.Fatal("disabled draft was mutated")
	}
	if _, exists := profiles[3].(map[string]any)["runtime"]; exists {
		t.Fatal("legacy subscription-only profile gained runtime metadata")
	}

	second, changed, err := normalizeAutomaticRuntimeProfiles(first)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("normalization is not idempotent")
	}
	if !runtimeStreamsEquivalent(first, second) {
		t.Fatalf("second normalization changed data:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestCompileRuntimeProfileInboundsLiftsXHTTPKeys(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"port":    float64(2087),
			"network": "xhttp",
			"xhttpSettings": map[string]any{
				"path":             "/api",
				"sessionPlacement": "header",
				"sessionKey":       "X-Session",
			},
			"runtime": map[string]any{"enabled": true, "id": "xhttp"},
		}},
	}
	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	var stream map[string]any
	if err := json.Unmarshal(got[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	xhttp := stream["xhttpSettings"].(map[string]any)
	if xhttp["sessionIDPlacement"] != "header" || xhttp["sessionIDKey"] != "X-Session" {
		t.Fatalf("XHTTP keys were not lifted: %#v", xhttp)
	}
	if _, exists := xhttp["sessionPlacement"]; exists {
		t.Fatalf("legacy sessionPlacement leaked into runtime: %#v", xhttp)
	}
}

func TestValidateRuntimeProfileBindingsRejectsCrossInboundWildcardConflict(t *testing.T) {
	parent := runtimeProfileTestParent()
	profileRaw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"port":    float64(2087),
			"network": "grpc",
			"runtime": map[string]any{"enabled": true, "id": "grpc"},
		}},
	}
	profiles, err := compileRuntimeProfileInbounds(parent, profileRaw)
	if err != nil {
		t.Fatal(err)
	}
	other := &model.Inbound{
		Listen:         "127.0.0.1",
		Port:           2087,
		Protocol:       model.VLESS,
		Tag:            "other",
		Settings:       parent.Settings,
		StreamSettings: `{"network":"grpc","security":"none","grpcSettings":{}}`,
		Sniffing:       parent.Sniffing,
	}
	cfg := &xray.Config{InboundConfigs: []xray.InboundConfig{*other.GenXrayInboundConfig(), profiles[0]}}
	if err := validateRuntimeProfileBindings(cfg); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("got error %v, want cross-inbound wildcard conflict", err)
	}
}

func TestValidateRuntimeProfileBindingsAllowsTCPAndUDPOnSamePort(t *testing.T) {
	tcpInbound := runtimeProfileTestParent().GenXrayInboundConfig()
	udpModel := runtimeProfileTestParent()
	udpModel.Tag = "hm-profile-7-kcp"
	udpModel.StreamSettings = `{"network":"kcp","security":"none","kcpSettings":{}}`
	udpInbound := udpModel.GenXrayInboundConfig()
	cfg := &xray.Config{InboundConfigs: []xray.InboundConfig{*tcpInbound, *udpInbound}}
	if err := validateRuntimeProfileBindings(cfg); err != nil {
		t.Fatalf("TCP and UDP should coexist on the same numeric port: %v", err)
	}
}

func TestValidateRuntimeProfileBindingsRejectsDuplicateSyntheticTag(t *testing.T) {
	first := runtimeProfileTestParent()
	first.Tag = "hm-profile-7-duplicate"
	first.Port = 2087
	second := runtimeProfileTestParent()
	second.Tag = first.Tag
	second.Port = 2088
	cfg := &xray.Config{InboundConfigs: []xray.InboundConfig{*first.GenXrayInboundConfig(), *second.GenXrayInboundConfig()}}
	if err := validateRuntimeProfileBindings(cfg); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("got error %v, want duplicate synthetic tag", err)
	}
}

func TestCompileRuntimeProfileInboundsTLSRequiresServerCertificate(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(8443),
			"network":  "ws",
			"security": "tls",
			"wsSettings": map[string]any{
				"path": "/runtime",
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "ws-tls",
				"tlsSettings": map[string]any{
					"certificates": []any{},
				},
			},
		}},
	}

	_, err := compileRuntimeProfileInbounds(parent, raw)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("error = %v, want missing certificate error", err)
	}
}

func TestCompileRuntimeProfileInboundsTLSFileCertificate(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(8443),
			"network":  "ws",
			"security": "tls",
			"wsSettings": map[string]any{
				"path": "/runtime",
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "ws-tls",
				"tlsSettings": map[string]any{
					"certificates": []any{map[string]any{
						"certificateFile": "/etc/ssl/fullchain.pem",
						"keyFile":         "/etc/ssl/privkey.pem",
					}},
					"settings": map[string]any{
						"fingerprint": "chrome",
					},
				},
			},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d synthetic inbounds, want 1", len(got))
	}
	if strings.Contains(string(got[0].StreamSettings), "fingerprint") {
		t.Fatalf("client-only TLS settings leaked into runtime: %s", got[0].StreamSettings)
	}
}

func TestCompileRuntimeProfileInboundsRealityRequiresPrivateServerSettings(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(9443),
			"network":  "xhttp",
			"security": "reality",
			"xhttpSettings": map[string]any{
				"path": "/runtime",
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "xhttp-reality",
				"realitySettings": map[string]any{
					"target":      "example.com:443",
					"serverNames": []any{"example.com"},
				},
			},
		}},
	}

	_, err := compileRuntimeProfileInbounds(parent, raw)
	if err == nil || !strings.Contains(err.Error(), "privateKey") {
		t.Fatalf("error = %v, want missing privateKey error", err)
	}
}

func TestCompileRuntimeProfileInboundsUsesSharedProfileFlow(t *testing.T) {
	parent := runtimeProfileTestParent()
	parent.Settings = `{"clients":[{"id":"11111111-2222-4333-8444-555555555555","email":"client","flow":""}],"decryption":"mlkem768x25519plus.native.0rtt.test","encryption":"mlkem768x25519plus.native.0rtt.test"}`
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(8443),
			"network":  "xhttp",
			"security": "none",
			"flow":     "xtls-rprx-vision",
			"xhttpSettings": map[string]any{
				"path": "/runtime",
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "xhttp-flow",
			},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d synthetic inbounds, want 1", len(got))
	}
	if !strings.Contains(string(got[0].Settings), `"flow": "xtls-rprx-vision"`) {
		t.Fatalf("profile flow was not applied to runtime clients: %s", got[0].Settings)
	}
}

func TestCompileRuntimeProfileInboundsRejectsFlowOnWebSocket(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(8443),
			"network":  "ws",
			"security": "tls",
			"flow":     "xtls-rprx-vision",
			"wsSettings": map[string]any{
				"path": "/runtime",
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "ws-flow",
				"tlsSettings": map[string]any{
					"certificates": []any{map[string]any{
						"certificateFile": "/etc/ssl/fullchain.pem",
						"keyFile":         "/etc/ssl/privkey.pem",
					}},
				},
			},
		}},
	}

	_, err := compileRuntimeProfileInbounds(parent, raw)
	if err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("error = %v, want incompatible flow error", err)
	}
}

func TestCompileRuntimeProfileInboundsAppliesProfileFinalMask(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(2087),
			"network":  "grpc",
			"security": "none",
			"grpcSettings": map[string]any{
				"serviceName": "masked",
			},
			"finalmask": map[string]any{
				"tcp": []any{map[string]any{"type": "none"}},
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "masked-grpc",
			},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d synthetic inbounds, want 1", len(got))
	}
	var stream map[string]any
	if err := json.Unmarshal(got[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	finalMask, ok := stream["finalmask"].(map[string]any)
	if !ok {
		t.Fatalf("profile finalmask missing from runtime stream: %#v", stream)
	}
	if masks, _ := finalMask["tcp"].([]any); len(masks) != 1 {
		t.Fatalf("profile finalmask was not preserved: %#v", finalMask)
	}
}

func TestCompileRuntimeProfileInboundsRejectsProfileFinalMaskWithReality(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(9443),
			"network":  "xhttp",
			"security": "reality",
			"xhttpSettings": map[string]any{
				"path": "/masked",
			},
			"finalmask": map[string]any{
				"tcp": []any{map[string]any{"type": "none"}},
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "masked-reality",
				"realitySettings": map[string]any{
					"target":      "example.com:443",
					"privateKey":  "test-private-key",
					"serverNames": []any{"example.com"},
				},
			},
		}},
	}

	_, err := compileRuntimeProfileInbounds(parent, raw)
	if err == nil || !strings.Contains(err.Error(), "finalmask.tcp") {
		t.Fatalf("error = %v, want finalmask/REALITY rejection", err)
	}
}

func TestCompileRuntimeProfileInboundsRejectsReservedParentTag(t *testing.T) {
	parent := runtimeProfileTestParent()
	parent.Tag = "hm-profile-manual"
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"port":    float64(2087),
			"network": "grpc",
			"runtime": map[string]any{"enabled": true, "id": "grpc"},
		}},
	}

	_, err := compileRuntimeProfileInbounds(parent, raw)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error = %v, want reserved-tag rejection", err)
	}
}

func TestCompileRuntimeProfileInboundsNormalizesXHTTPRuntimeSettings(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network": "tcp",
		"externalProxy": []any{map[string]any{
			"port":    float64(2087),
			"network": "xhttp",
			"xhttpSettings": map[string]any{
				"mode":                 "stream-one",
				"path":                 "/runtime",
				"scMaxEachPostBytes":   "1024",
				"scMaxBufferedPosts":   float64(30),
				"scMinPostsIntervalMs": "50-150",
				"scStreamUpServerSecs": "20-80",
				"uplinkDataPlacement":  "header",
				"uplinkDataKey":        "x_data",
				"uplinkHTTPMethod":     "GET",
				"headers":              map[string]any{"User-Agent": "x"},
				"uplinkChunkSize":      float64(4096),
				"noGRPCHeader":         true,
				"xmux":                 map[string]any{"maxConnections": float64(6)},
				"noSSEHeader":          true,
				"xPaddingObfsMode":     false,
				"xPaddingKey":          "stale",
				"sessionIDPlacement":   "path",
				"sessionIDKey":         "stale",
				"sessionIDTable":       "",
				"sessionIDLength":      "8-16",
				"seqPlacement":         "path",
				"seqKey":               "stale",
				"enableXmux":           true,
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "xhttp-runtime-cleanup",
			},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("inbound count = %d, want 1", len(got))
	}

	var stream map[string]any
	if err := json.Unmarshal(got[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	xhttp, _ := stream["xhttpSettings"].(map[string]any)
	if xhttp["mode"] != "stream-one" || xhttp["noSSEHeader"] != true {
		t.Fatalf("runtime XHTTP base fields changed: %#v", xhttp)
	}
	for _, key := range []string{
		"scMaxEachPostBytes",
		"scMaxBufferedPosts",
		"scMinPostsIntervalMs",
		"scStreamUpServerSecs",
		"uplinkDataPlacement",
		"uplinkDataKey",
		"uplinkHTTPMethod",
		"headers",
		"uplinkChunkSize",
		"noGRPCHeader",
		"xmux",
		"xPaddingKey",
		"sessionIDKey",
		"sessionIDLength",
		"seqKey",
		"enableXmux",
	} {
		if _, exists := xhttp[key]; exists {
			t.Errorf("inactive/client-only XHTTP key leaked into runtime: %s: %#v", key, xhttp)
		}
	}
}

func TestCompileRuntimeProfileInboundsCarriesFullRuntimeSockopt(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(2099),
			"network":  "ws",
			"security": "none",
			"wsSettings": map[string]any{
				"acceptProxyProtocol": true,
				"path":                "/sockopt",
				"host":                "",
				"headers":             map[string]any{},
				"heartbeatPeriod":     float64(0),
			},
			"sockopt": map[string]any{
				"domainStrategy": "UseIP",
				"tcpFastOpen":    true,
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "ws-runtime-sockopt",
				"mode":    "direct",
				"sockopt": map[string]any{
					"acceptProxyProtocol":  true,
					"mark":                 float64(27),
					"tcpKeepAliveInterval": float64(15),
					"tcpKeepAliveIdle":     float64(90),
					"tcpMaxSeg":            float64(1400),
					"tcpUserTimeout":       float64(30000),
					"tcpWindowClamp":       float64(65535),
					"tcpFastOpen":          true,
					"penetrate":            true,
					"V6Only":               false,
					"tcpcongestion":        "bbr",
					"tproxy":               "off",
					"trustedXForwardedFor": []any{"CF-Connecting-IP"},
					"customSockopt": []any{map[string]any{
						"system": "linux",
						"level":  "6",
						"opt":    "19",
						"type":   "int",
						"value":  "1",
					}},
				},
			},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d synthetic inbounds, want 1", len(got))
	}

	var stream map[string]any
	if err := json.Unmarshal(got[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	sockopt, ok := stream["sockopt"].(map[string]any)
	if !ok {
		t.Fatalf("runtime Sockopt missing: %#v", stream)
	}
	for key, want := range map[string]any{
		"acceptProxyProtocol":  true,
		"mark":                 float64(27),
		"tcpKeepAliveIdle":     float64(90),
		"tcpcongestion":        "bbr",
		"trustedXForwardedFor": []any{"CF-Connecting-IP"},
	} {
		gotValue, exists := sockopt[key]
		if !exists {
			t.Fatalf("runtime Sockopt field %q missing: %#v", key, sockopt)
		}
		if key == "trustedXForwardedFor" {
			list, _ := gotValue.([]any)
			if len(list) != 1 || list[0] != "CF-Connecting-IP" {
				t.Fatalf("trustedXForwardedFor = %#v", gotValue)
			}
			continue
		}
		if gotValue != want {
			t.Fatalf("runtime Sockopt %s = %#v, want %#v", key, gotValue, want)
		}
	}
	if sockopt["domainStrategy"] == "UseIP" {
		t.Fatal("client-side profile Sockopt leaked into runtime listener")
	}
	custom, _ := sockopt["customSockopt"].([]any)
	if len(custom) != 1 {
		t.Fatalf("customSockopt = %#v", sockopt["customSockopt"])
	}
}

func TestNormalizeHTTPUpgradeRuntimeHeadersMovesLegacyHost(t *testing.T) {
	stream := map[string]any{
		"network": "httpupgrade",
		"httpupgradeSettings": map[string]any{
			"host": "",
			"path": "/runtime",
			"headers": map[string]any{
				"HOST":   "legacy.example.com",
				"X-Test": "present",
			},
		},
	}

	if !normalizeHTTPUpgradeRuntimeHeaders(stream) {
		t.Fatal("expected legacy Host normalization")
	}
	settings := stream["httpupgradeSettings"].(map[string]any)
	if settings["host"] != "legacy.example.com" {
		t.Fatalf("host = %#v, want legacy.example.com", settings["host"])
	}
	headers := settings["headers"].(map[string]any)
	if headers["X-Test"] != "present" {
		t.Fatalf("custom header changed: %#v", headers)
	}
	for key := range headers {
		if strings.EqualFold(strings.TrimSpace(key), "host") {
			t.Fatalf("legacy Host leaked into runtime headers: %#v", headers)
		}
	}
}

func TestNormalizeHTTPUpgradeRuntimeHeadersExplicitHostWinsDeterministically(t *testing.T) {
	stream := map[string]any{
		"network": "httpupgrade",
		"httpupgradeSettings": map[string]any{
			"host": "explicit.example.com",
			"headers": map[string]any{
				"Host": "legacy-one.example.com",
				"host": "legacy-two.example.com",
			},
		},
	}

	if !normalizeHTTPUpgradeRuntimeHeaders(stream) {
		t.Fatal("expected duplicate Host cleanup")
	}
	settings := stream["httpupgradeSettings"].(map[string]any)
	if settings["host"] != "explicit.example.com" {
		t.Fatalf("explicit host was overwritten: %#v", settings["host"])
	}
	headers := settings["headers"].(map[string]any)
	if len(headers) != 0 {
		t.Fatalf("Host variants survived runtime normalization: %#v", headers)
	}
}

func TestCompileRuntimeProfileInboundsNormalizesHTTPUpgradeHostHeader(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(2087),
			"network":  "httpupgrade",
			"security": "none",
			"httpupgradeSettings": map[string]any{
				"path": "/runtime",
				"host": "public.example.com",
				"headers": map[string]any{
					"Host":   "legacy.example.com",
					"X-Test": "present",
				},
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "httpupgrade",
				"mode":    "direct",
			},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d synthetic inbounds, want 1", len(got))
	}
	var stream map[string]any
	if err := json.Unmarshal(got[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	settings := stream["httpupgradeSettings"].(map[string]any)
	if settings["host"] != "public.example.com" {
		t.Fatalf("runtime host = %#v", settings["host"])
	}
	headers := settings["headers"].(map[string]any)
	if headers["X-Test"] != "present" {
		t.Fatalf("custom header missing: %#v", headers)
	}
	for key := range headers {
		if strings.EqualFold(strings.TrimSpace(key), "host") {
			t.Fatalf("Host leaked into compiled runtime headers: %#v", headers)
		}
	}
}

func TestCompileRuntimeProfileInboundsSamePortKCPProfilesCollapse(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{
			map[string]any{
				"port":        float64(24443),
				"network":     "kcp",
				"security":    "none",
				"kcpSettings": map[string]any{"mtu": float64(1200), "tti": float64(20)},
				"runtime":     map[string]any{"enabled": true, "id": "kcp-a"},
			},
			map[string]any{
				"port":        float64(24443),
				"network":     "kcp",
				"security":    "none",
				"kcpSettings": map[string]any{"mtu": float64(1350), "tti": float64(50)},
				"runtime":     map[string]any{"enabled": true, "id": "kcp-b"},
			},
		},
	}
	topology, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.Synthetic) != 1 {
		t.Fatalf("got %d synthetic listeners, want one collapsed mKCP listener", len(topology.Synthetic))
	}
	if len(topology.PublicBindings) != 2 { // parent TCP + one shared UDP listener
		t.Fatalf("public bindings = %#v", topology.PublicBindings)
	}
	var stream map[string]any
	if err := json.Unmarshal(topology.Synthetic[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	kcpSettings, ok := stream["kcpSettings"].(map[string]any)
	if !ok || kcpSettings["mtu"] != float64(1350) || kcpSettings["tti"] != float64(50) {
		t.Fatalf("shared synthetic mKCP server must use deterministic core defaults: %#v", stream["kcpSettings"])
	}
}

func TestCompileRuntimeProfileInboundsSamePortKCPRejectsDifferentServerSecurity(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"externalProxy": []any{
			map[string]any{
				"port": float64(24443), "network": "kcp", "security": "none",
				"runtime": map[string]any{"enabled": true, "id": "plain"},
			},
			map[string]any{
				"port": float64(24443), "network": "kcp", "security": "tls",
				"runtime": map[string]any{
					"enabled": true, "id": "tls",
					"tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": "/tmp/cert", "keyFile": "/tmp/key"}}},
				},
			},
		},
	}
	_, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err == nil || !strings.Contains(err.Error(), "compatible server policy") {
		t.Fatalf("got %v, want incompatible UDP server policy", err)
	}
}

func TestCompileRuntimeProfileInboundsHysteriaSamePortAliasesParent(t *testing.T) {
	parent := &model.Inbound{
		Id: 9, Listen: "0.0.0.0", Port: 24443, Protocol: model.Hysteria, Tag: "hy-parent",
		Settings:       `{"clients":[{"auth":"secret","email":"hmstat_hy"}]}`,
		StreamSettings: `{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"udpIdleTimeout":60},"tlsSettings":{"certificates":[{"certificateFile":"/tmp/cert","keyFile":"/tmp/key"}]}}`,
		Sniffing:       `{"enabled":false}`,
	}
	raw := map[string]any{
		"network": "hysteria", "security": "tls",
		"hysteriaSettings": map[string]any{"version": float64(2), "udpIdleTimeout": float64(60)},
		"tlsSettings":      map[string]any{"certificates": []any{map[string]any{"certificateFile": "/tmp/cert", "keyFile": "/tmp/key"}}},
		"externalProxy": []any{map[string]any{
			"port": float64(24443), "network": "same", "security": "same",
			"runtime": map[string]any{},
		}},
	}
	topology, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.Synthetic) != 0 || len(topology.PublicBindings) != 1 {
		t.Fatalf("Hysteria same-port profile must alias parent: synthetic=%d bindings=%#v", len(topology.Synthetic), topology.PublicBindings)
	}
}

func TestCompileRuntimeProfileInboundsExplicitKCPDefaultsOwnedFinalMask(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"finalmask": map[string]any{
			"tcp": []any{map[string]any{"type": "sudoku"}},
		},
		"externalProxy": []any{map[string]any{
			"enabled":  true,
			"port":     float64(46237),
			"network":  "kcp",
			"security": "none",
			"kcpSettings": map[string]any{
				"mtu":              float64(1350),
				"tti":              float64(20),
				"uplinkCapacity":   float64(5),
				"downlinkCapacity": float64(20),
				"cwndMultiplier":   float64(1),
				"maxSendingWindow": float64(2097152),
			},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "owned-kcp-mask",
				"mode":    "direct",
			},
		}},
	}

	got, err := compileRuntimeProfileInbounds(parent, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("synthetic inbounds = %d, want 1", len(got))
	}

	var stream map[string]any
	if err := json.Unmarshal(got[0].StreamSettings, &stream); err != nil {
		t.Fatal(err)
	}
	if runtimeNetwork(stream) != "kcp" {
		t.Fatalf("network = %q", runtimeNetwork(stream))
	}
	kcp, _ := stream["kcpSettings"].(map[string]any)
	if kcp["tti"] != float64(20) {
		t.Fatalf("profile kcpSettings not preserved: %#v", kcp)
	}
	finalmask, _ := stream["finalmask"].(map[string]any)
	if _, inherited := finalmask["tcp"]; inherited {
		t.Fatalf("parent finalmask leaked into runtime listener: %#v", finalmask)
	}
	udp, _ := finalmask["udp"].([]any)
	if len(udp) != 1 || udp[0].(map[string]any)["type"] != "mkcp-legacy" {
		t.Fatalf("runtime finalmask = %#v", finalmask)
	}
}
