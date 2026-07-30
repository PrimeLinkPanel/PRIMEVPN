package sub

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestRawSubscriptionProfilesUseEachEffectiveStream(t *testing.T) {
	inbound := &model.Inbound{
		Protocol: model.VLESS,
		Listen:   "198.51.100.10",
		Port:     31688,
		Remark:   "profiles",
		Settings: `{
			"clients":[{
				"id":"11111111-2222-4333-8444-555555555555",
				"email":"profile-user",
				"enable":true,
				"flow":""
			}],
			"decryption":"none",
			"encryption":"none"
		}`,
		StreamSettings: `{
			"network":"httpupgrade",
			"security":"tls",
			"httpupgradeSettings":{
				"path":"/base",
				"host":"base.example"
			},
			"tlsSettings":{
				"serverName":"base.example",
				"settings":{"fingerprint":"chrome"}
			},
			"externalProxy":[
				{
					"enabled":true,
					"remark":"inherit",
					"dest":"inherit.example",
					"port":443,
					"network":"same",
					"security":"same",
					"forceTls":"same"
				},
				{
					"enabled":true,
					"remark":"websocket",
					"dest":"ws.example",
					"port":8443,
					"network":"ws",
					"security":"same",
					"forceTls":"same",
					"wsSettings":{
						"path":"/ws",
						"host":"ws.example",
						"headers":{}
					}
				},
				{
					"enabled":true,
					"remark":"grpc",
					"dest":"grpc.example",
					"port":9443,
					"network":"grpc",
					"security":"same",
					"forceTls":"same",
					"grpcSettings":{
						"serviceName":"grpc-service",
						"authority":"grpc.example",
						"multiMode":false
					}
				}
			]
		}`,
	}

	got := (&SubService{}).GetLink(inbound, "profile-user")
	lines := strings.Split(strings.TrimSpace(got), "\n")

	if len(lines) != 3 {
		t.Fatalf("link count = %d, want 3; links=%q", len(lines), got)
	}

	wantTypes := map[string]string{
		"443":  "httpupgrade",
		"8443": "ws",
		"9443": "grpc",
	}

	for _, line := range lines {
		parsed, err := url.Parse(line)
		if err != nil {
			t.Fatalf("parse link %q: %v", line, err)
		}

		wantType, ok := wantTypes[parsed.Port()]
		if !ok {
			t.Fatalf("unexpected endpoint port %q in %q", parsed.Port(), line)
		}

		query := parsed.Query()

		if gotType := query.Get("type"); gotType != wantType {
			t.Errorf(
				"port %s type = %q, want %q; link=%q",
				parsed.Port(),
				gotType,
				wantType,
				line,
			)
		}

		if security := query.Get("security"); security != "tls" {
			t.Errorf(
				"port %s security = %q, want tls; link=%q",
				parsed.Port(),
				security,
				line,
			)
		}
	}
}

func TestRawSubscriptionProfileFlowOverrideMatchesEffectiveEndpoint(t *testing.T) {
	inbound := &model.Inbound{
		Protocol: model.VLESS,
		Listen:   "198.51.100.10",
		Port:     443,
		Remark:   "profiles",
		Settings: `{
			"clients":[{
				"id":"11111111-2222-4333-8444-555555555555",
				"email":"profile-user",
				"enable":true,
				"flow":""
			}],
			"decryption":"none",
			"encryption":"mlkem768x25519plus.native.0rtt.test"
		}`,
		StreamSettings: `{
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[{
				"enabled":true,
				"dest":"profile.example",
				"port":8443,
				"network":"xhttp",
				"security":"reality",
				"flow":"xtls-rprx-vision",
				"xhttpSettings":{"path":"/runtime","mode":"auto"},
				"realitySettings":{
					"serverNames":["profile.example"],
					"shortIds":["0123456789abcdef"],
					"settings":{
						"publicKey":"public-key",
						"fingerprint":"chrome",
						"serverName":"profile.example",
						"spiderX":"/"
					}
				}
			}]
		}`,
	}

	link := strings.TrimSpace((&SubService{}).GetLink(inbound, "profile-user"))
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("flow"); got != "xtls-rprx-vision" {
		t.Fatalf("flow = %q, want profile override; link=%q", got, link)
	}
}

func TestSubscriptionProfileFlowOverrideCanExplicitlyClearParentFlow(t *testing.T) {
	if got, ok := subscriptionProfileFlowOverride(map[string]any{"flow": ""}); !ok || got != "" {
		t.Fatalf("got (%q, %v), want explicit empty override", got, ok)
	}
	if got, ok := subscriptionProfileFlowOverride(map[string]any{
		"runtime": map[string]any{"flow": "xtls-rprx-vision"},
	}); !ok || got != "xtls-rprx-vision" {
		t.Fatalf("legacy runtime.flow got (%q, %v)", got, ok)
	}
}

func TestRawExplicitKCPProfileUnderTCPParentEmitsOwnedFM(t *testing.T) {
	inbound := &model.Inbound{
		Protocol: model.VLESS,
		Listen:   "209.38.40.139",
		Port:     30856,
		Remark:   "TCP Test",
		Settings: `{
            "clients":[{
                "id":"d9d40015-cbb9-4f1b-ad8c-fece08887833",
                "email":"profile-user",
                "enable":true,
                "flow":""
            }],
            "decryption":"none",
            "encryption":"none"
        }`,
		StreamSettings: `{
            "network":"tcp",
            "security":"none",
            "tcpSettings":{"header":{"type":"none"}},
            "finalmask":{"tcp":[{"type":"sudoku","settings":{}}]},
            "externalProxy":[{
                "enabled":true,
                "dest":"209.38.40.139",
                "port":46237,
                "network":"kcp",
                "security":"none",
                "kcpSettings":{
                    "mtu":1350,
                    "tti":20,
                    "uplinkCapacity":5,
                    "downlinkCapacity":20,
                    "cwndMultiplier":1,
                    "maxSendingWindow":2097152
                },
                "runtime":{"enabled":true,"id":"kcp-profile","mode":"direct"}
            }]
        }`,
	}

	link := strings.TrimSpace((&SubService{}).GetLink(inbound, "profile-user"))
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("type") != "kcp" || query.Get("mtu") != "1350" || query.Get("tti") != "20" {
		t.Fatalf("unexpected mKCP link: %q", link)
	}

	var finalmask map[string]any
	if err := json.Unmarshal([]byte(query.Get("fm")), &finalmask); err != nil {
		t.Fatalf("decode fm from %q: %v", link, err)
	}
	if _, inherited := finalmask["tcp"]; inherited {
		t.Fatalf("parent TCP mask leaked into profile link: %#v", finalmask)
	}
	udp, _ := finalmask["udp"].([]any)
	if len(udp) != 1 || stringValue(udp[0].(map[string]any)["type"]) != "mkcp-legacy" {
		t.Fatalf("profile link fm = %#v", finalmask)
	}
}
