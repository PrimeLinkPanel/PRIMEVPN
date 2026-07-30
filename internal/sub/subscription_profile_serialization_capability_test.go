package sub

import (
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestRawSubscriptionOmitsProfileThatCannotRoundTrip(t *testing.T) {
	inbound := &model.Inbound{
		Protocol: model.VLESS,
		Listen:   "198.51.100.10",
		Port:     443,
		Remark:   "raw-capability",
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
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[
				{
					"enabled":true,
					"remark":"json-only",
					"dest":"json-only.example",
					"port":8443,
					"network":"ws",
					"security":"none",
					"wsSettings":{"path":"/json-only","headers":{}},
					"sockopt":{"tcpFastOpen":true}
				},
				{
					"enabled":true,
					"remark":"raw-compatible",
					"dest":"raw.example",
					"port":9443,
					"network":"ws",
					"security":"none",
					"wsSettings":{"path":"/raw","headers":{}}
				}
			]
		}`,
	}

	got := strings.TrimSpace((&SubService{}).GetLink(inbound, "profile-user"))
	lines := strings.Split(got, "\n")
	if len(lines) != 1 {
		t.Fatalf("raw link count = %d, want 1 compatible profile; links=%q", len(lines), got)
	}
	if !strings.Contains(lines[0], "raw.example:9443") {
		t.Fatalf("raw output selected wrong profile: %q", lines[0])
	}
	if strings.Contains(lines[0], "json-only.example") {
		t.Fatalf("raw output silently downgraded JSON-only profile: %q", lines[0])
	}
}

func TestClashTLSClientFieldsRemainDistinct(t *testing.T) {
	const pin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const ech = "ECH_CONFIG_VALUE"

	svc := &SubClashService{SubService: &SubService{}}
	stream := svc.streamData(`{
		"network":"ws",
		"security":"tls",
		"wsSettings":{"path":"/ws","headers":{}},
		"tlsSettings":{
			"serverName":"sni.example.com",
			"alpn":["h2"],
			"settings":{
				"fingerprint":"chrome",
				"allowInsecure":false,
				"pinnedPeerCertSha256":["` + pin + `"],
				"verifyPeerCertByName":"verify.example.com",
				"echConfigList":"` + ech + `"
			}
		}
	}`)
	inbound := &model.Inbound{
		Listen:   "203.0.113.10",
		Port:     443,
		Protocol: model.VLESS,
		Remark:   "tls-fields",
		Settings: `{"encryption":"none"}`,
	}
	client := model.Client{ID: "11111111-2222-4333-8444-555555555555"}

	proxy := svc.buildProxy(svc.SubService, inbound, client, stream, map[string]any{})
	if proxy == nil {
		t.Fatal("buildProxy returned nil for supported TLS profile")
	}
	if proxy["client-fingerprint"] != "chrome" {
		t.Fatalf("client-fingerprint = %v, want chrome", proxy["client-fingerprint"])
	}
	if proxy["fingerprint"] != pin {
		t.Fatalf("certificate fingerprint = %v, want %s", proxy["fingerprint"], pin)
	}
	if proxy["name-cert-verify"] != "verify.example.com" {
		t.Fatalf("name-cert-verify = %v", proxy["name-cert-verify"])
	}
	echOpts, _ := proxy["ech-opts"].(map[string]any)
	if echOpts["enable"] != true || echOpts["config"] != ech {
		t.Fatalf("ech-opts = %#v", proxy["ech-opts"])
	}
}

func TestClashRealityMihomoX25519Mapping(t *testing.T) {
	svc := &SubClashService{SubService: &SubService{}}
	inbound := &model.Inbound{
		Listen:   "203.0.113.11",
		Port:     443,
		Protocol: model.VLESS,
		Remark:   "reality-x25519",
		Settings: `{"encryption":"none"}`,
	}
	client := model.Client{ID: "11111111-2222-4333-8444-555555555555"}
	stream := map[string]any{
		"network":  "tcp",
		"security": "reality",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"realitySettings": map[string]any{
			"serverName":  "reality.example.com",
			"publicKey":   "PUBLIC_KEY",
			"shortId":     "ab12",
			"fingerprint": "chrome",
		},
	}

	proxy := svc.buildProxy(
		svc.SubService,
		inbound,
		client,
		stream,
		map[string]any{"mihomoX25519": true},
	)
	if proxy == nil {
		t.Fatal("buildProxy returned nil for supported REALITY profile")
	}
	opts, _ := proxy["reality-opts"].(map[string]any)
	if opts["support-x25519mlkem768"] != true {
		t.Fatalf("reality-opts = %#v", opts)
	}
}

func TestClashSubscriptionOmitsUnrepresentableRealityProfile(t *testing.T) {
	subReq := &SubService{}
	inbound := &model.Inbound{
		Listen:   "0.0.0.0",
		Port:     443,
		Protocol: model.VLESS,
		Remark:   "clash-capability",
		Settings: `{"encryption":"none"}`,
		StreamSettings: `{
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[{
				"enabled":true,
				"remark":"unsupported-reality",
				"dest":"reality.example.com",
				"port":443,
				"network":"tcp",
				"security":"reality",
				"tcpSettings":{"header":{"type":"none"}},
				"realitySettings":{
					"serverNames":["reality.example.com"],
					"shortIds":["ab12"],
					"settings":{
						"publicKey":"PUBLIC_KEY",
						"fingerprint":"chrome",
						"spiderX":"/",
						"mldsa65Verify":"MLDSA_VERIFY_VALUE"
					}
				}
			}]
		}`,
	}
	client := model.Client{
		ID:    "11111111-2222-4333-8444-555555555555",
		Email: "profile-user",
	}

	proxies := (&SubClashService{SubService: subReq}).getProxies(
		subReq,
		inbound,
		client,
		"panel.example.com",
	)
	if len(proxies) != 0 {
		t.Fatalf("Clash emitted a downgraded REALITY profile: %#v", proxies)
	}
}
