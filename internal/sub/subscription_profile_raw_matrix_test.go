package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func matrixClientSettings(protocol model.Protocol) string {
	switch protocol {
	case model.VMESS, model.VLESS:
		return fmt.Sprintf(
			`{
				"clients":[{
					"id":%q,
					"email":"matrix",
					"enable":true,
					"security":"auto"
				}],
				"decryption":"none",
				"encryption":"none"
			}`,
			parityClientID,
		)
	case model.Trojan:
		return `{
			"clients":[{
				"password":"matrix-password",
				"email":"matrix",
				"enable":true
			}]
		}`
	default:
		return "{}"
	}
}

func TestRawSubscriptionProfiles_VMessGrpcTLS(t *testing.T) {
	inbound := &model.Inbound{
		Protocol: model.VMESS,
		Listen:   "198.51.100.10",
		Port:     443,
		Remark:   "matrix",
		Settings: matrixClientSettings(model.VMESS),
		StreamSettings: `{
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[{
				"enabled":true,
				"network":"grpc",
				"security":"tls",
				"forceTls":"tls",
				"dest":"vmess.example",
				"port":8443,
				"remark":"grpc",
				"grpcSettings":{
					"serviceName":"matrix-grpc",
					"authority":"grpc-authority.example",
					"multiMode":false
				},
				"tlsSettings":{
					"serverName":"vmess-sni.example",
					"settings":{"fingerprint":"firefox"}
				}
			}]
		}`,
	}

	link := strings.TrimSpace(
		(&SubService{}).GetLink(inbound, "matrix"),
	)
	if !strings.HasPrefix(link, "vmess://") {
		t.Fatalf("unexpected VMess link: %q", link)
	}

	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimPrefix(link, "vmess://"),
	)
	if err != nil {
		t.Fatalf("decode VMess link: %v", err)
	}

	var object map[string]any
	if err := json.Unmarshal(decoded, &object); err != nil {
		t.Fatalf("parse VMess object: %v", err)
	}

	for key, want := range map[string]string{
		"add":       "vmess.example",
		"net":       "grpc",
		"path":      "matrix-grpc",
		"authority": "grpc-authority.example",
		"tls":       "tls",
		"sni":       "vmess-sni.example",
		"fp":        "firefox",
	} {
		if got, _ := object[key].(string); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestRawSubscriptionProfiles_TrojanWsTLS(t *testing.T) {
	inbound := &model.Inbound{
		Protocol: model.Trojan,
		Listen:   "198.51.100.10",
		Port:     443,
		Remark:   "matrix",
		Settings: matrixClientSettings(model.Trojan),
		StreamSettings: `{
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[{
				"enabled":true,
				"network":"ws",
				"security":"tls",
				"forceTls":"tls",
				"dest":"trojan.example",
				"port":9443,
				"remark":"ws",
				"wsSettings":{
					"path":"/matrix-ws",
					"host":"ws-host.example",
					"headers":{}
				},
				"tlsSettings":{
					"serverName":"trojan-sni.example",
					"settings":{"fingerprint":"chrome"}
				}
			}]
		}`,
	}

	link := strings.TrimSpace(
		(&SubService{}).GetLink(inbound, "matrix"),
	)
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse Trojan link: %v", err)
	}

	query := parsed.Query()
	for key, want := range map[string]string{
		"type":     "ws",
		"path":     "/matrix-ws",
		"host":     "ws-host.example",
		"security": "tls",
		"sni":      "trojan-sni.example",
		"fp":       "chrome",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestRawSubscriptionProfiles_VlessKcpNone(t *testing.T) {
	inbound := &model.Inbound{
		Protocol: model.VLESS,
		Listen:   "198.51.100.10",
		Port:     443,
		Remark:   "matrix",
		Settings: matrixClientSettings(model.VLESS),
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
			"externalProxy":[{
				"enabled":true,
				"network":"kcp",
				"security":"none",
				"forceTls":"none",
				"dest":"kcp.example",
				"port":2443,
				"remark":"kcp",
				"kcpSettings":{
					"mtu":1350,
					"tti":50,
					"uplinkCapacity":5,
					"downlinkCapacity":20,
					"congestion":false,
					"readBufferSize":2,
					"writeBufferSize":2,
					"header":{"type":"none"},
					"seed":""
				}
			}]
		}`,
	}

	link := strings.TrimSpace(
		(&SubService{}).GetLink(inbound, "matrix"),
	)
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse VLESS KCP link: %v", err)
	}

	if got := parsed.Query().Get("type"); got != "kcp" {
		t.Errorf("type = %q, want kcp", got)
	}
	if got := parsed.Query().Get("security"); got != "none" {
		t.Errorf("security = %q, want none", got)
	}
	if parsed.Query().Get("sni") != "" {
		t.Errorf("KCP/NONE link leaked parent SNI")
	}
}

func TestRawSubscriptionProfiles_AllModernDisabledIsEmpty(
	t *testing.T,
) {
	inbound := &model.Inbound{
		Protocol: model.VLESS,
		Listen:   "198.51.100.10",
		Port:     443,
		Remark:   "matrix",
		Settings: matrixClientSettings(model.VLESS),
		StreamSettings: `{
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[{
				"enabled":false,
				"network":"ws",
				"security":"same",
				"dest":"disabled.example",
				"port":8443,
				"wsSettings":{
					"path":"/disabled",
					"host":"disabled.example",
					"headers":{}
				}
			}]
		}`,
	}

	if got := strings.TrimSpace(
		(&SubService{}).GetLink(inbound, "matrix"),
	); got != "" {
		t.Fatalf("all-disabled profile list returned %q", got)
	}
}
