package sub

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

const parityClientID = "11111111-2222-4333-8444-555555555555"

func parityStream(base, profiles string) string {
	return strings.TrimSuffix(strings.TrimSpace(base), "}") +
		`,"externalProxy":` + profiles + `}`
}

func TestRawSubscriptionProfiles_MixedLegacyEntryByteParity(t *testing.T) {
	base := `{
		"network":"ws",
		"security":"tls",
		"wsSettings":{"path":"/base","host":"base.example","headers":{}},
		"tlsSettings":{"serverName":"base.sni","settings":{"fingerprint":"chrome"}}
	}`
	legacy := `{
		"forceTls":"tls",
		"dest":"legacy.example",
		"port":7443,
		"remark":"legacy",
		"host":"legacy-host.example",
		"path":"/legacy-path"
	}`
	modern := `{
		"enabled":true,
		"network":"grpc",
		"security":"same",
		"forceTls":"same",
		"dest":"modern.example",
		"port":9443,
		"remark":"modern",
		"grpcSettings":{
			"serviceName":"modern-service",
			"authority":"modern.example",
			"multiMode":false
		}
	}`
	settings := fmt.Sprintf(
		`{"clients":[{"id":%q,"email":"parity","enable":true}],"decryption":"none","encryption":"none"}`,
		parityClientID,
	)

	legacyOnly := &model.Inbound{
		Protocol:       model.VLESS,
		Listen:         "198.51.100.10",
		Port:           443,
		Remark:         "parity",
		Settings:       settings,
		StreamSettings: parityStream(base, `[`+legacy+`]`),
	}
	mixed := *legacyOnly
	mixed.StreamSettings = parityStream(
		base,
		`[`+legacy+`,`+modern+`]`,
	)

	service := &SubService{}
	want := strings.TrimSpace(
		service.GetLink(legacyOnly, "parity"),
	)
	got := strings.Split(
		strings.TrimSpace(service.GetLink(&mixed, "parity")),
		"\n",
	)

	if len(got) != 2 {
		t.Fatalf("mixed links = %d, want 2: %q", len(got), got)
	}
	if got[0] != want {
		t.Fatalf(
			"legacy link changed in mixed list\nwant: %s\ngot:  %s",
			want,
			got[0],
		)
	}
}

func TestRawSubscriptionProfiles_Shadowsocks2022ChachaByteParity(
	t *testing.T,
) {
	base := `{
		"network":"tcp",
		"security":"none",
		"tcpSettings":{"header":{"type":"none"}}
	}`
	legacy := `{
		"forceTls":"same",
		"dest":"ss.example",
		"port":8388,
		"remark":"ss"
	}`
	modern := `{
		"enabled":true,
		"network":"same",
		"security":"same",
		"forceTls":"same",
		"dest":"ss.example",
		"port":8388,
		"remark":"ss"
	}`
	settings := `{
		"method":"2022-blake3-chacha20-poly1305",
		"password":"inbound-password",
		"clients":[{
			"password":"client-password",
			"email":"parity",
			"enable":true
		}]
	}`

	makeInbound := func(profile string) *model.Inbound {
		return &model.Inbound{
			Protocol: model.Shadowsocks,
			Listen:   "198.51.100.10",
			Port:     8388,
			Remark:   "parity",
			Settings: settings,
			StreamSettings: parityStream(
				base,
				`[`+profile+`]`,
			),
		}
	}

	service := &SubService{}
	want := strings.TrimSpace(
		service.GetLink(makeInbound(legacy), "parity"),
	)
	got := strings.TrimSpace(
		service.GetLink(makeInbound(modern), "parity"),
	)

	if got != want {
		t.Fatalf(
			"modern Shadowsocks link changed raw bytes\nwant: %s\ngot:  %s",
			want,
			got,
		)
	}
}

func TestRawSubscriptionProfiles_MixedDisabledLegacyStaysDisabled(
	t *testing.T,
) {
	base := `{
		"network":"tcp",
		"security":"none",
		"tcpSettings":{"header":{"type":"none"}}
	}`

	disabledLegacy := `{
		"enabled":false,
		"forceTls":"same",
		"dest":"disabled.example",
		"port":443,
		"remark":"disabled"
	}`

	modern := `{
		"enabled":true,
		"network":"ws",
		"security":"same",
		"forceTls":"same",
		"dest":"included.example",
		"port":8443,
		"remark":"included",
		"wsSettings":{
			"path":"/ws",
			"host":"included.example",
			"headers":{}
		}
	}`

	inbound := &model.Inbound{
		Protocol: model.VLESS,
		Listen:   "198.51.100.10",
		Port:     443,
		Remark:   "parity",
		Settings: fmt.Sprintf(
			`{
				"clients":[{
					"id":%q,
					"email":"parity",
					"enable":true
				}],
				"decryption":"none",
				"encryption":"none"
			}`,
			parityClientID,
		),
		StreamSettings: parityStream(
			base,
			`[`+disabledLegacy+`,`+modern+`]`,
		),
	}

	lines := strings.Split(
		strings.TrimSpace(
			(&SubService{}).GetLink(inbound, "parity"),
		),
		"\n",
	)

	if len(lines) != 1 {
		t.Fatalf(
			"disabled legacy profile produced output: %q",
			lines,
		)
	}

	parsed, err := url.Parse(lines[0])
	if err != nil {
		t.Fatalf("parse included link: %v", err)
	}

	if parsed.Hostname() != "included.example" {
		t.Fatalf(
			"hostname = %q, want included.example",
			parsed.Hostname(),
		)
	}
}
