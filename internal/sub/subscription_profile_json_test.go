package sub

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestJSONSubscriptionModernProfileAddsOnePrimaryOutbound(t *testing.T) {
	tests := []struct {
		name     string
		protocol model.Protocol
		settings string
	}{
		{
			name:     "trojan",
			protocol: model.Trojan,
			settings: `{"clients":[]}`,
		},
		{
			name:     "shadowsocks",
			protocol: model.Shadowsocks,
			settings: `{"clients":[],"method":"aes-128-gcm","password":"server-password"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subReq := NewSubService("")
			subReq.address = "subscriber.example"
			subReq.usageShown = map[string]bool{}
			subReq.clientsByInbound = map[int]map[string]model.Client{}
			subReq.fullyPrimedInbounds = map[int]bool{}
			subReq.settingsByInbound = map[int]map[string]any{}

			inbound := &model.Inbound{
				Id:       901,
				Enable:   true,
				Listen:   "198.51.100.10",
				Port:     443,
				Protocol: tt.protocol,
				Settings: tt.settings,
				StreamSettings: `{
					"network":"tcp",
					"security":"none",
					"tcpSettings":{"header":{"type":"none"}},
					"externalProxy":[{
						"enabled":true,
						"dest":"198.51.100.20",
						"port":8443,
						"network":"grpc",
						"security":"none",
						"grpcSettings":{"serviceName":"mobile"},
						"runtime":{"enabled":true,"id":"mobile-grpc","mode":"direct"}
					}]
				}`,
			}
			client := model.Client{
				Email:    "client@example.invalid",
				Password: "client-password",
			}

			service := NewSubJsonService("", "", "", subReq)
			configs := service.getConfig(subReq, inbound, client, "subscriber.example")
			if len(configs) != 1 {
				t.Fatalf("got %d JSON configs, want 1", len(configs))
			}

			var config map[string]any
			if err := json.Unmarshal(configs[0], &config); err != nil {
				t.Fatal(err)
			}
			outbounds, ok := config["outbounds"].([]any)
			if !ok {
				t.Fatalf("outbounds missing from generated config: %#v", config)
			}
			want := 1 + len(service.defaultOutbounds)
			if len(outbounds) != want {
				t.Fatalf("got %d outbounds, want one profile outbound plus %d defaults (%d total)", len(outbounds), len(service.defaultOutbounds), want)
			}
		})
	}
}
