package service

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

func sharedPortTLSParent() (*model.Inbound, map[string]any) {
	parent := runtimeProfileTestParent()
	parent.Port = 443
	parent.Tag = "shared-all-transports"
	parent.StreamSettings = `{
		"network":"tcp",
		"security":"tls",
		"tcpSettings":{"header":{"type":"none"}},
		"tlsSettings":{"certificates":[{"certificateFile":"/tmp/test-cert.pem","keyFile":"/tmp/test-key.pem"}]}
	}`
	raw := map[string]any{
		"network":  "tcp",
		"security": "tls",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"tlsSettings": map[string]any{
			"certificates": []any{map[string]any{
				"certificateFile": "/tmp/test-cert.pem",
				"keyFile":         "/tmp/test-key.pem",
			}},
		},
		"externalProxy": []any{
			map[string]any{
				"enabled":     true,
				"port":        float64(443),
				"network":     "same",
				"security":    "same",
				"tlsSettings": map[string]any{"serverName": "raw.example.com"},
			},
			sharedTLSRuntimeProfile("ws", "ws-profile", "ws.example.com", map[string]any{"path": "/ws"}),
			sharedTLSRuntimeProfile("grpc", "grpc-profile", "grpc.example.com", map[string]any{"serviceName": "grpc"}),
			sharedTLSRuntimeProfile("httpupgrade", "hu-profile", "hu.example.com", map[string]any{"path": "/upgrade", "host": "hu.example.com"}),
			sharedTLSRuntimeProfile("xhttp", "xhttp-profile", "xhttp.example.com", map[string]any{"path": "/xhttp", "mode": "auto"}),
			map[string]any{
				"enabled":  true,
				"port":     float64(443),
				"network":  "kcp",
				"security": "same",
				"runtime": map[string]any{
					"enabled": true,
					"id":      "kcp-profile",
					"mode":    "direct",
				},
			},
		},
	}
	return parent, raw
}

func sharedTLSRuntimeProfile(network, id, sni string, transport map[string]any) map[string]any {
	profile := map[string]any{
		"enabled":     true,
		"port":        float64(443),
		"network":     network,
		"security":    "same",
		"tlsSettings": map[string]any{"serverName": sni},
		"runtime": map[string]any{
			"enabled": true,
			"id":      id,
			"mode":    "direct",
		},
	}
	profile[runtimeTransportKey(network)] = transport
	return profile
}

func TestCompileRuntimeProfileTopologyAllSixProfileTransportsShareNumericPort(t *testing.T) {
	parent, raw := sharedPortTLSParent()
	allocator := newSharedBackendAllocator(nil)
	allocator.reserve(runtimeSocketBinding{Listen: "0.0.0.0", Port: 443, Transport: "tcp"})

	topology, err := compileRuntimeProfileTopology(parent, raw, allocator)
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.SharedPlan.Groups) != 1 {
		t.Fatalf("shared groups = %d, want 1", len(topology.SharedPlan.Groups))
	}
	group := topology.SharedPlan.Groups[0]
	if group.Listen != "0.0.0.0" || group.Port != 443 || len(group.Routes) != 5 {
		t.Fatalf("unexpected shared group: %+v", group)
	}
	if len(topology.Synthetic) != 5 {
		t.Fatalf("synthetic inbounds = %d, want 5 (4 TCP backends + 1 UDP KCP)", len(topology.Synthetic))
	}

	publicFamilies := map[string]bool{}
	for _, binding := range topology.PublicBindings {
		publicFamilies[binding.Transport] = true
	}
	if !publicFamilies["tcp"] || !publicFamilies["udp"] {
		t.Fatalf("public bindings = %+v, want TCP frontmux + UDP KCP", topology.PublicBindings)
	}

	for _, route := range group.Routes {
		host, port, splitErr := net.SplitHostPort(route.Backend)
		if splitErr != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "443" {
			t.Fatalf("route backend is not a private non-public loopback endpoint: %+v err=%v", route, splitErr)
		}
	}

	all := []struct {
		tag    string
		stream []byte
	}{{topology.Parent.Tag, topology.Parent.StreamSettings}}
	for _, inbound := range topology.Synthetic {
		all = append(all, struct {
			tag    string
			stream []byte
		}{inbound.Tag, inbound.StreamSettings})
	}
	for _, inbound := range all {
		var stream map[string]any
		if err := json.Unmarshal(inbound.stream, &stream); err != nil {
			t.Fatal(err)
		}
		if runtimeNetwork(stream) == "kcp" {
			continue
		}
		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt["acceptProxyProtocol"] != true {
			t.Fatalf("inbound %q missing backend PROXY protocol: %#v", inbound.tag, stream)
		}
	}
}

func TestCompileRuntimeProfileTopologyRejectsInheritedParentECH(t *testing.T) {
	parent := runtimeProfileTestParent()
	parent.Port = 443
	parent.Tag = "inherited-ech"
	raw := map[string]any{
		"network":  "tcp",
		"security": "tls",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"tlsSettings": map[string]any{
			"serverName": "raw.example.com",
			"certificates": []any{map[string]any{
				"certificateFile": "/tmp/test-cert.pem",
				"keyFile":         "/tmp/test-key.pem",
			}},
			"settings": map[string]any{"echConfigList": "ECH-CONFIG"},
		},
		"externalProxy": []any{
			map[string]any{
				"enabled":  true,
				"port":     float64(443),
				"network":  "same",
				"security": "same",
			},
			sharedTLSRuntimeProfile("ws", "ws-profile", "ws.example.com", map[string]any{"path": "/ws"}),
		},
	}

	_, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err == nil || !strings.Contains(err.Error(), "ECH") {
		t.Fatalf("error = %v, want inherited ECH rejection", err)
	}
}

func TestCompileRuntimeProfileTopologyRejectsMissingParentSNI(t *testing.T) {
	parent, raw := sharedPortTLSParent()
	raw["externalProxy"] = []any{
		map[string]any{
			"enabled":     true,
			"port":        float64(443),
			"network":     "same",
			"security":    "same",
			"tlsSettings": map[string]any{"serverName": ""},
		},
		sharedTLSRuntimeProfile("ws", "ws-profile", "ws.example.com", map[string]any{"path": "/ws"}),
	}

	_, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err == nil || !strings.Contains(err.Error(), "non-empty exact client SNI") {
		t.Fatalf("error = %v, want missing mandatory parent SNI rejection", err)
	}
}

func TestCompileRuntimeProfileTopologyRejectsDuplicateSNI(t *testing.T) {
	parent, raw := sharedPortTLSParent()
	entries := raw["externalProxy"].([]any)
	entries[2].(map[string]any)["tlsSettings"] = map[string]any{"serverName": "WS.EXAMPLE.COM."}
	_, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error = %v, want ambiguous SNI", err)
	}
}

func TestCompileRuntimeProfileTopologyRejectsCleartextXHTTPOnSharedSocket(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":       true,
			"port":          float64(parent.Port),
			"network":       "xhttp",
			"security":      "none",
			"xhttpSettings": map[string]any{"path": "/xhttp", "mode": "auto"},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "clear-xhttp",
			},
		}},
	}
	_, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err == nil || !strings.Contains(err.Error(), "cleartext XHTTP") {
		t.Fatalf("error = %v, want cleartext XHTTP rejection", err)
	}
}

func TestCompileRuntimeProfileTopologyAllowsDirectCleartextXHTTP(t *testing.T) {
	parent := runtimeProfileTestParent()
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":       true,
			"port":          float64(parent.Port + 1),
			"network":       "xhttp",
			"security":      "none",
			"xhttpSettings": map[string]any{"path": "/xhttp", "mode": "auto"},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "clear-xhttp-direct",
			},
		}},
	}
	topology, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !topology.SharedPlan.Empty() || len(topology.Synthetic) != 1 || topology.Synthetic[0].Port != parent.Port+1 {
		t.Fatalf("unexpected direct XHTTP topology: %+v", topology)
	}
}

func TestSharedPortPlanDoesNotLeakIntoXrayJSON(t *testing.T) {
	parent, raw := sharedPortTLSParent()
	topology, err := compileRuntimeProfileTopology(parent, raw, newSharedBackendAllocator(nil))
	if err != nil {
		t.Fatal(err)
	}
	cfg := xray.Config{
		SharedPortPlan: topology.SharedPlan,
		InboundConfigs: append(
			[]xray.InboundConfig{topology.Parent},
			topology.Synthetic...,
		),
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "frontmux") || strings.Contains(string(encoded), "routes") {
		t.Fatalf("panel-only plan leaked into JSON: %s", encoded)
	}
}

func TestCompileRuntimeProfileTopologyRoutesRawAndCleartextGRPCOnOnePort(t *testing.T) {
	parent := runtimeProfileTestParent()
	parent.Port = 23587
	parent.Tag = "plain-raw-grpc"
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{
			map[string]any{
				"enabled":  true,
				"port":     float64(23587),
				"network":  "same",
				"security": "same",
			},
			map[string]any{
				"enabled":      true,
				"port":         float64(23587),
				"network":      "grpc",
				"security":     "none",
				"grpcSettings": map[string]any{"serviceName": ""},
				"runtime": map[string]any{
					"enabled": true,
					"id":      "grpc-shared",
					"mode":    "direct",
				},
			},
		},
	}

	topology, err := compileRuntimeProfileTopology(parent, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.SharedPlan.Groups) != 1 || len(topology.SharedPlan.Groups[0].Routes) != 2 {
		t.Fatalf("unexpected shared topology: %+v", topology.SharedPlan)
	}
	kinds := map[string]bool{}
	for _, route := range topology.SharedPlan.Groups[0].Routes {
		kinds[route.Kind] = true
	}
	if !kinds["raw-catch-all"] || !kinds["http2-preface"] {
		t.Fatalf("route kinds = %+v", kinds)
	}
	if topology.Parent.Port == parent.Port || len(topology.Synthetic) != 1 || topology.Synthetic[0].Port == parent.Port {
		t.Fatalf("public port leaked into private backends: parent=%d synthetic=%+v", topology.Parent.Port, topology.Synthetic)
	}
}

func TestStandaloneTopologyAllocatorNeverUsesPublicPortRangeCollision(t *testing.T) {
	parent := runtimeProfileTestParent()
	parent.Port = 30000
	parent.Tag = "public-in-backend-range"
	raw := map[string]any{
		"network":  "tcp",
		"security": "none",
		"tcpSettings": map[string]any{
			"header": map[string]any{"type": "none"},
		},
		"externalProxy": []any{map[string]any{
			"enabled":      true,
			"port":         float64(30000),
			"network":      "grpc",
			"security":     "none",
			"grpcSettings": map[string]any{},
			"runtime": map[string]any{
				"enabled": true,
				"id":      "grpc-shared",
			},
		}},
	}

	topology, err := compileRuntimeProfileTopology(parent, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range topology.SharedPlan.Groups {
		for _, route := range group.Routes {
			_, port, err := net.SplitHostPort(route.Backend)
			if err != nil {
				t.Fatal(err)
			}
			if port == "30000" {
				t.Fatalf("backend %q reused the public listener port", route.Backend)
			}
		}
	}
}
