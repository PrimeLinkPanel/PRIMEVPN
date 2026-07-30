package sub

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	wgutil "github.com/mhsanaei/PRIMEVPN/v3/internal/util/wireguard"
)

func hasDirectOutOutbound(svc *SubJsonService) bool {
	for _, raw := range svc.defaultOutbounds {
		var outbound map[string]any
		if err := json.Unmarshal(raw, &outbound); err != nil {
			continue
		}
		if outbound["tag"] == "direct_out" {
			return true
		}
	}
	return false
}

func outboundSettings(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("failed to unmarshal outbound: %v", err)
	}
	settings, _ := parsed["settings"].(map[string]any)
	if settings == nil {
		t.Fatal("outbound has no settings")
	}
	return settings
}

func TestSubJsonServiceBlankProfileInheritsNodeAddress(t *testing.T) {
	nodeID := 7
	subReq := &SubService{
		address: "panel.example.com",
		nodesByID: map[int]*model.Node{
			7: {Id: 7, Address: "node7.example.com"},
		},
	}
	inbound := &model.Inbound{
		NodeID:            &nodeID,
		Listen:            "0.0.0.0",
		Port:              443,
		Protocol:          model.VLESS,
		Remark:            "json-inherit",
		ShareAddrStrategy: "node",
		Settings:          `{"encryption":"none"}`,
		StreamSettings: `{
			"network":"tcp",
			"security":"none",
			"tcpSettings":{"header":{"type":"none"}},
			"externalProxy":[
				{"enabled":true,"forceTls":"same","dest":"","port":0,"remark":"inherit"}
			]
		}`,
	}
	client := model.Client{
		ID:    "11111111-2222-4333-8444-555555555555",
		Email: "user",
	}

	configs := NewSubJsonService("", "", "", subReq).getConfig(
		subReq,
		inbound,
		client,
		"panel.example.com",
	)
	if len(configs) != 1 {
		t.Fatalf("len(configs) = %d, want 1", len(configs))
	}

	var config map[string]any
	if err := json.Unmarshal(configs[0], &config); err != nil {
		t.Fatalf("unmarshal JSON subscription: %v", err)
	}
	outbounds, _ := config["outbounds"].([]any)
	if len(outbounds) == 0 {
		t.Fatalf("JSON subscription has no outbounds: %#v", config)
	}
	outbound, _ := outbounds[0].(map[string]any)
	settings, _ := outbound["settings"].(map[string]any)
	if settings["address"] != "node7.example.com" {
		t.Fatalf("JSON address = %v, want node7.example.com", settings["address"])
	}
	if settings["port"] != float64(443) {
		t.Fatalf("JSON port = %v, want 443", settings["port"])
	}
}

func TestSubJsonServiceInjectsGlobalFinalMask(t *testing.T) {
	finalMask := `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}}],"udp":[{"type":"noise","settings":{"noise":[{"type":"base64","packet":"SGVsbG8="}]}}],"quicParams":{"congestion":"bbr"}}`
	svc := NewSubJsonService("", "", finalMask, nil)

	if hasDirectOutOutbound(svc) {
		t.Fatal("direct_out outbound must never be emitted")
	}

	stream := svc.streamData(`{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`, "")
	if _, ok := stream["sockopt"]; ok {
		t.Fatal("legacy direct_out dialerProxy sockopt must never be set")
	}

	finalmask, _ := stream["finalmask"].(map[string]any)
	if finalmask == nil {
		t.Fatal("streamSettings is missing finalmask")
	}

	tcp, _ := finalmask["tcp"].([]any)
	if len(tcp) != 1 {
		t.Fatalf("tcp masks len = %d, want 1", len(tcp))
	}
	if first, _ := tcp[0].(map[string]any); first["type"] != "fragment" {
		t.Fatalf("tcp[0] type = %v, want fragment", first["type"])
	}

	udp, _ := finalmask["udp"].([]any)
	if len(udp) != 1 {
		t.Fatalf("udp masks len = %d, want 1", len(udp))
	}

	quic, _ := finalmask["quicParams"].(map[string]any)
	if quic == nil || quic["congestion"] != "bbr" {
		t.Fatalf("quicParams missing/wrong: %#v", finalmask["quicParams"])
	}
}

func TestSubJsonServiceMergesWithExistingFinalMask(t *testing.T) {
	finalMask := `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}`
	svc := NewSubJsonService("", "", finalMask, nil)

	stream := svc.streamData(`{
		"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}},
		"finalmask":{"tcp":[{"type":"sudoku"}]}
	}`, "")

	finalmask, _ := stream["finalmask"].(map[string]any)
	tcp, _ := finalmask["tcp"].([]any)
	if len(tcp) != 2 {
		t.Fatalf("tcp masks len = %d, want 2 (existing + global)", len(tcp))
	}
	a, _ := tcp[0].(map[string]any)
	b, _ := tcp[1].(map[string]any)
	if a["type"] != "sudoku" || b["type"] != "fragment" {
		t.Fatalf("tcp masks = %#v, want existing sudoku then global fragment", tcp)
	}
}

func TestSubJsonServiceNoFinalMaskWhenEmpty(t *testing.T) {
	svc := NewSubJsonService("", "", "", nil)
	stream := svc.streamData(`{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`, "")
	if _, ok := stream["finalmask"]; ok {
		t.Fatal("no finalmask should be emitted when subJsonFinalMask is empty")
	}
	if _, ok := stream["sockopt"]; ok {
		t.Fatal("legacy direct_out sockopt must never be set")
	}
}

// xray-core parses tlsSettings.pinnedPeerCertSha256 as a comma-separated string;
// the JSON subscription must emit that form, not an array, or v2ray clients fail
// to import the config (#5401).
func TestSubJsonServicePinnedCertJoinedToString(t *testing.T) {
	svc := NewSubJsonService("", "", "", nil)
	stream := svc.streamData(`{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com","settings":{"pinnedPeerCertSha256":["aa11","bb22"]}}}`, "")

	tls, _ := stream["tlsSettings"].(map[string]any)
	if tls == nil {
		t.Fatalf("tlsSettings missing: %#v", stream)
	}
	if got := tls["pinnedPeerCertSha256"]; got != "aa11,bb22" {
		t.Fatalf("pinnedPeerCertSha256 = %#v, want comma-separated string \"aa11,bb22\"", got)
	}
}

func TestSubJsonServiceVlessFlattened(t *testing.T) {
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VLESS, Settings: `{"encryption":"none"}`}
	client := model.Client{ID: "uuid-1", Flow: "xtls-rprx-vision"}

	settings := outboundSettings(t, NewSubJsonService("", "", "", nil).genVless(&SubService{}, inbound, nil, client, ""))
	if _, ok := settings["vnext"]; ok {
		t.Fatal("vless outbound must not use vnext")
	}
	if settings["address"] != "1.2.3.4" || settings["id"] != "uuid-1" || settings["encryption"] != "none" || settings["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flat vless settings wrong: %#v", settings)
	}
}

func TestSubJsonServiceVmessFlattened(t *testing.T) {
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VMESS, Settings: `{}`}
	client := model.Client{ID: "uuid-2"}

	settings := outboundSettings(t, NewSubJsonService("", "", "", nil).genVnext(inbound, nil, client, ""))
	if _, ok := settings["vnext"]; ok {
		t.Fatal("vmess outbound must not use vnext")
	}
	if settings["id"] != "uuid-2" || settings["security"] != "auto" {
		t.Fatalf("flat vmess settings wrong: %#v", settings)
	}
}

// Shadowsocks/Trojan outbounds must use the standard "servers" array so older
// bundled xray-cores (e.g. v2rayN) parse them; the flat top-level form only
// works on very recent xray-core.
func TestSubJsonServiceServerUsesServersArray(t *testing.T) {
	trojan := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.Trojan, Settings: `{}`}
	client := model.Client{Password: "p4ss"}

	settings := outboundSettings(t, NewSubJsonService("", "", "", nil).genServer(&SubService{}, trojan, nil, client, ""))
	server := firstServer(settings)
	if server == nil {
		t.Fatalf("trojan outbound must use a servers array, got: %#v", settings)
	}
	if server["password"] != "p4ss" || server["address"] != "1.2.3.4" {
		t.Fatalf("trojan server entry wrong: %#v", server)
	}
	if _, ok := server["method"]; ok {
		t.Fatalf("trojan must not carry method: %#v", server)
	}

	ss := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.Shadowsocks, Settings: `{"method":"aes-256-gcm"}`}
	ssSettings := outboundSettings(t, NewSubJsonService("", "", "", nil).genServer(&SubService{}, ss, nil, client, ""))
	ssServer := firstServer(ssSettings)
	if ssServer == nil {
		t.Fatalf("shadowsocks outbound must use a servers array, got: %#v", ssSettings)
	}
	if ssServer["method"] != "aes-256-gcm" {
		t.Fatalf("shadowsocks server entry must carry method: %#v", ssServer)
	}
}

func TestSubJsonServiceXmuxSuppressesGlobalMux(t *testing.T) {
	globalMux := `{"enabled":true,"concurrency":8}`
	svc := NewSubJsonService(globalMux, "", "", nil)

	// When xmux is present in xhttpSettings, the per-inbound xmux handles
	// multiplexing and the legacy outbound.Mux must NOT be set.
	stream := `{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.com"},"xhttpSettings":{"path":"/api","mode":"packet-up","xmux":{"maxConcurrency":"16-32"}}}`
	parsed := svc.streamData(stream, "")

	mux := globalMux
	if xhttp, ok := parsed["xhttpSettings"].(map[string]any); ok {
		if _, hasXmux := xhttp["xmux"]; hasXmux {
			mux = ""
		}
	}

	streamSettings, _ := json.Marshal(parsed)
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VLESS, Settings: `{"encryption":"none"}`}
	client := model.Client{ID: "uuid-1"}

	raw := svc.genVless(&SubService{}, inbound, streamSettings, client, mux)
	var ob map[string]any
	if err := json.Unmarshal(raw, &ob); err != nil {
		t.Fatalf("unmarshal outbound: %v", err)
	}
	if _, has := ob["mux"]; has {
		t.Fatal("outbound.Mux must NOT be set when per-inbound xmux is present")
	}

	// Verify xmux is still inside xhttpSettings in streamSettings.
	ss, _ := ob["streamSettings"].(map[string]any)
	if ss == nil {
		t.Fatal("streamSettings missing from outbound")
	}
	xhttp, _ := ss["xhttpSettings"].(map[string]any)
	if xhttp == nil {
		t.Fatal("xhttpSettings missing from streamSettings")
	}
	xmux, _ := xhttp["xmux"].(map[string]any)
	if xmux == nil {
		t.Fatal("xmux missing from xhttpSettings — per-inbound xmux must survive streamData()")
	}
	if xmux["maxConcurrency"] != "16-32" {
		t.Fatalf("xmux.maxConcurrency = %v, want 16-32", xmux["maxConcurrency"])
	}
}

func TestSubJsonServiceGlobalMuxWhenNoXmux(t *testing.T) {
	globalMux := `{"enabled":true,"concurrency":8}`
	svc := NewSubJsonService(globalMux, "", "", nil)

	// When no xmux is present, the global subJsonMux should be used.
	stream := `{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"example.com"},"xhttpSettings":{"path":"/api","mode":"packet-up"}}`
	parsed := svc.streamData(stream, "")

	mux := globalMux
	if xhttp, ok := parsed["xhttpSettings"].(map[string]any); ok {
		if _, hasXmux := xhttp["xmux"]; hasXmux {
			mux = ""
		}
	}

	streamSettings, _ := json.Marshal(parsed)
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VLESS, Settings: `{"encryption":"none"}`}
	client := model.Client{ID: "uuid-1"}

	raw := svc.genVless(&SubService{}, inbound, streamSettings, client, mux)
	var ob map[string]any
	if err := json.Unmarshal(raw, &ob); err != nil {
		t.Fatalf("unmarshal outbound: %v", err)
	}
	m, has := ob["mux"]
	if !has {
		t.Fatal("outbound.Mux must be set when global subJsonMux is configured and no per-inbound xmux")
	}
	mm, _ := m.(map[string]any)
	if mm["enabled"] != true || mm["concurrency"] != float64(8) {
		t.Fatalf("mux payload wrong: %#v", m)
	}
}

func realitySpiderXFromStream(t *testing.T, svc *SubJsonService, clientKey string) string {
	t.Helper()
	stream := svc.streamData(`{
		"network":"tcp","security":"reality","tcpSettings":{"header":{"type":"none"}},
		"realitySettings":{
			"serverNames":["reality.example.com"],
			"shortIds":["ab12cd"],
			"settings":{"publicKey":"PBKvalue","fingerprint":"firefox","spiderX":"/seed"}
		}
	}`, clientKey)
	rlty, _ := stream["realitySettings"].(map[string]any)
	if rlty == nil {
		t.Fatal("streamData dropped realitySettings")
	}
	spx, _ := rlty["spiderX"].(string)
	if len(spx) != 16 || spx[0] != '/' {
		t.Fatalf("spiderX = %q, want a 16-char /-prefixed value", spx)
	}
	return spx
}

func TestSubJsonServiceRealityDataDerivesPerClientSpiderX(t *testing.T) {
	svc := NewSubJsonService("", "", "", nil)

	alice := realitySpiderXFromStream(t, svc, "subAlice")
	if again := realitySpiderXFromStream(t, svc, "subAlice"); again != alice {
		t.Fatalf("spiderX not stable for the same client: %q vs %q", alice, again)
	}
	if bob := realitySpiderXFromStream(t, svc, "subBob"); bob == alice {
		t.Fatalf("spiderX identical across clients (fingerprintable): %q", alice)
	}
}

// streamData must tolerate malformed stored inbounds: unparseable stream JSON
// (with a finalMask configured, which writes into the map) and tls/reality
// security whose settings key is missing or null previously panicked the
// subscription request.
func TestSubJsonServiceStreamDataMalformedInputs(t *testing.T) {
	withMask := NewSubJsonService("", "", `{"tcp":[{"type":"fragment"}]}`, nil)
	stream := withMask.streamData("not-json", "clientKey")
	if _, ok := stream["finalmask"]; !ok {
		t.Fatal("finalMask must still apply when stream settings fail to parse")
	}

	svc := NewSubJsonService("", "", "", nil)
	noReality := svc.streamData(`{"network":"tcp","security":"reality"}`, "clientKey")
	if v, ok := noReality["realitySettings"]; ok {
		t.Fatalf("missing realitySettings must stay absent, got %v", v)
	}
	nullTls := svc.streamData(`{"network":"tcp","security":"tls","tlsSettings":null}`, "")
	if v, ok := nullTls["tlsSettings"]; ok {
		t.Fatalf("null tlsSettings must be dropped, got %v", v)
	}
}

func TestSubJsonServiceRealityDataSpiderXFallsBackWhenNoClientKey(t *testing.T) {
	svc := NewSubJsonService("", "", "", nil)

	stream := svc.streamData(`{
		"network":"tcp","security":"reality","tcpSettings":{"header":{"type":"none"}},
		"realitySettings":{
			"serverNames":["reality.example.com"],
			"shortIds":["ab12cd"],
			"settings":{"publicKey":"PBKvalue","fingerprint":"firefox"}
		}
	}`, "")

	rlty, _ := stream["realitySettings"].(map[string]any)
	if rlty == nil {
		t.Fatal("streamData dropped realitySettings")
	}
	spx, _ := rlty["spiderX"].(string)
	if len(spx) != 16 || spx[0] != '/' {
		t.Fatalf("spiderX fallback = %q, want random 16-char /-prefixed value", spx)
	}
}

func TestSubJsonServiceWireguard(t *testing.T) {
	serverPriv, serverPub, err := wgutil.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	clientPriv, _, err := wgutil.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}

	inbound := &model.Inbound{
		Listen:   "203.0.113.9",
		Port:     51820,
		Protocol: model.WireGuard,
		Settings: `{"secretKey":"` + serverPriv + `","mtu":1420}`,
	}
	client := model.Client{
		Email:        "user",
		PrivateKey:   clientPriv,
		PreSharedKey: "psk-value",
		KeepAlive:    25,
		AllowedIPs:   []string{"10.0.0.2/32", "fd00::2/128"},
	}

	raw := NewSubJsonService("", "", "", nil).genWireguard(inbound, client)
	if raw == nil {
		t.Fatal("genWireguard returned nil for a valid wireguard client")
	}
	settings := outboundSettings(t, raw)

	if settings["secretKey"] != clientPriv {
		t.Fatalf("secretKey = %v, want client private key", settings["secretKey"])
	}
	address, _ := settings["address"].([]any)
	if len(address) != 2 || address[0] != "10.0.0.2/32" || address[1] != "fd00::2/128" {
		t.Fatalf("address = %v, want client tunnel addresses", settings["address"])
	}
	if settings["mtu"] != float64(1420) {
		t.Fatalf("mtu = %v, want 1420", settings["mtu"])
	}

	peers, _ := settings["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("peers len = %d, want 1", len(peers))
	}
	peer, _ := peers[0].(map[string]any)
	if peer["publicKey"] != serverPub {
		t.Fatalf("peer publicKey = %v, want %v (derived from inbound secretKey)", peer["publicKey"], serverPub)
	}
	if peer["endpoint"] != "203.0.113.9:51820" {
		t.Fatalf("peer endpoint = %v, want 203.0.113.9:51820", peer["endpoint"])
	}
	if peer["preSharedKey"] != "psk-value" {
		t.Fatalf("peer preSharedKey = %v, want psk-value", peer["preSharedKey"])
	}
	if peer["keepAlive"] != float64(25) {
		t.Fatalf("peer keepAlive = %v, want 25", peer["keepAlive"])
	}
	allowed, _ := peer["allowedIPs"].([]any)
	if !reflect.DeepEqual(allowed, []any{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("peer allowedIPs = %v, want full tunnel", peer["allowedIPs"])
	}
}

func TestSubJsonServiceWireguardNoKey(t *testing.T) {
	inbound := &model.Inbound{Listen: "203.0.113.9", Port: 51820, Protocol: model.WireGuard, Settings: `{}`}
	client := model.Client{Email: "user"}

	if raw := NewSubJsonService("", "", "", nil).genWireguard(inbound, client); raw != nil {
		t.Fatalf("genWireguard = %s, want nil for a keyless wireguard client", raw)
	}
}

func modernProfileJSONOutbound(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal JSON subscription: %v", err)
	}
	outbounds, _ := config["outbounds"].([]any)
	if len(outbounds) == 0 {
		t.Fatalf("JSON subscription has no outbounds: %#v", config)
	}
	outbound, _ := outbounds[0].(map[string]any)
	if outbound == nil {
		t.Fatalf("first outbound has invalid shape: %#v", outbounds[0])
	}
	return outbound
}

func TestSubJsonServiceModernProfileProduction(t *testing.T) {
	t.Run("TLS", func(t *testing.T) {
		subReq := &SubService{}
		inbound := &model.Inbound{
			Listen:   "0.0.0.0",
			Port:     27543,
			Protocol: model.VLESS,
			Remark:   "modern-json-tls",
			Settings: `{"encryption":"none"}`,
			StreamSettings: `{
				"network":"tcp",
				"security":"none",
				"tcpSettings":{"header":{"type":"none"}},
				"externalProxy":[
					{
						"enabled":false,
						"network":"ws",
						"security":"tls",
						"dest":"disabled.example.com",
						"port":443
					},
					{
						"enabled":true,
						"remark":"modern-ws-tls",
						"dest":"cdn.example.com",
						"port":8443,
						"network":"ws",
						"security":"tls",
						"wsSettings":{
							"path":"/modern",
							"host":"origin.example.com",
							"headers":{"Host":"origin.example.com"}
						},
						"tlsSettings":{
							"serverName":"sni.example.com",
							"alpn":["h2"],
							"settings":{
								"fingerprint":"chrome",
								"allowInsecure":true
							}
						},
						"sockopt":{
							"tcpFastOpen":true,
							"domainStrategy":"UseIP",
							"acceptProxyProtocol":true,
							"V6Only":true,
							"trustedXForwardedFor":["127.0.0.1"]
						},
						"mux":{
							"enabled":true,
							"concurrency":4
						},
						"finalmask":{
							"tcp":[{"type":"sudoku"}]
						}
					}
				]
			}`,
		}
		client := model.Client{
			ID:    "11111111-2222-4333-8444-555555555555",
			Email: "modern-json-user",
		}

		configs := NewSubJsonService("", "", "", subReq).getConfig(
			subReq,
			inbound,
			client,
			"panel.example.com",
		)
		if len(configs) != 1 {
			t.Fatalf("len(configs) = %d, want 1 active profile", len(configs))
		}

		outbound := modernProfileJSONOutbound(t, configs[0])
		settings, _ := outbound["settings"].(map[string]any)
		if settings["address"] != "cdn.example.com" || settings["port"] != float64(8443) {
			t.Fatalf("endpoint settings = %#v", settings)
		}

		stream, _ := outbound["streamSettings"].(map[string]any)
		if stream["network"] != "ws" || stream["security"] != "tls" {
			t.Fatalf("effective stream = %#v", stream)
		}
		ws, _ := stream["wsSettings"].(map[string]any)
		if ws["path"] != "/modern" || ws["host"] != "origin.example.com" {
			t.Fatalf("wsSettings = %#v", ws)
		}
		tlsSettings, _ := stream["tlsSettings"].(map[string]any)
		if tlsSettings["serverName"] != "sni.example.com" {
			t.Fatalf("serverName = %v", tlsSettings["serverName"])
		}
		if tlsSettings["fingerprint"] != "chrome" {
			t.Fatalf("fingerprint = %v", tlsSettings["fingerprint"])
		}
		if tlsSettings["allowInsecure"] != true {
			t.Fatalf("allowInsecure = %v", tlsSettings["allowInsecure"])
		}

		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt["tcpFastOpen"] != true || sockopt["domainStrategy"] != "UseIP" {
			t.Fatalf("sockopt = %#v", sockopt)
		}
		for _, key := range []string{
			"acceptProxyProtocol",
			"V6Only",
			"trustedXForwardedFor",
		} {
			if _, exists := sockopt[key]; exists {
				t.Fatalf("listener-only sockopt key leaked: %s", key)
			}
		}

		finalmask, _ := stream["finalmask"].(map[string]any)
		tcpMasks, _ := finalmask["tcp"].([]any)
		if len(tcpMasks) != 1 {
			t.Fatalf("finalmask.tcp = %#v", finalmask["tcp"])
		}

		mux, _ := outbound["mux"].(map[string]any)
		if mux["enabled"] != true || mux["concurrency"] != float64(4) {
			t.Fatalf("mux = %#v", outbound["mux"])
		}
	})

	t.Run("Reality", func(t *testing.T) {
		subReq := &SubService{}
		inbound := &model.Inbound{
			Listen:   "0.0.0.0",
			Port:     27543,
			Protocol: model.VLESS,
			Remark:   "modern-json-reality",
			Settings: `{"encryption":"none"}`,
			StreamSettings: `{
				"network":"tcp",
				"security":"none",
				"tcpSettings":{"header":{"type":"none"}},
				"externalProxy":[
					{
						"enabled":true,
						"remark":"modern-reality",
						"dest":"reality-edge.example.com",
						"port":443,
						"network":"tcp",
						"security":"reality",
						"tcpSettings":{"header":{"type":"none"}},
						"realitySettings":{
							"serverNames":["reality-sni.example.com"],
							"shortIds":["ab12cd"],
							"settings":{
								"publicKey":"PROFILE_PUBLIC_KEY",
								"fingerprint":"firefox"
							}
						}
					}
				]
			}`,
		}
		client := model.Client{
			ID:    "11111111-2222-4333-8444-555555555555",
			Email: "modern-reality-user",
		}

		configs := NewSubJsonService("", "", "", subReq).getConfig(
			subReq,
			inbound,
			client,
			"panel.example.com",
		)
		if len(configs) != 1 {
			t.Fatalf("len(configs) = %d, want 1", len(configs))
		}

		outbound := modernProfileJSONOutbound(t, configs[0])
		settings, _ := outbound["settings"].(map[string]any)
		if settings["address"] != "reality-edge.example.com" || settings["port"] != float64(443) {
			t.Fatalf("endpoint settings = %#v", settings)
		}
		stream, _ := outbound["streamSettings"].(map[string]any)
		if stream["security"] != "reality" {
			t.Fatalf("security = %v", stream["security"])
		}
		realitySettings, _ := stream["realitySettings"].(map[string]any)
		if realitySettings["serverName"] != "reality-sni.example.com" {
			t.Fatalf("serverName = %v", realitySettings["serverName"])
		}
		if realitySettings["shortId"] != "ab12cd" {
			t.Fatalf("shortId = %v", realitySettings["shortId"])
		}
		if realitySettings["publicKey"] != "PROFILE_PUBLIC_KEY" {
			t.Fatalf("publicKey = %v", realitySettings["publicKey"])
		}
	})

	t.Run("Hysteria", func(t *testing.T) {
		subReq := &SubService{}
		inbound := &model.Inbound{
			Listen:   "0.0.0.0",
			Port:     27543,
			Protocol: model.Hysteria,
			Remark:   "modern-json-hysteria",
			Settings: `{"version":2}`,
			StreamSettings: `{
				"network":"hysteria",
				"security":"tls",
				"tlsSettings":{
					"serverName":"base-sni.example.com",
					"settings":{"fingerprint":"firefox","allowInsecure":false}
				},
				"hysteriaSettings":{
					"udpIdleTimeout":30,
					"masquerade":{"type":"proxy","url":"https://base.example.com"}
				},
				"externalProxy":[
					{
						"enabled":true,
						"remark":"modern-hysteria",
						"dest":"hy-edge.example.com",
						"port":2443,
						"network":"hysteria",
						"security":"tls",
						"tlsSettings":{
							"serverName":"profile-sni.example.com",
							"alpn":["h3"],
							"settings":{"fingerprint":"chrome","allowInsecure":true}
						},
						"hysteriaSettings":{
							"udpIdleTimeout":99,
							"masquerade":{"type":"proxy","url":"https://profile.example.com"}
						}
					}
				]
			}`,
		}
		client := model.Client{
			Email: "modern-hysteria-user",
			Auth:  "profile-auth",
		}

		configs := NewSubJsonService("", "", "", subReq).getConfig(
			subReq,
			inbound,
			client,
			"panel.example.com",
		)
		if len(configs) != 1 {
			t.Fatalf("len(configs) = %d, want 1", len(configs))
		}

		outbound := modernProfileJSONOutbound(t, configs[0])
		settings, _ := outbound["settings"].(map[string]any)
		if settings["address"] != "hy-edge.example.com" || settings["port"] != float64(2443) {
			t.Fatalf("endpoint settings = %#v", settings)
		}
		stream, _ := outbound["streamSettings"].(map[string]any)
		tlsSettings, _ := stream["tlsSettings"].(map[string]any)
		if tlsSettings["serverName"] != "profile-sni.example.com" {
			t.Fatalf("serverName = %v", tlsSettings["serverName"])
		}
		if tlsSettings["fingerprint"] != "chrome" {
			t.Fatalf("fingerprint = %v", tlsSettings["fingerprint"])
		}
		if tlsSettings["allowInsecure"] != true {
			t.Fatalf("allowInsecure = %v", tlsSettings["allowInsecure"])
		}
		hysteriaSettings, _ := stream["hysteriaSettings"].(map[string]any)
		if hysteriaSettings["auth"] != "profile-auth" {
			t.Fatalf("auth = %v", hysteriaSettings["auth"])
		}
		if hysteriaSettings["udpIdleTimeout"] != float64(99) {
			t.Fatalf("udpIdleTimeout = %v", hysteriaSettings["udpIdleTimeout"])
		}
		masquerade, _ := hysteriaSettings["masquerade"].(map[string]any)
		if masquerade["url"] != "https://profile.example.com" {
			t.Fatalf("masquerade = %#v", masquerade)
		}
	})
}
