package service

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/profilefinalmask"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/profilevalidation"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xhttpprofile"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

const runtimeProfileTagPrefix = "hm-profile-"

var runtimeProfileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type runtimeProfileSpec struct {
	ID      string
	Flow    *string
	TLS     map[string]any
	Reality map[string]any
	Sockopt map[string]any
	Source  map[string]any
}

type runtimeSocketBinding struct {
	Tag       string
	Listen    string
	Port      int
	Transport string
	Synthetic bool
}

// compileRuntimeProfileInbounds projects active runtime-marked structured
// subscription profiles into the topology automatically. The parent inbound remains the
// logical owner of protocol, clients, limits and statistics; synthetic
// listeners reuse the parent's already-normalized Settings payload, including
// hmstat_* runtime client identities. Markerless legacy/structured entries remain
// subscription-only and disabled profiles remain inert drafts.
func compileRuntimeProfileInbounds(parent *model.Inbound, rawParentStream map[string]any) ([]xray.InboundConfig, error) {
	topology, err := compileRuntimeProfileTopology(parent, rawParentStream, nil)
	if err != nil {
		return nil, err
	}
	return topology.Synthetic, nil
}

var automaticRuntimeTopologyFields = [...]string{"enabled", "mode", "listen", "port"}

// normalizeAutomaticRuntimeProfiles clones stream and materializes the hidden,
// stable runtime.id metadata for every active modern profile. Former topology
// controls are removed: listener enablement, mode, listen and port are derived
// exclusively from the profile plus its logical parent.
func normalizeAutomaticRuntimeProfiles(stream map[string]any) (map[string]any, bool, error) {
	normalized, err := cloneMap(stream)
	if err != nil {
		return nil, false, err
	}
	changed, err := normalizeAutomaticRuntimeProfilesInPlace(normalized)
	if err != nil {
		return nil, false, err
	}
	return normalized, changed, nil
}

func normalizeAutomaticRuntimeProfilesInPlace(normalized map[string]any) (bool, error) {
	entries, _ := normalized["externalProxy"].([]any)
	if len(entries) == 0 {
		return false, nil
	}

	type candidate struct {
		index   int
		profile map[string]any
		runtime map[string]any
		id      string
	}
	candidates := make([]candidate, 0, len(entries))
	usedIDs := make(map[string]int)

	// Reserve explicit IDs first so generated IDs never collide with operator or
	// older UI metadata that appears later in the profile list.
	for index, raw := range entries {
		profile, ok := raw.(map[string]any)
		if !ok || !automaticRuntimeProfileActive(profile) {
			continue
		}
		runtimeMetadata := map[string]any(nil)
		if value, exists := profile["runtime"]; exists && value != nil {
			runtimeMetadata, ok = value.(map[string]any)
			if !ok {
				return false, fmt.Errorf("profile %d: runtime must be an object", index+1)
			}
		}
		id := ""
		if runtimeMetadata != nil {
			if value, exists := runtimeMetadata["id"]; exists && value != nil {
				text, ok := value.(string)
				if !ok {
					return false, fmt.Errorf("profile %d: runtime.id must be a string", index+1)
				}
				id = strings.TrimSpace(text)
				if id != "" && !runtimeProfileIDPattern.MatchString(id) {
					return false, fmt.Errorf("profile %d: runtime.id must match %s", index+1, runtimeProfileIDPattern.String())
				}
			}
		}
		if id != "" {
			if previous, exists := usedIDs[id]; exists {
				return false, fmt.Errorf("profile %d: runtime.id %q duplicates runtime.id used by profile %d", index+1, id, previous+1)
			}
			usedIDs[id] = index
		}
		candidates = append(candidates, candidate{index: index, profile: profile, runtime: runtimeMetadata, id: id})
	}

	changed := false
	for _, item := range candidates {
		runtimeMetadata := item.runtime
		if runtimeMetadata == nil {
			runtimeMetadata = map[string]any{}
			item.profile["runtime"] = runtimeMetadata
			changed = true
		}
		id := item.id
		if id == "" {
			base := fmt.Sprintf("auto-profile-%d", item.index+1)
			id = base
			for suffix := 2; ; suffix++ {
				if _, exists := usedIDs[id]; !exists {
					break
				}
				id = fmt.Sprintf("%s-%d", base, suffix)
			}
			runtimeMetadata["id"] = id
			usedIDs[id] = item.index
			changed = true
		} else if stored, _ := runtimeMetadata["id"].(string); stored != id {
			runtimeMetadata["id"] = id
			changed = true
		}
		for _, key := range automaticRuntimeTopologyFields {
			if _, exists := runtimeMetadata[key]; exists {
				delete(runtimeMetadata, key)
				changed = true
			}
		}
	}
	return changed, nil
}

func automaticRuntimeProfileActive(profile map[string]any) bool {
	if enabled, present := profile["enabled"]; present {
		value, ok := enabled.(bool)
		if !ok || !value {
			return false
		}
	}
	return profilevalidation.IsModernProfile(profile) &&
		profilevalidation.HasRuntimeMarker(profile)
}

func parseRuntimeProfileSpec(profile map[string]any) (runtimeProfileSpec, error) {
	raw, ok := profile["runtime"].(map[string]any)
	if !ok {
		return runtimeProfileSpec{}, fmt.Errorf("automatic runtime metadata is missing")
	}
	id, ok := raw["id"].(string)
	if !ok {
		return runtimeProfileSpec{}, fmt.Errorf("runtime.id must be a string")
	}
	id = strings.TrimSpace(id)
	if !runtimeProfileIDPattern.MatchString(id) {
		return runtimeProfileSpec{}, fmt.Errorf("runtime.id must match %s", runtimeProfileIDPattern.String())
	}

	var flow *string
	flowValue, flowExists := profile["flow"]
	flowField := "flow"
	if !flowExists {
		// Phase-1 preview builds stored the override below runtime. Keep that
		// shape readable while all newly saved profiles use the shared top-level
		// field consumed by runtime and subscription generation alike.
		flowValue, flowExists = raw["flow"]
		flowField = "runtime.flow"
	}
	if flowExists {
		text, ok := flowValue.(string)
		if !ok {
			return runtimeProfileSpec{}, fmt.Errorf("%s must be a string", flowField)
		}
		if strings.ContainsAny(text, "\r\n\x00") {
			return runtimeProfileSpec{}, fmt.Errorf("%s contains invalid control characters", flowField)
		}
		flow = &text
	}

	return runtimeProfileSpec{
		ID:      id,
		Flow:    flow,
		TLS:     mapValue(raw["tlsSettings"]),
		Reality: mapValue(raw["realitySettings"]),
		Sockopt: mapValue(raw["sockopt"]),
		Source:  profile,
	}, nil
}

func buildRuntimeProfileStream(base map[string]any, spec runtimeProfileSpec) (map[string]any, error) {
	stream, err := cloneMap(base)
	if err != nil {
		return nil, err
	}
	profile := spec.Source

	baseNetwork := runtimeNetwork(stream)
	network, _ := profile["network"].(string)
	if network == "" || network == "same" {
		network = baseNetwork
	}
	if network == "" {
		network = "tcp"
	}
	if network != baseNetwork {
		for _, key := range runtimeTransportKeys() {
			delete(stream, key)
		}
		stream["network"] = network
	}
	transportKey := runtimeTransportKey(network)
	if transportKey == "" {
		return nil, fmt.Errorf("unsupported runtime transport %q", network)
	}
	if value, ok := profile[transportKey].(map[string]any); ok {
		cloned, err := cloneMap(value)
		if err != nil {
			return nil, err
		}
		if network == "xhttp" {
			cloned = xhttpprofile.NormalizeRuntimeSettings(cloned)
		}
		stream[transportKey] = cloned
	} else if _, exists := stream[transportKey]; !exists {
		stream[transportKey] = map[string]any{}
	}

	security, _ := profile["security"].(string)
	if security == "" || security == "same" {
		security, _ = profile["forceTls"].(string)
	}
	if security == "" || security == "same" {
		security, _ = stream["security"].(string)
	}
	if security == "" {
		security = "none"
	}

	switch security {
	case "none":
		stream["security"] = "none"
		delete(stream, "tlsSettings")
		delete(stream, "realitySettings")
	case "tls":
		stream["security"] = "tls"
		delete(stream, "realitySettings")
		if spec.TLS != nil {
			tls, err := cloneMap(spec.TLS)
			if err != nil {
				return nil, err
			}
			delete(tls, "settings")
			stream["tlsSettings"] = tls
		} else if baseSecurity, _ := base["security"].(string); baseSecurity != "tls" {
			return nil, fmt.Errorf("TLS runtime profile requires runtime.tlsSettings with server certificate/key settings")
		}
	case "reality":
		stream["security"] = "reality"
		delete(stream, "tlsSettings")
		if spec.Reality != nil {
			reality, err := cloneMap(spec.Reality)
			if err != nil {
				return nil, err
			}
			delete(reality, "settings")
			stream["realitySettings"] = reality
		} else if baseSecurity, _ := base["security"].(string); baseSecurity != "reality" {
			return nil, fmt.Errorf("REALITY runtime profile requires runtime.realitySettings with server private settings")
		}
	default:
		return nil, fmt.Errorf("unsupported runtime security %q", security)
	}

	if spec.Sockopt != nil {
		sockopt, err := cloneMap(spec.Sockopt)
		if err != nil {
			return nil, err
		}
		stream["sockopt"] = sockopt
	}

	// FinalMask follows transport ownership. "same" profiles inherit the
	// parent; an explicit transport detaches from the parent wrapper. Explicit
	// mKCP without a profile mask receives mkcp-legacy, matching subscription
	// output and the pinned core's compatibility wire format.
	if err := profilefinalmask.Apply(stream, profile, network); err != nil {
		return nil, err
	}
	if len(finalMaskRealityTcpMasks(stream)) > 0 {
		return nil, fmt.Errorf("finalmask.tcp is not supported with REALITY security")
	}
	prepareRuntimeStream(stream)
	if err := validateRuntimeServerSecurity(stream); err != nil {
		return nil, err
	}
	return stream, nil
}

func validateRuntimeServerSecurity(stream map[string]any) error {
	security, _ := stream["security"].(string)
	switch security {
	case "", "none":
		return nil
	case "tls":
		tls, ok := stream["tlsSettings"].(map[string]any)
		if !ok || tls == nil {
			return fmt.Errorf("TLS runtime profile is missing server tlsSettings")
		}
		certificates, ok := tls["certificates"].([]any)
		if !ok || len(certificates) == 0 {
			return fmt.Errorf("TLS runtime profile requires at least one server certificate")
		}
		for index, raw := range certificates {
			certificate, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("TLS runtime certificate %d must be an object", index+1)
			}
			certificateFile, _ := certificate["certificateFile"].(string)
			keyFile, _ := certificate["keyFile"].(string)
			inlineCertificate, _ := certificate["certificate"].([]any)
			inlineKey, _ := certificate["key"].([]any)
			fileBacked := strings.TrimSpace(certificateFile) != "" && strings.TrimSpace(keyFile) != ""
			inline := len(inlineCertificate) > 0 && len(inlineKey) > 0
			if !fileBacked && !inline {
				return fmt.Errorf("TLS runtime certificate %d requires certificateFile/keyFile or inline certificate/key", index+1)
			}
		}
		return nil
	case "reality":
		reality, ok := stream["realitySettings"].(map[string]any)
		if !ok || reality == nil {
			return fmt.Errorf("REALITY runtime profile is missing server realitySettings")
		}
		target, _ := reality["target"].(string)
		if strings.TrimSpace(target) == "" {
			target, _ = reality["dest"].(string)
		}
		privateKey, _ := reality["privateKey"].(string)
		serverNames, _ := reality["serverNames"].([]any)
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("REALITY runtime profile requires a server target")
		}
		if strings.TrimSpace(privateKey) == "" {
			return fmt.Errorf("REALITY runtime profile requires a server privateKey")
		}
		if len(serverNames) == 0 {
			return fmt.Errorf("REALITY runtime profile requires at least one serverName")
		}
		return nil
	default:
		return fmt.Errorf("unsupported runtime security %q", security)
	}
}

func prepareRuntimeStream(stream map[string]any) {
	delete(stream, "externalProxy")
	normalizeHTTPUpgradeRuntimeHeaders(stream)
	stripRuntimeClientSecuritySettings(stream)
	liftXhttpSessionIDKeys(stream)
	if len(finalMaskRealityTcpMasks(stream)) > 0 {
		delete(stream, "finalmask")
	}
}

// normalizeHTTPUpgradeRuntimeHeaders rewrites the legacy/client-facing Host
// header shape into the server-side shape required by the pinned Xray core.
// Xray v26.6.22 rejects any case variant of Host inside
// httpupgradeSettings.headers; the same value belongs in the independent host
// field. Keep persisted/subscription data untouched and normalize only the
// generated runtime config. An explicit host field wins over legacy headers.
func normalizeHTTPUpgradeRuntimeHeaders(stream map[string]any) bool {
	if runtimeNetwork(stream) != "httpupgrade" {
		return false
	}
	settings, ok := stream["httpupgradeSettings"].(map[string]any)
	if !ok || settings == nil {
		return false
	}
	headers, ok := settings["headers"].(map[string]any)
	if !ok || headers == nil {
		return false
	}

	hostKeys := make([]string, 0, 1)
	for key := range headers {
		if strings.EqualFold(strings.TrimSpace(key), "host") {
			hostKeys = append(hostKeys, key)
		}
	}
	if len(hostKeys) == 0 {
		return false
	}
	sort.Strings(hostKeys)

	explicitHost, _ := settings["host"].(string)
	if strings.TrimSpace(explicitHost) == "" {
		for _, key := range hostKeys {
			legacyHost, ok := headers[key].(string)
			if ok && strings.TrimSpace(legacyHost) != "" {
				settings["host"] = legacyHost
				break
			}
		}
	}
	for _, key := range hostKeys {
		delete(headers, key)
	}
	return true
}

func normalizeRuntimeProfileFlow(flow string) (string, error) {
	switch flow {
	case "":
		return "", nil
	case "xtls-rprx-vision":
		return flow, nil
	case "xtls-rprx-vision-udp443":
		// The panel accepts this client-facing alias but the current core uses
		// the canonical Vision flow on the server side.
		return "xtls-rprx-vision", nil
	default:
		return "", fmt.Errorf("unsupported flow %q", flow)
	}
}

func overrideRuntimeClientFlow(settingsJSON, flow string) (string, error) {
	var settings map[string]any
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		return "", err
	}
	clients, ok := settings["clients"].([]any)
	if !ok {
		return settingsJSON, nil
	}
	for index, raw := range clients {
		client, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if flow == "" {
			delete(client, "flow")
		} else {
			client["flow"] = flow
		}
		clients[index] = client
	}
	settings["clients"] = clients
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func stripRuntimeClientSecuritySettings(stream map[string]any) {
	if tls, ok := stream["tlsSettings"].(map[string]any); ok {
		delete(tls, "settings")
	}
	if reality, ok := stream["realitySettings"].(map[string]any); ok {
		delete(reality, "settings")
	}
}

func validateRuntimeProfileBindings(config *xray.Config) error {
	if config == nil {
		return nil
	}
	seenTags := make(map[string]runtimeSocketBinding, len(config.InboundConfigs))
	bindings := make([]runtimeSocketBinding, 0, len(config.InboundConfigs))

	for index := range config.InboundConfigs {
		inbound := &config.InboundConfigs[index]
		binding, err := runtimeBindingFromInboundConfig(inbound)
		if err != nil {
			if strings.HasPrefix(inbound.Tag, runtimeProfileTagPrefix) {
				return fmt.Errorf("runtime profile %q: %w", inbound.Tag, err)
			}
			continue
		}
		binding.Synthetic = strings.HasPrefix(inbound.Tag, runtimeProfileTagPrefix)

		if previous, exists := seenTags[inbound.Tag]; exists && (binding.Synthetic || previous.Synthetic) {
			return fmt.Errorf("runtime profile tag %q is duplicated", inbound.Tag)
		}
		seenTags[inbound.Tag] = binding

		for _, previous := range bindings {
			if !(binding.Synthetic || previous.Synthetic) || !runtimeBindingsConflict(previous, binding) {
				continue
			}
			return fmt.Errorf("runtime profile socket %s conflicts with inbound %q", runtimeBindingLabel(binding), previous.Tag)
		}
		bindings = append(bindings, binding)
	}
	return nil
}

func runtimeBindingFromInboundConfig(inbound *xray.InboundConfig) (runtimeSocketBinding, error) {
	listen := ""
	if len(inbound.Listen) > 0 {
		if err := json.Unmarshal(inbound.Listen, &listen); err != nil {
			return runtimeSocketBinding{}, fmt.Errorf("invalid listen address: %w", err)
		}
	}
	normalized, err := normalizeRuntimeListen(listen, false)
	if err != nil {
		return runtimeSocketBinding{}, err
	}
	stream := map[string]any{}
	if len(inbound.StreamSettings) > 0 {
		if err := json.Unmarshal(inbound.StreamSettings, &stream); err != nil {
			return runtimeSocketBinding{}, fmt.Errorf("invalid stream settings: %w", err)
		}
	}
	return runtimeSocketBinding{
		Tag:       inbound.Tag,
		Listen:    normalized,
		Port:      inbound.Port,
		Transport: runtimeTransportFamily(runtimeNetwork(stream)),
	}, nil
}

func runtimeBindingsConflict(left, right runtimeSocketBinding) bool {
	if left.Port != right.Port || left.Transport != right.Transport {
		return false
	}
	return runtimeListenOverlaps(left.Listen, right.Listen)
}

func runtimeListenOverlaps(left, right string) bool {
	leftIP := net.ParseIP(strings.Trim(left, "[]"))
	rightIP := net.ParseIP(strings.Trim(right, "[]"))
	if leftIP == nil || rightIP == nil {
		return left == right
	}
	if leftIP.IsUnspecified() || rightIP.IsUnspecified() {
		// Conservative by design: an IPv6 wildcard may also own IPv4 depending
		// on the host's v6-only socket setting. Reject ambiguity before Xray does.
		return true
	}
	return leftIP.Equal(rightIP)
}

func runtimeBindingLabel(binding runtimeSocketBinding) string {
	listen := binding.Listen
	if strings.Contains(listen, ":") && !strings.HasPrefix(listen, "[") {
		listen = "[" + listen + "]"
	}
	return fmt.Sprintf("%s/%s:%d", binding.Transport, listen, binding.Port)
}

func runtimeStreamsEquivalent(left, right map[string]any) bool {
	return reflect.DeepEqual(left, right)
}

func jsonDocumentsEquivalent(left, right string) bool {
	var leftValue any
	var rightValue any
	if json.Unmarshal([]byte(left), &leftValue) != nil || json.Unmarshal([]byte(right), &rightValue) != nil {
		return left == right
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func runtimeProfileTag(parentID int, profileID string) string {
	return fmt.Sprintf("%s%d-%s", runtimeProfileTagPrefix, parentID, profileID)
}

func normalizeRuntimeListen(listen string, strict bool) (string, error) {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return "0.0.0.0", nil
	}
	candidate := strings.TrimPrefix(strings.TrimSuffix(listen, "]"), "[")
	ip := net.ParseIP(candidate)
	if ip == nil {
		if strict {
			return "", fmt.Errorf("runtime.listen must be an IP literal; use dest for a public hostname")
		}
		return listen, nil
	}
	return ip.String(), nil
}

func resolveRuntimeProfilePort(profile map[string]any, fallback int) (int, error) {
	port := fallback
	if value, exists := profile["port"]; exists {
		parsed, present, err := strictJSONInt(value)
		if err != nil {
			return 0, fmt.Errorf("profile port: %w", err)
		}
		if present {
			port = parsed
		}
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("runtime port %d is outside 1..65535", port)
	}
	return port, nil
}

func strictJSONInt(value any) (int, bool, error) {
	if value == nil {
		return 0, false, nil
	}
	var number int64
	switch typed := value.(type) {
	case int:
		return typed, true, nil
	case int32:
		return int(typed), true, nil
	case int64:
		number = typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed {
			return 0, false, fmt.Errorf("must be an integer")
		}
		if typed > float64(1<<31-1) || typed < float64(-1<<31) {
			return 0, false, fmt.Errorf("is outside integer range")
		}
		number = int64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false, fmt.Errorf("must be an integer")
		}
		number = parsed
	default:
		return 0, false, fmt.Errorf("must be a JSON number")
	}
	converted := int(number)
	if int64(converted) != number {
		return 0, false, fmt.Errorf("is outside platform integer range")
	}
	return converted, true, nil
}

func mapValue(value any) map[string]any {
	mapped, _ := value.(map[string]any)
	return mapped
}

func cloneMap(source map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	var cloned map[string]any
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return nil, err
	}
	return cloned, nil
}

func runtimeProfileProtocolSupported(protocol model.Protocol) bool {
	switch protocol {
	case model.VLESS, model.VMESS, model.Trojan, model.Shadowsocks, model.Hysteria:
		return true
	default:
		return false
	}
}

func runtimeNetwork(stream map[string]any) string {
	network, _ := stream["network"].(string)
	if network == "" {
		return "tcp"
	}
	return network
}

func runtimeTransportFamily(network string) string {
	if network == "kcp" || network == "hysteria" {
		return "udp"
	}
	return "tcp"
}

func runtimeTransportKeys() []string {
	return []string{"tcpSettings", "kcpSettings", "wsSettings", "grpcSettings", "httpupgradeSettings", "xhttpSettings", "hysteriaSettings"}
}

func runtimeTransportKey(network string) string {
	switch network {
	case "tcp":
		return "tcpSettings"
	case "kcp":
		return "kcpSettings"
	case "ws":
		return "wsSettings"
	case "grpc":
		return "grpcSettings"
	case "httpupgrade":
		return "httpupgradeSettings"
	case "xhttp":
		return "xhttpSettings"
	case "hysteria":
		return "hysteriaSettings"
	default:
		return ""
	}
}
