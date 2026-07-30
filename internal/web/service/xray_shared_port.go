package service

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/frontmux"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/profilevalidation"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

const (
	sharedPortClassificationMS   = 3000
	sharedPortMaxInspectBytes    = 64 * 1024
	sharedPortMaxConcurrentConns = 2 * 1024
	sharedPortTagPrefix          = "hm-frontmux-"
)

type runtimeProfileTopology struct {
	Parent         xray.InboundConfig
	Synthetic      []xray.InboundConfig
	PublicBindings []runtimeSocketBinding
	SharedPlan     frontmux.Plan
}

type runtimeCompiledEndpoint struct {
	config        xray.InboundConfig
	publicBinding runtimeSocketBinding
	stream        map[string]any
	settings      string
	profile       map[string]any
	clientECH     bool
	position      int
	parent        bool
	suppressed    bool
}

type sharedBackendAllocator struct {
	usedSockets map[string]struct{}
	usedPorts   map[int]struct{}
}

func newSharedBackendAllocator(existing []xray.InboundConfig) *sharedBackendAllocator {
	allocator := &sharedBackendAllocator{
		usedSockets: make(map[string]struct{}, len(existing)),
		usedPorts:   make(map[int]struct{}, len(existing)),
	}
	for index := range existing {
		binding, err := runtimeBindingFromInboundConfig(&existing[index])
		if err != nil {
			continue
		}
		allocator.reserve(binding)
	}
	return allocator
}

func (a *sharedBackendAllocator) reserve(binding runtimeSocketBinding) {
	if a == nil {
		return
	}
	if a.usedSockets == nil {
		a.usedSockets = map[string]struct{}{}
	}
	if a.usedPorts == nil {
		a.usedPorts = map[int]struct{}{}
	}
	a.usedSockets[net.JoinHostPort(binding.Listen, fmt.Sprintf("%d", binding.Port))] = struct{}{}
	// Conservatively reserve the whole TCP port. A wildcard listener on any
	// address would overlap a loopback backend using that same port.
	if binding.Transport == "tcp" {
		a.usedPorts[binding.Port] = struct{}{}
	}
}

func (a *sharedBackendAllocator) allocate(tag string) (string, int, error) {
	if a == nil {
		a = &sharedBackendAllocator{}
	}
	if a.usedSockets == nil {
		a.usedSockets = map[string]struct{}{}
	}
	if a.usedPorts == nil {
		a.usedPorts = map[int]struct{}{}
	}

	seed := sha256.Sum256([]byte(tag))
	addressStart := binary.BigEndian.Uint32(seed[:4])
	portStart := int(binary.BigEndian.Uint16(seed[4:6]))
	const addressSlots = 64 * 256 * 254
	const portBase = 30000
	const portSlots = 30000 // 30000..59999; panel helper ports live above this.
	for offset := 0; offset < portSlots; offset++ {
		port := portBase + (portStart+offset)%portSlots
		if _, exists := a.usedPorts[port]; exists {
			continue
		}
		value := (addressStart + uint32(offset)) % addressSlots
		second := 64 + value/(256*254)
		remaining := value % (256 * 254)
		third := remaining / 254
		fourth := 1 + remaining%254
		listen := fmt.Sprintf("127.%d.%d.%d", second, third, fourth)
		key := net.JoinHostPort(listen, fmt.Sprintf("%d", port))
		if _, exists := a.usedSockets[key]; exists {
			continue
		}
		a.usedSockets[key] = struct{}{}
		a.usedPorts[port] = struct{}{}
		return listen, port, nil
	}
	return "", 0, fmt.Errorf("exhausted shared-port loopback backend port range")
}

// compileRuntimeProfileTopology compiles parent + runtime profile listeners as
// one atomic topology. Same TCP socket collisions inside one logical inbound are
// automatically converted into a frontmux public listener with private Xray
// loopback backends. UDP collisions remain rejected; TCP and UDP may use the
// same numeric port because the kernel treats them as separate sockets.
func compileRuntimeProfileTopology(
	parent *model.Inbound,
	rawParentStream map[string]any,
	allocator *sharedBackendAllocator,
) (runtimeProfileTopology, error) {
	if parent == nil {
		return runtimeProfileTopology{}, nil
	}
	if rawParentStream == nil {
		rawParentStream = map[string]any{}
	}
	normalizedStream, _, err := normalizeAutomaticRuntimeProfiles(rawParentStream)
	if err != nil {
		return runtimeProfileTopology{}, fmt.Errorf("normalize automatic runtime profiles: %w", err)
	}
	rawParentStream = normalizedStream
	if err := profilevalidation.ValidateStreamMap(rawParentStream, profilevalidation.Options{
		Protocol: string(parent.Protocol),
	}); err != nil {
		return runtimeProfileTopology{}, fmt.Errorf("subscription profile semantic validation failed: %w", err)
	}
	if strings.HasPrefix(strings.TrimSpace(parent.Tag), runtimeProfileTagPrefix) ||
		strings.HasPrefix(strings.TrimSpace(parent.Tag), sharedPortTagPrefix) {
		return runtimeProfileTopology{}, fmt.Errorf("inbound tag prefix %q and %q are reserved", runtimeProfileTagPrefix, sharedPortTagPrefix)
	}

	baseStream, err := cloneMap(rawParentStream)
	if err != nil {
		return runtimeProfileTopology{}, fmt.Errorf("clone parent stream settings: %w", err)
	}
	prepareRuntimeStream(baseStream)
	baseStreamJSON, err := json.MarshalIndent(baseStream, "", "  ")
	if err != nil {
		return runtimeProfileTopology{}, fmt.Errorf("marshal parent runtime stream: %w", err)
	}

	parentRuntime := *parent
	parentRuntime.StreamSettings = string(baseStreamJSON)
	parentConfig := *parentRuntime.GenXrayInboundConfig()
	parentListen, err := normalizeRuntimeListen(parent.Listen, false)
	if err != nil {
		return runtimeProfileTopology{}, fmt.Errorf("normalize parent listen address: %w", err)
	}

	entries, _ := rawParentStream["externalProxy"].([]any)
	var defaultProfile map[string]any
	if len(entries) > 0 {
		defaultProfile, _ = entries[0].(map[string]any)
	}

	endpoints := []runtimeCompiledEndpoint{{
		config: parentConfig,
		publicBinding: runtimeSocketBinding{
			Tag:       parent.Tag,
			Listen:    parentListen,
			Port:      parent.Port,
			Transport: runtimeTransportFamily(runtimeNetwork(baseStream)),
		},
		stream:    baseStream,
		settings:  parentRuntime.Settings,
		profile:   defaultProfile,
		clientECH: effectiveProfileUsesECH(rawParentStream, defaultProfile),
		position:  0,
		parent:    true,
	}}

	seenIDs := make(map[string]int)
	for index, raw := range entries {
		profile, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if enabledValue, present := profile["enabled"]; present {
			enabled, ok := enabledValue.(bool)
			if !ok {
				return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %d: enabled must be a boolean", parent.Id, index+1)
			}
			if !enabled {
				continue
			}
		}

		if !automaticRuntimeProfileActive(profile) {
			continue
		}
		spec, err := parseRuntimeProfileSpec(profile)
		if err != nil {
			return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %d: %w", parent.Id, index+1, err)
		}
		if !runtimeProfileProtocolSupported(parent.Protocol) {
			return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %q: protocol %q does not support runtime profiles", parent.Id, spec.ID, parent.Protocol)
		}
		if previous, exists := seenIDs[spec.ID]; exists {
			return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %q duplicates runtime.id used by profile %d", parent.Id, spec.ID, previous+1)
		}
		seenIDs[spec.ID] = index

		stream, err := buildRuntimeProfileStream(baseStream, spec)
		if err != nil {
			return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %q: %w", parent.Id, spec.ID, err)
		}
		listen := parentListen
		port, err := resolveRuntimeProfilePort(profile, parent.Port)
		if err != nil {
			return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %q: %w", parent.Id, spec.ID, err)
		}

		settings := parentRuntime.Settings
		if spec.Flow != nil {
			if parent.Protocol != model.VLESS {
				return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %q: flow is only valid for VLESS", parent.Id, spec.ID)
			}
			runtimeFlow, flowErr := normalizeRuntimeProfileFlow(*spec.Flow)
			if flowErr != nil {
				return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %q: %w", parent.Id, spec.ID, flowErr)
			}
			if runtimeFlow != "" {
				streamJSON, marshalErr := json.Marshal(stream)
				if marshalErr != nil {
					return runtimeProfileTopology{}, fmt.Errorf("marshal profile stream for flow validation: %w", marshalErr)
				}
				if !inboundCanEnableTlsFlow(string(parent.Protocol), string(streamJSON), parentRuntime.Settings) {
					return runtimeProfileTopology{}, fmt.Errorf("inbound %d profile %q: flow %q is incompatible with the effective transport/security", parent.Id, spec.ID, *spec.Flow)
				}
			}
			settings, err = overrideRuntimeClientFlow(settings, runtimeFlow)
			if err != nil {
				return runtimeProfileTopology{}, fmt.Errorf("override client flow: %w", err)
			}
		}

		binding := runtimeSocketBinding{
			Tag:       runtimeProfileTag(parent.Id, spec.ID),
			Listen:    listen,
			Port:      port,
			Transport: runtimeTransportFamily(runtimeNetwork(stream)),
			Synthetic: true,
		}
		if runtimeBindingsConflict(endpoints[0].publicBinding, binding) &&
			runtimeStreamsEquivalent(baseStream, stream) &&
			jsonDocumentsEquivalent(parentRuntime.Settings, settings) {
			// Subscription alias of the exact parent listener. It contributes no
			// second runtime endpoint and therefore no frontmux route.
			continue
		}

		streamJSON, err := json.MarshalIndent(stream, "", "  ")
		if err != nil {
			return runtimeProfileTopology{}, fmt.Errorf("marshal runtime stream: %w", err)
		}
		synthetic := parentRuntime
		synthetic.Listen = listen
		synthetic.Port = port
		synthetic.Tag = binding.Tag
		synthetic.Settings = settings
		synthetic.StreamSettings = string(streamJSON)

		endpoints = append(endpoints, runtimeCompiledEndpoint{
			config:        *synthetic.GenXrayInboundConfig(),
			publicBinding: binding,
			stream:        stream,
			settings:      settings,
			profile:       profile,
			clientECH:     effectiveProfileUsesECH(rawParentStream, profile),
			position:      index,
		})
	}

	if allocator == nil {
		allocator = newSharedBackendAllocator(nil)
	}
	return planRuntimeProfileEndpoints(parent, endpoints, allocator)
}

func canonicalUDPServerStream(
	parentStream map[string]any,
	endpoint runtimeCompiledEndpoint,
) (map[string]any, error) {
	stream, err := cloneMap(endpoint.stream)
	if err != nil {
		return nil, err
	}
	network := runtimeNetwork(stream)
	switch network {
	case "kcp":
		// Per-profile mKCP values are client-side tuning knobs. A same-port
		// runtime group owns one server transport policy. Reuse the parent
		// policy when the parent itself is mKCP; otherwise let the pinned core
		// apply its deterministic server defaults.
		if runtimeNetwork(parentStream) == "kcp" {
			if value, ok := parentStream["kcpSettings"].(map[string]any); ok {
				cloned, cloneErr := cloneMap(value)
				if cloneErr != nil {
					return nil, cloneErr
				}
				stream["kcpSettings"] = cloned
			} else {
				stream["kcpSettings"] = map[string]any{}
			}
		} else {
			stream["kcpSettings"] = map[string]any{
				"mtu":              1350,
				"tti":              50,
				"uplinkCapacity":   5,
				"downlinkCapacity": 20,
				"cwndMultiplier":   1,
				"maxSendingWindow": 2 * 1024 * 1024,
			}
		}
	case "hysteria":
		// Hysteria profile transport values are client-facing. The logical
		// inbound owns one server auth/idle/masquerade policy for every alias.
		if value, ok := parentStream["hysteriaSettings"].(map[string]any); ok {
			cloned, cloneErr := cloneMap(value)
			if cloneErr != nil {
				return nil, cloneErr
			}
			stream["hysteriaSettings"] = cloned
		} else {
			stream["hysteriaSettings"] = map[string]any{}
		}
	default:
		return nil, fmt.Errorf("transport %q is not a supported same-port UDP profile family", network)
	}
	return stream, nil
}

func collapseSameProtocolUDPGroup(
	parent *model.Inbound,
	endpoints []runtimeCompiledEndpoint,
	indexes []int,
	parentStream map[string]any,
) (int, error) {
	if len(indexes) < 2 {
		return indexes[0], nil
	}
	network := runtimeNetwork(endpoints[indexes[0]].stream)
	if network == "hysteria" {
		if parent.Protocol != model.Hysteria {
			return 0, fmt.Errorf("Hysteria UDP groups require a Hysteria logical inbound")
		}
	} else if network == "kcp" {
		if parent.Protocol == model.Hysteria {
			return 0, fmt.Errorf("Hysteria logical inbounds cannot contain mKCP runtime profiles")
		}
	} else {
		return 0, fmt.Errorf("transport %q is not supported by same-port UDP aliasing", network)
	}

	owner := indexes[0]
	for _, index := range indexes {
		if endpoints[index].parent {
			owner = index
			break
		}
		if endpoints[index].config.Tag < endpoints[owner].config.Tag {
			owner = index
		}
	}

	canonical, err := canonicalUDPServerStream(parentStream, endpoints[owner])
	if err != nil {
		return 0, err
	}
	for _, index := range indexes {
		if runtimeNetwork(endpoints[index].stream) != network {
			return 0, fmt.Errorf("same UDP socket mixes transports %q and %q", network, runtimeNetwork(endpoints[index].stream))
		}
		candidate, candidateErr := canonicalUDPServerStream(parentStream, endpoints[index])
		if candidateErr != nil {
			return 0, candidateErr
		}
		if !runtimeStreamsEquivalent(canonical, candidate) ||
			!jsonDocumentsEquivalent(endpoints[owner].settings, endpoints[index].settings) {
			return 0, fmt.Errorf(
				"same UDP socket requires one compatible server policy; profile %q differs in security, server TLS/REALITY, FinalMask, Sockopt or protocol settings",
				endpoints[index].config.Tag,
			)
		}
	}

	streamJSON, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshal canonical UDP server stream: %w", err)
	}
	endpoints[owner].stream = canonical
	endpoints[owner].config.StreamSettings = streamJSON
	for _, index := range indexes {
		if index != owner {
			endpoints[index].suppressed = true
		}
	}
	return owner, nil
}

func planRuntimeProfileEndpoints(
	parent *model.Inbound,
	endpoints []runtimeCompiledEndpoint,
	allocator *sharedBackendAllocator,
) (runtimeProfileTopology, error) {
	if allocator == nil {
		allocator = newSharedBackendAllocator(nil)
	}
	// Always reserve the operator-visible sockets before allocating private
	// loopback backends. This keeps standalone validation/compiler call sites
	// safe even when they do not use the global config allocator.
	for index := range endpoints {
		allocator.reserve(endpoints[index].publicBinding)
	}

	groups := make(map[string][]int)
	for index := range endpoints {
		binding := endpoints[index].publicBinding
		key := runtimeBindingGroupKey(binding)
		groups[key] = append(groups[key], index)
	}

	// Overlapping but non-identical listens cannot be represented by one stable
	// public listener and would still race at bind time (e.g. 0.0.0.0 vs 127.0.0.1).
	for left := 0; left < len(endpoints); left++ {
		for right := left + 1; right < len(endpoints); right++ {
			if !runtimeBindingsConflict(endpoints[left].publicBinding, endpoints[right].publicBinding) {
				continue
			}
			if runtimeBindingGroupKey(endpoints[left].publicBinding) != runtimeBindingGroupKey(endpoints[right].publicBinding) {
				return runtimeProfileTopology{}, fmt.Errorf(
					"runtime socket %s overlaps %s through non-identical listen addresses; use the same listen value for automatic shared-port mode",
					runtimeBindingLabel(endpoints[right].publicBinding),
					endpoints[left].publicBinding.Tag,
				)
			}
		}
	}

	hasSharedTCPGroup := false
	for _, indexes := range groups {
		if len(indexes) > 1 && endpoints[indexes[0]].publicBinding.Transport == "tcp" {
			hasSharedTCPGroup = true
			break
		}
	}
	if hasSharedTCPGroup {
		transports := inboundTransports(parent.Protocol, parent.StreamSettings, parent.Settings)
		if transports&transportTCP != 0 && transports&transportUDP != 0 {
			return runtimeProfileTopology{}, fmt.Errorf(
				"inbound %d protocol %q owns both TCP and UDP on the parent socket; automatic TCP shared-port mode would move its UDP listener to a private backend. Restrict the parent to TCP or use a separate UDP inbound",
				parent.Id, parent.Protocol,
			)
		}
	}

	sharedPlan := frontmux.Plan{}
	publicBindings := make([]runtimeSocketBinding, 0, len(groups))
	groupKeys := make([]string, 0, len(groups))
	for key := range groups {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)

	for _, key := range groupKeys {
		indexes := groups[key]
		if len(indexes) == 1 {
			publicBindings = append(publicBindings, endpoints[indexes[0]].publicBinding)
			continue
		}
		binding := endpoints[indexes[0]].publicBinding
		if binding.Transport == "udp" {
			owner, err := collapseSameProtocolUDPGroup(parent, endpoints, indexes, endpoints[0].stream)
			if err != nil {
				return runtimeProfileTopology{}, fmt.Errorf(
					"inbound %d shared UDP socket %s: %w",
					parent.Id, runtimeBindingLabel(binding), err,
				)
			}
			publicBindings = append(publicBindings, endpoints[owner].publicBinding)
			continue
		}
		if runtime.GOOS != "linux" {
			return runtimeProfileTopology{}, fmt.Errorf("automatic shared-port mode currently requires Linux")
		}

		group := frontmux.Group{
			ID:                 fmt.Sprintf("%s%d-%s-%d", sharedPortTagPrefix, parent.Id, sanitizeTagPart(binding.Listen), binding.Port),
			Listen:             binding.Listen,
			Port:               binding.Port,
			ClassificationMS:   sharedPortClassificationMS,
			MaxInspectBytes:    sharedPortMaxInspectBytes,
			MaxConcurrentConns: sharedPortMaxConcurrentConns,
			Routes:             make([]frontmux.Route, 0, len(indexes)),
		}
		for _, endpointIndex := range indexes {
			endpoint := &endpoints[endpointIndex]
			backendListen, backendPort, err := allocator.allocate(endpoint.config.Tag)
			if err != nil {
				return runtimeProfileTopology{}, err
			}
			enableSharedBackendProxyProtocol(endpoint.stream)
			streamJSON, err := json.MarshalIndent(endpoint.stream, "", "  ")
			if err != nil {
				return runtimeProfileTopology{}, fmt.Errorf("marshal shared backend stream %q: %w", endpoint.config.Tag, err)
			}
			listenJSON, _ := json.Marshal(backendListen)
			endpoint.config.Listen = listenJSON
			endpoint.config.Port = backendPort
			endpoint.config.StreamSettings = streamJSON

			route, err := sharedRouteForEndpoint(*endpoint, backendListen)
			if err != nil {
				return runtimeProfileTopology{}, fmt.Errorf(
					"inbound %d endpoint %q cannot use automatic shared-port mode: %w",
					parent.Id, endpoint.config.Tag, err,
				)
			}
			group.Routes = append(group.Routes, route)
		}
		if err := group.Validate(); err != nil {
			return runtimeProfileTopology{}, fmt.Errorf("inbound %d shared socket %s: %w", parent.Id, runtimeBindingLabel(binding), err)
		}
		sharedPlan.Groups = append(sharedPlan.Groups, group)
		publicBindings = append(publicBindings, runtimeSocketBinding{
			Tag:       group.ID,
			Listen:    binding.Listen,
			Port:      binding.Port,
			Transport: "tcp",
			Synthetic: true,
		})
	}

	if err := sharedPlan.Validate(); err != nil {
		return runtimeProfileTopology{}, err
	}
	topology := runtimeProfileTopology{
		PublicBindings: publicBindings,
		SharedPlan:     sharedPlan.Canonical(),
	}
	for _, endpoint := range endpoints {
		if endpoint.suppressed {
			continue
		}
		if endpoint.parent {
			topology.Parent = endpoint.config
		} else {
			topology.Synthetic = append(topology.Synthetic, endpoint.config)
		}
	}
	return topology, nil
}

func sharedRouteForEndpoint(endpoint runtimeCompiledEndpoint, backendListen string) (frontmux.Route, error) {
	network := runtimeNetwork(endpoint.stream)
	security, _ := endpoint.stream["security"].(string)
	security = strings.ToLower(strings.TrimSpace(security))
	if security == "" {
		security = "none"
	}
	route := frontmux.Route{
		ID:       endpoint.config.Tag,
		Backend:  net.JoinHostPort(backendListen, fmt.Sprintf("%d", endpoint.config.Port)),
		Network:  network,
		Security: security,
	}

	switch security {
	case "tls", "reality":
		if security == "tls" && endpoint.clientECH {
			return frontmux.Route{}, fmt.Errorf("TLS ECH hides the routable SNI; disable ECH or use a distinct port")
		}
		sni, err := sharedEndpointServerName(endpoint)
		if err != nil {
			return frontmux.Route{}, err
		}
		route.Kind = frontmux.KindTLSSNI
		route.SNI = []string{sni}
		return route, nil
	case "none":
		switch network {
		case "tcp":
			route.Kind = frontmux.KindRaw
			return route, nil
		case "ws", "httpupgrade":
			hosts, paths, err := sharedHTTP1Selectors(endpoint.stream, network)
			if err != nil {
				return frontmux.Route{}, err
			}
			route.Kind = frontmux.KindHTTP1
			route.Hosts = hosts
			route.Paths = paths
			return route, nil
		case "grpc":
			route.Kind = frontmux.KindHTTP2
			return route, nil
		case "xhttp":
			return frontmux.Route{}, fmt.Errorf("cleartext XHTTP can negotiate HTTP/1 or HTTP/2 and is not unambiguous in phase 1; use TLS/REALITY with a unique SNI")
		default:
			return frontmux.Route{}, fmt.Errorf("transport %q is not supported by the TCP frontmux", network)
		}
	default:
		return frontmux.Route{}, fmt.Errorf("security %q is not supported", security)
	}
}

func sharedEndpointServerName(endpoint runtimeCompiledEndpoint) (string, error) {
	profile := endpoint.profile
	security, _ := endpoint.stream["security"].(string)
	var candidate string
	if profile != nil {
		if security == "tls" {
			if keepBlank, _ := profile["keepSniBlank"].(bool); keepBlank {
				return "", fmt.Errorf("SNI cannot be blank on a shared TLS socket")
			}
			if override, _ := profile["overrideSniFromAddress"].(bool); override {
				candidate, _ = profile["dest"].(string)
			}
			if candidate == "" {
				if tls, _ := profile["tlsSettings"].(map[string]any); tls != nil {
					candidate, _ = tls["serverName"].(string)
				}
			}
			if candidate == "" {
				candidate, _ = profile["sni"].(string)
			}
		} else {
			if reality, _ := profile["realitySettings"].(map[string]any); reality != nil {
				if settings, _ := reality["settings"].(map[string]any); settings != nil {
					candidate, _ = settings["serverName"].(string)
				}
				if candidate == "" {
					if names, _ := reality["serverNames"].([]any); len(names) == 1 {
						candidate, _ = names[0].(string)
					}
				}
			}
		}
	}
	if candidate == "" {
		if security == "tls" {
			if tls, _ := endpoint.stream["tlsSettings"].(map[string]any); tls != nil {
				candidate, _ = tls["serverName"].(string)
			}
		} else if reality, _ := endpoint.stream["realitySettings"].(map[string]any); reality != nil {
			if names, _ := reality["serverNames"].([]any); len(names) == 1 {
				candidate, _ = names[0].(string)
			}
		}
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", fmt.Errorf("a non-empty exact client SNI/serverName is required")
	}
	normalized, err := frontmux.NormalizeServerName(candidate)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(normalized, "*") {
		return "", fmt.Errorf("wildcard SNI %q is not an exact routing selector", candidate)
	}
	return normalized, nil
}

func sharedHTTP1Selectors(stream map[string]any, network string) ([]string, []string, error) {
	settingsKey := runtimeTransportKey(network)
	settings, _ := stream[settingsKey].(map[string]any)
	if settings == nil {
		return nil, nil, fmt.Errorf("missing %s", settingsKey)
	}
	path, _ := settings["path"].(string)
	normalizedPath, err := frontmux.NormalizeHTTPPath(path)
	if err != nil {
		return nil, nil, err
	}
	hosts := []string{}
	if host, _ := settings["host"].(string); strings.TrimSpace(host) != "" {
		normalized, err := frontmux.NormalizeHTTPHost(host)
		if err != nil {
			return nil, nil, err
		}
		if normalized != "" {
			hosts = append(hosts, normalized)
		}
	}
	if headers, _ := settings["headers"].(map[string]any); headers != nil {
		for key, value := range headers {
			if !strings.EqualFold(strings.TrimSpace(key), "host") {
				continue
			}
			switch typed := value.(type) {
			case string:
				normalized, err := frontmux.NormalizeHTTPHost(typed)
				if err != nil {
					return nil, nil, err
				}
				if normalized != "" {
					hosts = append(hosts, normalized)
				}
			case []any:
				for _, raw := range typed {
					text, ok := raw.(string)
					if !ok {
						continue
					}
					normalized, err := frontmux.NormalizeHTTPHost(text)
					if err != nil {
						return nil, nil, err
					}
					if normalized != "" {
						hosts = append(hosts, normalized)
					}
				}
			}
		}
	}
	return uniqueSortedStrings(hosts), []string{normalizedPath}, nil
}

func effectiveProfileUsesECH(parentStream, profile map[string]any) bool {
	if profile != nil {
		if value, _ := profile["echConfigList"].(string); strings.TrimSpace(value) != "" {
			return true
		}
		if tls, present := profile["tlsSettings"].(map[string]any); present {
			settings, _ := tls["settings"].(map[string]any)
			value, _ := settings["echConfigList"].(string)
			// A profile-level TLS object replaces the inherited client TLS
			// settings, so an explicit blank value also disables inherited ECH.
			return strings.TrimSpace(value) != ""
		}
	}
	tls, _ := parentStream["tlsSettings"].(map[string]any)
	settings, _ := tls["settings"].(map[string]any)
	value, _ := settings["echConfigList"].(string)
	return strings.TrimSpace(value) != ""
}

func enableSharedBackendProxyProtocol(stream map[string]any) {
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		sockopt = map[string]any{}
		stream["sockopt"] = sockopt
	}
	sockopt["acceptProxyProtocol"] = true
	settingsKey := ""
	switch runtimeNetwork(stream) {
	case "tcp":
		settingsKey = "tcpSettings"
	case "ws":
		settingsKey = "wsSettings"
	case "httpupgrade":
		settingsKey = "httpupgradeSettings"
	}
	if settingsKey != "" {
		settings, _ := stream[settingsKey].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			stream[settingsKey] = settings
		}
		settings["acceptProxyProtocol"] = true
	}
}

func runtimeBindingGroupKey(binding runtimeSocketBinding) string {
	return binding.Transport + "|" + binding.Listen + "|" + fmt.Sprintf("%d", binding.Port)
}

func sanitizeTagPart(value string) string {
	replacer := strings.NewReplacer(":", "-", ".", "-", "[", "", "]", "")
	value = strings.Trim(replacer.Replace(value), "-")
	if value == "" || value == "0-0-0-0" || value == "--" {
		return "any"
	}
	return value
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// newSharedBackendAllocatorForConfig reserves every public/listener port that
// can appear in the final runtime before selecting private frontmux backends.
// Reserving the whole TCP port (rather than one address) prevents a backend on
// 127/8 from later colliding with a wildcard listener injected after the main
// inbound pass.
func newSharedBackendAllocatorForConfig(
	cfg *xray.Config,
	inbounds []*model.Inbound,
) (*sharedBackendAllocator, error) {
	allocator := newSharedBackendAllocator(nil)
	if cfg != nil {
		for index := range cfg.InboundConfigs {
			binding, err := runtimeBindingFromInboundConfig(&cfg.InboundConfigs[index])
			if err != nil {
				return nil, fmt.Errorf("template inbound %q: %w", cfg.InboundConfigs[index].Tag, err)
			}
			allocator.reserve(binding)
		}
	}

	// The API listener is injected by Xray process startup and may not be
	// present in the user template. Reserve it explicitly.
	allocator.reserve(runtimeSocketBinding{
		Tag:       "api",
		Listen:    "127.0.0.1",
		Port:      reservedAPIPort(),
		Transport: "tcp",
	})

	for _, inbound := range inbounds {
		if inbound == nil || !inbound.Enable || inbound.NodeID != nil {
			continue
		}
		// Reserve the numeric port conservatively even for UDP-only parents.
		// A later protocol/settings heal can turn it into a TCP listener, and a
		// private backend must never occupy an operator-visible public port.
		allocator.reserve(runtimeSocketBinding{
			Tag:       inbound.Tag,
			Listen:    "0.0.0.0",
			Port:      inbound.Port,
			Transport: "tcp",
		})

		var stream map[string]any
		if strings.TrimSpace(inbound.StreamSettings) == "" {
			continue
		}
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &stream); err != nil {
			return nil, fmt.Errorf("inbound %d stream settings: %w", inbound.Id, err)
		}
		if _, err := normalizeAutomaticRuntimeProfilesInPlace(stream); err != nil {
			return nil, fmt.Errorf("inbound %d automatic runtime metadata: %w", inbound.Id, err)
		}
		entries, _ := stream["externalProxy"].([]any)
		for index, raw := range entries {
			profile, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if !automaticRuntimeProfileActive(profile) {
				continue
			}
			spec, err := parseRuntimeProfileSpec(profile)
			if err != nil {
				return nil, fmt.Errorf("inbound %d profile %d: %w", inbound.Id, index+1, err)
			}
			port, err := resolveRuntimeProfilePort(profile, inbound.Port)
			if err != nil {
				return nil, fmt.Errorf("inbound %d profile %q: %w", inbound.Id, spec.ID, err)
			}
			allocator.reserve(runtimeSocketBinding{
				Tag:       runtimeProfileTag(inbound.Id, spec.ID),
				Listen:    "0.0.0.0",
				Port:      port,
				Transport: "tcp",
			})
		}
	}
	return allocator, nil
}

// validateSharedPortPlanAgainstXrayConfig proves that every public frontmux
// socket is absent from Xray's listener set. Private loopback backends are
// already represented in cfg.InboundConfigs and therefore remain covered by
// validateRuntimeProfileBindings.
func validateSharedPortPlanAgainstXrayConfig(cfg *xray.Config) error {
	if cfg == nil || cfg.SharedPortPlan.Empty() {
		return nil
	}
	if err := cfg.SharedPortPlan.Validate(); err != nil {
		return fmt.Errorf("shared-port plan validation failed: %w", err)
	}

	xrayBindings := make([]runtimeSocketBinding, 0, len(cfg.InboundConfigs))
	for index := range cfg.InboundConfigs {
		binding, err := runtimeBindingFromInboundConfig(&cfg.InboundConfigs[index])
		if err != nil {
			return fmt.Errorf("generated inbound %q: %w", cfg.InboundConfigs[index].Tag, err)
		}
		xrayBindings = append(xrayBindings, binding)
	}

	for _, group := range cfg.SharedPortPlan.Groups {
		public := runtimeSocketBinding{
			Tag:       group.ID,
			Listen:    group.Listen,
			Port:      group.Port,
			Transport: "tcp",
			Synthetic: true,
		}
		for _, binding := range xrayBindings {
			if !runtimeBindingsConflict(public, binding) {
				continue
			}
			return fmt.Errorf(
				"shared-port listener %s conflicts with generated Xray inbound %q",
				runtimeBindingLabel(public),
				binding.Tag,
			)
		}
	}
	return nil
}
