package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

// modernSubscriptionProfileLinks is the raw/share-link counterpart of the
// JSON and Clash effective-stream paths. Legacy externalProxy-only records keep
// using the historical generators; a modern profile list is rendered from each
// profile's merged transport/security stream instead of reusing the inbound
// stream for every endpoint.
func (s *SubService) modernSubscriptionProfileLinks(
	inbound *model.Inbound,
	email string,
) (string, bool) {
	if inbound == nil {
		return "", false
	}

	baseStream := unmarshalStreamSettings(inbound.StreamSettings)
	rawProfiles, ok := baseStream["externalProxy"].([]any)
	if !ok || len(rawProfiles) == 0 {
		return "", false
	}

	hasModernProfile := false
	for _, rawProfile := range rawProfiles {
		profile, _ := rawProfile.(map[string]any)
		if isModernSubscriptionProfile(profile) {
			hasModernProfile = true
			break
		}
	}
	if !hasModernProfile {
		return "", false
	}

	switch inbound.Protocol {
	case model.VMESS, model.VLESS, model.Trojan, model.Shadowsocks:
	default:
		return "", false
	}

	client, ok := s.clientForLink(inbound, email)
	if !ok {
		return "", true
	}

	defaultAddress := s.resolveInboundAddress(inbound)
	links := make([]string, 0, len(rawProfiles))

	for _, rawProfile := range rawProfiles {
		profile, ok := rawProfile.(map[string]any)
		if !ok || profile == nil {
			continue
		}
		if enabled, present := profile["enabled"].(bool); present && !enabled {
			continue
		}

		if !isModernSubscriptionProfile(profile) {
			links = append(
				links,
				s.legacySubscriptionProfileLinks(
					inbound,
					email,
					baseStream,
					profile,
				)...,
			)
			continue
		}

		singleStream, _ := deepCloneJSON(
			baseStream,
		).(map[string]any)
		if singleStream == nil {
			continue
		}

		singleStream["externalProxy"] = []any{
			deepCloneJSON(profile),
		}

		endpoints := expandSubscriptionEndpoints(
			singleStream,
			defaultAddress,
			inbound.Port,
		)

		for _, endpoint := range endpoints {
			if endpoint.Profile != nil &&
				endpointExcludedFromSubType(
					endpoint.Profile,
					"raw",
				) {
				continue
			}
			if endpoint.Profile != nil &&
				!subscriptionProfileFormatCompatible(
					endpoint.Profile,
					endpoint.Stream,
					subscriptionFormatRaw,
				) {
				continue
			}

			link := s.modernSubscriptionProfileLink(
				inbound,
				client,
				email,
				endpoint,
			)
			if link != "" {
				links = append(links, link)
			}
		}
	}

	return strings.Join(links, "\n"), true
}

func (s *SubService) legacySubscriptionProfileLinks(
	inbound *model.Inbound,
	email string,
	baseStream map[string]any,
	profile map[string]any,
) []string {
	legacyStream, _ := deepCloneJSON(
		baseStream,
	).(map[string]any)
	if legacyStream == nil {
		return nil
	}

	legacyStream["externalProxy"] = []any{
		deepCloneJSON(profile),
	}

	encoded, err := json.Marshal(legacyStream)
	if err != nil {
		return nil
	}

	legacyInbound := *inbound
	legacyInbound.StreamSettings = string(encoded)

	rendered := strings.TrimSpace(
		s.getLegacyLink(&legacyInbound, email),
	)
	if rendered == "" {
		return nil
	}

	return strings.Split(rendered, "\n")
}

func (s *SubService) modernSubscriptionProfileLink(
	inbound *model.Inbound,
	client model.Client,
	email string,
	endpoint subscriptionEndpoint,
) string {
	switch inbound.Protocol {
	case model.VMESS:
		return s.modernVMessProfileLink(
			inbound,
			client,
			email,
			endpoint,
		)
	case model.VLESS:
		return s.modernVLESSProfileLink(
			inbound,
			client,
			email,
			endpoint,
		)
	case model.Trojan:
		return s.modernTrojanProfileLink(
			inbound,
			client,
			email,
			endpoint,
		)
	case model.Shadowsocks:
		return s.modernShadowsocksProfileLink(
			inbound,
			client,
			email,
			endpoint,
		)
	default:
		return ""
	}
}

func (s *SubService) modernProfileRemark(
	inbound *model.Inbound,
	email string,
	endpoint subscriptionEndpoint,
	network string,
) string {
	if endpoint.Profile != nil {
		return s.endpointRemark(
			inbound,
			email,
			endpoint.Profile,
			network,
		)
	}

	return s.genRemark(inbound, email, "", network)
}

func normalizedProfileSecurity(stream map[string]any) string {
	security := strings.ToLower(
		strings.TrimSpace(stringValue(stream["security"])),
	)
	if security == "" {
		return "none"
	}
	return security
}

func (s *SubService) modernVMessProfileLink(
	inbound *model.Inbound,
	client model.Client,
	email string,
	endpoint subscriptionEndpoint,
) string {
	stream := endpoint.Stream
	network := stringValue(stream["network"])

	obj := map[string]any{
		"v":    "2",
		"add":  endpoint.Address,
		"port": endpoint.Port,
		"type": "none",
		"id":   client.ID,
		"scy":  normalizeVmessSecurity(client.Security),
	}

	applyVmessNetworkParams(stream, network, obj)

	if finalMask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskObj(finalMask, obj)
	}

	security := normalizedProfileSecurity(stream)
	obj["tls"] = security

	if security == "tls" {
		applyVmessTLSParams(stream, obj)
	}

	obj["ps"] = s.modernProfileRemark(
		inbound,
		email,
		endpoint,
		network,
	)

	return buildVmessLink(obj)
}

func (s *SubService) modernVLESSProfileLink(
	inbound *model.Inbound,
	client model.Client,
	email string,
	endpoint subscriptionEndpoint,
) string {
	stream := endpoint.Stream
	network := stringValue(stream["network"])
	params := map[string]string{
		"type": network,
	}

	inboundSettings := s.linkSettings(inbound)
	if encryption, ok := inboundSettings["encryption"].(string); ok {
		params["encryption"] = encryption
	}

	applyShareNetworkParams(stream, network, params)

	if finalMask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalMask, params)
	}

	security := normalizedProfileSecurity(stream)
	switch security {
	case "tls":
		applyShareTLSParams(stream, params)
	case "reality":
		applyShareRealityParams(stream, params, subKey(client))
	default:
		params["security"] = "none"
	}

	flow := client.Flow
	if override, exists := subscriptionProfileFlowOverride(endpoint.Profile); exists {
		flow = override
	}
	if flow != "" && vlessFlowAllowed(network, security, inboundSettings) {
		params["flow"] = flow
	}

	clientID := client.ID
	if endpoint.Profile != nil {
		clientID = applyVlessRoute(
			clientID,
			hostVlessRoute(endpoint.Profile),
		)
	}

	base := fmt.Sprintf(
		"vless://%s@%s",
		clientID,
		joinHostPort(endpoint.Address, endpoint.Port),
	)

	return buildLinkWithParams(
		base,
		params,
		s.modernProfileRemark(
			inbound,
			email,
			endpoint,
			network,
		),
	)
}

func (s *SubService) modernTrojanProfileLink(
	inbound *model.Inbound,
	client model.Client,
	email string,
	endpoint subscriptionEndpoint,
) string {
	stream := endpoint.Stream
	network := stringValue(stream["network"])
	params := map[string]string{
		"type": network,
	}

	applyShareNetworkParams(stream, network, params)

	if finalMask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalMask, params)
	}

	security := normalizedProfileSecurity(stream)
	switch security {
	case "tls":
		applyShareTLSParams(stream, params)
	case "reality":
		applyShareRealityParams(stream, params, subKey(client))
		if network == "tcp" && client.Flow != "" {
			params["flow"] = client.Flow
		}
	default:
		params["security"] = "none"
	}

	base := fmt.Sprintf(
		"trojan://%s@%s",
		encodeUserinfo(client.Password),
		joinHostPort(endpoint.Address, endpoint.Port),
	)

	return buildLinkWithParams(
		base,
		params,
		s.modernProfileRemark(
			inbound,
			email,
			endpoint,
			network,
		),
	)
}

func (s *SubService) modernShadowsocksProfileLink(
	inbound *model.Inbound,
	client model.Client,
	email string,
	endpoint subscriptionEndpoint,
) string {
	inboundSettings := s.linkSettings(inbound)
	method := stringValue(inboundSettings["method"])
	inboundPassword := stringValue(inboundSettings["password"])

	var userInfo string
	if strings.HasPrefix(method, "2022") {
		userInfo = fmt.Sprintf(
			"%s:%s:%s",
			url.QueryEscape(method),
			url.QueryEscape(inboundPassword),
			url.QueryEscape(client.Password),
		)
	} else {
		userInfo = base64.RawURLEncoding.EncodeToString(
			[]byte(fmt.Sprintf("%s:%s", method, client.Password)),
		)
	}

	stream := endpoint.Stream
	network := stringValue(stream["network"])
	params := map[string]string{
		"type": network,
	}

	applyShareNetworkParams(stream, network, params)

	if finalMask, ok := stream["finalmask"].(map[string]any); ok {
		applyFinalMaskParams(finalMask, params)
	}

	security := normalizedProfileSecurity(stream)
	switch security {
	case "tls":
		applyShareTLSParams(stream, params)
	case "reality":
		applyShareRealityParams(stream, params, subKey(client))
	default:
		params["security"] = "none"
	}
	params["security"] = security

	// Keep SIP002 TCP HTTP-header compatibility identical to the historical
	// generator.
	if network == "tcp" && params["headerType"] == "http" {
		host := params["host"]
		delete(params, "type")
		delete(params, "headerType")
		delete(params, "host")
		delete(params, "path")
		params["plugin"] = "obfs-local;obfs=http;obfs-host=" + host
	}

	base := fmt.Sprintf(
		"ss://%s@%s",
		userInfo,
		joinHostPort(endpoint.Address, endpoint.Port),
	)

	return buildLinkWithParams(
		base,
		params,
		s.modernProfileRemark(
			inbound,
			email,
			endpoint,
			network,
		),
	)
}
